//! One bounded asynchronous writer for the existing plain-text output log.
//! Producers never wait for disk I/O or queue space. Explicit flush/shutdown
//! waits are bounded; a stalled underlying writer can outlive that deadline.

use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const RECORD_LIMIT: usize = 4096;
const BYTE_LIMIT: usize = 4 * 1024 * 1024;
const BUFFER_SIZE: usize = 64 * 1024;
const FLUSH_INTERVAL: Duration = Duration::from_millis(50);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const OPEN: u8 = 0;
const CLOSING: u8 = 1;
const CLOSED: u8 = 2;
const FAILED: u8 = 3;

#[derive(Clone, Copy)]
pub(crate) enum Source {
    Host = 0,
    Agent = 1,
    Kernel = 2,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LogOutputStats {
    /// Records admitted to the asynchronous queue, not persistence receipts.
    pub accepted: u64,
    /// Records accepted by BufWriter, including bytes not yet flushed.
    pub processed: u64,
    pub pending_records: usize,
    /// Allocated String capacity held by queued/in-flight records.
    pub pending_bytes: usize,
    pub buffered_bytes: usize,
    pub bytes_written: u64,
    pub write_calls: u64,
    pub io_ns: u64,
    /// Includes admission rejection and queued records discarded after failure.
    pub host_dropped: u64,
    pub agent_dropped: u64,
    pub kernel_dropped: u64,
    pub errors: u64,
    pub last_error: Option<String>,
    pub closed: bool,
}

#[derive(Clone, Debug)]
struct StoredError {
    kind: io::ErrorKind,
    message: String,
}

impl StoredError {
    fn from_io(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn to_io(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

struct Shared {
    accepted: AtomicU64,
    processed: AtomicU64,
    pending_records: AtomicUsize,
    pending_bytes: AtomicUsize,
    buffered_bytes: AtomicUsize,
    bytes_written: AtomicU64,
    write_calls: AtomicU64,
    io_ns: AtomicU64,
    dropped: [AtomicU64; 3],
    errors: AtomicU64,
    first_error: OnceLock<StoredError>,
    status: AtomicU8,
    completed: Mutex<bool>,
    completion: Condvar,
}

impl Shared {
    fn new() -> Self {
        Self {
            accepted: AtomicU64::new(0),
            processed: AtomicU64::new(0),
            pending_records: AtomicUsize::new(0),
            pending_bytes: AtomicUsize::new(0),
            buffered_bytes: AtomicUsize::new(0),
            bytes_written: AtomicU64::new(0),
            write_calls: AtomicU64::new(0),
            io_ns: AtomicU64::new(0),
            dropped: std::array::from_fn(|_| AtomicU64::new(0)),
            errors: AtomicU64::new(0),
            first_error: OnceLock::new(),
            status: AtomicU8::new(OPEN),
            completed: Mutex::new(false),
            completion: Condvar::new(),
        }
    }

    fn drop_record(&self, source: Source) {
        self.dropped[source as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn check(&self) -> io::Result<()> {
        if let Some(error) = self.first_error.get() {
            return Err(error.to_io());
        }
        if self.status.load(Ordering::Acquire) != OPEN {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "output writer is closed"));
        }
        Ok(())
    }

    fn fail(&self, error: io::Error) {
        if self.first_error.set(StoredError::from_io(error)).is_ok() {
            self.errors.fetch_add(1, Ordering::Relaxed);
            // Deliberately bypass logger: routing this through it would recurse
            // into the failed output. Only the first writer error is printed.
            eprintln!("[output] 写入失败: {}", self.first_error.get().unwrap().message);
        }
        self.status.store(FAILED, Ordering::Release);
    }

    fn complete(&self) {
        if self.status.load(Ordering::Acquire) != FAILED {
            self.status.store(CLOSED, Ordering::Release);
        }
        *self.completed.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.completion.notify_all();
    }

    fn wait_completed(&self, timeout: Duration) -> io::Result<()> {
        let complete = self.completed.lock().unwrap_or_else(|p| p.into_inner());
        let (complete, _) = self
            .completion
            .wait_timeout_while(complete, timeout, |done| !*done)
            .unwrap_or_else(|p| p.into_inner());
        if !*complete {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "output shutdown timed out"));
        }
        self.first_error.get().map_or(Ok(()), |error| Err(error.to_io()))
    }

    fn stats(&self) -> LogOutputStats {
        LogOutputStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            processed: self.processed.load(Ordering::Relaxed),
            pending_records: self.pending_records.load(Ordering::Relaxed),
            pending_bytes: self.pending_bytes.load(Ordering::Relaxed),
            buffered_bytes: self.buffered_bytes.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            write_calls: self.write_calls.load(Ordering::Relaxed),
            io_ns: self.io_ns.load(Ordering::Relaxed),
            host_dropped: self.dropped[0].load(Ordering::Relaxed),
            agent_dropped: self.dropped[1].load(Ordering::Relaxed),
            kernel_dropped: self.dropped[2].load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            last_error: self.first_error.get().map(|error| error.message.clone()),
            closed: self.status.load(Ordering::Acquire) != OPEN,
        }
    }
}

struct Record {
    text: String,
    source: Source,
    shared: Arc<Shared>,
    processed: bool,
}

impl Drop for Record {
    fn drop(&mut self) {
        if !self.processed {
            self.shared.drop_record(self.source);
        }
        self.shared.pending_records.fetch_sub(1, Ordering::Relaxed);
        self.shared
            .pending_bytes
            .fetch_sub(self.text.capacity(), Ordering::Relaxed);
    }
}

enum Message {
    Record(Record),
    Flush(mpsc::SyncSender<Result<(), StoredError>>),
    Shutdown,
}

pub(crate) struct AsyncOutput {
    sender: mpsc::SyncSender<Message>,
    shared: Arc<Shared>,
    // Serializes publication and shutdown only; never held across disk I/O,
    // payload formatting, a wait for queue capacity, or a flush acknowledgement.
    admission: Mutex<()>,
    handle: Mutex<Option<JoinHandle<()>>>,
    record_limit: usize,
    byte_limit: usize,
}

impl AsyncOutput {
    pub(crate) fn new(writer: impl Write + Send + 'static) -> io::Result<Self> {
        Self::with_limits(writer, RECORD_LIMIT, BYTE_LIMIT)
    }

    fn with_limits(writer: impl Write + Send + 'static, record_limit: usize, byte_limit: usize) -> io::Result<Self> {
        let shared = Arc::new(Shared::new());
        // Keep a few control slots independent of the record admission limit.
        let (sender, receiver) = mpsc::sync_channel(record_limit + 16);
        let worker_shared = shared.clone();
        let handle = thread::Builder::new().name("log-output".into()).spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_writer(writer, receiver, &worker_shared)
            }));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => worker_shared.fail(error),
                Err(_) => worker_shared.fail(io::Error::other("output writer panicked")),
            }
            worker_shared.complete();
        })?;
        Ok(Self {
            sender,
            shared,
            admission: Mutex::new(()),
            handle: Mutex::new(Some(handle)),
            record_limit,
            byte_limit,
        })
    }

    pub(crate) fn enqueue(&self, source: Source, text: String) -> io::Result<()> {
        let _admission = self.admission.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(error) = self.shared.check() {
            self.shared.drop_record(source);
            return Err(error);
        }
        let pending_bytes = self.shared.pending_bytes.load(Ordering::Relaxed);
        if self.shared.pending_records.load(Ordering::Relaxed) >= self.record_limit
            || text.capacity() > self.byte_limit.saturating_sub(pending_bytes)
        {
            self.shared.drop_record(source);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "output queue budget exhausted",
            ));
        }
        self.shared.pending_records.fetch_add(1, Ordering::Relaxed);
        self.shared.pending_bytes.fetch_add(text.capacity(), Ordering::Relaxed);
        let message = Message::Record(Record {
            text,
            source,
            shared: self.shared.clone(),
            processed: false,
        });
        match self.sender.try_send(message) {
            Ok(()) => {
                self.shared.accepted.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::TrySendError::Full(_)) => Err(io::Error::new(io::ErrorKind::WouldBlock, "output queue full")),
            Err(mpsc::TrySendError::Disconnected(_)) => self.shared.first_error.get().map_or_else(
                || Err(io::Error::new(io::ErrorKind::BrokenPipe, "output writer disconnected")),
                |error| Err(error.to_io()),
            ),
        }
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        self.shared.check()
    }

    pub(crate) fn stats(&self) -> LogOutputStats {
        self.shared.stats()
    }

    pub(crate) fn flush(&self) -> io::Result<()> {
        let (reply, receiver) = mpsc::sync_channel(1);
        {
            let _admission = self.admission.lock().unwrap_or_else(|p| p.into_inner());
            self.shared.check()?;
            self.sender
                .try_send(Message::Flush(reply))
                .map_err(|error| match error {
                    mpsc::TrySendError::Full(_) => {
                        io::Error::new(io::ErrorKind::WouldBlock, "output control queue full")
                    }
                    mpsc::TrySendError::Disconnected(_) => {
                        io::Error::new(io::ErrorKind::BrokenPipe, "output writer disconnected")
                    }
                })?;
        }
        match receiver.recv_timeout(CONTROL_TIMEOUT) {
            Ok(result) => result.map_err(|error| error.to_io()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(io::Error::new(io::ErrorKind::TimedOut, "output flush timed out"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => self.shared.first_error.get().map_or_else(
                || Err(io::Error::new(io::ErrorKind::BrokenPipe, "output writer disconnected")),
                |error| Err(error.to_io()),
            ),
        }
    }

    pub(crate) fn shutdown(&self) -> io::Result<()> {
        self.shutdown_with_timeout(CONTROL_TIMEOUT)
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> io::Result<()> {
        {
            let _admission = self.admission.lock().unwrap_or_else(|p| p.into_inner());
            if self.shared.status.load(Ordering::Acquire) == OPEN {
                self.shared.status.store(CLOSING, Ordering::Release);
                if let Err(error) = self.sender.try_send(Message::Shutdown) {
                    if matches!(error, mpsc::TrySendError::Full(_)) {
                        self.shared.status.store(OPEN, Ordering::Release);
                        return Err(io::Error::new(io::ErrorKind::WouldBlock, "output control queue full"));
                    }
                }
            }
        }
        let result = self.shared.wait_completed(timeout);
        // Never turn the bounded wait into an unbounded join.
        let mut handle = self.handle.lock().unwrap_or_else(|p| p.into_inner());
        if handle.as_ref().is_some_and(JoinHandle::is_finished) {
            let _ = handle.take().unwrap().join();
        }
        result
    }
}

struct MeasuredWriter<W> {
    writer: W,
    shared: Arc<Shared>,
}

impl<W: Write> Write for MeasuredWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let start = Instant::now();
        let result = self.writer.write(bytes);
        self.shared.io_ns.fetch_add(
            start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        self.shared.write_calls.fetch_add(1, Ordering::Relaxed);
        if let Ok(count) = result {
            self.shared.bytes_written.fetch_add(count as u64, Ordering::Relaxed);
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        let start = Instant::now();
        let result = self.writer.flush();
        self.shared.io_ns.fetch_add(
            start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        result
    }
}

fn flush_buffer<W: Write>(
    writer: &mut BufWriter<MeasuredWriter<W>>,
    pending: &mut Option<Instant>,
    shared: &Shared,
) -> io::Result<()> {
    let result = writer.flush();
    shared.buffered_bytes.store(writer.buffer().len(), Ordering::Relaxed);
    if writer.buffer().is_empty() {
        *pending = None;
    }
    result
}

fn run_writer<W: Write>(writer: W, receiver: mpsc::Receiver<Message>, shared: &Arc<Shared>) -> io::Result<()> {
    let mut writer = BufWriter::with_capacity(
        BUFFER_SIZE,
        MeasuredWriter {
            writer,
            shared: shared.clone(),
        },
    );
    let mut pending_since: Option<Instant> = None;
    let result = (|| {
        loop {
            let wait = pending_since.map_or(FLUSH_INTERVAL, |since| FLUSH_INTERVAL.saturating_sub(since.elapsed()));
            match receiver.recv_timeout(wait) {
                Ok(Message::Record(mut record)) => {
                    let calls_before = shared.write_calls.load(Ordering::Relaxed);
                    let result = writer.write_all(record.text.as_bytes());
                    shared.buffered_bytes.store(writer.buffer().len(), Ordering::Relaxed);
                    if writer.buffer().is_empty() {
                        pending_since = None;
                    } else if pending_since.is_none()
                        || (result.is_ok() && shared.write_calls.load(Ordering::Relaxed) != calls_before)
                    {
                        pending_since = Some(Instant::now());
                    }
                    result?;
                    record.processed = true;
                    shared.processed.fetch_add(1, Ordering::Relaxed);
                    drop(record);
                    if writer.buffer().len() == writer.capacity()
                        || pending_since.is_some_and(|since| since.elapsed() >= FLUSH_INTERVAL)
                    {
                        flush_buffer(&mut writer, &mut pending_since, shared)?;
                    }
                }
                Ok(Message::Flush(reply)) => {
                    let result = flush_buffer(&mut writer, &mut pending_since, shared);
                    let response = result.as_ref().map(|_| ()).map_err(|error| StoredError {
                        kind: error.kind(),
                        message: error.to_string(),
                    });
                    // Publish sticky failure before the acknowledgement wakes a caller.
                    if let Err(error) = &response {
                        shared.fail(error.to_io());
                    }
                    let _ = reply.send(response);
                    result?;
                }
                Ok(Message::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    flush_buffer(&mut writer, &mut pending_since, shared)?;
                    return Ok(());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if pending_since.is_some() {
                        flush_buffer(&mut writer, &mut pending_since, shared)?;
                    }
                }
            }
        }
    })();
    // An error must not trigger another implicit BufWriter write during drop.
    // The failed bytes remain accounted for by the sticky error/byte counters.
    let _ = writer.into_parts();
    shared.buffered_bytes.store(0, Ordering::Relaxed);
    // Drop queued tickets before signalling completion to shutdown callers.
    drop(receiver);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Written {
        bytes: Vec<u8>,
        calls: u64,
    }

    struct FakeWriter {
        written: Arc<Mutex<Written>>,
        first_write: Option<mpsc::Sender<()>>,
        release: Option<mpsc::Receiver<()>>,
        max_write: usize,
        fail_after: Option<usize>,
    }

    impl FakeWriter {
        fn new() -> (Self, Arc<Mutex<Written>>) {
            let written = Arc::new(Mutex::new(Written::default()));
            (
                Self {
                    written: written.clone(),
                    first_write: None,
                    release: None,
                    max_write: usize::MAX,
                    fail_after: None,
                },
                written,
            )
        }
    }

    impl Write for FakeWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(first) = self.first_write.take() {
                first.send(()).unwrap();
            }
            if let Some(release) = self.release.take() {
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            let mut written = self.written.lock().unwrap();
            written.calls += 1;
            let remaining = self
                .fail_after
                .map_or(usize::MAX, |limit| limit.saturating_sub(written.bytes.len()));
            if remaining == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "synthetic broken writer"));
            }
            let count = bytes.len().min(self.max_write).min(remaining);
            written.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stalled_writer_keeps_record_budget_and_nonblocking_source_drops() {
        let (mut writer, written) = FakeWriter::new();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        writer.first_write = Some(started_tx);
        writer.release = Some(release_rx);
        let output = AsyncOutput::with_limits(writer, 3, BUFFER_SIZE * 2).unwrap();
        let first = "h".repeat(BUFFER_SIZE);
        output.enqueue(Source::Host, first.clone()).unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        output.enqueue(Source::Agent, "agent\n".into()).unwrap();
        output.enqueue(Source::Kernel, "kernel\n".into()).unwrap();
        for source in [Source::Host, Source::Agent, Source::Kernel] {
            assert_eq!(
                output.enqueue(source, "overflow\n".into()).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
        let stats = output.stats();
        assert_eq!(stats.accepted, 3);
        assert_eq!(stats.pending_records, 3);
        assert_eq!(
            (stats.host_dropped, stats.agent_dropped, stats.kernel_dropped),
            (1, 1, 1)
        );
        assert_eq!(
            output
                .shutdown_with_timeout(Duration::from_millis(10))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(output.check().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        release_tx.send(()).unwrap();
        output.shutdown().unwrap();
        let stats = output.stats();
        assert_eq!(stats.processed, 3);
        assert_eq!(
            (stats.pending_records, stats.pending_bytes, stats.buffered_bytes),
            (0, 0, 0)
        );
        assert_eq!(
            written.lock().unwrap().bytes,
            format!("{first}agent\nkernel\n").as_bytes()
        );
    }

    #[test]
    fn byte_budget_counts_owned_capacity_even_for_short_strings() {
        let (writer, _) = FakeWriter::new();
        let output = AsyncOutput::with_limits(writer, 10, 32).unwrap();
        let mut oversized = String::with_capacity(33);
        oversized.push('x');
        assert_eq!(
            output.enqueue(Source::Agent, oversized).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let stats = output.stats();
        assert_eq!(stats.accepted, 0);
        assert_eq!(stats.agent_dropped, 1);
        assert_eq!((stats.pending_records, stats.pending_bytes), (0, 0));
        output.shutdown().unwrap();
    }

    #[test]
    fn byte_budget_also_bounds_multiple_pending_records() {
        let (mut writer, _) = FakeWriter::new();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        writer.first_write = Some(started_tx);
        writer.release = Some(release_rx);
        let output = AsyncOutput::with_limits(writer, 10, BUFFER_SIZE + 8).unwrap();
        output.enqueue(Source::Host, "h".repeat(BUFFER_SIZE)).unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        output.enqueue(Source::Agent, "12345678".into()).unwrap();
        assert_eq!(
            output.enqueue(Source::Kernel, "x".into()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(output.stats().pending_bytes, BUFFER_SIZE + 8);
        assert_eq!(output.stats().pending_records, 2);
        assert_eq!(output.stats().kernel_dropped, 1);
        release_tx.send(()).unwrap();
        output.shutdown().unwrap();
        assert_eq!(output.stats().pending_bytes, 0);
    }

    #[test]
    fn flush_reports_partial_write_failure_and_check_keeps_it_sticky() {
        let (mut writer, written) = FakeWriter::new();
        writer.max_write = 2;
        writer.fail_after = Some(5);
        let output = AsyncOutput::new(writer).unwrap();
        output.enqueue(Source::Host, "0123456789".into()).unwrap();
        assert_eq!(output.flush().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(output.check().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(output.shutdown().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        let stats = output.stats();
        assert_eq!(stats.errors, 1);
        assert_eq!(stats.bytes_written, 5);
        assert_eq!(stats.write_calls, 4);
        assert_eq!(
            (stats.pending_records, stats.pending_bytes, stats.buffered_bytes),
            (0, 0, 0)
        );
        assert_eq!(written.lock().unwrap().bytes, b"01234");
    }

    #[test]
    fn sparse_records_flush_without_a_followup_record_or_explicit_flush() {
        let (mut writer, written) = FakeWriter::new();
        let (first_write_tx, first_write_rx) = mpsc::channel();
        writer.first_write = Some(first_write_tx);
        let output = AsyncOutput::new(writer).unwrap();
        output.enqueue(Source::Kernel, "tail\n".into()).unwrap();
        first_write_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        output.shutdown().unwrap();
        assert_eq!(written.lock().unwrap().bytes, b"tail\n");
        assert_eq!(output.stats().accepted, 1);
        assert_eq!(output.stats().processed, 1);
    }
}
