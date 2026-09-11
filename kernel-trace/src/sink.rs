//! Bounded output buffering with a maximum pending age for sparse streams.
//!
//! Call `flush_due` after writes and after receive timeouts, using `wait_timeout`
//! for the next receive. Explicitly call `flush` when closing the stream so I/O
//! errors are observable; `BufWriter`'s drop remains a best-effort fallback.

use std::io::{self, BufWriter, Write};
use std::time::{Duration, Instant};

const BUFFER_CAPACITY: usize = 64 * 1024;
const FLUSH_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Default)]
pub struct OutputStats {
    /// Whole records accepted by the buffer, including records still pending.
    pub records: u64,
    /// Bytes successfully accepted by the underlying writer.
    pub bytes_written: u64,
    /// Underlying `write` attempts, including attempts returning an error.
    pub write_calls: u64,
    /// Aggregate wall time spent in underlying `write` and `flush` calls.
    pub io_ns: u64,
    pub pending_bytes: usize,
}

pub struct BufferedOutput<W: Write> {
    writer: BufWriter<MeasuredWriter<W>>,
    records: u64,
    pending_since: Option<Instant>,
}

impl<W: Write> BufferedOutput<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: BufWriter::with_capacity(BUFFER_CAPACITY, MeasuredWriter::new(writer)),
            records: 0,
            pending_since: None,
        }
    }

    /// Accept a complete record, including its caller-provided line ending.
    /// A returned I/O error can follow a partial write; callers should stop
    /// rather than retry the entire record and duplicate an accepted prefix.
    pub fn write_record(&mut self, record: &str) -> io::Result<()> {
        self.write_record_at(record, Instant::now())
    }

    fn write_record_at(&mut self, record: &str, now: Instant) -> io::Result<()> {
        let prior_write_calls = self.writer.get_ref().write_calls;
        let result = self.writer.write_all(record.as_bytes());
        if self.writer.buffer().is_empty() {
            self.pending_since = None;
        } else if self.pending_since.is_none()
            || (result.is_ok() && self.writer.get_ref().write_calls != prior_write_calls)
        {
            // A successful automatic write emptied the old batch before
            // buffering this record. Otherwise retain the first record's age.
            self.pending_since = Some(now);
        }
        result?;
        self.records = self.records.saturating_add(1);
        // BufWriter may retain an exactly full buffer until the next write.
        // Flush that boundary too, even if no next record arrives.
        if self.writer.buffer().len() == self.writer.capacity() {
            self.flush()?;
        }
        Ok(())
    }

    pub fn flush_due(&mut self) -> io::Result<()> {
        self.flush_due_at(Instant::now())
    }

    fn flush_due_at(&mut self, now: Instant) -> io::Result<()> {
        if self
            .pending_since
            .is_some_and(|since| now.saturating_duration_since(since) >= FLUSH_INTERVAL)
        {
            self.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        let result = self.writer.flush();
        if self.writer.buffer().is_empty() {
            self.pending_since = None;
        }
        result
    }

    /// Delay until pending bytes reach their deadline, or 50 ms while idle.
    pub fn wait_timeout(&self) -> Duration {
        self.wait_timeout_at(Instant::now())
    }

    fn wait_timeout_at(&self, now: Instant) -> Duration {
        self.pending_since.map_or(FLUSH_INTERVAL, |since| {
            FLUSH_INTERVAL.saturating_sub(now.saturating_duration_since(since))
        })
    }

    /// Read counters without flushing or otherwise touching the underlying I/O.
    pub fn stats(&self) -> OutputStats {
        let measured = self.writer.get_ref();
        OutputStats {
            records: self.records,
            bytes_written: measured.bytes_written,
            write_calls: measured.write_calls,
            io_ns: measured.io_ns,
            pending_bytes: self.writer.buffer().len(),
        }
    }
}

struct MeasuredWriter<W> {
    writer: W,
    bytes_written: u64,
    write_calls: u64,
    io_ns: u64,
}

impl<W> MeasuredWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            bytes_written: 0,
            write_calls: 0,
            io_ns: 0,
        }
    }

    fn record_elapsed(&mut self, start: Instant) {
        let ns = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        self.io_ns = self.io_ns.saturating_add(ns);
    }
}

impl<W: Write> Write for MeasuredWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let start = Instant::now();
        let result = self.writer.write(bytes);
        self.record_elapsed(start);
        self.write_calls = self.write_calls.saturating_add(1);
        if let Ok(written) = result {
            self.bytes_written = self.bytes_written.saturating_add(written as u64);
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        let start = Instant::now();
        let result = self.writer.flush();
        self.record_elapsed(start);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Written {
        bytes: Vec<u8>,
        calls: u64,
        flushes: u64,
    }

    struct FakeWriter {
        written: Arc<Mutex<Written>>,
        max_write: usize,
        fail_after: Option<usize>,
        fail_flush: bool,
    }

    impl FakeWriter {
        fn new() -> (Self, Arc<Mutex<Written>>) {
            let written = Arc::new(Mutex::new(Written::default()));
            (
                Self {
                    written: written.clone(),
                    max_write: usize::MAX,
                    fail_after: None,
                    fail_flush: false,
                },
                written,
            )
        }
    }

    impl Write for FakeWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let mut written = self.written.lock().unwrap();
            written.calls += 1;
            let remaining = self
                .fail_after
                .map_or(usize::MAX, |limit| limit.saturating_sub(written.bytes.len()));
            if remaining == 0 {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "synthetic failure"));
            }
            let count = bytes.len().min(self.max_write).min(remaining);
            written.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.written.lock().unwrap().flushes += 1;
            if self.fail_flush {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "synthetic flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn ten_thousand_records_are_batched_without_changing_bytes() {
        let (writer, written) = FakeWriter::new();
        let mut output = BufferedOutput::new(writer);
        let start = Instant::now();
        let record = "a complete synthetic record with a newline\n";
        for _ in 0..10_000 {
            output.write_record_at(record, start).unwrap();
        }
        assert_eq!(output.stats().records, 10_000);
        assert!(output.stats().write_calls < 10);
        output.flush().unwrap();
        let stats = output.stats();
        assert_eq!(written.lock().unwrap().bytes, record.repeat(10_000).as_bytes());
        assert_eq!(stats.bytes_written, (record.len() * 10_000) as u64);
        assert_eq!(stats.pending_bytes, 0);
        assert!(stats.write_calls < 10);
    }

    #[test]
    fn empty_boundary_and_large_records_preserve_order() {
        let (writer, written) = FakeWriter::new();
        let mut output = BufferedOutput::new(writer);
        let mut expected = Vec::new();
        for (i, size) in [
            0,
            1,
            BUFFER_CAPACITY - 1,
            BUFFER_CAPACITY,
            BUFFER_CAPACITY + 1,
            BUFFER_CAPACITY * 3 + 17,
        ]
        .into_iter()
        .enumerate()
        {
            let record = ((b'a' + i as u8) as char).to_string().repeat(size);
            output.write_record(&record).unwrap();
            expected.extend_from_slice(record.as_bytes());
            assert!(output.stats().pending_bytes < BUFFER_CAPACITY);
        }
        output.flush().unwrap();
        assert_eq!(output.stats().records, 6);
        assert_eq!(output.stats().bytes_written, expected.len() as u64);
        assert_eq!(written.lock().unwrap().bytes, expected);
    }

    #[test]
    fn idle_timeout_flushes_pending_data_once_and_stats_do_not_flush() {
        let (writer, written) = FakeWriter::new();
        let mut output = BufferedOutput::new(writer);
        let start = Instant::now();
        assert_eq!(output.wait_timeout_at(start), FLUSH_INTERVAL);
        output.write_record_at("small\n", start).unwrap();
        assert_eq!(output.stats().pending_bytes, 6);
        assert_eq!(output.stats().write_calls, 0);
        output
            .flush_due_at(start + FLUSH_INTERVAL - Duration::from_nanos(1))
            .unwrap();
        assert_eq!(output.stats().write_calls, 0);
        assert_eq!(output.wait_timeout_at(start + FLUSH_INTERVAL), Duration::ZERO);
        output.flush_due_at(start + FLUSH_INTERVAL).unwrap();
        assert_eq!(output.stats().pending_bytes, 0);
        assert_eq!(output.stats().write_calls, 1);
        assert_eq!(output.wait_timeout_at(start + FLUSH_INTERVAL), FLUSH_INTERVAL);
        output.flush_due_at(start + Duration::from_secs(1)).unwrap();
        assert_eq!(written.lock().unwrap().flushes, 1);
    }

    #[test]
    fn continuous_small_records_cannot_postpone_the_first_deadline() {
        let (writer, written) = FakeWriter::new();
        let mut output = BufferedOutput::new(writer);
        let start = Instant::now();
        for millis in [0, 10, 20, 30, 40] {
            output
                .write_record_at("x\n", start + Duration::from_millis(millis))
                .unwrap();
        }
        assert_eq!(
            output.wait_timeout_at(start + Duration::from_millis(49)),
            Duration::from_millis(1)
        );
        output.flush_due_at(start + FLUSH_INTERVAL).unwrap();
        assert_eq!(written.lock().unwrap().bytes, b"x\nx\nx\nx\nx\n");
        assert_eq!(output.stats().write_calls, 1);
    }

    #[test]
    fn automatic_flush_starts_a_new_deadline_for_the_remaining_batch() {
        let (writer, _) = FakeWriter::new();
        let mut output = BufferedOutput::new(writer);
        let start = Instant::now();
        output
            .write_record_at(&"a".repeat(BUFFER_CAPACITY - 10), start)
            .unwrap();
        output
            .write_record_at(&"b".repeat(20), start + Duration::from_millis(40))
            .unwrap();
        assert_eq!(output.stats().write_calls, 1);
        assert_eq!(output.stats().pending_bytes, 20);
        assert_eq!(
            output.wait_timeout_at(start + Duration::from_millis(40)),
            FLUSH_INTERVAL
        );
        output.flush_due_at(start + FLUSH_INTERVAL).unwrap();
        assert_eq!(output.stats().pending_bytes, 20);
        output.flush_due_at(start + Duration::from_millis(90)).unwrap();
        assert_eq!(output.stats().pending_bytes, 0);
    }

    #[test]
    fn partial_writes_count_only_successful_bytes_and_expose_broken_pipe() {
        let (mut writer, written) = FakeWriter::new();
        writer.max_write = 2;
        writer.fail_after = Some(5);
        let mut output = BufferedOutput::new(writer);
        output.write_record("abcdefghij").unwrap();
        let error = output.flush().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        let stats = output.stats();
        assert_eq!(stats.records, 1);
        assert_eq!(stats.bytes_written, 5);
        assert_eq!(stats.pending_bytes, 5);
        assert_eq!(stats.write_calls, 4);
        assert_eq!(written.lock().unwrap().bytes, b"abcde");
    }

    #[test]
    fn failed_large_record_is_not_counted_as_accepted() {
        let (mut writer, _) = FakeWriter::new();
        writer.max_write = 2;
        writer.fail_after = Some(5);
        let mut output = BufferedOutput::new(writer);
        let error = output.write_record(&"x".repeat(BUFFER_CAPACITY + 1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        let stats = output.stats();
        assert_eq!(stats.records, 0);
        assert_eq!(stats.bytes_written, 5);
        assert_eq!(stats.write_calls, 4);
        assert_eq!(stats.pending_bytes, 0);
    }

    #[test]
    fn underlying_flush_failure_is_visible_without_counting_a_write() {
        let (mut writer, written) = FakeWriter::new();
        writer.fail_flush = true;
        let mut output = BufferedOutput::new(writer);
        output.write_record("one\n").unwrap();
        assert_eq!(output.flush().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(output.stats().records, 1);
        assert_eq!(output.stats().bytes_written, 4);
        assert_eq!(output.stats().write_calls, 1);
        assert_eq!(output.stats().pending_bytes, 0);
        assert_eq!(written.lock().unwrap().flushes, 1);
    }
}
