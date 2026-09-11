//! Deterministic sample joining the real report lanes, tickets, counters, and
//! buffered output. All records and writes are synthetic; no process is read.

use crate::report_queue;
use crate::sink::{BufferedOutput, OutputStats};
use crate::stats::{PipelineCounters, Queued};
use std::io::{self, Write};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

const SVC_CAPACITY: usize = 3;
const UPROBE_CAPACITY: usize = 10;

struct SampleReport {
    syscall: bool,
    sequence: usize,
    record: String,
}

fn record(syscall: bool, sequence: usize) -> String {
    let kind = if syscall { "svc.enter" } else { "uprobe.hit" };
    format!("{{\"type\":\"{kind}\",\"sequence\":{sequence},\"pid\":123,\"detail\":\"basic\"}}\n")
}

fn offer(
    sender: &report_queue::Sender<Queued<SampleReport>>,
    counters: &PipelineCounters,
    syscall: bool,
    sequence: usize,
) {
    let event = counters.event(syscall);
    // Here received counts the sample's generated reports, before admission.
    event.received.fetch_add(1, Relaxed);
    let queue = if syscall {
        &counters.report_queue
    } else {
        &counters.uprobe_report_queue
    };
    let report = SampleReport {
        syscall,
        sequence,
        record: record(syscall, sequence),
    };
    let accepted = match Queued::try_new(report, queue) {
        Ok(queued) => sender.try_send(syscall, queued).is_ok(),
        Err(_) => false,
    };
    if accepted {
        event.reports_enqueued.fetch_add(1, Relaxed);
    } else {
        event.reports_dropped.fetch_add(1, Relaxed);
    }
}

#[derive(Default)]
struct Written {
    bytes: Vec<u8>,
    calls: u64,
}

struct SegmentedWriter(Arc<Mutex<Written>>);

impl Write for SegmentedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(7);
        let mut written = self.0.lock().unwrap();
        written.calls += 1;
        written.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn deliver(
    queued: Queued<SampleReport>,
    counters: &PipelineCounters,
    output: &mut BufferedOutput<SegmentedWriter>,
    order: &mut Vec<(bool, usize)>,
) {
    let (report, _) = queued.dequeue();
    counters.event(report.syscall).delivered.fetch_add(1, Relaxed);
    assert_eq!(report.record, record(report.syscall, report.sequence));
    order.push((report.syscall, report.sequence));
    output.write_record(&report.record).unwrap();
    output.flush_due().unwrap();
}

fn verify_output(written: &Written, stats: OutputStats, order: &[(bool, usize)]) {
    let expected: String = order
        .iter()
        .map(|&(syscall, sequence)| record(syscall, sequence))
        .collect();
    assert_eq!(written.bytes, expected.as_bytes());
    assert_eq!(stats.records, order.len() as u64);
    assert_eq!(stats.bytes_written, expected.len() as u64);
    assert_eq!(stats.write_calls, written.calls);
    assert_eq!(stats.pending_bytes, 0);
    assert_eq!(written.bytes.iter().filter(|&&byte| byte == b'\n').count(), order.len());
}

#[test]
fn gated_bursts_preserve_accounting_priority_and_complete_buffered_output() {
    let counters = PipelineCounters::new(1, 1, 1, SVC_CAPACITY, UPROBE_CAPACITY);
    let (sender, receiver) = report_queue::channel(SVC_CAPACITY, UPROBE_CAPACITY);
    let (ready_tx, ready_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    let producer_counters = counters.clone();
    let producer = std::thread::spawn(move || {
        // The consumer is gated off until both bursts have filled their lanes.
        // The syscall overflow therefore cannot depend on OS scheduling.
        for sequence in 0..7 {
            offer(&sender, &producer_counters, true, sequence);
        }
        for sequence in 0..12 {
            offer(&sender, &producer_counters, false, sequence);
        }
        ready_tx.send(()).unwrap();
        resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        for sequence in 7..12 {
            offer(&sender, &producer_counters, true, sequence);
        }
        for sequence in 12..15 {
            offer(&sender, &producer_counters, false, sequence);
        }
        ready_tx.send(()).unwrap();
        // Dropping this final sender leaves a buffered tail to be drained.
    });

    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let initial = counters.snapshot();
    assert_eq!(initial.report_queue.pending, SVC_CAPACITY);
    assert_eq!(initial.uprobe_report_queue.pending, UPROBE_CAPACITY);
    assert_eq!((initial.svc.reports_dropped, initial.uprobe.reports_dropped), (4, 2));

    let written = Arc::new(Mutex::new(Written::default()));
    let mut output = BufferedOutput::new(SegmentedWriter(written.clone()));
    let mut order = Vec::new();
    for _ in 0..SVC_CAPACITY + UPROBE_CAPACITY {
        let report = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        deliver(report, &counters, &mut output, &mut order);
    }
    let mut expected_order: Vec<_> = (0..8).map(|sequence| (false, sequence)).collect();
    expected_order.push((true, 0));
    expected_order.extend((8..10).map(|sequence| (false, sequence)));
    expected_order.extend([(true, 1), (true, 2)]);
    assert_eq!(order, expected_order);

    // The producer still owns the sender, but is waiting at the gate. Sparse
    // output must flush on the sink's 50 ms deadline without another record.
    let timeout = output.wait_timeout();
    assert!(timeout <= Duration::from_millis(50));
    assert!(matches!(
        receiver.recv_timeout(timeout),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    output.flush_due().unwrap();
    verify_output(&written.lock().unwrap(), output.stats(), &expected_order);
    assert_eq!(counters.snapshot().report_queue.pending, 0);
    assert_eq!(counters.snapshot().uprobe_report_queue.pending, 0);

    // Pause consumption again so the second burst has deterministic overflow.
    resume_tx.send(()).unwrap();
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    loop {
        match receiver.recv_timeout(output.wait_timeout()) {
            Ok(report) => deliver(report, &counters, &mut output, &mut order),
            Err(mpsc::RecvTimeoutError::Timeout) => output.flush_due().unwrap(),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    producer.join().unwrap();
    output.flush().unwrap();
    expected_order.extend((12..15).map(|sequence| (false, sequence)));
    expected_order.extend((7..10).map(|sequence| (true, sequence)));
    assert_eq!(order, expected_order);
    verify_output(&written.lock().unwrap(), output.stats(), &expected_order);

    let final_stats = counters.snapshot();
    for (event, generated, accepted, dropped) in [(&final_stats.svc, 12, 6, 6), (&final_stats.uprobe, 15, 13, 2)] {
        assert_eq!(event.received, generated);
        assert_eq!(event.reports_enqueued, accepted);
        assert_eq!(event.reports_dropped, dropped);
        assert_eq!(event.received, event.reports_enqueued + event.reports_dropped);
        assert_eq!(event.delivered, event.reports_enqueued);
    }
    assert_eq!(final_stats.report_queue.pending, 0);
    assert_eq!(final_stats.uprobe_report_queue.pending, 0);
    assert_eq!(final_stats.report_queue.high_water, SVC_CAPACITY);
    assert_eq!(final_stats.uprobe_report_queue.high_water, UPROBE_CAPACITY);
    assert!(matches!(receiver.try_recv(), Err(mpsc::TryRecvError::Disconnected)));
}
