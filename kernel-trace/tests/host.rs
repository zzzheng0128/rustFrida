//! Pure host-side regression tests without Aya, BPF loading, or target processes.
//!
//! rustc --edition=2021 --test kernel-trace/tests/host.rs -o /tmp/ktrace-tests
//! /tmp/ktrace-tests
//! Use an optimized binary and --ignored --nocapture for the synthetic benchmark.

#![allow(dead_code)]

const TASK_COMM_LEN: usize = 16;
#[path = "../../kernel-trace-common/src/thread_names.rs"]
mod thread_names;

#[path = "../src/argspec.rs"]
mod argspec;
#[path = "../src/hwbp_lifecycle.rs"]
mod hwbp_lifecycle;
#[path = "../src/load.rs"]
mod load;
#[path = "../src/procinfo.rs"]
mod procinfo;
#[path = "../src/report_queue.rs"]
mod report_queue;
#[path = "../src/sink.rs"]
mod sink;
#[path = "../src/stackwalk.rs"]
mod stackwalk;
#[path = "../src/stats.rs"]
mod stats;

#[path = "support/pipeline_sample.rs"]
mod pipeline_sample;
