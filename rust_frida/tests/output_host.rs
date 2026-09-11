//! Owned, host-only output samples. No device or agent connection is opened.
//! CARGO_PKG_VERSION=0.1.0 rustc --edition=2021 --test rust_frida/tests/output_host.rs -o /tmp/rf-output-tests
//! /tmp/rf-output-tests
#![allow(dead_code)]

#[path = "../src/agent_events.rs"]
mod agent_events;
#[path = "../../shared/agent_log.rs"]
mod agent_log;
#[path = "../src/log_output.rs"]
mod log_output;
#[path = "../src/logger.rs"]
mod logger;
#[path = "../src/output_paths.rs"]
mod output_paths;

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

struct SampleDir(PathBuf);

impl SampleDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rf-output-sample-{}-{timestamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn run(&self, mode: &str) -> std::process::Output {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "output_process_sample", "--nocapture"])
            .env("RF_OUTPUT_SAMPLE_MODE", mode)
            .env("RF_OUTPUT_SAMPLE_DIR", &self.0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut timed_out = false;
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                timed_out = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        assert!(!timed_out, "output sample {mode} exceeded its deadline");
        assert!(
            output.status.success(),
            "sample {mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
}

impl Drop for SampleDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn mixed_sources_keep_complete_blocks_without_console_echo() {
    let dir = SampleDir::new();
    let output = dir.run("mixed");
    let text = fs::read_to_string(dir.0.join("session.log")).unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains("sample-event-"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("sample-event-"));
    assert!(!text.contains('\u{1b}'));
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 6 * 100 * 3);
    let mut seen = std::collections::BTreeSet::new();
    for block in lines.chunks_exact(3) {
        let marker = block[0].split("sample-event-").nth(1).unwrap();
        assert_eq!(block[1], format!("middle-{marker}"));
        assert_eq!(block[2], format!("end-{marker}"));
        let producer: usize = marker.split('-').next().unwrap().parse().unwrap();
        if producer % 3 == 1 {
            assert!(block[0].starts_with("[agent#"));
        }
        if producer % 3 == 2 {
            assert!(block[0].starts_with("[kernel]"));
        }
        assert!(seen.insert(marker.to_owned()), "duplicated sample record {marker}");
    }
    assert_eq!(seen.len(), 600);
}

#[test]
fn process_exit_flushes_accepted_tail() {
    let dir = SampleDir::new();
    dir.run("exit");
    let text = fs::read_to_string(dir.0.join("session.log")).unwrap();
    assert_eq!(text.lines().count(), 32);
    for index in 0..32 {
        assert!(text.contains(&format!("exit-tail-{index}\n")));
    }
}

#[test]
fn repeat_initialization_does_not_truncate_either_file() {
    let dir = SampleDir::new();
    dir.run("reinit");
    assert!(fs::read_to_string(dir.0.join("session.log"))
        .unwrap()
        .contains("first-output"));
    assert_eq!(
        fs::read_to_string(dir.0.join("untouched.log")).unwrap(),
        "keep existing data\n"
    );
}

#[test]
fn default_without_output_keeps_console_messages() {
    let dir = SampleDir::new();
    let output = dir.run("console");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sample-host-console"));
    assert!(stdout.contains("sample-agent-console"));
    assert!(!dir.0.join("session.log").exists());
}

#[test]
fn interactive_output_is_mirrored_without_hiding_prompts_or_rewriting_details() {
    let dir = SampleDir::new();
    let output = dir.run("interactive");
    let text = fs::read_to_string(dir.0.join("session.log")).unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("session-help"));
    assert!(stderr.contains("scene-sample"));
    assert!(!stdout.contains("args: fd=7"));
    assert!(!text.contains('\u{1b}'));
    assert_eq!(
        text,
        concat!(
            "session-help\n\n",
            "  args: fd=7 buf=0x1234 count=16\n",
            "scene-sample\n",
        )
    );
}

#[test]
#[ignore = "isolated subprocess helper; the parent supplies owned sample paths"]
fn output_process_sample() {
    let Ok(mode) = std::env::var("RF_OUTPUT_SAMPLE_MODE") else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os("RF_OUTPUT_SAMPLE_DIR").unwrap());
    if mode == "console" {
        logger::stdout_line("sample-host-console", "sample-host-console");
        logger::agent_line(0, "sample-agent-console", "sample-agent-console");
        return;
    }
    logger::init_output_file(dir.join("session.log").to_str().unwrap()).unwrap();
    match mode.as_str() {
        "interactive" => {
            crate::console_log!("\u{1b}[36m{}\u{1b}[0m", "session-help");
            crate::console_log!();
            logger::text_line("  args: fd=7 buf=0x1234 count=16");
            logger::stderr_line("scene-sample", "scene-sample");
        }
        "mixed" => {
            let workers: Vec<_> = (0..6)
                .map(|producer| {
                    std::thread::spawn(move || {
                        for index in 0..100 {
                            let marker = format!("{producer}-{index:03}");
                            let message = format!("sample-event-{marker}\nmiddle-{marker}\nend-{marker}");
                            match producer % 3 {
                                0 => logger::stdout_line(&message, &message),
                                1 => logger::agent_line(producer as u32, &message, &message),
                                _ => logger::write_kernel_record(&message).unwrap(),
                            }
                        }
                    })
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
            logger::flush_output().unwrap();
        }
        "exit" => {
            for index in 0..32 {
                logger::write_kernel_record(&format!("exit-tail-{index}")).unwrap();
            }
            // Exercise the CLI's process::exit paths, which skip Rust Drop.
            std::process::exit(0);
        }
        "reinit" => {
            logger::stdout_line("first-output", "first-output");
            logger::flush_output().unwrap();
            let other = dir.join("untouched.log");
            fs::write(&other, "keep existing data\n").unwrap();
            assert!(logger::init_output_file(other.to_str().unwrap()).is_err());
            assert!(logger::init_output_file(dir.join("session.log").to_str().unwrap()).is_err());
        }
        _ => panic!("unknown sample mode"),
    }
    logger::shutdown_output().unwrap();
}
