use clap::Parser;
use ldmonitor::DlopenMonitor;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<u32>,
}

fn main() -> anyhow::Result<()> {
    unsafe {
        let _ = libc::prctl(libc::PR_SET_NAME, b"ldmain\0".as_ptr(), 0, 0, 0);
    }

    env_logger::init();

    let opt = Opt::parse();
    let monitor = DlopenMonitor::new(opt.pid)?;

    println!("Monitoring android_dlopen_ext calls...");
    println!("Press Ctrl-C to exit.");

    while let Some(info) = monitor.recv() {
        if let Some(ns_pid) = info.ns_pid {
            if ns_pid != info.host_pid {
                println!(
                    "android_dlopen_ext called: pid={} (host_pid={}), uid={}, path={}",
                    ns_pid, info.host_pid, info.uid, info.path
                );
            } else {
                println!(
                    "android_dlopen_ext called: pid={}, uid={}, path={}",
                    info.pid(),
                    info.uid,
                    info.path
                );
            }
        } else {
            println!(
                "android_dlopen_ext called: host_pid={} (ns_pid unknown), uid={}, path={}",
                info.host_pid, info.uid, info.path
            );
        }
    }

    Ok(())
}
