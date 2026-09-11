#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod agent_events;
#[path = "../../shared/agent_log.rs"]
mod agent_log;
mod anomaly;
mod args;
mod communication;
mod http_rpc;
mod injection;
mod log_output;
mod logger;
mod output_paths;
mod proc_mem;
mod process;
mod props;
mod remote_agent;
mod repl;
mod scene;
mod selinux;
mod server;
mod session;
mod spawn;
mod trace_bridge;
mod types;

/// 解析 `--rpc-port` 参数为绑定地址：
/// * 纯数字 → `0.0.0.0:<port>`
/// * 带冒号 → 原样使用（例如 `127.0.0.1:9191`）
pub(crate) fn parse_rpc_bind(arg: &str) -> String {
    if arg.contains(':') {
        arg.to_string()
    } else {
        format!("0.0.0.0:{}", arg)
    }
}

use crate::logger::{DIM, RESET};
#[cfg(feature = "kernel-trace")]
use anyhow::{anyhow, Result as AnyResult};
use args::Args;
use clap::Parser;
#[cfg(feature = "qbdi")]
use communication::send_qbdi_helper;
use communication::{send_command, start_socketpair_handler};
use injection::{inject_via_bootstrapper, watch_and_inject, InjectionResult};
use nix::sys::ptrace;
use nix::unistd::Pid;
use process::{attach_to_process, call_target_function, find_pid_by_name};
use repl::{
    load_script_file, load_script_file_pre_resume, print_eval_result, print_help, rewrite_jseval_for_agent,
    run_js_repl, schedule_java_worker_ready_after_resume, script_uses_java_api,
    try_jseval_on_main_thread_if_java_or_dsl, try_loadjs_on_main_thread_if_java, try_managedcounter_on_main_thread,
    CommandCompleter, EVAL_DEFAULT_TIMEOUT_SECS, EVAL_JAVA_TIMEOUT_SECS, EVAL_RECOMP_TIMEOUT_SECS,
};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use session::{Session, SessionManager};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use types::get_string_table_names;

const AGENT_SHUTDOWN_WAIT_SECS: u64 = 1;

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn wait_process_alive(pid: i32, seconds: u64, label: &str) -> bool {
    for elapsed in 0..seconds {
        if !std::path::Path::new(&format!("/proc/{}/status", pid)).exists() {
            log_warn!("{}: 进程 {} 在 {}s 后退出", label, pid, elapsed);
            return false;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let alive = std::path::Path::new(&format!("/proc/{}/status", pid)).exists();
    if alive {
        log_success!("{}: 进程 {} 存活 {}s", label, pid, seconds);
    } else {
        log_warn!("{}: 进程 {} 在检查结束时已退出", label, pid);
    }
    alive
}

fn set_current_thread_name(name: &'static [u8]) {
    unsafe {
        let _ = libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0);
    }
}

fn cleanup_remote_loader_mappings(pid: i32, injection: &InjectionResult) {
    if pid <= 0 || injection.libc_munmap == 0 {
        return;
    }
    let mut ranges = Vec::new();
    if injection.loader_stack != 0 && injection.loader_stack_size != 0 {
        ranges.push(("loader stack", injection.loader_stack, injection.loader_stack_size));
    }
    if injection.loader_alloc_base != 0 && injection.loader_alloc_size != 0 {
        ranges.push((
            "loader mapping",
            injection.loader_alloc_base,
            injection.loader_alloc_size,
        ));
    }
    if ranges.is_empty() {
        return;
    }
    if !std::path::Path::new(&format!("/proc/{}/status", pid)).exists() {
        return;
    }

    let tid = injection::choose_injection_thread(pid);
    if let Err(e) = attach_to_process(tid) {
        log_warn!("loader 残留清理跳过: attach tid={} 失败: {}", tid, e);
        return;
    }
    for (label, base, size) in ranges {
        match call_target_function(
            tid,
            injection.libc_munmap as usize,
            &[base as usize, size as usize],
            None,
        ) {
            Ok(ret) if ret == 0 => log_verbose!("已清理 {}: 0x{:x}+0x{:x}", label, base, size),
            Ok(ret) => log_verbose!("清理 {} 返回 {}: 0x{:x}+0x{:x}", label, ret, base, size),
            Err(e) => log_warn!("清理 {} 失败: {}", label, e),
        }
    }
    let _ = ptrace::detach(Pid::from_raw(tid), None);
    unsafe {
        libc::kill(pid, libc::SIGCONT);
    }
}

fn main() {
    set_current_thread_name(b"CrRendererMain\0");

    // Fix #8: 先解析参数（--help/--version 在此退出），再打印 banner
    let args = Args::parse();

    // mode=trace 不接受 pid/watch_so/name/spawn；
    // mode=inject 维持原行为；
    // mode=hybrid 需要 pid/name 之一。
    #[cfg(feature = "kernel-trace")]
    {
        use crate::args::RunMode;
        match args.mode {
            RunMode::Trace => {
                if args.pid.is_some() || args.watch_so.is_some() || args.name.is_some() {
                    log_error!("--mode=trace 与 --pid/--watch-so/--name 互斥；改用 --trace-pid/--trace-uid 等");
                    std::process::exit(1);
                }
                // --spawn 允许:tracer 先 attach(uid 过滤),再 monkey 拉起 app,
                // 从进程出生开始全量采集(无需 frida spawn 门控)
            }
            RunMode::Hybrid => {
                if args.pid.is_none() && args.name.is_none() && args.spawn.is_none() {
                    log_error!("--mode=hybrid 必须同时指定 --pid、--name 或 --spawn（要注入的进程）");
                    std::process::exit(1);
                }
            }
            RunMode::Inject => {
                if args.pid.is_none()
                    && args.watch_so.is_none()
                    && args.name.is_none()
                    && args.spawn.is_none()
                    && args.dump_props.is_none()
                    && args.set_prop.is_none()
                    && args.del_prop.is_none()
                    && args.repack_props.is_none()
                    && !args.server
                {
                    log_error!(
                        "必须指定 --pid、--name、--watch-so、--spawn、--server 或属性管理操作；或使用 --mode=trace/--mode=hybrid"
                    );
                    std::process::exit(1);
                }
            }
        }
    }
    // 当 kernel-trace feature 未启用时，保留原 required 行为：必须有 target
    #[cfg(not(feature = "kernel-trace"))]
    {
        if args.pid.is_none()
            && args.watch_so.is_none()
            && args.name.is_none()
            && args.spawn.is_none()
            && args.dump_props.is_none()
            && args.set_prop.is_none()
            && args.del_prop.is_none()
            && args.repack_props.is_none()
            && !args.server
        {
            log_error!("必须指定 --pid、--name、--watch-so、--spawn 或 --server");
            std::process::exit(1);
        }
    }

    // 初始化 verbose 模式
    logger::VERBOSE.store(args.verbose, Ordering::Relaxed);
    #[cfg(feature = "kernel-trace")]
    if let Err(e) = output_paths::validate_distinct_outputs(args.output.as_deref(), args.trace_output.as_deref()) {
        eprintln!("输出参数无效: {e}");
        std::process::exit(1);
    }
    if let Some(ref path) = args.output {
        if let Err(e) = logger::init_output_file(path) {
            eprintln!("初始化日志文件 '{}' 失败: {}", path, e);
            std::process::exit(1);
        }
        #[cfg(feature = "kernel-trace")]
        let _ = kernel_trace::set_diagnostic_sink(trace_diagnostic_line);
    }

    logger::print_banner();

    // --dump-props: 独立操作，dump 后退出
    if let Some(ref profile_name) = args.dump_props {
        match props::dump_props(profile_name) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("Dump 属性失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --set-prop: 独立操作，修改属性后退出
    if let Some(ref set_args) = args.set_prop {
        match props::set_prop(&set_args[0], &set_args[1]) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("设置属性失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --del-prop: 独立操作，删除属性后退出
    if let Some(ref del_args) = args.del_prop {
        match props::del_prop(&del_args[0], &del_args[1]) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("删除属性失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --repack-props: 独立操作，重排后退出
    if let Some(ref profile_name) = args.repack_props {
        match props::repack_props(profile_name) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("重排失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --profile 校验: 仅 --spawn 或 --server 可用
    if args.profile.is_some() && args.spawn.is_none() && !args.server {
        log_error!("--profile 仅在 --spawn 或 --server 模式下可用");
        std::process::exit(1);
    }

    // 属性 profile 预处理
    if let Some(ref profile_name) = args.profile {
        match props::prep_prop_profile(profile_name) {
            Ok(profile_dir) => {
                spawn::set_prop_profile(Some(profile_dir));
            }
            Err(e) => {
                log_error!("属性 profile 预处理失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    // ── kernel-trace 模式分发（mode=trace / mode=hybrid）──
    // mode=trace：纯 eBPF 内核取证，不注入 agent，事件 JSONL 输出到 stdout/文件
    // mode=hybrid：legacy 注入 + 并行跑 eBPF 取证（事件同时输出到 JSONL）
    #[cfg(feature = "kernel-trace")]
    {
        use crate::args::RunMode;
        match args.mode {
            RunMode::Trace => {
                if let Err(e) = run_trace_mode(&args) {
                    log_error!("[trace] {:#}", e);
                    std::process::exit(1);
                }
                return;
            }
            RunMode::Hybrid => {
                // hybrid: 启动后台 trace thread，事件写入指定文件或终端；
                // 注入完成后再回来合并 REPL（这里只启动 trace，不阻塞注入流程）
                log_info!("[hybrid] 启动后台 kernel-trace 线程");
                if let Err(e) = start_background_tracer(&args) {
                    log_error!("[hybrid] KernelTracer 启动失败: {:#}", e);
                    std::process::exit(1);
                }
                // 走原 inject 流程
            }
            RunMode::Inject => {
                // 原行为，不动
            }
        }
    }

    // ── Server daemon 模式 ──
    if args.server {
        server::run_server(&args);
        return;
    }

    // ── 以下为 legacy 单 session 模式 ──

    // 解析 --name 到 PID（如果指定）
    let resolved_pid: Option<i32> = if let Some(ref name) = args.name {
        match find_pid_by_name(name) {
            Ok(pid) => {
                log_success!("按名称 '{}' 找到进程 PID: {}", name, pid);
                Some(pid)
            }
            Err(e) => {
                log_error!("{}", e);
                std::process::exit(1);
            }
        }
    } else {
        args.pid
    };

    // 解析字符串覆盖参数（格式：name=value）
    let mut string_overrides = std::collections::HashMap::new();
    let available_names = get_string_table_names();

    for s in &args.strings {
        if let Some((name, value)) = s.split_once('=') {
            if available_names.contains(&name) {
                string_overrides.insert(name.to_string(), value.to_string());
            } else {
                log_warn!("未知的字符串名称 '{}', 可用名称: {}", name, available_names.join(", "));
            }
        } else {
            log_warn!("无效的字符串格式 '{}', 应为 name=value", s);
        }
    }

    // 打印字符串覆盖信息
    if !string_overrides.is_empty() {
        log_info!("字符串覆盖列表 ({} 个):", string_overrides.len());
        for (name, value) in &string_overrides {
            logger::text_line(&format!("     {} = {}", name, value));
        }
    }

    if let Some(ref package) = args.spawn {
        if env_flag("RF_DIAG_ZYM_PASSIVE_SETARGV0") {
            spawn::register_cleanup_handler();
            match spawn::spawn_passive_setargv0_launch(package) {
                Ok(pid) => {
                    let hold_secs = env_u64("RF_DIAG_HOLD_SECS", 20);
                    wait_process_alive(pid as i32, hold_secs, "RF_DIAG_ZYM_PASSIVE_SETARGV0");
                    spawn::cleanup_zygote_patches();
                    return;
                }
                Err(e) => {
                    log_error!("Passive setArgV0 诊断失败: {}", e);
                    spawn::cleanup_zygote_patches();
                    std::process::exit(1);
                }
            }
        }

        if env_flag("RF_DIAG_SPAWN_ONLY") {
            spawn::register_cleanup_handler();
            match spawn::spawn_only_and_resume(package) {
                Ok(pid) => {
                    let hold_secs = env_u64("RF_DIAG_HOLD_SECS", 20);
                    wait_process_alive(pid as i32, hold_secs, "RF_DIAG_SPAWN_ONLY");
                    spawn::cleanup_zygote_patches();
                    return;
                }
                Err(e) => {
                    log_error!("Spawn-only 诊断失败: {}", e);
                    spawn::cleanup_zygote_patches();
                    std::process::exit(1);
                }
            }
        }
    }

    // 根据参数选择注入方式，返回 (target_pid, host_fd)
    let (target_pid, injection): (Option<i32>, InjectionResult) = if let Some(ref package) = args.spawn {
        // Spawn 模式：注册信号处理函数，确保 Ctrl+C 时还原 Zygote patch
        spawn::register_cleanup_handler();
        // Spawn 模式：注入 Zygote 后启动 App
        match spawn::spawn_and_inject(package, &string_overrides) {
            Ok((pid, result)) => (Some(pid), result),
            Err(e) => {
                log_error!("Spawn 注入失败: {}", e);
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
        }
    } else if let Some(so_pattern) = &args.watch_so {
        // 使用 eBPF 监听 SO 加载
        if let Err(e) = crate::selinux::patch_selinux() {
            log_warn!("SELinux patch 失败（非致命）: {}", e);
        }
        match watch_and_inject(so_pattern, args.timeout, &string_overrides) {
            Ok(result) => (Some(result.target_pid), result),
            Err(e) => {
                log_error!("注入失败: {}", e);
                std::process::exit(1);
            }
        }
    } else if let Some(pid) = resolved_pid {
        // 直接附加到指定 PID（来自 --pid 或 --name 解析结果）
        // 注入前 patch SELinux policy，确保目标进程能读写 memfd
        if let Err(e) = crate::selinux::patch_selinux() {
            log_warn!("SELinux patch 失败（非致命）: {}", e);
        }
        match inject_via_bootstrapper(pid, &string_overrides) {
            Ok(result) => (Some(pid), result),
            Err(e) => {
                log_error!("注入失败: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        log_error!("必须指定 --pid、--name、--watch-so、--spawn 或 --server");
        std::process::exit(1);
    };

    // 创建 legacy session (id=0)
    let label = if let Some(ref pkg) = args.spawn {
        pkg.clone()
    } else if let Some(ref name) = args.name {
        name.clone()
    } else if let Some(pid) = target_pid {
        format!("PID:{}", pid)
    } else {
        "unknown".to_string()
    };
    let session = Arc::new(Session::new(0, label));
    if let Some(pid) = target_pid {
        session.pid.store(pid, Ordering::Relaxed);
    }
    session.set_remote_agent_info(injection.loader_ctx_addr, injection.agent_current_thread_eval_impl);

    // 在 agent 连接前就启动监控，覆盖 spawn 的早期窗口：这时目标仍可能处于
    // 停止态，若注入失败或恢复后立即崩溃，不能依赖 REPL 循环才发现。
    let mut anomaly_monitor = target_pid.map(|pid| {
        anomaly::Monitor::start(
            pid,
            session.clone(),
            args.output.as_deref().or(args.trace_output.as_deref()),
        )
    });

    // 启动 socketpair handler（在 host_fd 上读写）
    let _handle = start_socketpair_handler(injection.host_fd, session.clone());

    // 等待 agent 连接，默认超时 30s（可通过 --connect-timeout 调整）
    {
        log_info!("等待 agent 连接... (最长 {}s)", args.connect_timeout);
        let connected = if args.spawn.is_some() {
            session.wait_connected_with_signal(args.connect_timeout, || spawn::signal_received())
        } else {
            session.wait_connected(args.connect_timeout)
        };

        if args.spawn.is_some() && spawn::signal_received() {
            log_info!("收到终止信号，正在清理...");
            spawn::cleanup_zygote_patches();
            std::process::exit(1);
        }

        if !connected {
            log_error!("等待 agent 连接超时 ({}s)，请检查:", args.connect_timeout);
            if let Some(pid) = target_pid {
                if std::path::Path::new(&format!("/proc/{}/status", pid)).exists() {
                    log_warn!("  目标进程 {} 仍在运行（agent 可能崩溃或未加载）", pid);
                } else {
                    log_warn!("  目标进程 {} 已退出（可能被 OOM 或信号终止）", pid);
                }
            }
            log_warn!("  1. dmesg | grep -i 'deny\\|avc'  （SELinux 拦截？）");
            log_warn!("  2. logcat | grep -E 'FATAL|crash'  （agent 崩溃？）");
            log_warn!("  3. 使用 --verbose 重新运行查看详细注入日志");
            log_warn!("  4. adb logcat | grep -i art  （查看 agent 日志）");
            if let Some(pid) = target_pid {
                if args.spawn.is_some() {
                    let _ = spawn::resume_child(pid as u32);
                }
            }
            std::process::exit(1);
        }
    }
    let sender = session.get_sender().unwrap();

    // 传递 verbose 标志给 agent
    if args.verbose {
        let _ = send_command(sender, "__set_verbose__");
    }

    // ── RPC HTTP 服务器（如启用）──
    // legacy 模式只有一个 session (id=0)，用 SessionManager 包一层供 http_rpc 复用
    if let Some(ref rpc_arg) = args.rpc_port {
        let mgr = Arc::new(SessionManager::new());
        mgr.insert_session(session.clone());
        let bind = parse_rpc_bind(rpc_arg);
        if let Err(e) = http_rpc::start(mgr, &bind) {
            log_error!("{}", e);
        }
    }

    #[cfg(feature = "qbdi")]
    {
        if let Err(e) = send_qbdi_helper(sender, crate::injection::QBDI_HELPER_SO.to_vec()) {
            log_error!("发送 QBDI helper 失败: {}", e);
            std::process::exit(1);
        }
    }

    // Spawn 模式: propload → jsinit → loadjs → resume
    if let Some(ref _package) = args.spawn {
        if let Some(pid) = target_pid {
            if spawn::signal_received() {
                log_info!("收到终止信号，正在清理...");
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
            let mut post_resume_java_worker_needed = false;
            if let Some(script_path) = &args.load_script {
                log_info!("子进程暂停中，准备加载脚本");
                match load_script_file_pre_resume(&session, script_path) {
                    Ok(state) => {
                        post_resume_java_worker_needed |= state.needs_post_resume_java_worker();
                    }
                    Err(e) => {
                        log_error!("{}", e);
                        spawn::abort_pending_children_and_cleanup_zygote_patches();
                        std::process::exit(1);
                    }
                }
            }
            // resume: hook 已就位，恢复子进程
            if let Err(e) = spawn::resume_child(pid as u32) {
                log_error!("恢复子进程失败: {}", e);
            }
            schedule_java_worker_ready_after_resume(session.clone(), post_resume_java_worker_needed);
        }
    }

    // 非 spawn 模式: --load-script 在 resume 后加载（进程已在运行）
    if args.spawn.is_none() {
        if let Some(script_path) = &args.load_script {
            if let Err(e) = load_script_file(&session, script_path, false) {
                log_error!("{}", e);
            }
        }
    }

    // %reload 用：记住最近一次加载的脚本路径
    let mut last_script_path: Option<String> = args.load_script.clone();

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            std::process::exit(1);
        }
    };
    rl.set_helper(Some(CommandCompleter::new()));
    let _ = rl.load_history(".rustfrida_history");
    crate::console_log!("  {DIM}输入 help 查看命令，exit 退出{RESET}");

    // 发送 shutdown 到 agent，随后等待 agent 完整清理并主动关闭 socket
    let send_shutdown = |s: &Session| {
        if let Some(sender) = s.get_sender() {
            s.shutdown_requested.store(true, Ordering::Release);
            if let Err(e) = send_command(sender, "shutdown") {
                log_error!("发送 shutdown 失败: {}", e);
            } else {
                log_info!("已发送 shutdown，等待 agent 主动断开连接...");
            }
        }
    };

    loop {
        // 检测 agent 是否已断连（agent 崩溃或目标进程被杀）
        if session.disconnected.load(Ordering::Acquire) {
            log_error!("Agent 连接已断开，请重新注入");
            break;
        }

        // Spawn 模式：检测是否收到终止信号
        if args.spawn.is_some() && spawn::signal_received() {
            log_info!("收到终止信号，正在退出...");
            send_shutdown(&session);
            break;
        }

        match rl.readline("rustfrida> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                if line == "help" {
                    print_help();
                    continue;
                }
                if line == "exit" || line == "quit" {
                    log_info!("退出交互模式");
                    send_shutdown(&session);
                    break;
                }
                if line == "jsrepl" {
                    run_js_repl(&session);
                    continue;
                }
                // %reload [path]: 清理 JS 引擎并重新加载脚本（不退出进程）
                if line == "%reload" || line.starts_with("%reload ") {
                    let arg = line["%reload".len()..].trim();
                    let path = if arg.is_empty() {
                        last_script_path.clone()
                    } else {
                        Some(arg.to_string())
                    };
                    match path {
                        None => {
                            log_warn!("用法: %reload <path>（未指定 --load-script 时必须给路径）");
                        }
                        Some(p) => {
                            if let Err(e) = load_script_file(&session, &p, true) {
                                log_error!("{}", e);
                            } else {
                                last_script_path = Some(p);
                            }
                        }
                    }
                    continue;
                }
                // 校验 hfl 必须带 <module> <offset> 两个参数
                {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if matches!(parts.first().copied(), Some("hfl")) && parts.len() < 3 {
                        log_warn!("用法: {} <module> <offset>", parts[0]);
                        continue;
                    }
                }
                let is_recomp = line.starts_with("recomp");
                let is_eval_cmd = line.starts_with("jseval ")
                    || line.starts_with("loadjs ")
                    || line == "jsinit"
                    || line == "jsclean"
                    || line.starts_with("managedcounter ")
                    || is_recomp;
                if is_eval_cmd {
                    session.eval_state.clear();
                }
                let handled_by_main_thread = match try_managedcounter_on_main_thread(&session, &line)
                    .and_then(|handled| {
                        if handled {
                            Ok(true)
                        } else {
                            try_loadjs_on_main_thread_if_java(&session, &line)
                        }
                    })
                    .and_then(|handled| {
                        if handled {
                            Ok(true)
                        } else {
                            try_jseval_on_main_thread_if_java_or_dsl(&session, &line)
                        }
                    }) {
                    Ok(v) => v,
                    Err(e) => {
                        log_error!("{}", e);
                        continue;
                    }
                };
                if !handled_by_main_thread {
                    let command = rewrite_jseval_for_agent(&line).unwrap_or_else(|| line.clone());
                    match send_command(sender, &command) {
                        Ok(_) => {}
                        Err(e) => {
                            log_error!("发送命令失败: {}", e);
                            break;
                        }
                    }
                }
                if is_eval_cmd {
                    let timeout = if is_recomp {
                        EVAL_RECOMP_TIMEOUT_SECS
                    } else if script_uses_java_api(&line) {
                        EVAL_JAVA_TIMEOUT_SECS
                    } else {
                        EVAL_DEFAULT_TIMEOUT_SECS
                    };
                    print_eval_result(&session, timeout);
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                log_info!("退出交互模式");
                send_shutdown(&session);
                break;
            }
            Err(e) => {
                log_error!("读取输入失败: {}", e);
                break;
            }
        }
    }

    let _ = rl.save_history(".rustfrida_history");

    // 等待 agent 完成清理并主动关闭 socket。交互路径不能无限等：
    // 超时后直接返回，并跳过远端 loader 残留清理，避免打断仍在清理中的 agent。
    let start = std::time::Instant::now();
    let shutdown_deadline = std::time::Duration::from_secs(AGENT_SHUTDOWN_WAIT_SECS);
    while !session.disconnected.load(Ordering::Acquire) && start.elapsed() < shutdown_deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let total = start.elapsed();
    let agent_disconnected = session.disconnected.load(Ordering::Acquire);
    if agent_disconnected && total.as_secs() >= 1 {
        log_info!("agent 已断开 (总耗时 {}s)", total.as_secs());
    } else if !agent_disconnected {
        log_warn!(
            "agent 清理等待超过 {}s，已返回交互；目标内资源保留，跳过 loader 残留清理",
            AGENT_SHUTDOWN_WAIT_SECS
        );
    }

    if agent_disconnected {
        if let Some(pid) = target_pid {
            cleanup_remote_loader_mappings(pid, &injection);
        }
    }

    // Spawn 模式：agent 完整退出后再还原 Zygote patch，避免两个清理流程交错。
    if args.spawn.is_some() {
        spawn::cleanup_zygote_patches();
    }

    if let Some(monitor) = anomaly_monitor.as_mut() {
        monitor.stop();
    }
}

// =====================================================================
// kernel-trace 模式实现（仅在 feature = "kernel-trace" 时编译）
// =====================================================================

#[cfg(feature = "kernel-trace")]
fn build_trace_options(args: &Args) -> AnyResult<kernel_trace::TraceOptions> {
    use kernel_trace::parse_signal;
    use kernel_trace::{parse_process_group, parse_syscall_list};

    // --trace-reg-name 隐含启用 --trace-show-regs（单 reg 也需要先读 /proc/pid/syscall 抓 33 GPR）
    let show_regs = args.trace_show_regs || args.trace_reg_name.is_some();

    // syscall 名白名单（数字、名字、%分组均可）
    let syscall_names = match &args.trace_syscall {
        Some(spec) => parse_syscall_list(spec).map_err(|e| anyhow!("[trace] --trace-syscall 解析失败: {e}"))?,
        None => Vec::new(),
    };
    // syscall 名黑名单
    let no_syscall_names = match &args.trace_no_syscall {
        Some(spec) => parse_syscall_list(spec).map_err(|e| anyhow!("[trace] --trace-no-syscall 解析失败: {e}"))?,
        None => Vec::new(),
    };
    // 进程分组
    let process_groups: Vec<&'static str> = match &args.trace_group {
        Some(spec) => parse_process_group(spec).map_err(|e| anyhow!("[trace] --trace-group 解析失败: {e}"))?,
        None => Vec::new(),
    };
    // 过滤规则
    let filter_rules = match &args.trace_filter {
        Some(spec) => {
            kernel_trace::parse_filter_list(spec).map_err(|e| anyhow!("[trace] --trace-filter 解析失败: {e}"))?
        }
        None => Vec::new(),
    };
    // --kill 信号解析
    let kill_signal = match &args.trace_kill {
        Some(s) => Some(parse_signal(s).map_err(|e| anyhow!("[trace] --trace-kill 解析失败: {e}"))?),
        None => None,
    };

    // spawn 模式下没显式给 trace 目标时,自动用包名解析 uid 作为过滤
    // (spawn 前 pid 不存在;uid 过滤天然覆盖主进程+全部 fork 子进程)
    let trace_uid = if args.trace_uid == 0 && args.trace_pid == 0 {
        if let Some(ref pkg) = args.spawn {
            let uid = std::fs::metadata(format!("/data/data/{}", pkg))
                .map(|m| {
                    use std::os::unix::fs::MetadataExt;
                    m.uid()
                })
                .unwrap_or(0);
            if uid != 0 {
                log_info!("[trace] spawn 包 {} → uid {} 自动作为过滤", pkg, uid);
            }
            uid
        } else {
            0
        }
    } else {
        args.trace_uid
    };

    Ok(kernel_trace::TraceOptions {
        pid: args.trace_pid,
        uid: trace_uid,
        nr: args.trace_nr,
        tid_blacklist: args.trace_tid_blacklist.clone(),
        full_tname: args.full_tname,
        show_regs,
        unwind_stack: args.trace_unwind_stack,
        reg_name: args.trace_reg_name.clone(),
        uprobe_lib: args.trace_uprobe_lib.clone(),
        uprobe_offset: args.trace_uprobe_offset.unwrap_or(0),
        enable_syscall: !args.trace_disable_syscall,
        syscall_names,
        no_syscall_names,
        uid_blacklist: args.trace_no_uid.clone(),
        process_groups,
        filter_rules,
        kill_signal,
        dumphex: args.trace_dumphex,
        color: args.trace_color,
        output_path: args.trace_output.as_ref().map(std::path::PathBuf::from),
        decode_args: args.trace_decode_args,
        lib_range: args.trace_lib.clone(),
        lib_only: args.trace_lib_only,
        stack_trace: !args.trace_no_stack,
        full_detail: args.trace_full_detail,
        hw_breakpoints: Vec::new(),
    })
}

#[cfg(feature = "kernel-trace")]
type TraceOutput = kernel_trace::sink::BufferedOutput<Box<dyn std::io::Write + Send>>;

#[cfg(feature = "kernel-trace")]
fn open_trace_output(path: Option<&str>) -> std::io::Result<TraceOutput> {
    let writer: Box<dyn std::io::Write + Send> = match path {
        Some(path) => Box::new(std::fs::OpenOptions::new().create(true).append(true).open(path)?),
        None => Box::new(std::io::stdout()),
    };
    Ok(kernel_trace::sink::BufferedOutput::new(writer))
}

#[cfg(feature = "kernel-trace")]
fn write_unified_kernel(record: &str) -> std::io::Result<()> {
    match logger::write_kernel_record(record) {
        // The common writer counts rejected records by source. Keep reading
        // kernel reports so a slow file cannot block the event reader forever.
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        result => result,
    }
}

#[cfg(feature = "kernel-trace")]
fn trace_diagnostic_line(line: &str) {
    if logger::has_output_file() {
        let _ = write_unified_kernel(line);
    } else {
        eprintln!("{line}");
    }
}

#[cfg(feature = "kernel-trace")]
struct TraceLivePrinter {
    svc: bool,
    uprobe: bool,
    hwbp: bool,
    every: u64,
    counts: [u64; 3],
}

#[cfg(feature = "kernel-trace")]
impl TraceLivePrinter {
    fn from_env() -> Self {
        let spec = std::env::var("RF_TRACE_LIVE").unwrap_or_default();
        let all = matches!(spec.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "all");
        let enabled = |name: &str| all || spec.split(',').any(|part| part.trim().eq_ignore_ascii_case(name));
        let every = std::env::var("RF_TRACE_LIVE_EVERY")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(500);
        Self {
            svc: enabled("svc"),
            uprobe: enabled("uprobe"),
            hwbp: enabled("hwbp"),
            every,
            counts: [0; 3],
        }
    }

    fn enabled(&self) -> bool {
        self.svc || self.uprobe || self.hwbp
    }

    fn print(&mut self, report: &kernel_trace::TraceReport) {
        let (enabled, slot) = match report.event_kind {
            "svc.enter" => (self.svc, 0),
            "uprobe.hit" => (self.uprobe, 1),
            "hwbp.hit" => (self.hwbp, 2),
            _ => return,
        };
        if !enabled {
            return;
        }
        self.counts[slot] = self.counts[slot].saturating_add(1);
        let count = self.counts[slot];
        if count > 3 && count % self.every != 0 {
            return;
        }
        let mut pretty = report.to_pretty();
        pretty.insert_str(0, "[trace-live] ");
        logger::stderr_line(&pretty, &pretty);
    }
}

#[cfg(feature = "kernel-trace")]
fn log_trace_output(
    output: Option<&TraceOutput>,
    previous: &mut kernel_trace::sink::OutputStats,
    last: &mut std::time::Instant,
) {
    let now = std::time::Instant::now();
    if now.duration_since(*last) < std::time::Duration::from_secs(5) {
        return;
    }
    if let Some(output) = output {
        let current = output.stats();
        trace_diagnostic_line(&format!(
            "[trace-output] 已接纳={} 实写字节={} 缓冲字节={} | 增量记录={} 增量write={} 输出I/O耗时={:.1}ms",
            current.records,
            current.bytes_written,
            current.pending_bytes,
            current.records.saturating_sub(previous.records),
            current.write_calls.saturating_sub(previous.write_calls),
            current.io_ns.saturating_sub(previous.io_ns) as f64 / 1_000_000.0,
        ));
        *previous = current;
    }
    if logger::has_output_file() {
        let current = logger::output_stats();
        // Keep low-frequency output health visible even when events go to file.
        let status = format!(
            "[output] 入队={} 已处理={} 待处理={} 占用={}KiB 缓冲={}B 实写={}B | 丢弃 host={} agent={} kernel={} 错误={}",
            current.accepted, current.processed, current.pending_records,
            current.pending_bytes / 1024, current.buffered_bytes, current.bytes_written,
            current.host_dropped, current.agent_dropped, current.kernel_dropped, current.errors,
        );
        logger::stderr_line(&status, &status);
    }
    let callbacks = trace_bridge::callback_stats();
    trace_diagnostic_line(&format!(
        "[trace-js] svc已发送={} 限流省略={} | uprobe已发送={} 限流省略={} | hwbp已发送={} 限流省略={} | 连接或发送不可用={} 超时熔断={}",
        callbacks.svc_sent,
        callbacks.svc_limited,
        callbacks.uprobe_sent,
        callbacks.uprobe_limited,
        callbacks.hwbp_sent,
        callbacks.hwbp_limited,
        callbacks.unavailable,
        callbacks.timed_out,
    ));
    *last = now;
}

/// mode=trace：纯 eBPF 内核取证，不注入 agent。
/// 事件以 JSONL 输出到 stdout 或 --trace-output 指定的文件。
#[cfg(feature = "kernel-trace")]
fn run_trace_mode(args: &Args) -> AnyResult<()> {
    log_info!("[trace] 启动内核态取证器");
    let nr_name = if args.trace_nr >= 0 {
        kernel_trace::nr_to_name(args.trace_nr as i64).unwrap_or("?")
    } else {
        "(任意)"
    };
    log_info!(
        "[trace] filter: pid={} uid={} nr={}({}) tid_blacklist={:?}",
        args.trace_pid,
        args.trace_uid,
        args.trace_nr,
        nr_name,
        args.trace_tid_blacklist
    );
    log_info!(
        "[trace] features: show_regs={} unwind_stack={} reg_name={:?}",
        args.trace_show_regs,
        args.trace_unwind_stack,
        args.trace_reg_name
    );
    if let Some(ref lib) = args.trace_uprobe_lib {
        log_info!("[trace] uprobe: lib={} offset={:?}", lib, args.trace_uprobe_offset);
    }
    if !args.trace_disable_syscall {
        log_info!("[trace] tracepoint: raw_syscalls/sys_enter (always-on 除非 --trace-disable-syscall)");
    } else {
        log_info!("[trace] tracepoint 已禁用（--trace-disable-syscall）");
    }

    let opts = match build_trace_options(args) {
        Ok(o) => o,
        Err(e) => {
            log_error!("{}", e);
            std::process::exit(2);
        }
    };
    let file_output = args.trace_output.is_some();
    let unified_output = logger::has_output_file();
    let mut output = open_trace_output(args.trace_output.as_deref())?;
    let tracer = match kernel_trace::KernelTracer::start(opts) {
        Ok(t) => t,
        Err(e) => {
            log_error!("[trace] KernelTracer 启动失败: {:#}", e);
            std::process::exit(1);
        }
    };

    // spawn:tracer 已 attach(uid 过滤从出生覆盖),现在拉起 app
    if let Some(ref pkg) = args.spawn {
        log_info!("[trace] spawn 拉起 app: {}", pkg);
        let out = std::process::Command::new("monkey")
            .args(["-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"])
            .output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => log_error!("[trace] monkey 拉起失败: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => log_error!("[trace] monkey 执行失败: {}", e),
        }
    }

    log_info!(
        "[trace] 就绪：按 Ctrl+C 停止。事件输出到 {}",
        args.output
            .as_deref()
            .or(args.trace_output.as_deref())
            .unwrap_or("stdout")
    );

    // 用户态→内核态 动态指令通道：stdin 每行一条命令，
    // 实时改 FILTER map（pid/uid/nr/any）或动态挂 uprobe 断点（brk lib 0xoff）
    let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let cmd_tx = tracer.command_tx();
        std::thread::Builder::new()
            .name("trace-cmd".into())
            .spawn(move || {
                use std::io::BufRead;
                let help = "[trace-cmd] 动态指令: pid N | uid N | nr N | any | brk <lib> <0xoff> | pause N | cont N";
                logger::stderr_line(help, help);
                let stdin = std::io::stdin();
                for line in stdin.lock().lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => break,
                    };
                    match kernel_trace::TraceCommand::parse(&line) {
                        Some(cmd) => {
                            let _ = cmd_tx.send(cmd);
                        }
                        None => {
                            let t = line.trim();
                            if !t.is_empty() {
                                let message = format!("[trace-cmd] 未识别命令: {t}");
                                logger::stderr_line(&message, &message);
                            }
                        }
                    }
                }
            })
            .ok();
    }

    let mut formatted = String::with_capacity(2048);
    let mut previous_output = output.stats();
    let mut last_output = std::time::Instant::now();
    let mut live = TraceLivePrinter::from_env();
    if live.enabled() {
        log_info!(
            "[trace-live] enabled={}{}{} every={}",
            if live.svc { "svc " } else { "" },
            if live.uprobe { "uprobe " } else { "" },
            if live.hwbp { "hwbp " } else { "" },
            live.every
        );
    }
    let result = (|| -> std::io::Result<()> {
        loop {
            match tracer.recv_timeout(output.wait_timeout()) {
                Ok(report) => {
                    live.print(&report);
                    formatted.clear();
                    if file_output {
                        // Strict JSONL: dumps are already included in the JSON object.
                        report.write_jsonl(&mut formatted);
                        formatted.push('\n');
                        output.write_record(&formatted)?;
                    }
                    if unified_output || !file_output {
                        formatted.clear();
                        report.write_pretty(&mut formatted);
                        for block in &report.dump_blocks {
                            formatted.push_str(block);
                        }
                        if unified_output {
                            write_unified_kernel(&formatted)?;
                        } else {
                            output.write_record(&formatted)?;
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
            output.flush_due()?;
            logger::check_output()?;
            log_trace_output(
                (file_output || !unified_output).then_some(&output),
                &mut previous_output,
                &mut last_output,
            );
        }
        output.flush()?;
        logger::flush_output()
    })();
    stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    tracer.stop();
    result.map_err(|error| anyhow::anyhow!("输出失败（缓冲数据可能尚未输出）: {error}"))
}

/// mode=hybrid：trace 事件写到指定文件或终端，主流程继续。
#[cfg(feature = "kernel-trace")]
fn start_background_tracer(args: &Args) -> AnyResult<()> {
    let opts = build_trace_options(args)?;
    let file_output = args.trace_output.is_some();
    let unified_output = logger::has_output_file();
    let mut output = open_trace_output(args.trace_output.as_deref())?;
    // Fail synchronously on output/lock/load errors before continuing startup.
    let tracer = kernel_trace::KernelTracer::start(opts)?;
    let guard = scene::SceneGuard::new(args.spawn.as_deref().unwrap_or("app"));
    let guard_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    guard.start_watcher(guard_stop.clone());

    std::thread::spawn(move || {
        trace_bridge::register_tracer(tracer.command_tx());
        let mut jsonl = String::with_capacity(2048);
        let mut pretty = String::with_capacity(2048);
        let mut previous_output = output.stats();
        let mut last_output = std::time::Instant::now();
        let mut live = TraceLivePrinter::from_env();
        if live.enabled() {
            log_info!(
                "[trace-live] enabled={}{}{} every={}",
                if live.svc { "svc " } else { "" },
                if live.uprobe { "uprobe " } else { "" },
                if live.hwbp { "hwbp " } else { "" },
                live.every
            );
        }
        let result = (|| -> std::io::Result<()> {
            loop {
                match tracer.recv_timeout(output.wait_timeout()) {
                    Ok(report) => {
                        live.print(&report);
                        jsonl.clear();
                        report.write_jsonl(&mut jsonl);
                        // Record before any callback or potentially blocking output.
                        guard.record_event(report.host_pid, &report.comm, &jsonl);
                        // HWBP 的完整记录含寄存器、16 条指令、堆栈和映射
                        // 注释；文件需要全部保留，但实时 JS 回调只发送有
                        // 用的现场字段，避免每次 jseval 解析数 KB 的重复文本。
                        if report.event_kind == "hwbp.hit" {
                            let mut callback_jsonl = String::with_capacity(2048);
                            report.write_callback_jsonl(&mut callback_jsonl);
                            trace_bridge::push_hwbp_event_jsonl(&callback_jsonl);
                        } else {
                            trace_bridge::push_event_jsonl(&jsonl, report.event_kind == "svc.enter");
                        }
                        if unified_output {
                            pretty.clear();
                            report.write_pretty(&mut pretty);
                            for block in &report.dump_blocks {
                                pretty.push_str(block);
                            }
                            write_unified_kernel(&pretty)?;
                        }
                        let write_result = if file_output {
                            // Explicit file output continues even when JS mutes console output.
                            jsonl.push('\n');
                            let result = output.write_record(&jsonl);
                            jsonl.pop();
                            result
                        } else if !unified_output && trace_bridge::host_should_print() {
                            pretty.clear();
                            report.write_pretty(&mut pretty);
                            for block in &report.dump_blocks {
                                pretty.push_str(block);
                            }
                            output.write_record(&pretty)
                        } else {
                            Ok(())
                        };
                        write_result?;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
                output.flush_due()?;
                logger::check_output()?;
                log_trace_output(
                    (file_output || !unified_output).then_some(&output),
                    &mut previous_output,
                    &mut last_output,
                );
            }
            output.flush()?;
            logger::flush_output()
        })();
        if let Err(error) = result {
            log_error!("[trace-output] 写入失败，停止追踪（缓冲数据可能尚未输出）: {}", error);
        }
        guard_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        tracer.stop();
    });
    Ok(())
}
