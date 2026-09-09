with open('/Users/freeman/project/douyin/rustFrida/rust_frida/src/main.rs', 'r') as f:
    content = f.read()

# 1. Insert if args.no_repl before the REPL loop
old_loop = '''    loop {
        // 检测 agent 是否已断连（agent 崩溃或目标进程被杀）'''

no_repl_block = '''    if args.no_repl {
        log_info!("--no-repl 模式: 跳过 REPL，等待目标进程退出或 agent 断开...");
        loop {
            if session.disconnected.load(Ordering::Acquire) {
                log_info!("agent 已断开，退出 --no-repl 模式");
                break;
            }
            if args.spawn.is_some() && spawn::signal_received() {
                log_info!("收到终止信号，退出 --no-repl 模式...");
                send_shutdown(&session);
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    } else {

    loop {
        // 检测 agent 是否已断连（agent 崩溃或目标进程被杀）'''

# Only replace the first occurrence
if old_loop in content:
    content = content.replace(old_loop, no_repl_block, 1)
    print("Inserted no-repl block before REPL loop")
else:
    print("ERROR: Could not find REPL loop insertion point")
    exit(1)

# 2. Close the else block after rl.save_history
old_save = '''    let _ = rl.save_history(".rustfrida_history");

    // 等待 agent 完成清理并主动关闭 socket'''

new_save = '''    let _ = rl.save_history(".rustfrida_history");
    }

    // 等待 agent 完成清理并主动关闭 socket'''

if old_save in content:
    content = content.replace(old_save, new_save, 1)
    print("Inserted closing brace after rl.save_history")
else:
    print("ERROR: Could not find rl.save_history insertion point")
    exit(1)

with open('/Users/freeman/project/douyin/rustFrida/rust_frida/src/main.rs', 'w') as f:
    f.write(content)

print("main.rs patched successfully")
