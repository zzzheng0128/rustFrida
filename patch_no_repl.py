import re

# Read main.rs
with open('/Users/freeman/project/douyin/rustFrida/rust_frida/src/main.rs', 'r') as f:
    content = f.read()

# Find the REPL loop and wrap it with if/else
# Insert after: println!("  {DIM}输入 help 查看命令，exit 退出{RESET}");
insert_after = '    println!("  {DIM}输入 help 查看命令，exit 退出{RESET}");'

no_repl_block = '''

    // --no-repl: 跳过交互式 REPL，保持运行直到目标进程退出或收到信号
    if args.no_repl {
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
    } else {'''

# Find the send_shutdown closure and move it before the if/else
# Original location: after println!, before loop
send_shutdown_pattern = r'''(    println!\("  \{DIM\}输入 help 查看命令，exit 退出\{RESET\}"\);)

    // 发送 shutdown 到 agent，随后等待 agent 完整清理并主动关闭 socket
    let send_shutdown = \|s: &Session\| \{'''

send_shutdown_replacement = r'''\1
    }\2'''

# First, move send_shutdown to before println
# Find the block from "    // %reload 用" to "    println!"
reload_section = '''    // %reload 用：记住最近一次加载的脚本路径
    let mut last_script_path: Option<String> = args.load_script.clone();

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            exit_after_spawn_cleanup(args.spawn.is_some(), 1);
        }
    };
    rl.set_helper(Some(CommandCompleter::new()));
    let _ = rl.load_history(".rustfrida_history");
    println!("  {DIM}输入 help 查看命令，exit 退出{RESET}");'''

new_reload_section = '''    // %reload 用：记住最近一次加载的脚本路径
    let mut last_script_path: Option<String> = args.load_script.clone();

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

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            exit_after_spawn_cleanup(args.spawn.is_some(), 1);
        }
    };
    rl.set_helper(Some(CommandCompleter::new()));
    let _ = rl.load_history(".rustfrida_history");
    println!("  {DIM}输入 help 查看命令，exit 退出{RESET}");'''

content = content.replace(reload_section, new_reload_section)

# Now insert no_repl block after println
content = content.replace(
    '    println!("  {DIM}输入 help 查看命令，exit 退出{RESET}");',
    '    println!("  {DIM}输入 help 查看命令，exit 退出{RESET}");' + no_repl_block
)

# Remove the duplicate send_shutdown inside the loop
old_send_shutdown = '''    // 发送 shutdown 到 agent，随后等待 agent 完整清理并主动关闭 socket
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

    loop {'''

content = content.replace(old_send_shutdown, '    loop {')

# Close the else block before rl.save_history
old_save_history = '''    let _ = rl.save_history(".rustfrida_history");

    // 等待 agent 完成清理并主动关闭 socket'''

new_save_history = '''    let _ = rl.save_history(".rustfrida_history");
    }

    // 等待 agent 完成清理并主动关闭 socket'''

content = content.replace(old_save_history, new_save_history)

with open('/Users/freeman/project/douyin/rustFrida/rust_frida/src/main.rs', 'w') as f:
    f.write(content)

print("main.rs modified successfully")
