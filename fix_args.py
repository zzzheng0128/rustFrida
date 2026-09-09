with open('/Users/freeman/project/douyin/rustFrida/rust_frida/src/args.rs', 'r') as f:
    content = f.read()

# Remove duplicate server field (lines 155-160 in current file)
old_duplicate = '''    ///
    /// 启动后进入 server REPL，支持同时管理多个注入 session。
    /// 配合 --profile 使用可在整个 server 生命周期内持续生效。
    #[arg(long = "server", conflicts_with_all = ["pid", "watch_so", "name", "spawn"])]
    pub(crate) server: bool,

'''

content = content.replace(old_duplicate, '', 1)

# Fix rpc_port comment - add back the header
old_rpc = '''    ///
    /// 格式: --rpc-port <PORT> 或 --rpc-port <HOST:PORT>（默认绑定 0.0.0.0）。'''

new_rpc = '''    /// 启动 HTTP RPC 服务器，暴露 agent 端 `rpc.exports` 注册的方法。
    ///
    /// 格式: --rpc-port <PORT> 或 --rpc-port <HOST:PORT>（默认绑定 0.0.0.0）。'''

content = content.replace(old_rpc, new_rpc, 1)

with open('/Users/freeman/project/douyin/rustFrida/rust_frida/src/args.rs', 'w') as f:
    f.write(content)

print("args.rs fixed")
