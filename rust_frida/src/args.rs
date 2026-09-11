#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use clap::{ArgGroup, Parser};

fn parse_pid(s: &str) -> std::result::Result<i32, String> {
    match s.parse::<i32>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err("PID 必须是正整数".to_string()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum RunMode {
    /// 默认：attach + 注入 agent + REPL（保留原有所有功能）
    Inject,
    /// 纯 eBPF 内核态取证器：sys_enter tracepoint + 可选 uprobe，打印 JSONL 到 stdout
    Trace,
    /// attach 注入 agent 的同时，并行跑 eBPF 取证（事件透传给 JS `Trace` API）
    Hybrid,
}

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "ARM64 Android 动态插桩工具，通过 ptrace 注入 agent.so，支持 QuickJS 脚本/inline hook/Stalker 追踪",
    long_about = "\
ARM64 Android 动态插桩工具。通过 ptrace 注入 agent.so 到目标进程，支持 QuickJS 脚本执行、\
inline hook、Stalker 追踪等功能。

常见用法:
  rustfrida --pid 1234                         # 注入到指定 PID
  rustfrida --name com.example.app             # 按进程名注入
  rustfrida --watch-so libnative.so            # 等待 SO 加载后自动注入
  rustfrida --spawn com.example.app            # Spawn 模式：启动前注入
  rustfrida --pid 1234 -l script.js            # 注入并执行 JS 脚本
  rustfrida --pid 1234 --verbose               # 显示详细注入调试信息
  rustfrida --mode=trace -p 1234 --show-regs   # 纯 eBPF 取证：syscall+regs，JSONL 输出
  rustfrida --mode=hybrid --pid 1234 --show-regs --unwind-stack  # 注入 + 内核取证并行

内核取证（需启用 kernel-trace feature 编译: cargo build -p rust_frida --features kernel-trace）:
  rustfrida --mode=trace --show-regs --unwind-stack --pid 1234 --nr 56
  rustfrida --mode=trace --uprobe-lib /apex/.../libart.so --uprobe-offset 0x1234
  rustfrida --mode=trace --config-file /sdcard/trace.json   # stackplz-style config.json

属性伪装:
  rustfrida --dump-props default                                    # Dump 属性快照
  rustfrida --set-prop default ro.build.fingerprint=google/...      # 修改属性值
  rustfrida --set-prop default ro.debuggable=0                      # 可多次调用
  rustfrida --spawn com.app --profile default                       # Spawn 并应用

Server daemon 模式（多 session 并发）:
  rustfrida --server                                                # 启动 server
  rustfrida --server --profile default                              # 启动 + 属性伪装持续生效

注入后进入 REPL，输入 help 查看可用命令（jsinit / loadjs / jsrepl / jhook 等）。",
    group(ArgGroup::new("target").required(false).multiple(true).args(["pid", "watch_so", "name", "spawn", "dump_props", "set_prop", "del_prop", "repack_props", "server", "mode"]))
)]
pub(crate) struct Args {
    /// 目标进程的PID（与 --watch-so、--name、--spawn 互斥）
    #[arg(
        short,
        long,
        conflicts_with_all = ["watch_so", "name", "spawn"],
        allow_hyphen_values = true,
        value_parser = parse_pid
    )]
    pub(crate) pid: Option<i32>,

    /// 监听指定 SO 路径加载，自动附加到加载该 SO 的进程（需要 ldmonitor eBPF 组件：cargo build -p ldmonitor）
    #[arg(short = 'w', long = "watch-so", conflicts_with_all = ["name", "spawn"])]
    pub(crate) watch_so: Option<String>,

    /// 按进程名注入（与 --pid、--watch-so、--spawn 互斥）
    #[arg(short = 'n', long = "name", conflicts_with = "spawn")]
    pub(crate) name: Option<String>,

    /// Spawn 模式：启动 App 前注入，确保能 hook 到 Application.onCreate() 等早期代码
    #[arg(short = 'f', long = "spawn")]
    pub(crate) spawn: Option<String>,

    /// 监听超时时间（秒），默认无限等待
    #[arg(short = 't', long = "timeout")]
    pub(crate) timeout: Option<u64>,

    /// 等待 agent 连接的超时时间（秒），默认 10 秒
    #[arg(long = "connect-timeout", default_value = "10")]
    pub(crate) connect_timeout: u64,

    /// 覆盖字符串表中的指定值（可多次使用），格式: name=value
    ///
    /// 可用名称及用途:
    ///   sym_name     — loader 查找的导出符号（高级调试）
    ///   dlsym_err    — dlsym 调用错误消息前缀
    ///   cmdline      — procfs cmdline 路径
    ///   output_path  — 日志输出路径
    #[arg(short = 's', long = "string", value_name = "NAME=VALUE")]
    pub(crate) strings: Vec<String>,

    /// 加载并执行JavaScript脚本文件
    #[arg(short = 'l', long = "load-script", value_name = "FILE")]
    pub(crate) load_script: Option<String>,

    /// 显示详细注入信息（地址、偏移等）
    #[arg(short = 'v', long = "verbose")]
    pub(crate) verbose: bool,

    /// 统一记录 agent/hook、kernel 和宿主日志（终端同款可读文本，覆盖文件）
    ///
    /// 事件不重复刷屏；交互提示仍显示在终端。只改变输出位置，不改变参数解码或详情预算。
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub(crate) output: Option<String>,

    /// Dump 本机属性到 profile（独立操作，不注入进程）
    ///
    /// 复制 /dev/__properties__/ 二进制文件到 profile 目录，
    /// 之后用 --set-prop 修改单个属性值。
    #[arg(
        long = "dump-props",
        value_name = "PROFILE",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "set_prop"]
    )]
    pub(crate) dump_props: Option<String>,

    /// 修改 profile 中的属性值（类似 magisk resetprop）
    ///
    /// 直接 patch profile 目录中的二进制属性区域文件。可多次调用设置不同属性。
    /// 格式: --set-prop <PROFILE> <key=value>
    #[arg(
        long = "set-prop",
        value_name = "PROFILE",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "dump_props"],
        num_args = 2,
        value_names = ["PROFILE", "KEY=VALUE"]
    )]
    pub(crate) set_prop: Option<Vec<String>>,

    /// 删除 profile 中的属性
    ///
    /// 清零属性值和 serial，使属性不可读。
    /// 格式: --del-prop <PROFILE> <key>
    #[arg(
        long = "del-prop",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "dump_props", "set_prop", "repack_props"],
        num_args = 2,
        value_names = ["PROFILE", "KEY"]
    )]
    pub(crate) del_prop: Option<Vec<String>>,

    /// 重排 profile 消除空洞（重新 dump + 重放变更日志）
    #[arg(
        long = "repack-props",
        value_name = "PROFILE",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "dump_props", "set_prop", "del_prop"]
    )]
    pub(crate) repack_props: Option<String>,

    /// 指定属性覆盖 profile（--spawn 或 --server 模式可用）
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Server daemon 模式：多 session 并发 spawn/inject，profile 持续生效
    ///
    /// 启动后进入 server REPL，支持同时管理多个注入 session。
    /// 配合 --profile 使用可在整个 server 生命周期内持续生效。
    #[arg(long = "server", conflicts_with_all = ["pid", "watch_so", "name", "spawn"])]
    pub(crate) server: bool,

    /// 启动 HTTP RPC 服务器，暴露 agent 端 `rpc.exports` 注册的方法。
    ///
    /// 格式: --rpc-port <PORT> 或 --rpc-port <HOST:PORT>（默认绑定 0.0.0.0）。
    /// 路由：
    ///   GET  /sessions                        列出 session
    ///   POST /rpc/<session>/<method>          调用 rpc.exports[method]，请求体为 JSON 参数数组
    ///
    /// 在 legacy 模式下 session_id 为 0，在 --server 模式下为 list 命令显示的 id。
    #[arg(long = "rpc-port", value_name = "PORT_OR_ADDR")]
    pub(crate) rpc_port: Option<String>,

    // =================================================================
    // 运行模式（mode = inject|trace|hybrid）
    // =================================================================
    /// 运行模式
    ///
    /// - inject（默认）：attach + 注入 agent + REPL（保留所有原有功能）
    /// - trace：纯 eBPF 内核态取证，不注入任何 agent；事件以 JSONL 输出到 stdout
    /// - hybrid：inject + 同一进程跑 eBPF 取证；trace 事件通过 socketpair 转发给 agent JS
    ///
    /// mode=trace/hybrid 需要启用 kernel-trace feature 编译。
    #[arg(long = "mode", value_enum, default_value_t = RunMode::Inject)]
    pub(crate) mode: RunMode,

    // =================================================================
    // kernel-trace 子选项（mode=trace 或 mode=hybrid 时生效）
    // =================================================================
    /// [trace] 只跟踪这个 PID（0 = 不过滤）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-pid", value_name = "PID", default_value_t = 0)]
    pub(crate) trace_pid: u32,

    /// [trace] 只跟踪这个 UID（0 = 不过滤）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-uid", value_name = "UID", default_value_t = 0)]
    pub(crate) trace_uid: u32,

    /// [trace] 只跟踪这个 syscall 号（-1 = 不过滤）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-nr", value_name = "NR", default_value_t = -1)]
    pub(crate) trace_nr: i32,

    /// [trace] TID 黑名单（逗号分隔，最多 5 个）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-tid-blacklist", value_delimiter = ',')]
    pub(crate) trace_tid_blacklist: Vec<u32>,

    /// [trace] 包含默认排除的运行时/渲染线程；显式 TID 黑名单仍生效
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "full-tname")]
    pub(crate) full_tname: bool,

    /// [trace] 读 /proc/<pid>/syscall 抓 33 个 ARM64 GPR（仿 stackplz ShowRegs）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-show-regs")]
    pub(crate) trace_show_regs: bool,

    /// [trace] 读 /proc/<pid>/stack 抓 kernel backtrace（仿 stackplz UnwindStack）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-unwind-stack")]
    pub(crate) trace_unwind_stack: bool,

    /// [trace] 单 reg 提取模式（x0..x30 / sp / pc / pstate / fp / lr）
    ///
    /// 与 --trace-show-regs 互斥（单 reg 时不需要全 dump）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-reg-name", value_name = "REG", conflicts_with = "trace_show_regs")]
    pub(crate) trace_reg_name: Option<String>,

    /// [trace] 通用 uprobe：目标库绝对路径
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-uprobe-lib", value_name = "LIB")]
    pub(crate) trace_uprobe_lib: Option<String>,

    /// [trace] uprobe 偏移（与 --trace-uprobe-lib 配对）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-uprobe-offset", value_name = "OFFSET", value_parser = parse_maybe_hex_u64)]
    pub(crate) trace_uprobe_offset: Option<u64>,

    /// [trace] 不挂 sys_enter tracepoint（只挂 uprobe 时用）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-disable-syscall")]
    pub(crate) trace_disable_syscall: bool,

    /// [trace/hybrid] 单独的 kernel JSONL 数据（append），不包含 agent/hook 和宿主日志
    ///
    /// 需要终端同款统一文本请用 --output；两者可同时使用，但必须指向不同文件。
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-output", value_name = "FILE")]
    pub(crate) trace_output: Option<String>,

    /// [trace] stackplz 风格的 config.json 路径（高级配置）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-config", value_name = "FILE")]
    pub(crate) trace_config: Option<String>,

    // =================================================================
    // stackplz 风格扩展（mode=trace 时生效）
    // =================================================================
    /// [trace] syscall 名白名单（逗号分隔，可含 %file/%net/%read/%write/%attr/%exec/%process/%signal/%kill/%exit/%dup/%epoll/%stat/%recv/%send/%clone/%all）
    ///
    /// 与 --trace-nr 互斥。例: --trace-syscall openat,connect,sendto  或  --trace-syscall %file
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-syscall", value_name = "LIST", conflicts_with = "trace_nr")]
    pub(crate) trace_syscall: Option<String>,

    /// [trace] syscall 名黑名单（逗号分隔）
    ///
    /// 例: --trace-no-syscall recvfrom,recvmsg
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-no-syscall", value_name = "LIST")]
    pub(crate) trace_no_syscall: Option<String>,

    /// [trace] UID 黑名单（逗号分隔）
    ///
    /// 例: --trace-no-uid 1000,1001
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-no-uid", value_delimiter = ',')]
    pub(crate) trace_no_uid: Vec<u32>,

    /// [trace] 进程分组（app/iso/root/system/shell/media/all）
    ///
    /// 多个用逗号分隔。例: --trace-group app  或  --trace-group app,iso
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-group", value_name = "GROUP")]
    pub(crate) trace_group: Option<String>,

    /// [trace] 过滤规则（可多次使用）
    ///
    /// 格式: w:/PATH（路径白名单）b:/PATH（路径黑名单）eq:0xHEX（寄存器等值）ne:0xHEX（不等）bx:HEX（buffer 头 8 字节等值）
    /// 例: -f w:/system -f b:/dev  或  --trace-filter "w:/system,b:/dev"
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-filter", value_name = "RULES")]
    pub(crate) trace_filter: Option<String>,

    /// [trace] 命中事件后给目标进程发信号（默认 SIGSTOP），需配合 stdin 'c' 回车恢复
    ///
    /// 格式: --trace-kill [SIGNAL]，SIGNAL 可为 SIGSTOP/SIGCONT/SIGKILL/SIGTERM/SIGUSR1/SIGUSR2 或数字
    /// 例: --trace-kill SIGSTOP
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-kill", value_name = "SIGNAL", default_missing_value = "SIGSTOP", num_args = 0..=1)]
    pub(crate) trace_kill: Option<String>,

    /// [trace] buffer 字段以 hex+ASCII 显示（仿 stackplz --dumphex）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "dumphex")]
    pub(crate) trace_dumphex: bool,

    /// [trace] 输出用 ANSI 颜色（仿 stackplz --color，受 NO_COLOR/TERM=dumb 影响）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "color")]
    pub(crate) trace_color: bool,

    /// [trace] 语义解析 syscall 参数（字符串解引用、buffer 最多32B预览；完整块另加 --dumphex）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-decode-args")]
    pub(crate) trace_decode_args: bool,

    /// [trace] 按 LR 所属库标记/限定 svc（SO 名、包名或逗号分隔列表）
    ///
    /// all/* 只匹配 Android 应用目录中的 SO；系统库路径排除。PC 在 libc 不影响 LR 命中。
    /// 配合 --trace-lib-only 才丢弃未命中事件。自有样本位于 /data/local/tmp 时请用具体 SO 名。
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-lib", value_name = "SUBSTR")]
    pub(crate) trace_lib: Option<String>,

    /// [trace] 只输出 --trace-lib 命中的事件（丢弃其它 svc）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-lib-only", requires = "trace_lib")]
    pub(crate) trace_lib_only: bool,

    /// [trace] 关闭用户态堆栈回溯；svc 的 LR/PC 模块归属仍保留
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-no-stack")]
    pub(crate) trace_no_stack: bool,

    /// [trace] 禁用默认的详情预算/排队保护，每条事件尝试完整解析（高负载时可能影响响应）
    #[cfg(feature = "kernel-trace")]
    #[arg(long = "trace-full-detail")]
    pub(crate) trace_full_detail: bool,
}

/// 解析 u64，支持 0x 前缀十六进制（如 0x135ff8）或十进制
#[cfg(feature = "kernel-trace")]
fn parse_maybe_hex_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex offset: {e}"))
    } else {
        s.parse::<u64>().map_err(|e| format!("invalid offset: {e}"))
    }
}
