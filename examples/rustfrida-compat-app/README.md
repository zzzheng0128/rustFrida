# RustFrida compatibility demo

> **只跑这个 demo 时只看本页顶部的快速开始。** `使用文档.md` 是通用框架参考，
> `doc/` 主要是实现和历史记录，暂时不需要阅读。

## 快速开始

在仓库根目录执行下面三条命令：

```bash
# 1. 构建测试 APK（首次运行或修改 App C/Java 代码后执行）
bash examples/rustfrida-compat-app/build_demo.sh

# 2. 构建 RustFrida（修改 RustFrida 后执行；只改 JS 可跳过）
# .build-android.sh 默认输出到仓库根目录的 rustfrida_target/
bash .build-android.sh rust_frida

# 3. 安装、spawn、运行 60 秒并拉回日志（0=全部通道）
RUN_SECS=60 BUILD_RF=0 bash examples/rustfrida-compat-app/run_demo_spawn.sh 0
```

同一个入口也提供 `mkpm.kpm` 能力总览。它使用 `kpctl` 控制已经合并的 KPM，
不会另加载 `wxshadow.kpm` 或其他旧模块：

```bash
# 8：status、compatdemo 自己的 SVC/sysmon、hide、redirect、boot_time、inode、readlink、wxshadow/CRC32
bash examples/rustfrida-compat-app/run_demo_spawn.sh 8

# 单项：9=probe，10=wxshadow+CRC32，11=hide，12=redirect，13=boot_time，14=inode，15=readlink
bash examples/rustfrida-compat-app/run_demo_spawn.sh 10
```

`run_demo_spawn.sh` 是唯一需要记住的运行入口。选择 8--15 时，它会自动安装并启动
`com.rustfrida.compatdemo`，加载同一份 `mkpm.kpm`，再用 `kpctl` 切换对应小模块。
设备没有 `kpctl` 时，脚本会优先使用本机
`../dyidre/tools/kpctl/kpctl`（可用 `KPCTL_HOST=/path/to/kpctl` 覆盖）并自动
`adb push` 到 `/data/local/tmp/kpctl`；也可以提前放在 `/data/adb/ap/bin/kpctl`。
每一轮的控制回显和 RustFrida 输出都保存到 `runs/compat-demo/<时间戳>/`。

运行结果在：

```text
runs/compat-demo/<时间戳>/
```

重点看 `rf-output.log`（实时摘要）和 `SUMMARY.txt`（最终统计）；需要完整事件时再看
`trace-output.jsonl`。

每次注入还会启动 RustFrida 宿主侧异常监控。它不改写 ART 的全局 `SIGSEGV` 链，
而是每 100ms 检查目标 `/proc/<pid>`、Agent socket 和设备 `boot_id`。目标被信号终止、
Agent 意外断开、PID 被复用或设备重启时，会生成 `anomaly.jsonl`；记录包括退出状态、
最后一份 `/proc` 快照、`logcat` crash 缓冲、`dmesg` 尾部、`bootreason` 和 pstore 文件名。
`SUMMARY.txt` 中的 `unexpected_anomalies`、`fatal_log_lines`、`device_reboot` 用于快速
判定。`expected=true` 表示用户主动退出或目标正常返回，不能当作闪退。

需要观察 agent 自身的 SIGABRT/SIGILL 等信号时，可在启动命令前加
`RF_AGENT_CRASH_HANDLER=1`。SIGSEGV/SIGBUS 仍交由 ART/libsigchain 处理，App 的
native/managed 崩溃以 `anomaly.jsonl`、`logcat.txt` 和设备 pstore 为准。

运行器会把设备连接、安装、推送、spawn 和最终结果标成颜色：绿色 `[成功]`、红色
`[失败]`、黄色 `[警告]`。`SUMMARY.txt` 的 `run_verdict=pass|partial|fail` 是运行链路判定，
通道是否真正命中仍看对应事件计数。日志里若出现非法控制帧，只会保留首几次和指数采样，
并附带 `len/count/preview`；这类诊断不会再无限刷屏。设置 `NO_COLOR=1` 可关闭终端颜色。

RustFrida 的 Android 产物默认位于仓库根目录的
`rustfrida_target/aarch64-linux-android/release/rustfrida`。旧的 `target/` 目录不要与
它混用；如必须使用旧目录，构建和运行时都显式设置 `CARGO_TARGET_DIR=target`。

这是一个完全自包含的 Android 可用性测试 App。它在加载
`libcompatdemo.so` 时通过 `.init_array` 分配对象并初始化计数器；启动后自动执行
Java 检测、动态 `payload.dex` 加载，以及四条命名压力线程：

- `rf-svc`：arm64 原始 `svc`，读取 `/proc/self/stat`、时钟和随机数；
- `rf-uprobe`：调用 `rf_uprobe_hot`，用于 `KT>brk` 软件探针；
- `rf-hwbp`：反复读写 `.init_array` 分配的对象并调用硬件断点目标；
- `rf-method`：反复切换对象里的 C 函数指针（模拟 vtable/结构体方法），用于验证
  “写指针 → HWBP 识别 → JS 找到新地址 → Interceptor.attach”链路；
- `rf-agent`：调用 `Native.nativeAgentTick`，用于 Java/native agent hook。
- `DexProbe`：每次动态创建 `InMemoryDexClassLoader` 后，脚本会切换到该
  loader 并 hook `DexPayload.run(int)`，验证动态 Dex 类也能被观察。

RustFrida 脚本还会安装 Java hook 和 C 函数 hook，并通过 `KT>` 下发 uprobe、执行
硬件断点、读观察点和写观察点。地址从 `Native.nativeInfo()` 运行时获取，适配
ASLR；脚本对 Pixel 6 的 MTE tagged heap pointer 做了去 tag 处理。

## 构建

在仓库根目录执行：

```bash
bash examples/rustfrida-compat-app/build_demo.sh
```

脚本会先生成 `app/src/main/assets/payload.dex`，再构建 debug APK。可以用
`GRADLE_BIN=/path/to/gradle`、`ANDROID_SDK_ROOT=...` 覆盖默认工具路径。

## spawn 可用性测试

先构建 RustFrida，再执行：

```bash
CARGO_TARGET_DIR=rustfrida_target bash .build-android.sh rust_frida
bash examples/rustfrida-compat-app/run_demo_spawn.sh
```

默认运行 90 秒，日志和 JSONL 保存在 `runs/compat-demo/<timestamp>/`。缩短实验：

```bash
RUN_SECS=30 BUILD_RF=0 bash examples/rustfrida-compat-app/run_demo_spawn.sh 0
```

开启极限档：

```bash
EXTREME=1 RUN_SECS=60 BUILD_RF=0 bash examples/rustfrida-compat-app/run_demo_spawn.sh 0
```

极限档提高 SVC、uprobe、对象读写、HWBP 和 agent 批量频率，增加并发对象线程、
重复 in-memory Dex 加载以及短线程创建/回收；仍保持 `KT_HWBP_SWEEP=0`，避免把已知
内核硬件断点槽位记账问题混入框架压力测试。

结构体方法实验对 `method_slot_addr` 下发一个 8 字节写观察点。native writer 在写入
新函数地址前发布一个 epoch，并在写后等待；JS 收到该 HWBP 后从 slot 重新读取函数
指针、按地址安装一次 `Interceptor`，再调用 `nativeMethodHookReady()` 放行 writer。
因此 hook 安装窗口内不会执行新方法；如果观察点或 agent 消失，native 侧 500 ms
超时会自动放行，避免把测试进程永久卡住。没有这个 gate 时，单靠异步 ring 事件无法
保证零丢失，最多只能做到事后发现。

脚本使用 `--mode=hybrid`，开启 syscall、uprobe、HWBP 和 agent；完整事件流写入
`trace-output.jsonl`。默认还会把 SVC 和 HWBP 的首 3 条、之后每 100 条摘要实时打印到
`rf-output.log`；可用 `RF_TRACE_LIVE=svc,hwbp,uprobe` 和
`RF_TRACE_LIVE_EVERY=1` 调整通道及频率。HWBP 报告包含完整 ARM64 寄存器、PC 处
的当前 4 字节指令和连续 16 条指令窗口，原始 word 和可读汇编；不支持的指令保留为 `.word 0x...`，方便再用
`llvm-objdump`/Capstone 精确反汇编。运行器会把清空前的历史保存到
`device-before/logcat-all.txt`，然后清空 logcat；`logcat.txt` 只用于本轮的
`fatal_log_lines` 和 `[HEARTBEAT]` 判定。

## 多硬件断点矩阵

选择 `16`（或 `hwbp-matrix`）会在同一个 spawn 会话中同时下发 10 个规格：6 个执行
断点（`rf_hwbp_hot`、`rf_uprobe_hot`、`rf_agent_hot`、`rf_object_step`、`rf_method_v1`、
`rf_method_v2`）和 4 个 8 字节观察点（`read_slot`、`write_slot`、`method_slot`、
`method_epoch`）。目标地址由 `Native.nativeInfo()` 运行时计算，适配 ASLR。

硬件槽位按线程计费。默认按 ARM64 常见的 6 个执行槽位和 4 个观察槽位限制；内核
返回 `ENOSPC` 时 host 会记录 `active/target/partial`，停止自动补挂，不会反复打开
设备断点。每个规格的 `[HWBP-MATRIX]` 行包含 `source`（demo 触发次数）、`observed`
（RustFrida/JS 实时回调次数）、`missing` 和 `verdict`。执行断点样本可能显示
`CALLBACK_PARTIAL`，读写观察点在实时回调预算不足时显示 `CALLBACK_LIMITED`；这两种
状态只说明 JS 观察端限流，不能用来判断硬件槽位。槽位是否真的挂满以
`[trace-cmd] hwbp attached ... active=... target=... partial=false`、内核 ring/队列统计
和 `SUMMARY.txt` 的 `hwbp_matrix_host_ok=1` 为准。`FAIL` 只在 host 没有对应命中或
attach 失败时使用。日常阅读使用 `5`，只有测槽位上限时使用 `16`。

运行器默认把 `KT_HWBP_MAX_BREAKPOINTS=6` 和 `KT_HWBP_MAX_WATCHPOINTS=4` 传给目标，
也可以临时调小做边界实验，例如：

```bash
KT_HWBP_MAX_BREAKPOINTS=5 RUN_SECS=6 bash run_demo_spawn.sh 16
```

预期第 6 个执行断点出现“执行断点槽位已满(5)”，`hwbp_matrix_host_ok=0`；这表示
边界拒绝路径生效，不是应用崩溃。

### HWBP 取消与地址轮换

选择 `19`（`hwbp-rotate`）运行真实的调试轮换流程。脚本先挂一个执行断点，命中
3 次后按顺序发送：

```text
KT>bpdel 0x旧地址
KT>x 0x新地址
```

两条命令进入同一个 FIFO 队列，tracer 会先删除旧地址的所有 HWBP 规格并关闭其
每线程 link，再处理新地址。`rf-output.log` 中必须按顺序看到：

```text
[HWBP-ROTATE] phase=hit ...
[HWBP-ROTATE] phase=detach ...
[trace-cmd] hwbp detached: 0x... (1 个规格)
[HWBP-ROTATE] phase=attach ...
[trace-cmd] hwbp attached: ... partial=false  # 理想情况；线程退出时可为 true
```

`SUMMARY.txt` 的 `hwbp_rotate_ok=1` 表示槽位轮换证据完整；若还要确认每次 attach
都覆盖了当时的全部线程，再看 `hwbp_rotate_coverage_full=1`。短暂的
`partial=true` 可能只是 attach 期间线程退出，不等于槽位没有释放。只看到 `cmd queued` 只
表示命令进入队列，不能证明槽位已经释放。轮换实验默认使用
`rf_hwbp_hot`、`rf_object_step`、`rf_method_v1`、`rf_method_v2` 四个会被 demo
调用的入口，每个地址命中 3 次后换下一个。

手工控制时，`bpdel` 只接受绝对地址，并按地址删除所有类型（同一地址上的 x/r/w
会一起删除）；可以从 `hwbp.hit.bp.addr`、`[trace-cmd] hwbp attached` 的 `= 0x...`
或 `locations` 取得地址。`KT>unsub` 只停止 JS 事件投递，不释放硬件槽位；要释放
槽位必须发送 `KT>bpdel 0x地址`。删除后等待 host 的 `hwbp detached`，再复用新地址。

直接运行：

```bash
RUN_SECS=20 bash run_demo_spawn.sh 19
```

如果看到 `hwbp detached: ... (0 个规格)` 或新的 `hwbp attach failed`，本轮不能算
槽位复用成功，应检查地址是否是当前进程的绝对地址、进程是否已经退出，以及 Pixel
设备的硬件槽位统计。`partial=true` 表示某个线程在 attach 期间退出；只要
`hwbp_rotate_ok=1`，槽位复用仍然成功，但 `hwbp_rotate_coverage_full` 会是 `0`。

选择 `17`（或 `uprobe-matrix`）会同时下发 6 个 `KT>brk` 软件探针，分别覆盖
`rf_uprobe_hot`、`rf_hwbp_hot`、`rf_agent_hot`、`rf_object_step`、`rf_method_v1` 和
`rf_method_v2`。demo 的 `nativeUprobeMatrixBurst()` 每轮按固定顺序调用这 6 个目标，
每个目标都能在 `[UPROBE-MATRIX]` 中和自己的源端计数对账。软件探针没有 ARM 调试
寄存器槽位限制，极限主要由 attach 数量、uprobe ring、用户态队列和输出速度决定；
`PARTIAL` 是背压证据，`FAIL` 表示目标被调用但没有收到对应 `uprobe.hit`。

选择 `18`（`uprobe-limit`）会下发最多 32 个互不相同的 native 软件探针入口，用于
测并发 attach 和事件通道的上限。`UPROBE_TARGETS=1/4/8/16/32` 可做阶梯测试；每个
目标在 `[UPROBE-MATRIX]` 中有自己的 `source/observed/missing/verdict`。软件探针没有
ARM 调试寄存器槽位，达到上限通常表现为 attach 失败、ring 丢弃或用户态队列背压，
不能把 `rf_exit_code=0` 单独当成成功。

## 按通道运行

`run_demo_spawn.sh` 是新手入口。不带参数时显示菜单；也可以把编号或名称作为第一个
参数，多个值用逗号分隔：

运行器默认使用 `LOW_FREQ=1` 低频档，并自动开启 `--trace-full-detail`，便于在终端逐条查看事件。需要压测时使用
`EXTREME=1`；普通频率可显式使用 `LOW_FREQ=0 EXTREME=0`。HWBP 命中会在
`rf-output.log` 和 `trace-output.jsonl` 中给出 `instructions`，内容是命中 PC
起连续 16 条 ARM64 指令（每项含 `pc`、`word`、`bytes`、`asm`）。
host 文本会把已解析的地址直接写成 `0x地址(模块.so+0x偏移)`；JSONL 的原始地址保持不变，
对应偏移统一位于 `locations`，便于脚本继续把 `event.pc`/`event.lr` 当作纯地址使用。

| 选择 | 通道 | 代码和观察目标 |
| --- | --- | --- |
| `0` | `all` | C、Java、SVC、JNI、HWBP、uprobe、GumTrace 全部 |
| `1` | `c` | `test_compat_demo.js` 的 `installNativeHook()` → `rf_agent_hot` |
| `2` | `java` | `installJavaHooks()`、`DexProbe` 和 `DexPayload.run()` |
| `3` | `svc` | `native_demo.c` 的 `nativeSvcBurst()` / `.init_array` raw SVC |
| `4` | `jnitrace` | `installJniTrace()` → `Native.nativeRegisterJniProbe()` → `JniProbe` |
| `5` | `hwbp` | `armKernelTrace()` 的执行/读/写观察点和 method-slot gate |
| `6` | `uprobe` | `KT>brk libcompatdemo.so` 软件探针 |
| `16` | `hwbp-matrix` | 6 个执行断点 + 4 个读写观察点的硬件槽位矩阵 |
| `19` | `hwbp-rotate` | 单槽位命中 3 次后 `bpdel`，轮换 4 个执行地址 |
| `17` | `uprobe-matrix` | 6 个不同 native 入口的软件探针矩阵 |
| `18` | `uprobe-limit` | 最多 32 个不同入口的软件探针极限，`UPROBE_TARGETS` 可调 |
| `7` | `gumtrace` | `installGumTrace()` 追踪 `libcompatdemo.so!rf_agent_hot` |
| `8` | `mkpm` | 单一 `mkpm.kpm` 的全部子功能 |
| `9` | `mkpm-probe` | `kpctl syscall` + compatdemo 的 raw SVC/proc/socket/mmap 探针 |
| `10` | `mkpm-crc32` | `wxshadow enable/disable` + CRC32 对照 |
| `11` | `mkpm-hide` | `hide maps` 开关 + compatdemo maps 对照 |
| `12` | `mkpm-redirect` | UID+精确路径重定向 + compatdemo marker 对照 |
| `13` | `mkpm-time` | 目标 UID 的 `CLOCK_BOOTTIME` 减 600 秒，与 root shell `/proc/uptime` 对照 |
| `14` | `mkpm-inode` | 下发 `emaps addino`，对照 App 与 root shell 看到的 maps inode |
| `15` | `mkpm-readlink` | 目标 UID 的指定 symlink 返回 `ENOENT`，root shell 仍能读到原目标 |

`13` 只改目标 UID 的 `clock_gettime(CLOCK_BOOTTIME)` 输出，不改系统全局时钟；日志会给出 App 与 root shell 的绝对差，约 600 秒才算生效。`14` 会把规则目标设为 inode `1`，然后在规则仍启用时分别读取 App 的 `/proc/self/maps` 和 root shell 的同一文件：两边 inode 不同才表示按 UID 隔离的改写真正生效。`15` 在应用私有目录创建测试 symlink，App 读取应为 `-ENOENT`，root shell 读取应保留原始目标。

Pixel6 上 runner 默认复用已经加载的 `mkpm`。KPM 的 exit 路径会先清空本模块回调，
再保留 KernelPatch 的无回调跳板，避免卸载后其他 CPU 访问已释放的 hook 链；设置
`KPM_RELOAD=1` 可在 force-stop 应用后验证这条路径。修改 KPM 后仍建议重启设备，
因为每次显式 reload 都会保留少量空链槽位，长时间反复 reload 应以重启回收为界。

例如：

```bash
bash examples/rustfrida-compat-app/run_demo_spawn.sh 1,2
bash examples/rustfrida-compat-app/run_demo_spawn.sh jnitrace,gumtrace
```

模式会写入 `debug.rustfrida.compat.mode`，因此 App 的 `StressRunner` 只启动所选
线程，不会让单通道实验混入其他事件。所有模式仍使用同一份
`test_compat_demo.js`，便于复制后扩展组合场景。

代码位置：`CompatApplication.onCreate()` 是最早启动入口，`MainActivity` 负责选择模式，
`StressRunner` 是各压力线程，`native_demo.c` 是 C/SVC/HWBP/JNI 注册和 mkpm 探针实现，
`JniProbe.java` 是动态 JNI 注册目标。脚本位于 `test_compat_demo.js`；可复用的独立
GumTrace 模板位于 [`../../examples/templates/07_gumtrace.js`](../../examples/templates/07_gumtrace.js)。
其他通用能力模板集中在 [`../../examples/templates/`](../../examples/templates/)：
`08_memory_dump.js`（内存转储）、`09_file_io.js`（读写文件）、`10_memory_rw.js`
（内存读写）、`11_backtrace.js`（堆栈）和 `12_method_call.js`（方法调用）。
