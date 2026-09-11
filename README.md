# rustFrida

ARM64 Android 动态插桩和内核事件观察工具。首页只保留日常入口；历史实验脚本和
`doc/` 专项资料保留，不需要时可以跳过。

当前兼容性结论只采信 Pixel 6（serial `18201FDF6002GR`，Android 15、内核
`6.1.99-android14-11-gd6f926cfde54-ab12786694`）。Pixel 5（serial
`0A291FDD40011F`，4.19）属于另一组实验，旧日志不与 Pixel 6 合并。

## 最快跑通兼容性 demo

在仓库根目录执行：

```bash
# 首次运行或修改 demo 的 C/Java 代码后执行
bash examples/rustfrida-compat-app/build_demo.sh
# 如果系统没有 gradle 命令，改为：
# GRADLE_BIN=/path/to/gradle bash examples/rustfrida-compat-app/build_demo.sh

# 修改 RustFrida 后执行；只修改 JS 时可以跳过。
# .build-android.sh 默认把 Android 产物写入 rustfrida_target/
bash .build-android.sh rust_frida

# 安装 APK、spawn 注入并运行 60 秒（默认全部通道、低频可读档）
DEVICE_SERIAL=18201FDF6002GR RUN_SECS=60 BUILD_RF=0 \
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 0

# 也可以让新手按菜单选择，或直接组合编号/名称
bash examples/rustfrida-compat-app/run_demo_spawn.sh       # 交互菜单
bash examples/rustfrida-compat-app/run_demo_spawn.sh 1,2   # C + Java
bash examples/rustfrida-compat-app/run_demo_spawn.sh jnitrace,gumtrace
bash examples/rustfrida-compat-app/run_demo_spawn.sh 8     # mkpm 全部子模块
bash examples/rustfrida-compat-app/run_demo_spawn.sh 13    # boot_time UID 偏移对照
bash examples/rustfrida-compat-app/run_demo_spawn.sh 14    # inode 替换观察
bash examples/rustfrida-compat-app/run_demo_spawn.sh 15    # readlink UID 隔离对照
```

菜单 `8–15` 会加载 `mkpms/dist/mkpm.kpm` 并用 `kpctl` 控制 `syscall`、`hide`、
`wxshadow`、`redirect`、`emaps`、`boot_time` 和 `readlink`。Pixel6 默认复用已经加载的
KPM，修改 KPM 后重启设备再运行；显式设置 `KPM_RELOAD=1` 会在 force-stop 应用后走受保护的卸载路径。设备没有 `kpctl` 时，脚本自动从
`../dyidre/tools/kpctl/kpctl`（或 `KPCTL_HOST` 指定的位置）推送 aarch64 二进制，
因此不需要额外的 adb shell 步骤。

运行器默认 `LOW_FREQ=1`，各通道低频触发并逐条显示实时样本；内核通道同时自动使用
`--trace-full-detail`，适合确认断点和寄存器现场。
需要压测时显式设置 `EXTREME=1`（会自动关闭低频）；普通频率可用 `LOW_FREQ=0 EXTREME=0`。
HWBP 命中事件的 `instructions` 字段包含从命中 PC 开始的 16 条 ARM64 指令，每项带
`pc`、`word`、`bytes` 和 `asm`。
host 日志会把已解析的地址直接显示为 `0x地址(模块.so+0x偏移)`；JSONL 保留原始地址，
偏移统一放在 `locations` 对象中。

运行步骤、编译细节、成功判据和错误排查统一看根目录的[使用与兼容性手册](使用文档.md)；
兼容性 demo README 只补充代码结构和实验背景。

构建目录统一使用 `rustfrida_target/`，最终二进制是：

```text
rustfrida_target/aarch64-linux-android/release/rustfrida
```

仓库里原来的 `target/` 是 Cargo 默认目录，可能存在旧 agent。只有需要兼容旧脚本时
才显式执行 `CARGO_TARGET_DIR=target bash .build-android.sh rust_frida`，不要混用两套
目录里的 `rustfrida` 和 `libagent.so`。

结果保存在：

```text
runs/compat-demo/<时间戳>/
```

- `rf-output.log`：实时摘要和 JS 日志
- `SUMMARY.txt`：最终统计
- `trace-output.jsonl`：完整事件流
- `logcat.txt`：设备 logcat

## 按目的选择入口

| 目的 | 入口 |
| --- | --- |
| 按菜单跑兼容性 demo（all/C/Java/SVC/JNITrace/HWBP/uprobe/GumTrace） | [examples/rustfrida-compat-app/README.md](examples/rustfrida-compat-app/README.md) |
| 写一个新的 JS 脚本 | [examples/templates/README.md](examples/templates/README.md) |
| 日常 attach、spawn、hybrid、`KT>` 命令 | [使用文档.md](使用文档.md) |
| 查看文档分类 | [DOCS.md](DOCS.md) |

## 通用运行方式

换成自己的应用时，不要直接修改兼容性 demo 的包名就运行。`run_demo_spawn.sh` 还依赖
demo 的 `Native.nativeInfo()`、`libcompatdemo.so` 和源端计数器；其他应用请按
[脚本适配清单](SCRIPT_GUIDE.md#换成其他应用时要传什么) 替换包名、脚本、模块/符号或偏移、
Java/JNI 配置，再用下面的通用命令启动。

先构建并推送二进制：

```bash
bash .build-android.sh rust_frida
adb push rustfrida_target/aarch64-linux-android/release/rustfrida /data/local/tmp/rustfrida
adb shell su -c 'chmod 755 /data/local/tmp/rustfrida'
```

attach 已运行进程：

```bash
adb shell su -c '/data/local/tmp/rustfrida --name com.example.app -l /data/local/tmp/script.js'
```

spawn 启动前注入：

```bash
adb shell su -c '(sleep 60; echo exit) | timeout 65 \
  /data/local/tmp/rustfrida --spawn com.example.app -l /data/local/tmp/script.js'
```

spawn 的非交互命令必须保持 stdin 打开，否则 REPL 提前退出，脚本和 hook 也会被清理。
`KT>` 命令只在 `--mode=hybrid` 下生效。

## JS 模板

新脚本从 `examples/templates/` 复制：

- `01_native_hook.js`：native 函数观察
- `02_java_hook.js`：Java 方法观察
- `03_kernel_trace.js`：uprobe、SVC、HWBP
- `04_jni_trace.js`：`RegisterNatives` 观察
- `05_memory_probe.js`：内存读取
- `06_agent_replace.js`：native 替换
- `07_gumtrace.js`：GumTrace 指令级追踪（默认目标为兼容性 demo）
- `08_memory_dump.js`：模块可读区间分块转储 + `.map`
- `09_file_io.js`：文本/二进制文件读写
- `10_memory_rw.js`：分配内存、整数/指针/字节读写
- `11_backtrace.js`：ARM64 native 堆栈采集
- `12_method_call.js`：`NativeFunction` 和 Java 方法调用
- `13_kpm_control.js`：JS 通过 `libc.syscall(45)` 低频调用 APatch supercall 控制 `mkpm`

根目录中的 `test_*.js`、`probe_*.js` 是历史回归和设备实验，不作为新脚本模板。

## 环境要求

- Android ARM64 开发机，已 root 或具备 `su`
- Android NDK 25 或更高版本
- Rust 工具链和 `aarch64-linux-android` target
- Python 3
- 已配置 Android SDK/`adb`

首次初始化子模块：

```bash
git submodule update --init --recursive
```

遇到具体问题时，再按 [DOCS.md](DOCS.md) 的分类打开专项记录即可。
