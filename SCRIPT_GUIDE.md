# rustFrida JS 脚本指南

新脚本只从下面两处复制：

- [`script_template.js`](script_template.js)：通用的地址、字符串、hex 和低频采样辅助函数。
- [`examples/templates/`](examples/templates/)：按场景拆开的最小可运行模板。

模板对应关系：

| 文件 | 场景 |
| --- | --- |
| `01_native_hook.js` | `Interceptor.attach` 观察 native 导出 |
| `02_java_hook.js` | `Java.ready` + `Java.use` 观察 Java 方法 |
| `03_kernel_trace.js` | `KT>` uprobe/HWBP 控制和事件摘要 |
| `04_jni_trace.js` | JNIEnv 函数表系统 JNI 追踪（类/方法/字段/字符串/数组/注册等） |
| `05_memory_probe.js` | 只读模块内存并输出十六进制 |
| `06_agent_replace.js` | `hook()` 替换式 native hook |
| `07_gumtrace.js` | GumTrace 指令级追踪；默认目标为兼容性 demo |
| `08_memory_dump.js` | 模块可读区间转储到文件 |
| `09_file_io.js` | 文本和二进制文件读写 |
| `10_memory_rw.js` | 内存分配、读写和指针字段 |
| `11_backtrace.js` | ARM64 native 堆栈采集 |
| `12_method_call.js` | native/Java 方法主动调用 |

根目录的 `test_*`、`probe_*`、`*_stress` 和 `test_all.js` 是历史回归或设备专用实验。它们可以用于复现问题，但包含固定包名、偏移、压测入口和临时诊断逻辑，不作为通用脚本模板。

## 最小运行

attach 已运行进程：

```bash
adb push examples/templates/01_native_hook.js /data/local/tmp/
adb shell 'su -c "/data/local/tmp/rustfrida --name com.example.app \
  -l /data/local/tmp/01_native_hook.js"'
```

spawn 启动前注入：

```bash
adb push examples/templates/02_java_hook.js /data/local/tmp/
adb shell 'su -c "(sleep 60; echo exit) | timeout 65 \
  /data/local/tmp/rustfrida --spawn com.example.app \
  -l /data/local/tmp/02_java_hook.js"'
```

spawn 的非交互 stdin 必须保活。stdin 直接 EOF 会让 REPL 退出并清理 hook；只看到 `loaded`、没有命中时先检查这一点。

## 换成其他应用时要传什么

`examples/rustfrida-compat-app/run_demo_spawn.sh` 是自包含的兼容性 demo 运行器，固定使用
`com.rustfrida.compatdemo`、`libcompatdemo.so` 以及 demo 自己的 Java/native 计数器。换成
其他应用时不要只把 `--spawn` 后的包名替换掉；请复制一个模板脚本，或者直接使用下面的
通用命令，并替换目标配置。

| 项目 | 必须提供的值 | 在脚本中的位置 |
| --- | --- | --- |
| 进程 | 包名，例如 `com.example.app` | `--spawn`（启动前注入）或 `--name`/`--pid`（已运行进程） |
| 脚本 | 推送到设备的 JS 路径 | `-l /data/local/tmp/app.js` |
| native 导出 | ELF 名和导出符号 | `TARGET_MODULE`、`TARGET_SYMBOL` |
| native 偏移 | 当前 APK/ABI 的模块相对偏移 | `TARGET_OFFSET` 或 `KT>x/KT>r/KT>w` |
| Java | 完整类名、方法名、重载签名 | `TARGET_CLASS`、`TARGET_METHOD`、`TARGET_OVERLOAD` |
| JNI | `RegisterNatives` 地址和目标 ABI | `04_jni_trace.js` 中的 `Jni.addr` 与结构体读取 |
| GumTrace | 目标模块、符号或偏移、输出文件 | `TARGET_MODULE`、`TARGET_SYMBOL`/`TARGET_OFFSET`、`TRACE_FILE` |
| KPM（可选） | 已加载的模块名、superkey/KP 版本、目标 UID 和测试路径 | `13_kpm_control.js` 的配置；开关不要放进高频回调 |

一个只观察 native 导出的新应用示例：

```bash
adb push examples/templates/01_native_hook.js /data/local/tmp/app.js
adb shell 'su -c "(sleep 60; echo exit) | timeout 70 \
  /data/local/tmp/rustfrida --spawn com.example.app \
  -l /data/local/tmp/app.js"'
```

一个需要 uprobe/HWBP 的新应用示例：

```bash
adb push my_app_trace.js /data/local/tmp/my_app_trace.js
adb shell 'su -c "(sleep 120; echo exit) | timeout 135 \
  /data/local/tmp/rustfrida --spawn com.example.app --mode=hybrid \
  -l /data/local/tmp/my_app_trace.js \
  --trace-lib libfoo.so --trace-lib-only --trace-disable-syscall \
  --trace-no-stack --trace-output /data/local/tmp/my_app.jsonl"'
```

JS 中至少要把这些 demo 值替换成目标应用的值：

```js
var TARGET_MODULE = "libfoo.so";
var TARGET_SYMBOL = "foo_entry"; // 有导出符号时使用
var TARGET_OFFSET = null;         // 没有导出符号时填当前版本的 0x 偏移

// 只在确认模块已经加载、且偏移属于当前 arm64 ELF 后下断点。
console.log("KT>sub");
console.log("KT>brk libfoo.so 0x1234");       // uprobe
console.log("KT>x libfoo.so+0x1234");         // 执行 HWBP
console.log("KT>rw libfoo.so+0x5678 8");      // 读写观察点
```

偏移必须从当前 APK 中的 arm64 `libfoo.so` 重新计算，例如用 `readelf -Ws`、`nm -D`
或 `llvm-objdump -d`；不能沿用 `libcompatdemo.so` 的偏移。`KT>x`、`KT>r/w/rw` 使用
模块基址加偏移，运行时会处理 ASLR；如果直接写绝对地址，该地址必须来自本轮进程的
`Process.findModuleByName(...).base`，不能从上一次运行复制。

通用脚本不需要手工传 UID：`--spawn`/`--name` 已经确定了注入目标，hybrid 的内核过滤
会按目标进程归属处理。只有纯 `--mode=trace`、同 UID 有多个进程，或需要排除其他进程时，
才显式加 `--trace-pid <pid>` 或 `--trace-uid <uid>`。SVC 过滤可用
`--trace-lib <so>` + `--trace-lib-only`，这只按调用 LR 所属模块过滤，不会自动安装
uprobe/HWBP；断点仍要由 JS 输出 `KT>` 命令。

换应用后的成功判定也要改为目标自身的标志：看到 `attached/installed/armed` 只说明
安装成功，还必须看到对应 `c#`、Java 命中、`uprobe.hit` 或 `hwbp.hit`。兼容性 demo
里的 `nativeCounters()`、`sourceBaseline` 和 `com.rustfrida.compatdemo.*` 不适用于别的
应用；如果需要“源端触发数和观察端数”对账，要在目标测试 app 中增加自己的原子计数器，
或只使用 host 的 JSONL 事件统计。

## QuickJS 兼容规则

脚本运行在项目自己的 QuickJS agent 中，是 Frida 风格子集：

1. `Java.use`、`Jni.addr` 和其他 Java/JNI 操作放进 `Java.ready`，特别是 spawn 模式。
2. 不依赖 `setTimeout`、`setInterval`、`setImmediate`；等待模块使用加载回调或目标热函数中的轻量检查。
3. 地址 API 可能返回空值、`NativePointer`、number 或 bigint；调用 `.add()`、`.isNull()` 和读内存方法前判空。
4. `readU64` 等结果可能是 bigint，不要直接使用 number 位运算符。
5. 高频 hook 只打印前几次和周期样本；完整事件使用 host 的 `--trace-output` JSONL。
6. hook 回调中只做固定签名、短路径操作；复杂解析放到低频分支，并用 `try/catch` 保护读内存。

## Java.ready 的 spawn 时机

预加载脚本可能早于 Java VM 或目标 ClassLoader。脚本顶层可以打印配置和注册普通 native hook，但 Java 安装逻辑必须由 `Java.ready` 驱动。如果 spawn 后没有 `installed` 或 `ready` 日志，等到 REPL 提示符出现后执行：

```text
%reload /data/local/tmp/02_java_hook.js
```

`%reload` 适合确认时机问题；长期脚本仍应保持安装函数幂等，避免重复 attach。

## native 和 JNI

native 导出：

```js
var p = Module.findExportByName("libc.so", "getpid");
if (p !== null && !p.isNull()) {
    Interceptor.attach(p, {
        onEnter: function () { console.log("enter"); },
        onLeave: function (retval) { console.log("return " + retval); }
    });
}
```

模块偏移：

```js
var m = Process.findModuleByName("libfoo.so");
if (m) {
    var address = m.base.add(0x1234);
    // 在确认映射和长度后再读 address。
}
```

JNI 系统调用观察使用 `04_jni_trace.js`。模板从 `Jni.addr(name)` 解析当前线程
`JNIEnv->functions` 表中的常用槽位，覆盖 `FindClass`、`GetMethodID`、字段读写、
`Call*MethodA`、字符串/数组、异常、`RegisterNatives`、引用管理和
`DirectByteBuffer`。兼容 demo 的 `JniProbe.probeExercise()` 会主动触发这些路径，方便
先确认“已安装”再确认“有命中”。所有 `Jni.addr(...)` 都必须在 `Java.ready` 内调用；spawn 时
只看到脚本加载而没有 `table hooks installed`，先检查 Java worker 是否 ready。
`RegisterNatives` 的方法表按 `JNINativeMethod{name, signature, fnPtr}` 解析；如果
目标 ART 对某个槽位没有实现，模板会记录 `unavailable` 并继续安装其他槽位。

## KT> 桥

`03_kernel_trace.js` 展示完整流程：设置 `UPROBE`/`HWBP`，定义 `__kt_on_ack` 和 `__kt_on_event`，先输出 `KT>sub`，再输出断点命令。

```js
console.log("KT>sub");
console.log("KT>brk libfoo.so 0x1234");
console.log("KT>x libfoo.so+0x1234");
console.log("KT>r libfoo.so+0x5678 8");
```

只有 `--mode=hybrid` 会消费这些命令。`--trace-lib-only` 只过滤 syscall 的 LR，不能替代 `KT>` 断点配置；`--trace-disable-syscall` 只关闭 svc 采集，不会关闭 uprobe/HWBP。

## 运行前检查

- 模块已加载，库名和偏移对应当前 APK/ABI。
- 脚本和二进制已推送到设备，权限可执行。
- spawn 使用 stdin 保活；hybrid 才使用 `KT>`。
- 首次验证先关闭 syscall 堆栈：`--trace-disable-syscall --trace-no-stack`。
- 设备上只保留一个 kernel-trace 会话，避免断点槽位和事件归属混乱。

更完整的构建、参数和排查说明见 [`使用文档.md`](使用文档.md) 与 [`doc/动态调试.md`](doc/动态调试.md)。
