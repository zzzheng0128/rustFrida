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
| `04_jni_trace.js` | `Jni.addr("RegisterNatives")` 观察 JNI 注册 |
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

JNI 注册观察使用 `04_jni_trace.js`。`Jni.addr("RegisterNatives")` 也必须在 `Java.ready` 内调用；注册表解析失败时先降低一次读取数量，再检查 `JNINativeMethod` 布局和目标 ABI。

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
