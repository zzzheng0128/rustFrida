# rustFrida JS 模板

这些文件是可复制的最小示例，不依赖项目中的一次性压测数据：

| 文件 | 用途 |
| --- | --- |
| `01_native_hook.js` | `Interceptor.attach` 观察 native 导出 |
| `02_java_hook.js` | `Java.ready` + `Java.use` 观察 Java 方法 |
| `03_kernel_trace.js` | hybrid 模式的 `KT>` uprobe/HWBP 桥接；含 `bpdel` 释放和复用辅助函数 |
| `04_jni_trace.js` | `Jni.addr("RegisterNatives")` 观察 JNI 注册 |
| `05_memory_probe.js` | 只读模块内存并输出 hex |
| `06_agent_replace.js` | `hook()` 替换式 native hook，并显式调用 `$orig` |
| `07_gumtrace.js` | GumTrace 指令级追踪（默认目标为兼容性 demo） |
| `08_memory_dump.js` | 按模块可读映射分块转储到文件，并生成 `.map` |
| `09_file_io.js` | 文本/二进制文件的静态和流式读写 |
| `10_memory_rw.js` | `Memory.alloc`、指针读写和字节读写 |
| `11_backtrace.js` | `hook()` 寄存器现场上的 ARM64 帧指针堆栈 |
| `12_method_call.js` | `NativeFunction` native 调用 + Java 方法调用 |
| `13_kpm_control.js` | JS 通过 `libc.syscall(45)` 直接调用 APatch supercall，低频控制 `mkpm` |

`script_template.js` 是通用辅助函数骨架。复制模板后只改配置和业务回调，
不要把 `test_*`、`probe_*`、`*_stress` 当成长期脚本；它们是历史回归或设备实验记录。

## 常用能力怎么选

- 要保存一段 so 的原始内容，用 `08_memory_dump.js`；它默认最多写 2 MiB，
  可调 `TARGET_MODULE`、`PROTECTION`、`MAX_BYTES` 和 `OUTPUT`。
- 要把事件持续写到设备文件，用 `09_file_io.js` 的 `new File(path, "a")`；
  脚本结束前调用 `flush()` 和 `close()`。
- 要验证地址或结构体字段，用 `10_memory_rw.js`；先在 `Memory.alloc()` 私有区验证，
  再替换为确认过的目标地址。
- 要看 native 调用栈，用 `11_backtrace.js`；`hook()` 的 `this` 才有完整 ARM64
  寄存器，回调最后要 `return this.$orig()`。
- 要主动执行函数，用 `12_method_call.js`；`NativeFunction` 的返回值和参数类型
  必须按真实 ABI 填写，Java 方法放在 `Java.ready` 中调用。
- 要从 JS 做 KPM 状态检查或开关实验，用 `13_kpm_control.js`；它通过 libc 的
  `syscall(45)` 直接进入 APatch supercall，默认只执行 `hello/nums/list/info/status`。
  先修改 `SUPERKEY`、`KP_VERSION`，再按需调用 `Kpm.hide`、`Kpm.syscall`、
  `Kpm.boot` 或 `Kpm.control`。目标 UID 必须在 APatch 的 supercall 允许范围内；
  若返回负 errno，先用主机上的 `kpctl` 验证 key、版本和 UID 授权。
  `control()` 仍是同步调用，不能放进 HWBP/uprobe 高频回调；需要严格时序或批量
  压测时使用主机的 `run_demo_spawn.sh`/`kpctl`。

模板不会自动加载或卸载 KPM；先由主机执行 `kpctl load/list`，再把脚本推到设备：

```bash
adb push examples/templates/13_kpm_control.js /data/local/tmp/
adb shell su -c '/data/local/tmp/rustfrida --spawn com.example.app \
  -l /data/local/tmp/13_kpm_control.js'
```

可直接调用的封装包括 `Kpm.hide.*`、`Kpm.wxshadow()`、`Kpm.antidetect()`、
`Kpm.syscall.*`、`Kpm.boot.*`、`Kpm.redirectExact()` 和 `Kpm.emapsInode()`；
未封装的 ctl0 命令直接写成 `Kpm.control("<命令>")`。例如：

```js
Kpm.control("ehide 10283 addprefix /data/local/tmp/demo");
Kpm.control("redirect 10283 addexact /proc/self/maps /data/local/tmp/maps");
Kpm.control("evm 10283 print on");
```

设备文件若位于 `/data/local/tmp`，先执行：

```bash
adb shell 'su -c "touch /data/local/tmp/rustfrida-file-template.log; chmod 666 /data/local/tmp/rustfrida-file-template.log"'
# 08_memory_dump.js 还会写这个旁路映射文件；两个路径都要预创建。
adb shell 'su -c "touch /data/local/tmp/rustfrida-memory.dump /data/local/tmp/rustfrida-memory.dump.map; chmod 666 /data/local/tmp/rustfrida-memory.dump /data/local/tmp/rustfrida-memory.dump.map"'
```

## 最小运行

```bash
adb push examples/templates/01_native_hook.js /data/local/tmp/
adb shell 'su -c "/data/local/tmp/rustfrida --name com.example.app -l /data/local/tmp/01_native_hook.js"'
```

Spawn 的非交互运行要保持 stdin 打开：

```bash
adb shell 'su -c "(sleep 60; echo exit) | timeout 65 /data/local/tmp/rustfrida --spawn com.example.app -l /data/local/tmp/02_java_hook.js"'
```
