#!/usr/bin/env bash
set -Eeuo pipefail

# RustFrida 兼容性 demo 的新手入口。
# 用法：run_demo_spawn.sh 0（RustFrida 全部通道）、1,2（C+Java）或 c,java。
# mkpm 能力总览也从这里进入：8=mkpm 全部，9-14=单项 KPM 探针。
# 运行器只负责选通道、构建/推送和收集结果；具体业务代码在 app/ 与 JS 文件中。
#
# 日志字段速查（先看这个，再看具体事件）：
#   运行档位：默认 LOW_FREQ=1（低频，便于逐条阅读）；设置 EXTREME=1 才进入
#              压力档，并自动使用 LOW_FREQ=0。LOW_FREQ=0 EXTREME=0 是普通档。
#   module/so_tag：事件归属的 ELF 模块，例如 libcompatdemo.so；它不是 KPM
#                  是否加载成功的标志。KPM 模块名要看 `mkpm:` 或 `info`。
#   detail=full：已生成寄存器、参数、堆栈和指令等完整详情。
#   detail=basic：事件已到达，但详情被限流/排队保护裁剪；同时看
#                 detail_reason=budget 或 detail_reason=queue_delay。
#   地址偏移：host 文本直接写在 0x 地址后；JSONL 统一放在 locations；basic
#              模式也会优先使用已有的 maps 缓存。
#   `detail: "..."`（kpctl status 输出）：这是可用的 ctl0 命令提示，
#                         不是事件详情，也不是失败原因。
#   reason=...：trace 的详情原因是 budget/queue_delay；scene 的 reason 可能是
#               "zombie (crashed/exited, awaiting reap)" 或 "process gone"。
#               scene 文件落盘表示取证完成；zombie 本身表示进程异常退出。
#
# 判定规则：
#   成功至少要有“安装/启用”字样和一次对应结果；仅有 rf_exit_code=0、
#   detail=basic、crc_match=true 或 status 输出中的 detail 行都不够。
#   失败关键词：failed、FAIL、error=、not found、timeout、rc=-<errno>；
#   事件通道还要检查 SUMMARY.txt 中对应计数是否大于 0。
#   终端中的 [成功]/[失败]/[警告] 分别为绿色/红色/黄色；NO_COLOR=1 可关闭颜色。

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$ROOT/../.." && pwd)"
RUN_SECS="${RUN_SECS:-90}"
STARTUP_WAIT_SECS="${STARTUP_WAIT_SECS:-60}"
VERIFY_DRAIN_SECS="${VERIFY_DRAIN_SECS:-2}"
BUILD_RF="${BUILD_RF:-0}"
BUILD_APP="${BUILD_APP:-0}"
INSTALL_APP="${INSTALL_APP:-1}"
DEVICE_SERIAL="${DEVICE_SERIAL:-}"
ADB_BIN="${ADB_BIN:-/Users/freeman/Library/Android/sdk/platform-tools/adb}"
RF_BIN="${RF_BIN:-$REPO_ROOT/rustfrida_target/aarch64-linux-android/release/rustfrida}"
APK="$ROOT/app/build/outputs/apk/debug/app-debug.apk"
JS_FILE="$ROOT/test_compat_demo.js"
PACKAGE="com.rustfrida.compatdemo"
KP_KEY="${KP_SUPERKEY:-amigo123}"
KPM_FILE="${KPM_FILE:-$REPO_ROOT/mkpms/dist/mkpm.kpm}"
KPM_REMOTE="${KPM_REMOTE:-/data/local/tmp/mkpm.kpm}"
KPCTL_REMOTE="${KPCTL_REMOTE:-}"
KPCTL_HOST="${KPCTL_HOST:-$REPO_ROOT/../dyidre/tools/kpctl/kpctl}"
KPM_RF_HOLD_SECS="${KPM_RF_HOLD_SECS:-12}"
KPM_RF_TIMEOUT_SECS="${KPM_RF_TIMEOUT_SECS:-$((KPM_RF_HOLD_SECS + 20))}"
KPM_RELOAD="${KPM_RELOAD:-0}"
KPM_MARKER="/data/local/tmp/rfcompat-mkpm-marker"
KPM_MAP_PATH="/data/local/tmp/rfcompat-mkpm-map"
KPM_READLINK_PATH="/data/user/0/com.rustfrida.compatdemo/rfcompat-readlink"
KPM_READLINK_TARGET="/data/local/tmp/rfcompat-readlink-target"
KPM_REDIRECT_TO="${KPM_REDIRECT_TO:-/data/local/tmp/rfcompat-mkpm-target}"
KPM_CRC_PHASE_PROP="debug.rustfrida.compat.crc_phase"
KPM_RESULT_DIR=""

# 颜色只用于交互终端；SUMMARY、lane.log 和 rf-output.log 保持纯文本，便于
# grep、归档和后续分析。设置 NO_COLOR=1 可关闭终端颜色。
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'
    C_GREEN=$'\033[1;32m'
    C_RED=$'\033[1;31m'
    C_YELLOW=$'\033[1;33m'
    C_CYAN=$'\033[1;36m'
else
    C_RESET=''; C_GREEN=''; C_RED=''; C_YELLOW=''; C_CYAN=''
fi

status_ok()   { printf '%s[成功]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
status_fail() { printf '%s[失败]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
status_warn() { printf '%s[警告]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
status_step() { printf '%s[步骤]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }

adb_do() {
    if [[ -n "$DEVICE_SERIAL" ]]; then
        "$ADB_BIN" -s "$DEVICE_SERIAL" "$@"
    else
        "$ADB_BIN" "$@"
    fi
}

# 运行时也打印一次判定规则。这样用户只看终端或最终目录里的 SUMMARY.txt，
# 不需要打开源码猜 `detail`、`reason`、`module` 分别代表什么。
LOG_GUIDE_PRINTED=0
print_log_guide() {
    if [[ "$LOG_GUIDE_PRINTED" == "1" ]]; then
        return
    fi
    LOG_GUIDE_PRINTED=1
    cat <<'GUIDE'
[compat-runner] 日志字段与成功判定
  module/so_tag       事件所属 ELF（如 libcompatdemo.so）；KPM 名称看 `mkpm:`。
  detail=full         已输出寄存器/参数/堆栈/指令等详情；低频内核档会自动开启此模式。
  detail=basic        事件已收到，但详情因限流或排队保护被裁剪。
  detail_reason=budget       详情预算耗尽，基础事件仍然到达。
  detail_reason=queue_delay  队列等待过长，基础事件仍然到达。
  地址偏移                  host 文本直接显示为 0x地址(模块.so+0x偏移)，
                            JSONL 放在 locations；basic 也会优先使用缓存。
  `detail: "..."`            kpctl 的命令提示，不是结果，也不是失败原因。
  scene.meta reason=...      进程现场原因；现场文件已写出表示取证成功，
                            但 zombie (crashed/exited, awaiting reap) 仍表示应用崩溃。

  通用成功：出现 installed/enabled/armed/started 或 `ok`，并有对应事件/对照。
  通用失败：出现 failed/FAIL/error=/not found/timeout/rc=-<errno>，或预期计数为 0。
  rf_exit_code=0 只表示运行器退出正常；功能仍需看下面的专用标志。

  C       `native C hook installed` + `c#` 命中
  Java    `Java hooks installed`、Dex hook installed + `java#`/`dex#`
  SVC     `svc.enter` 且 SUMMARY 的 svc_json_events > 0
  uprobe  `KT>brk` 后出现 `uprobe.hit`
  HWBP    `KT>x/r/w` 后出现 `hwbp.hit`；需要看到 pc/far/regs 和
          `instructions`（命中 PC 起连续 16 条 ARM64 指令，含 asm）
  HWBP轮换  选择 19；每个地址命中 3 次后要看到 `phase=detach`、host 的
          `hwbp detached`，再看到下一个 `phase=attach`；这证明槽位被复用。
  JNI     `table hooks installed=93/93` 且 `observed_jni_system>0`，并看到 `registered=1`
  GumTrace `GumTrace armed` + `GumTrace started`，且 gumtrace 输出文件非空
  KPM     `loaded (rc=0)`，status 中目标开关为 1，控制命令返回 `ok` 或有效结果
  CRC32   `WXSHADOW installed` + `PROBE1 crc_match=true`；NORMAL 对照应为 false
  boot    输出 `目标约 600s，规则生效`
  hide    会动态加入 `libcompatdemo.so` token；应看到 maps_has_demo=0/1/0，分别对应开/关/恢复。
  inode   输出 `关闭=<原值>，开启=1`；redirect 在 Pixel6 上应看到 `supported=1`，
          且同一 App 开启后读到 `data=mkpm-redirect-target`（只做 App 内前后对照，
          不读取 shell 结果）；其他未完成 ABI 验证的内核
          看到 `supported=0` 才是安全熔断 WARN。
          runner 下发的是 `eredirect <uid> addexact ...`，菜单中的 redirect 是易懂简称。

  结果文件：rf-output.log（终端镜像）、trace-output.jsonl（完整事件）、
  SUMMARY.txt（计数和退出码）；失败时再看同目录的具体 lane.log 和 logcat.txt。
  终端标记：绿色 [成功]、红色 [失败]、黄色 [警告]；NO_COLOR=1 可关闭颜色。
  若出现“未知 frame kind”，只保留首几次和指数采样，带 len/count/preview，避免刷屏。
GUIDE
}

usage() {
    print_log_guide
    cat <<'HELP'
RustFrida compatibility demo

选择实验通道（可选多个，用逗号分隔）：
  0  all       全部通道
  1  c         native C Interceptor hook
  2  java      Java hook + 动态 Dex
  3  svc       原始 SVC / syscall 事件
  4  jnitrace  RegisterNatives 注册表观察
  5  hwbp      执行、读、写硬件断点
 19  hwbp-rotate 命中 3 次后 bpdel，轮换到下一个地址，验证槽位复用
 16 hwbp-matrix  同时挂 6 个执行断点 + 4 个读写观察点，验证槽位上限
  6  uprobe    native 软件探针（KT>brk）
 17 uprobe-matrix 同时挂 6 个软件探针，验证并发 attach/事件队列上限
 18 uprobe-limit  32 个独立软件探针，支持 UPROBE_TARGETS=1/4/8/16/32 阶梯
  7  gumtrace  GumTrace 指令级追踪（demo 自己的 rf_agent_hot）
  8  mkpm      加载一个 mkpm.kpm，依次演示 status/probe/hide/redirect/time/inode/crc32
  9  mkpm-probe   kpctl syscall + compatdemo raw SVC 探针
 10  mkpm-crc32   wxshadow 开/关 + CRC32 内存对照
  11  mkpm-hide    hide maps 开/关 + compatdemo maps 对照
  12  mkpm-redirect redirect UID+精确路径替换 + App 内关闭/开启对照
 13  mkpm-time    目标 UID 的 CLOCK_BOOTTIME 减 600 秒，和 shell 对照
 14  mkpm-inode   emaps addino + rfcompat-mkpm-map inode 对照
 15  mkpm-readlink antidetect readlink：目标 UID 返回 ENOENT，shell 返回原目标

示例：
  bash examples/rustfrida-compat-app/run_demo_spawn.sh       # 交互菜单，默认 all
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 0     # 全部
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 1,2   # C + Java
  bash examples/rustfrida-compat-app/run_demo_spawn.sh c,java,jnitrace
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 8     # mkpm 能力总览
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 10    # 只做 wxshadow/CRC32
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 13    # 只看 boot_time
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 15    # 只看 readlink UID 隔离
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 16    # 多 HWBP 槽位矩阵
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 19    # HWBP 命中后取消并轮换地址
  bash examples/rustfrida-compat-app/run_demo_spawn.sh 17    # 多 uprobe 槽位矩阵
  UPROBE_TARGETS=32 bash examples/rustfrida-compat-app/run_demo_spawn.sh 18 # 软件断点极限

环境变量：RUN_SECS=60（观察者 armed 后的运行时长）、STARTUP_WAIT_SECS=60（spawn/注入
          阶段最长等待）、VERIFY_DRAIN_SECS=2（退出前最终对账后的 drain 秒数）、
          LOW_FREQ=1（默认低频）、EXTREME=1（压力档，会覆盖低频）、
          LOW_FREQ=0（普通频率）、BUILD_APP=1、BUILD_RF=1、DEVICE_SERIAL=...
          KPM_RF_HOLD_SECS=12（KPM 探针保持时间）、KPM_RF_TIMEOUT_SECS=32（远端兜底超时）
          KT_HWBP_MAX_BREAKPOINTS=6、KT_HWBP_MAX_WATCHPOINTS=4（用于验证设备
          的执行/观察槽位上限；默认按 Pixel 6 常见的 6+4 运行）、
          KPM_RELOAD=1（应用 force-stop 后验证受保护的 mkpm 卸载；反复多次后重启回收空链槽位）

日志字段和成功/失败判定：执行脚本后会自动打印“日志字段与成功判定”速查表。
`detail=basic reason=budget/queue_delay` 是详情降级，不等于功能失败；
`detail: "..."` 是 kpctl 的命令提示，不是成功或失败结果。
HELP
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then usage; exit 0; fi

MODE_INPUT="${1:-${DEMO_MODE:-}}"
if [[ -z "$MODE_INPUT" && -t 0 ]]; then
    usage
    read -r -p "请输入模式（默认 0/all）：" MODE_INPUT || true
fi
MODE_INPUT="${MODE_INPUT:-0}"

# 将数字和名称规范化为稳定的逗号列表，并拒绝拼写错误，避免“跑了但没有事件”。
# 使用 case 而不是关联数组，兼容 macOS 自带的 Bash 3.2。
map_mode() {
    case "$1" in
        c|1) echo c;; java|2) echo java;; svc|3) echo svc;;
        jnitrace|4) echo jnitrace;; hwbp|5) echo hwbp;; hwbp-matrix|16) echo hwbp-matrix;;
        hwbp-rotate|19) echo hwbp-rotate;;
        uprobe|6) echo uprobe;; uprobe-matrix|17) echo uprobe-matrix;; uprobe-limit|18) echo uprobe-limit;; gumtrace|7) echo gumtrace;;
        mkpm|kpm|mkpm-all|8) echo mkpm-all;;
        mkpm-probe|kpm-probe|9) echo mkpm-probe;;
        mkpm-crc32|kpm-crc32|10) echo mkpm-crc32;;
        mkpm-hide|kpm-hide|11) echo mkpm-hide;;
        mkpm-redirect|kpm-redirect|12) echo mkpm-redirect;;
        mkpm-time|kpm-time|13) echo mkpm-time;;
        mkpm-inode|kpm-inode|14) echo mkpm-inode;;
        mkpm-readlink|kpm-readlink|15) echo mkpm-readlink;;
        *) return 1;;
    esac
}
selected_csv=""
has_all=0
IFS=',' read -r -a requested <<< "$MODE_INPUT"
for raw in "${requested[@]}"; do
    token="${raw//[[:space:]]/}"
    [[ -z "$token" ]] && continue
    if [[ "$token" == "0" || "$token" == "all" ]]; then has_all=1; continue; fi
    if ! lane="$(map_mode "$token")"; then
        status_fail "无效模式: $raw"
        usage >&2
        exit 2
    fi
    case ",$selected_csv," in
        *,"$lane",*) ;;
        *) selected_csv="${selected_csv:+$selected_csv,}$lane";;
    esac
done
if (( has_all == 1 )) || [[ -z "$selected_csv" ]]; then
    MODE_SPEC="all"
else
    # 按菜单顺序输出，方便 system property、日志和摘要直接比较。
    ordered=(c java svc jnitrace hwbp hwbp-matrix hwbp-rotate uprobe uprobe-matrix uprobe-limit gumtrace mkpm-all mkpm-probe mkpm-crc32 mkpm-hide mkpm-redirect mkpm-time mkpm-inode mkpm-readlink)
    normalized=()
    IFS=',' read -r -a selected_parts <<< "$selected_csv"
    for lane in "${ordered[@]}"; do
        for old in "${selected_parts[@]}"; do [[ "$old" == "$lane" ]] && normalized+=("$lane"); done
    done
    ((${#normalized[@]} > 0)) || { status_fail "没有选择有效模式"; exit 2; }
    MODE_SPEC="${normalized[0]}"
    for ((i = 1; i < ${#normalized[@]}; i++)); do
        MODE_SPEC="$MODE_SPEC,${normalized[$i]}"
    done
fi

print_log_guide
printf '[compat-runner] selected modes=%s\n' "$MODE_SPEC"

# KPM 能力演示和普通 RustFrida 压测共用这个入口。KPM 轮次会在本函数内
# 完成 App 构建/启动、kpctl 自动下发、mkpm.kpm 加载、控制和日志回收，
# 不再跳转到第二个 runner；所有探针均来自这个 demo App。
run_kpm_demo() {
    local lane_spec="$1"
    local kpm_mode="${lane_spec//mkpm-/}"
    local kpm_run_id="$(date +%Y%m%d-%H%M%S)"
    local kpm_run_dir="${RUN_DIR:-$REPO_ROOT/runs/compat-demo/$kpm_run_id}"
    local kpm_main_log="$kpm_run_dir/mkpm.log"
    local inode_before="" inode_after="" inode_verdict="not-run"
    local hide_on_demo="" hide_off_demo="" hide_restored_demo="" hide_verdict="not-run"
    local redirect_before_open="" redirect_after_open="" redirect_after_data=""
    local redirect_compare_scope="app-only"
    local redirect_supported="unknown" redirect_verdict="not-run" kpm_verdict=0
    local kpm_device_serial="unknown" kpm_device_model="unknown" kpm_device_kernel="unknown"
    local kpm_remote_probe=/data/local/tmp/rfcompat-mkpm-probe.js
    local kpm_remote_crc=/data/local/tmp/rfcompat-mkpm-crc32.js
    local kpm_remote_rf=/data/local/tmp/rustfrida
    local kpm_ctl="${KPCTL_REMOTE:-}"
    KPM_RESULT_DIR="$kpm_run_dir"

    mkdir -p "$kpm_run_dir"
    # KPM 单项在主 trace 流程之外运行，也要把设备身份写入本轮目录，
    # 避免多台手机同时在线时把 Pixel 5 的结果混进 Pixel 6 报告。
    kpm_device_serial="$(adb_do get-serialno 2>/dev/null | tr -d '\r\n ' || true)"
    kpm_device_model="$(adb_do shell getprop ro.product.model 2>/dev/null | tr -d '\r\n' || true)"
    kpm_device_kernel="$(adb_do shell uname -r 2>/dev/null | tr -d '\r\n' || true)"
    mkdir -p "$kpm_run_dir/device-before"
    printf '%s\n' "$kpm_device_serial" > "$kpm_run_dir/device-before/serial.txt"
    printf '%s\n' "$kpm_device_model" > "$kpm_run_dir/device-before/model.txt"
    printf '%s\n' "$kpm_device_kernel" > "$kpm_run_dir/device-before/kernel-release.txt"
    kpm_log() { echo "[$(date +%H:%M:%S)] [mkpm] $*" | tee -a "$kpm_main_log"; }
    kpm_su() { adb_do shell su -c "$1"; }
    kpm_best() {
        local label command rc
        label="$1"; command="$2"; rc=0
        kpm_log "$label"
        set +e
        kpm_su "$command" 2>&1 | tr -d '\0' | tee -a "$kpm_main_log"
        rc="${PIPESTATUS[0]:-1}"
        set -e
        if (( rc != 0 )); then
            kpm_log "$label -> rc=${rc}（继续记录）"
            status_fail "${label} 失败 rc=${rc}（继续记录）"
        else
            status_ok "${label} 成功"
        fi
        return 0
    }
    kpm_required() {
        local label="$1" command="$2" rc
        kpm_log "$label"
        set +e
        kpm_su "$command" 2>&1 | tr -d '\0' | tee -a "$kpm_main_log"
        rc="${PIPESTATUS[0]:-1}"
        set -e
        if (( rc == 0 )); then
            status_ok "${label} 成功"
        else
            status_fail "${label} 失败 rc=${rc}"
            return "$rc"
        fi
    }
    kpm_control() {
        local command="$1"
        kpm_best "control mkpm '$command'" \
            "$kpm_ctl --key '$KP_KEY' control mkpm \"$command\""
    }
    kpm_has() {
        [[ "$kpm_mode" == "all" ]] && return 0
        case ",$kpm_mode," in *,"$1",*) return 0;; esac
        return 1
    }
    kpm_pid() {
        adb_do shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r' | awk '{print $1}'
    }
    kpm_uid() {
        if [[ -n "${TARGET_UID:-}" ]]; then printf '%s' "$TARGET_UID"; return; fi
        adb_do shell cmd package list packages -U 2>/dev/null | tr -d '\r' |
            awk -v p="$PACKAGE" '$0 ~ ("package:" p " uid:") { sub(/^.*uid:/, ""); print $1; exit }'
    }
    kpm_push_runtime() {
        local rf_bin="${RF_BIN:-$REPO_ROOT/rustfrida_target/aarch64-linux-android/release/rustfrida}"
        [[ -x "$rf_bin" ]] || {
            kpm_log "找不到 RustFrida: ${rf_bin}；先执行 bash .build-android.sh rust_frida"
            return 1
        }
        adb_do push "$rf_bin" "$kpm_remote_rf" | tee -a "$kpm_main_log"
        adb_do shell su -c "chmod 755 $kpm_remote_rf"
        adb_do push "$ROOT/test_mkpm_probe.js" "$kpm_remote_probe" | tee -a "$kpm_main_log"
        adb_do push "$ROOT/test_mkpm_wxshadow_crc32.js" "$kpm_remote_crc" | tee -a "$kpm_main_log"
    }
    kpm_attach() {
        local label script pid output rc
        label="$1"; script="$2"; pid="$3"; output="$kpm_run_dir/$1.log"; rc=0
        kpm_log "$label: attach pid=${pid} script=${script}（实时输出，完整日志=${output}）"
        set +e
        (sleep "$KPM_RF_HOLD_SECS") |
            adb_do shell su -c "timeout $KPM_RF_TIMEOUT_SECS $kpm_remote_rf --pid $pid -l $script" 2>&1 |
            tee "$output" | tee -a "$kpm_main_log"
        rc="${PIPESTATUS[1]:-1}"
        set -e
        # Ctrl-C/设备掉线时 adb 可能只退出本地管道，远端 rustfrida 仍会
        # 占着目标线程的 ptrace。清理它，避免下一轮出现二次 attach 或把
        # 应用留在 stopped 状态；正常 rc=0 不打扰其他用户进程。
        if (( rc != 0 )); then
            adb_do shell su -c "for p in \$(pidof rustfrida 2>/dev/null); do kill -TERM \$p; done" >/dev/null 2>&1 || true
        fi
        kpm_log "$label: rustfrida rc=$rc"
        if (( rc == 0 )); then
            status_ok "${label} 成功"
        else
            status_fail "${label} 失败 rc=${rc}"
        fi
        # RustFrida 进程 rc=0 只代表 REPL 正常退出；CRC 是否生效必须看
        # 脚本自己的 PHASE_VERDICT。把专用判定单独高亮，避免“进程成功”
        # 掩盖 hook 安装失败或 CRC 对照失败。
        if [[ "$label" == crc32-* ]]; then
            local crc_verdict
            crc_verdict="$(grep -aE '\[CRC\]\[PHASE_VERDICT\].*result=(PASS|FAIL)' "$output" 2>/dev/null | tail -1 || true)"
            if [[ "$crc_verdict" == *"result=PASS"* ]]; then
                status_ok "${label} 功能验证 PASS"
            elif [[ -n "$crc_verdict" ]]; then
                status_fail "${label} 功能验证 FAIL（${crc_verdict#*] }）"
            else
                status_fail "${label} 功能验证失败：未找到 CRC PHASE_VERDICT（详见 ${output}）"
            fi
        fi
        return 0
    }
    kpm_probe() {
        local label="$1" pid
        pid="$(kpm_pid || true)"
        [[ -n "$pid" ]] || { kpm_log "$label: 找不到 $PACKAGE 进程，跳过"; return 0; }
        kpm_attach "$label" "$kpm_remote_probe" "$pid"
    }
    kpm_start_app() {
        adb_do shell monkey -p "$PACKAGE" 1 >/dev/null 2>&1 ||
            adb_do shell am start -n "$PACKAGE/.MainActivity" >/dev/null
        for _ in 1 2 3 4 5 6 7 8; do
            [[ -n "$(kpm_pid || true)" ]] && return 0
            sleep 1
        done
        return 1
    }
    kpm_restart_app() {
        local reason="$1" pid
        pid="$(kpm_pid || true)"
        kpm_log "重启 ${PACKAGE}（${reason}，旧 pid=${pid:-<none>}）"
        adb_do shell su -c "am force-stop ${PACKAGE}" >/dev/null 2>&1 || true
        sleep 1
        if kpm_start_app; then
            pid="$(kpm_pid || true)"
            kpm_log "重启 ${PACKAGE} 完成（新 pid=${pid:-<none>}）"
            return 0
        fi
        kpm_log "重启 ${PACKAGE} 失败：未取得新 PID"
        return 1
    }

    [[ -f "$KPM_FILE" ]] || {
        kpm_log "找不到 mkpm 产物: $KPM_FILE"
        kpm_log "先构建 mkpms/dist/mkpm.kpm，或设置 KPM_FILE=/path/to/mkpm.kpm"
        return 2
    }
    if [[ "$BUILD_APP" == "1" || ! -f "$APK" ]]; then bash "$ROOT/build_demo.sh"; fi
    if [[ "$BUILD_RF" == "1" || ! -x "${RF_BIN:-$REPO_ROOT/rustfrida_target/aarch64-linux-android/release/rustfrida}" ]]; then
        (cd "$REPO_ROOT" && CARGO_TARGET_DIR=rustfrida_target bash .build-android.sh rust_frida)
    fi
    adb_do wait-for-device >/dev/null
    adb_do install -r -d "$APK" | tee -a "$kpm_main_log"
    adb_do shell su -c "printf 'rfcompat-map\\n' > '$KPM_MAP_PATH'; chmod 644 '$KPM_MAP_PATH'"
    adb_do shell su -c "setprop debug.rustfrida.compat.mode mkpm; setprop debug.rustfrida.compat.extreme 0"
    adb_do shell su -c "am force-stop $PACKAGE"

    # 先处理 KPM，再启动测试 App。显式 reload 时这样可以确保旧进程已经停止，
    # 避免 wxshadow 的 page-fault hook 在卸载窗口仍被应用线程触发。
    if [[ -z "$kpm_ctl" ]]; then
        for candidate in /data/local/tmp/kpctl /data/adb/ap/bin/kpctl; do
            if kpm_su "test -x '$candidate'" >/dev/null 2>&1; then kpm_ctl="$candidate"; break; fi
        done
    fi
    if [[ -z "$kpm_ctl" && -x "$KPCTL_HOST" ]]; then
        kpm_log "设备没有 kpctl，从本机下发: $KPCTL_HOST"
        adb_do push "$KPCTL_HOST" /data/local/tmp/kpctl | tee -a "$kpm_main_log"
        kpm_su "chmod 755 /data/local/tmp/kpctl"
        kpm_ctl=/data/local/tmp/kpctl
    fi
    [[ -n "$kpm_ctl" ]] || {
        kpm_log "找不到 kpctl；设置 KPCTL_HOST=/path/to/aarch64/kpctl，脚本会自动 push"
        return 2
    }
    kpm_log "kpctl=$kpm_ctl package=$PACKAGE"

    local kpm_loaded=0
    if [[ "$KPM_RELOAD" == "1" ]]; then
        # 先 force-stop 应用，再执行 KPM 的受保护卸载；默认跨轮次复用已加载模块。
        kpm_best "显式卸载旧 mkpm" "$kpm_ctl --key '$KP_KEY' unload mkpm"
    else
        if kpm_su "$kpm_ctl --key '$KP_KEY' list" 2>/dev/null | tr -d '\r\0' | grep -qx 'mkpm'; then
            kpm_loaded=1
            kpm_log "检测到 mkpm 已加载，复用现有实例（如需换二进制请重启或设置 KPM_RELOAD=1）"
        fi
    fi
    if (( kpm_loaded == 0 )); then
        adb_do push "$KPM_FILE" "$KPM_REMOTE" | tee -a "$kpm_main_log"
        kpm_required "加载合并 mkpm.kpm" "$kpm_ctl --key '$KP_KEY' load '$KPM_REMOTE'"
    fi
    kpm_best "确认模块列表" "$kpm_ctl --key '$KP_KEY' list"
    kpm_control status

    kpm_start_app || kpm_log "启动 $PACKAGE 后未立即取得 PID，后续探针可能跳过"

    kpm_push_runtime || return 2
    if kpm_has mkpm-probe || kpm_has probe; then
        local probe_uid="$(kpm_uid || true)"
        [[ -n "$probe_uid" ]] && kpm_control "syscall filter uid $probe_uid"
        kpm_control "syscall preset io"
        kpm_control "syscall path on"
        kpm_control "syscall clear"
        kpm_control "syscall start"
        kpm_probe probe-sysmon
        kpm_control "syscall read 0 128"
        kpm_control "syscall stop"
        kpm_control "syscall detach-all"
        kpm_control "syscall filter clear"
    fi
    if kpm_has mkpm-time || kpm_has time; then
        kpm_log "boot_time：只对目标 UID 将 CLOCK_BOOTTIME 减少 600 秒，root shell 读取 /proc/uptime 作对照"
        local time_uid="$(kpm_uid || true)"
        [[ -n "$time_uid" ]] && kpm_control "boot uid $time_uid"
        kpm_control "boot time 600 0"
        kpm_control "boot status"
        [[ -n "$time_uid" ]] && kpm_control "syscall filter uid $time_uid"
        kpm_control "syscall attach 113 2"
        kpm_control "syscall status"
        kpm_control "syscall start"
        kpm_probe boot-time
        local boot_log="$kpm_run_dir/boot-time.log"
        local app_boot_ns="$(grep -aoE '"boot_time_ns":-?[0-9]+' "$boot_log" | tail -1 | sed 's/.*://' || true)"
        local shell_uptime_raw="$(kpm_su "cat /proc/uptime" 2>/dev/null | tr -d '\r' | head -1 || true)"
        local shell_uptime="${shell_uptime_raw%% *}"
        # toybox awk 的正则转义和 macOS awk 不完全一致；这里直接做数值
        # 转换，避免小数点转义导致 shell 对照值为空。
        local shell_boot_ns="$(awk -v s="$shell_uptime" 'BEGIN { if (s ~ /^[0-9]/) printf "%.0f", (s + 0) * 1000000000; }' 2>/dev/null || true)"
        if [[ "$app_boot_ns" =~ ^-?[0-9]+$ && "$shell_boot_ns" =~ ^[0-9]+$ ]]; then
            local boot_delta_sec="$(awk -v a="$app_boot_ns" -v s="$shell_boot_ns" 'BEGIN { d=s-a; if (d<0) d=-d; printf "%.3f", d/1000000000; }')"
            local boot_verdict="未达标"
            if awk -v d="$boot_delta_sec" 'BEGIN { exit !(d >= 590 && d <= 610) }'; then boot_verdict="规则生效"; fi
            kpm_log "boot_time 对照：App=${app_boot_ns}ns，root shell /proc/uptime=${shell_boot_ns}ns，绝对差=${boot_delta_sec}s（目标约 600s，${boot_verdict}）"
        else
            kpm_log "boot_time 对照：无法解析 App 或 shell 数值（app=${app_boot_ns:-?} shell=${shell_uptime:-?}）"
        fi
        kpm_control "syscall read 0 64"
        kpm_control "syscall status"
        kpm_control "syscall stop"
        kpm_control "syscall detach-all"
        kpm_control "syscall filter clear"
        kpm_control "boot clear"
        kpm_control "boot status"
        kpm_control "boot off"
    fi
    if kpm_has mkpm-hide || kpm_has hide; then
        kpm_control "hide status"
        # 动态加入 demo 自己的 so 名称，才能验证 maps 过滤本身；只看
        # maps_has_frida 会把“规则存在”和“规则生效”混为一谈。
        kpm_control "hide token add libcompatdemo.so"
        kpm_control "hide enable maps"
        kpm_probe hide-on
        kpm_control "hide disable maps"
        kpm_probe hide-off
        kpm_control "hide enable maps"
        kpm_probe hide-restored
        local hide_on_log="$kpm_run_dir/hide-on.log"
        local hide_off_log="$kpm_run_dir/hide-off.log"
        local hide_restored_log="$kpm_run_dir/hide-restored.log"
        hide_on_demo="$(grep -aoE '"maps_has_demo":[0-9]+' "$hide_on_log" 2>/dev/null | tail -1 | sed 's/.*://' || true)"
        hide_off_demo="$(grep -aoE '"maps_has_demo":[0-9]+' "$hide_off_log" 2>/dev/null | tail -1 | sed 's/.*://' || true)"
        hide_restored_demo="$(grep -aoE '"maps_has_demo":[0-9]+' "$hide_restored_log" 2>/dev/null | tail -1 | sed 's/.*://' || true)"
        if [[ "$hide_on_demo" == "0" && "$hide_off_demo" == "1" && "$hide_restored_demo" == "0" ]]; then
            hide_verdict="pass"
            kpm_log "hide 结果：开启=${hide_on_demo}，关闭=${hide_off_demo}，恢复=${hide_restored_demo}（libcompatdemo.so 在 maps 视角按开关隐藏）"
            status_ok "hide maps 功能验证 PASS"
        else
            hide_verdict="fail"
            kpm_verdict=1
            kpm_log "hide 结果：开启=${hide_on_demo:-?}，关闭=${hide_off_demo:-?}，恢复=${hide_restored_demo:-?}（未形成有效开关对照）"
            status_fail "hide maps 功能验证 FAIL（详见 hide-on.log/hide-off.log/hide-restored.log）"
        fi
        kpm_control "hide token del libcompatdemo.so"
    fi
    if kpm_has mkpm-inode || kpm_has inode; then
        local uid="$(kpm_uid || true)"
        if [[ -n "$uid" ]]; then
            kpm_log "inode：先读取关闭规则时的测试 VMA，再启用 emaps 后读取同一测试 VMA（uid=${uid}）"
            kpm_control "hide disable maps"
            # 先确保上一轮没有遗留 emaps 规则，然后读取同一个 App 的原始值。
            # 不需要 root shell 对照；探针每次都会重新 mmap/munmap 测试文件。
            kpm_control "emaps $uid unhook"
            kpm_control "emaps $uid clear"
            kpm_control "emaps $uid list"
            local inode_pid="$(kpm_pid || true)"
            if [[ -n "$inode_pid" ]]; then
                kpm_attach inode-before "$kpm_remote_probe" "$inode_pid"
            else
                kpm_log "inode：找不到 $PACKAGE 进程，无法读取关闭规则基线"
            fi
            local inode_before_log="$kpm_run_dir/inode-before.log"
            inode_before="$(grep -aoE '"maps_target_inode":[0-9]+' "$inode_before_log" 2>/dev/null | tail -1 | sed 's/.*://' || true)"

            # 再启用目标 UID 的 inode 替换规则，重新在同一个 App 进程内读取。
            kpm_control "emaps $uid addino rfcompat-mkpm-map 1"
            kpm_control "emaps $uid hook"
            kpm_control "emaps $uid list"
            if [[ -n "$inode_pid" ]]; then
                kpm_attach inode-after "$kpm_remote_probe" "$inode_pid"
            else
                kpm_log "inode：找不到 $PACKAGE 进程，跳过探针"
            fi
            local inode_after_log="$kpm_run_dir/inode-after.log"
            inode_after="$(grep -aoE '"maps_target_inode":[0-9]+' "$inode_after_log" 2>/dev/null | tail -1 | sed 's/.*://' || true)"
            if [[ "$inode_before" =~ ^[0-9]+$ && "$inode_after" == "1" && "$inode_before" != "1" ]]; then
                inode_verdict="pass"
                kpm_log "inode 结果：关闭=${inode_before}，开启=${inode_after}，目标=1（同一 App 进程内值已改变，规则生效）"
                status_ok "inode 功能验证 PASS"
            elif [[ "$inode_before" =~ ^[0-9]+$ && "$inode_after" =~ ^[0-9]+$ ]]; then
                inode_verdict="fail"
                kpm_verdict=1
                kpm_log "inode 结果：关闭=${inode_before}，开启=${inode_after}，目标=1（值未按预期改变）"
                status_fail "inode 功能验证 FAIL（详见 inode-before.log/inode-after.log）"
            elif [[ -n "$inode_after" ]]; then
                inode_verdict="review"
                kpm_verdict=1
                kpm_log "inode 结果：关闭=${inode_before:-?}，开启=${inode_after}（无法形成有效基线，查看 inode-before.log）"
            else
                inode_verdict="fail"
                kpm_verdict=1
                kpm_log "inode 结果：探针没有返回 maps_target_inode（查看 inode-before.log/inode-after.log）"
                status_fail "inode 功能验证 FAIL（没有有效 maps_target_inode）"
            fi
            kpm_control "emaps $uid del rfcompat-mkpm-map"
            kpm_control "emaps $uid unhook"
            kpm_control "emaps $uid clear"
            kpm_control "hide enable maps"
        else
            kpm_log "inode：无法解析 $PACKAGE UID，跳过"
        fi
    fi
    if kpm_has mkpm-readlink || kpm_has readlink; then
        local readlink_uid="$(kpm_uid || true)"
        if [[ -n "$readlink_uid" ]]; then
            kpm_log "readlink：创建应用私有 symlink，目标 UID 返回 ENOENT，root shell 返回原始目标"
            # 应用数据目录对 root 的 SELinux 写入可能被拒绝；由 debug APK 的
            # run-as 在自己的目录创建 symlink，root 只负责读取作对照。
            kpm_su "printf 'rfcompat-readlink-target\\n' > '$KPM_READLINK_TARGET'"
            adb_do shell "run-as $PACKAGE sh -c 'rm -f \"$KPM_READLINK_PATH\"; ln -s \"$KPM_READLINK_TARGET\" \"$KPM_READLINK_PATH\"'" 2>&1 | tee -a "$kpm_main_log"
            kpm_control "antidetect enable"
            kpm_control "antidetect name add rfcompat-readlink"
            kpm_control "antidetect status"
            local readlink_pid="$(kpm_pid || true)"
            if [[ -n "$readlink_pid" ]]; then
                kpm_attach readlink-target "$kpm_remote_probe" "$readlink_pid"
            else
                kpm_log "readlink：找不到 $PACKAGE 进程，跳过探针"
            fi
            local readlink_log="$kpm_run_dir/readlink-target.log"
            local app_readlink_rc="$(grep -aoE '"readlink_rc":[-0-9]+' "$readlink_log" | tail -1 | sed 's/.*://' || true)"
            local app_readlink_target="$(grep -aoE '"readlink_target":"[^"]*"' "$readlink_log" | tail -1 | sed 's/.*:"//; s/"$//' || true)"
            local shell_readlink_target="$(kpm_su "readlink '$KPM_READLINK_PATH'" 2>/dev/null | tr -d '\r' | head -1 || true)"
            printf '%s\n' "$shell_readlink_target" > "$kpm_run_dir/readlink-shell.log"
            if [[ "$app_readlink_rc" == "-2" && -n "$shell_readlink_target" && -z "$app_readlink_target" ]]; then
                kpm_log "readlink 结果：App rc=${app_readlink_rc}，root shell=${shell_readlink_target}（UID 视角已分离，规则生效）"
            else
                kpm_log "readlink 结果：App rc=${app_readlink_rc:-?} target=${app_readlink_target:-<空>}，root shell=${shell_readlink_target:-<空>}（请查看 readlink-target.log）"
            fi
            kpm_control "antidetect name del rfcompat-readlink"
            kpm_control "antidetect status"
            adb_do shell "run-as $PACKAGE rm -f '$KPM_READLINK_PATH'" >/dev/null 2>&1 || true
            kpm_su "rm -f '$KPM_READLINK_TARGET'"
        else
            kpm_log "readlink：无法解析 $PACKAGE UID，跳过"
        fi
    fi
    if kpm_has mkpm-redirect || kpm_has redirect; then
        local uid="$(kpm_uid || true)"
        if [[ -n "$uid" ]]; then
            kpm_log "redirect：仅做同一 App 前后对照（不读取 shell）；先读取不存在的 marker，再启用 UID+精确路径规则读取替换内容（uid=${uid}）"
            # marker 保持不存在，关闭规则时应得到 -ENOENT；目标文件使用无换行
            # 的固定内容，便于从 nativeKpmProbe JSON 中精确判断是否真的读到了替换文件。
            kpm_su "rm -f '$KPM_MARKER'; printf 'mkpm-redirect-target' > '$KPM_REDIRECT_TO'; chmod 644 '$KPM_REDIRECT_TO'"
            # 已发布到设备的 mkpm 使用 dysvcpit 的正式子系统名
            # `eredirect`；菜单仍称 redirect，便于新手按功能理解。
            kpm_control "eredirect $uid unhook"
            kpm_control "eredirect $uid clear"
            kpm_control "eredirect $uid status"
            redirect_supported="$(grep -aoE 'redirect: supported=[01]' "$kpm_main_log" 2>/dev/null | tail -1 | sed 's/.*=//' || true)"
            kpm_probe redirect-before
            local redirect_before_log="$kpm_run_dir/redirect-before.log"
            redirect_before_open="$(grep -aoE '"open_marker":-?[0-9]+' "$redirect_before_log" 2>/dev/null | tail -1 | sed 's/.*://' || true)"

            if [[ "$redirect_supported" != "1" ]]; then
                # 只有明确完成 do_filp_open ABI/符号验证的设备才允许安装；
                # supported=0 或状态缺失都安全熔断。Pixel6 当前版本应为 1。
                redirect_verdict="unsupported"
                if [[ "$redirect_supported" == "0" ]]; then
                    kpm_log "redirect 结果：supported=0，当前内核安全熔断，跳过 addexact/hook（不会修改文件系统路径）"
                    status_warn "redirect 在当前内核安全熔断（未安装 filesystem hook）"
                else
                    kpm_log "redirect 结果：未读到 supported=1（实际=${redirect_supported:-<空>}），安全跳过 addexact/hook（不会修改文件系统路径）"
                    status_warn "redirect 状态未知，安全跳过 filesystem hook"
                fi
            else
                kpm_control "eredirect $uid addexact $KPM_MARKER $KPM_REDIRECT_TO"
                kpm_control "eredirect $uid hook"
                kpm_probe redirect-after
                local redirect_after_log="$kpm_run_dir/redirect-after.log"
                redirect_after_open="$(grep -aoE '"open_marker":-?[0-9]+' "$redirect_after_log" 2>/dev/null | tail -1 | sed 's/.*://' || true)"
                redirect_after_data="$(grep -aoE '"marker_data":"[^"]*"' "$redirect_after_log" 2>/dev/null | tail -1 | sed 's/.*:"//; s/"$//' || true)"
                if [[ "$redirect_before_open" =~ ^-?[0-9]+$ && "$redirect_before_open" == "-2" \
                      && "$redirect_after_open" =~ ^[0-9]+$ \
                      && "$redirect_after_data" == "mkpm-redirect-target" ]]; then
                    redirect_verdict="pass"
                    kpm_log "redirect 结果：App 内关闭 open=${redirect_before_open}，开启 open=${redirect_after_open} data=${redirect_after_data}（同一 App 读到替换内容，规则生效；未使用 shell 对照）"
                    status_ok "redirect 功能验证 PASS"
                elif [[ -n "$redirect_after_open" || -n "$redirect_after_data" ]]; then
                    redirect_verdict="fail"
                    kpm_verdict=1
                    kpm_log "redirect 结果：App 内关闭 open=${redirect_before_open:-?}，开启 open=${redirect_after_open:-?} data=${redirect_after_data:-<空>}（未读到预期替换内容；未使用 shell 对照）"
                    status_fail "redirect 功能验证 FAIL（详见 redirect-before.log/redirect-after.log）"
                else
                    redirect_verdict="fail"
                    kpm_verdict=1
                    kpm_log "redirect 结果：App 内探针没有返回有效 open_marker（关闭=${redirect_before_open:-?}，开启=${redirect_after_open:-?}；未使用 shell 对照）"
                    status_fail "redirect 功能验证 FAIL（没有有效探针结果）"
                fi
            fi
            # 未支持的内核没有添加规则，跳过 del，避免把预期的
            # error=-ENOENT 误报成一次失败清理。
            if [[ "$redirect_supported" == "1" ]]; then
                kpm_control "eredirect $uid del $KPM_MARKER"
            fi
            kpm_control "eredirect $uid unhook"
            kpm_control "eredirect $uid clear"
            kpm_best "删除 redirect 测试文件" "rm -f '$KPM_REDIRECT_TO'"
        else
            kpm_log "redirect：无法解析 $PACKAGE UID，跳过"
        fi
    fi
    if kpm_has mkpm-crc32 || kpm_has crc32; then
        local pid="$(kpm_pid || true)"
        if [[ -n "$pid" ]]; then
            # CRC32 必须拆成三个独立 attach，才能让全局 wxshadow 开关真正形成
            # A(原始) -> B(NORMAL 改写) -> A'(WXSHADOW 恢复) 对照。
            kpm_control "wxshadow enable"
            kpm_best "选择 CRC 阶段 wx" "setprop $KPM_CRC_PHASE_PROP wx"
            kpm_attach crc32-wxshadow-A "$kpm_remote_crc" "$pid"
            # 每个 CRC 阶段使用独立进程，避免上一阶段的 hook/线程状态
            # 影响下一阶段；这也是 NORMAL 失去响应时的明确隔离边界。
            kpm_restart_app "CRC wx -> normal 阶段隔离" || true
            pid="$(kpm_pid || true)"
            kpm_control "wxshadow disable"
            kpm_best "选择 CRC 阶段 normal" "setprop $KPM_CRC_PHASE_PROP normal"
            if [[ -n "$pid" ]]; then
                kpm_attach crc32-normal-B "$kpm_remote_crc" "$pid"
            else
                kpm_log "crc32-normal-B：重启后找不到 $PACKAGE 进程，跳过"
            fi
            kpm_restart_app "CRC normal -> wx-restore 阶段隔离" || true
            pid="$(kpm_pid || true)"
            kpm_control "wxshadow enable"
            kpm_best "选择 CRC 阶段 wx-restore" "setprop $KPM_CRC_PHASE_PROP wx-restore"
            if [[ -n "$pid" ]]; then
                kpm_attach crc32-wx-restore-A "$kpm_remote_crc" "$pid"
            else
                kpm_log "crc32-wx-restore-A：重启后找不到 $PACKAGE 进程，跳过"
            fi
            kpm_best "清理 CRC 阶段属性" "setprop $KPM_CRC_PHASE_PROP all"
        else
            kpm_log "crc32：找不到 $PACKAGE 进程，跳过"
        fi
    fi
    kpm_control "syscall stop"
    kpm_control "syscall detach-all"
    adb_do shell su -c "am force-stop $PACKAGE" >/dev/null 2>&1 || true
    adb_do shell su -c "rm -f '$KPM_MAP_PATH' '$KPM_MARKER' '$KPM_REDIRECT_TO'" >/dev/null 2>&1 || true
    adb_do shell su -c "setprop debug.rustfrida.compat.mode all" >/dev/null 2>&1 || true
    local crc_phase_pass_count=0 crc_phase_fail_count=0 crc_java_ready_errors=0
    if kpm_has mkpm-crc32 || kpm_has crc32; then
        # 进程 rc=0 只能说明 RustFrida 收尾成功；CRC 必须三个独立阶段
        # 都输出 PASS，且不能出现 Java.ready 回调异常，才算本轮通过。
        crc_phase_pass_count="$( (grep -aE '\[CRC\]\[PHASE_VERDICT\].*result=PASS' "$kpm_main_log" 2>/dev/null || true) | wc -l | tr -d ' ' )"
        crc_phase_fail_count="$( (grep -aE '\[CRC\]\[PHASE_VERDICT\].*result=FAIL' "$kpm_main_log" 2>/dev/null || true) | wc -l | tr -d ' ' )"
        crc_java_ready_errors="$( (grep -aE '\[Java\.ready\] callback #[0-9]+ error:' "$kpm_main_log" 2>/dev/null || true) | wc -l | tr -d ' ' )"
        if [[ "$crc_phase_pass_count" == "3" && "$crc_phase_fail_count" == "0" && "$crc_java_ready_errors" == "0" ]]; then
            status_ok "CRC 三阶段验证通过（WXSHADOW/NORMAL/WX-restore）"
        else
            status_fail "CRC 验证失败：PASS=${crc_phase_pass_count}/3 FAIL=${crc_phase_fail_count} Java.ready_errors=${crc_java_ready_errors}（详见 ${kpm_run_dir}）"
            kpm_verdict=1
        fi
    fi
    {
        echo "run_id=$kpm_run_id"
        echo "selected_modes=$lane_spec"
        echo "package=$PACKAGE"
        echo "kpm=$KPM_FILE"
        echo "kpctl=$kpm_ctl"
        echo "run_dir=$kpm_run_dir"
        echo "main_log=$kpm_main_log"
        echo "device_serial=$kpm_device_serial"
        echo "device_model=$kpm_device_model"
        echo "device_kernel=$kpm_device_kernel"
        echo "crc_phase_pass_count=$crc_phase_pass_count"
        echo "crc_phase_fail_count=$crc_phase_fail_count"
        echo "crc_java_ready_errors=$crc_java_ready_errors"
        echo "inode_before=$inode_before"
        echo "inode_after=$inode_after"
        echo "inode_verdict=$inode_verdict"
        echo "hide_on_demo=$hide_on_demo"
        echo "hide_off_demo=$hide_off_demo"
        echo "hide_restored_demo=$hide_restored_demo"
        echo "hide_verdict=$hide_verdict"
        echo "redirect_supported=$redirect_supported"
        echo "redirect_compare_scope=$redirect_compare_scope"
        echo "redirect_before_open=$redirect_before_open"
        echo "redirect_after_open=$redirect_after_open"
        echo "redirect_after_data=$redirect_after_data"
        echo "redirect_verdict=$redirect_verdict"
        echo "kpm_verdict=$kpm_verdict"
        grep -aE "\\[mkpm\\]|\\[mkpm-probe\\]|\\[CRC\\].*(VERDICT|PROBE|COMPARE|PHASE|CALL)" "$kpm_main_log" || true
        # syscall read 的首行和 boot_time 事件没有 [mkpm] 前缀，单独收进摘要。
        grep -aE '^(next=|event .* nr=113 )' "$kpm_main_log" || true
    } > "$kpm_run_dir/SUMMARY.txt"
    cat "$kpm_run_dir/SUMMARY.txt"
    return "$kpm_verdict"
}

if [[ "$MODE_SPEC" == mkpm-* || "$MODE_SPEC" == *,mkpm-* ]]; then
    IFS=',' read -r -a kpm_parts <<< "$MODE_SPEC"
    for lane in "${kpm_parts[@]}"; do
        [[ "$lane" == mkpm-* ]] || {
            status_fail "mkpm 模式不能和 C/Java 等模式混选，请单独执行"
            exit 2
        }
    done
    if run_kpm_demo "$MODE_SPEC"; then
        status_ok "mkpm 实验完成；结果见 ${KPM_RESULT_DIR}/SUMMARY.txt"
        exit 0
    else
        rc=$?
        status_fail "mkpm 实验失败 rc=${rc}；结果目录 ${KPM_RESULT_DIR:-$REPO_ROOT/runs/compat-demo}"
        exit "$rc"
    fi
fi

has_lane() {
    # all 只包含菜单中的基础通道；矩阵/轮换是独立实验，必须显式选择，
    # 否则普通 all 测试会被“未产生矩阵对账行”误报为失败。
    case "$1" in
        hwbp-matrix|hwbp-rotate|uprobe-matrix|uprobe-limit)
            [[ "$MODE_SPEC" == "$1" ]] && return 0
            return 1
            ;;
    esac
    [[ "$MODE_SPEC" == "all" ]] && return 0
    [[ "$1" == "hwbp" && "$MODE_SPEC" == "hwbp-matrix" ]] && return 0
    [[ "$1" == "hwbp" && "$MODE_SPEC" == "hwbp-rotate" ]] && return 0
    [[ "$1" == "uprobe" && "$MODE_SPEC" == "uprobe-matrix" ]] && return 0
    [[ "$1" == "uprobe" && "$MODE_SPEC" == "uprobe-limit" ]] && return 0
    case ",$MODE_SPEC," in *,"$1",*) return 0;; esac
    return 1
}
NEEDS_KERNEL=0
if has_lane svc || has_lane uprobe || has_lane hwbp; then
    NEEDS_KERNEL=1
fi
NEEDS_GUM=0; has_lane gumtrace && NEEDS_GUM=1
NEEDS_SVC=0; has_lane svc && NEEDS_SVC=1
EXTREME="${EXTREME:-0}"
LOW_FREQ="${LOW_FREQ:-1}"
if [[ "$EXTREME" == "1" ]]; then
    # 压力档明确覆盖低频开关，避免两个变量组合出含义不清的档位。
    LOW_FREQ=0
fi
case "$LOW_FREQ" in
    0|1) ;;
    *) echo "[compat-runner] LOW_FREQ 只能是 0 或 1（当前: ${LOW_FREQ}）" >&2; exit 2 ;;
esac
EXTREME_PROP=debug.rustfrida.compat.extreme
LOW_FREQ_PROP=debug.rustfrida.compat.low_freq
MODE_PROP=debug.rustfrida.compat.mode
UPROBE_TARGETS_PROP=debug.rustfrida.compat.uprobe_targets
UPROBE_TARGETS="${UPROBE_TARGETS:-32}"
if ! [[ "$UPROBE_TARGETS" =~ ^[0-9]+$ ]] || (( UPROBE_TARGETS < 1 || UPROBE_TARGETS > 32 )); then
    echo "[compat-runner] UPROBE_TARGETS 必须是 1..32（当前: ${UPROBE_TARGETS}）" >&2
    exit 2
fi
HWBP_MAX_BREAKPOINTS="${KT_HWBP_MAX_BREAKPOINTS:-6}"
HWBP_MAX_WATCHPOINTS="${KT_HWBP_MAX_WATCHPOINTS:-4}"
if ! [[ "$HWBP_MAX_BREAKPOINTS" =~ ^[0-9]+$ ]] || (( HWBP_MAX_BREAKPOINTS < 1 || HWBP_MAX_BREAKPOINTS > 32 )); then
    echo "[compat-runner] KT_HWBP_MAX_BREAKPOINTS 必须是 1..32（当前: ${HWBP_MAX_BREAKPOINTS}）" >&2
    exit 2
fi
if ! [[ "$HWBP_MAX_WATCHPOINTS" =~ ^[0-9]+$ ]] || (( HWBP_MAX_WATCHPOINTS < 1 || HWBP_MAX_WATCHPOINTS > 32 )); then
    echo "[compat-runner] KT_HWBP_MAX_WATCHPOINTS 必须是 1..32（当前: ${HWBP_MAX_WATCHPOINTS}）" >&2
    exit 2
fi
if ! [[ "$RUN_SECS" =~ ^[0-9]+$ ]] || (( RUN_SECS < 1 )); then
    echo "[compat-runner] RUN_SECS 必须是正整数（当前: ${RUN_SECS}）" >&2
    exit 2
fi
if ! [[ "$STARTUP_WAIT_SECS" =~ ^[0-9]+$ ]] || (( STARTUP_WAIT_SECS < 10 )); then
    echo "[compat-runner] STARTUP_WAIT_SECS 必须是不小于 10 的整数（当前: ${STARTUP_WAIT_SECS}）" >&2
    exit 2
fi
if ! [[ "$VERIFY_DRAIN_SECS" =~ ^[0-9]+$ ]] || (( VERIFY_DRAIN_SECS > 10 )); then
    echo "[compat-runner] VERIFY_DRAIN_SECS 必须是 0..10 的整数（当前: ${VERIFY_DRAIN_SECS}）" >&2
    exit 2
fi
TRACE_LIVE="${RF_TRACE_LIVE:-svc,hwbp,uprobe}"
if [[ -n "${RF_TRACE_LIVE_EVERY:-}" ]]; then
    TRACE_LIVE_EVERY="$RF_TRACE_LIVE_EVERY"
elif [[ "$LOW_FREQ" == "1" ]]; then
    # 低频档事件本来就少，默认逐条显示；压测仍按 100 条采样。
    TRACE_LIVE_EVERY=1
else
    TRACE_LIVE_EVERY=100
fi

if [[ "$BUILD_APP" == "1" || ! -f "$APK" ]]; then
    status_step "构建兼容性 demo APK"
    if bash "$ROOT/build_demo.sh"; then
        status_ok "APK 构建完成"
    else
        rc=$?
        status_fail "APK 构建失败 rc=$rc"
        exit "$rc"
    fi
fi
if [[ "$BUILD_RF" == "1" || ! -x "$RF_BIN" ]]; then
    status_step "构建 RustFrida Android 二进制"
    if (cd "$REPO_ROOT" && CARGO_TARGET_DIR=rustfrida_target bash .build-android.sh rust_frida); then
        status_ok "RustFrida 构建完成"
    else
        rc=$?
        status_fail "RustFrida 构建失败 rc=$rc"
        exit "$rc"
    fi
fi
[[ -x "$RF_BIN" ]] || { status_fail "找不到 rustfrida 二进制: $RF_BIN"; exit 2; }

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${RUN_DIR:-$REPO_ROOT/runs/compat-demo/$RUN_ID}"
mkdir -p "$RUN_DIR"
DEVICE_RF=/data/local/tmp/rf
DEVICE_JS=/data/local/tmp/test_compat_demo.js
DEVICE_TRACE=/data/local/tmp/rf-compat-demo-$RUN_ID.jsonl
DEVICE_ANOMALY="$DEVICE_TRACE.anomaly.jsonl"
DEVICE_GUM_TRACE=/data/local/tmp/gumtrace-compatdemo.log
TRACE_LIB=libcompatdemo.so

# 每轮保存设备健康状态；pstore 只读，不会修改手机。设备重启时 adb 可能暂时
# 离线，因此每个命令都单独容错，等设备恢复后再抓完整现场。
capture_device_state() {
    local label="$1"
    local dir="$RUN_DIR/device-$label"
    mkdir -p "$dir"
    # 每轮把 serial/model 一起归档，避免多设备（尤其 Pixel 5/Pixel 6）
    # 时只看事件日志而误把不同内核的结果合并。
    adb_do get-serialno > "$dir/serial.txt" 2>&1 || true
    adb_do shell getprop ro.product.model > "$dir/model.txt" 2>&1 || true
    adb_do shell getprop ro.build.version.release > "$dir/android-release.txt" 2>&1 || true
    adb_do shell uname -r > "$dir/kernel-release.txt" 2>&1 || true
    adb_do shell su -c 'cat /proc/sys/kernel/random/boot_id' > "$dir/boot-id.txt" 2>&1 || true
    adb_do shell su -c 'getprop ro.boot.bootreason' > "$dir/bootreason.txt" 2>&1 || true
    adb_do shell su -c 'cat /proc/uptime' > "$dir/uptime.txt" 2>&1 || true
    adb_do shell su -c 'cat /proc/loadavg' > "$dir/loadavg.txt" 2>&1 || true
    adb_do shell su -c 'ls -l /sys/fs/pstore' > "$dir/pstore-list.txt" 2>&1 || true
    adb_do shell su -c 'cat /sys/fs/pstore/console-ramoops-0' > "$dir/console-ramoops-0.txt" 2>&1 || true
    adb_do shell su -c 'cat /sys/fs/pstore/pmsg-ramoops-0' > "$dir/pmsg-ramoops-0.txt" 2>&1 || true
    adb_do logcat -b all -d -v threadtime > "$dir/logcat-all.txt" 2>&1 || true
}

wait_device_bounded() {
    local seconds="${1:-45}"
    local i
    for ((i = 0; i < seconds; i++)); do
        if adb_do get-state >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}


if (( NEEDS_KERNEL == 1 )); then
    RF_MODE=hybrid
    TRACE_ARGS="--trace-lib $TRACE_LIB --trace-lib-only --trace-decode-args --trace-no-stack --trace-output $DEVICE_TRACE"
    (( NEEDS_SVC == 1 )) || TRACE_ARGS="$TRACE_ARGS --trace-disable-syscall"
    if [[ "$LOW_FREQ" == "1" && "$EXTREME" != "1" ]]; then
        # 低频档没有必要启用详情预算，避免刚开始几条 HWBP 就显示 basic。
        TRACE_ARGS="$TRACE_ARGS --trace-full-detail"
    fi
else
    RF_MODE=inject
    TRACE_ARGS=""
fi

printf '[compat-runner] mode=%s app_mode=%s run=%ss\n' "$MODE_SPEC" "$RF_MODE" "$RUN_SECS"
printf '[compat-runner] output=%s\n' "$RUN_DIR"
status_step "等待 Android 设备"
if adb_do wait-for-device >/dev/null; then
    DEVICE_SERIAL_RESOLVED="$(adb_do get-serialno 2>/dev/null | tr -d '\r\n ' || true)"
    DEVICE_MODEL_RESOLVED="$(adb_do shell getprop ro.product.model 2>/dev/null | tr -d '\r\n' || true)"
    DEVICE_KERNEL_RESOLVED="$(adb_do shell uname -r 2>/dev/null | tr -d '\r\n' || true)"
    status_ok "Android 设备已连接 serial=${DEVICE_SERIAL_RESOLVED:-unknown} model=${DEVICE_MODEL_RESOLVED:-unknown} kernel=${DEVICE_KERNEL_RESOLVED:-unknown}"
    if [[ "${DEVICE_SERIAL_RESOLVED:-}" == "0A291FDD40011F" || "${DEVICE_MODEL_RESOLVED:-}" == "Pixel 5" ]]; then
        status_warn "检测到 Pixel 5；本轮只采信 Pixel 6，建议设置 DEVICE_SERIAL=18201FDF6002GR"
    fi
    capture_device_state before
else
    rc=$?
    status_fail "等待 Android 设备失败 rc=$rc"
    exit "$rc"
fi
if [[ "$INSTALL_APP" == "1" ]]; then
    status_step "安装 APK"
    if adb_do install -r -d "$APK" | tee "$RUN_DIR/install.log"; then
        status_ok "APK 安装完成"
    else
        rc=$?
        status_fail "APK 安装失败 rc=${rc}；查看 $RUN_DIR/install.log"
        exit "$rc"
    fi
else
    status_step "复用设备上已安装的 APK（INSTALL_APP=0）"
    status_ok "跳过安装，避免重复安装触发目标进程被系统 SIGKILL"
fi
status_step "推送 RustFrida 与测试脚本"
if adb_do push "$RF_BIN" "$DEVICE_RF" | tee "$RUN_DIR/push-rf.log" &&
   adb_do push "$JS_FILE" "$DEVICE_JS" | tee "$RUN_DIR/push-js.log"; then
    status_ok "运行文件已推送"
else
    rc=$?
    status_fail "运行文件推送失败 rc=$rc；查看 push-rf.log/push-js.log"
    exit "$rc"
fi
if adb_do shell su -c "chmod 755 $DEVICE_RF" &&
   adb_do shell su -c "setprop $MODE_PROP $MODE_SPEC" &&
   adb_do shell su -c "setprop $UPROBE_TARGETS_PROP $UPROBE_TARGETS"; then
    status_ok "设备运行参数已设置"
else
    rc=$?
    status_fail "设备运行参数设置失败 rc=$rc"
    exit "$rc"
fi
if [[ "$EXTREME" == "1" ]]; then
    adb_do shell su -c "setprop $EXTREME_PROP 1" || {
        rc=$?; status_fail "设置压力档失败 rc=$rc"; exit "$rc";
    }
else
    adb_do shell su -c "setprop $EXTREME_PROP 0" || {
        rc=$?; status_fail "关闭压力档失败 rc=$rc"; exit "$rc";
    }
fi
adb_do shell su -c "setprop $LOW_FREQ_PROP $LOW_FREQ" || {
    rc=$?; status_fail "设置低频档失败 rc=$rc"; exit "$rc";
}
# 先保存 device-before/logcat-all，再清空 logcat，保证本轮 fatal/heartbeat 统计不
# 混入历史进程；pstore 和清空前日志仍保存在 device-before/ 目录中。
adb_do logcat -c >/dev/null 2>&1 || true
echo "cleared_before_run=1" > "$RUN_DIR/logcat-baseline.txt"
if (( NEEDS_GUM == 1 )); then
    # GumTrace 由 demo 进程写文件；root 先创建并放开权限，避免脚本只报 EACCES。
    adb_do shell "su -c 'touch $DEVICE_GUM_TRACE; chmod 666 $DEVICE_GUM_TRACE'" || {
        rc=$?; status_fail "准备 GumTrace 输出文件失败 rc=$rc"; exit "$rc";
    }
fi

# 通过字符串传给 adb shell，保证设备上的 su 收到一个完整命令。
# 设备端 timeout 必须覆盖启动/注入阶段和真正的 RUN_SECS；此前直接用
# RUN_SECS 会在 pre-resume Java 尚未完成时杀掉 RustFrida，造成 Broken pipe。
DEVICE_TIMEOUT_SECS=$((RUN_SECS + STARTUP_WAIT_SECS + VERIFY_DRAIN_SECS + 15))
command="su -c 'am force-stop $PACKAGE; rm -f $DEVICE_TRACE $DEVICE_ANOMALY; RF_TRACE_LIVE=$TRACE_LIVE RF_TRACE_LIVE_EVERY=$TRACE_LIVE_EVERY KT_HWBP_SCOPE=threads KT_HWBP_SWEEP=0 KT_HWBP_MAX_BREAKPOINTS=$HWBP_MAX_BREAKPOINTS KT_HWBP_MAX_WATCHPOINTS=$HWBP_MAX_WATCHPOINTS timeout $DEVICE_TIMEOUT_SECS $DEVICE_RF --spawn $PACKAGE --mode=$RF_MODE -l $DEVICE_JS $TRACE_ARGS'"
keep_secs="$RUN_SECS"
profile="normal"
if [[ "$EXTREME" == "1" ]]; then profile="extreme";
elif [[ "$LOW_FREQ" == "1" ]]; then profile="low-frequency"; fi
status_step "启动 spawn 实验 mode=${MODE_SPEC}，armed 后运行 ${RUN_SECS}s，启动等待上限 ${STARTUP_WAIT_SECS}s，profile=${profile}（live=${TRACE_LIVE} every=${TRACE_LIVE_EVERY}）"
set +e
# 只有脚本报告 observers armed 后才开始 RUN_SECS 倒计时；这段等待发生在
# 主机侧，不会阻塞 adb 输出。若启动阶段超时，仍发送 exit 并由摘要标出。
(
    startup_deadline=$(( $(date +%s) + STARTUP_WAIT_SECS ))
    armed=0
    while (( $(date +%s) < startup_deadline )); do
        if [[ -f "$RUN_DIR/rf-output.log" ]] &&
           grep -aqE '\[COMPAT\] observers armed|\[COMPAT\] .* matrix armed|GumTrace started' "$RUN_DIR/rf-output.log"; then
            armed=1
            break
        fi
        sleep 1
    done
    if (( armed == 0 )); then
        printf '[compat-runner] 启动阶段 %ss 内未看到 armed 标志，仍发送 exit\n' "$STARTUP_WAIT_SECS" >&2
    else
        sleep "$keep_secs"
        # 先留出短暂 drain 时间，让已经进入内核 ring 的软件探针事件到达
        # JS；随后传 force=true 强制输出最终快照，绕过普通 4.5s 节流。
        # 表达式包含 Java.use，RustFrida 会把它发给保存基线的 Java
        # worker；直接 jseval 会落到 raw worker，拿不到同一份计数状态。
        # 这里不使用 Java.perform：该兼容层的 Java API 不保证提供它。
        sleep "$VERIFY_DRAIN_SECS"
        printf "jseval Java.use('java.lang.String') && __compat_verify(true)\n"
    fi
    printf 'exit\n'
) | adb_do shell "$command" 2>&1 | tee "$RUN_DIR/rf-output.log"
# PIPESTATUS[1] 才是 adb/rustfrida 的退出码；PIPESTATUS[0] 是 sleep 管道。
status="${PIPESTATUS[1]}"
set -e
echo "$status" > "$RUN_DIR/rf-exit-code"
if [[ "$status" == "0" ]]; then
    status_ok "RustFrida 运行结束 rc=0"
else
    status_fail "RustFrida 运行失败 rc=${status}；先查看 $RUN_DIR/rf-output.log"
fi

if adb_do shell su -c "test -f $DEVICE_TRACE" >/dev/null 2>&1; then
    adb_do pull "$DEVICE_TRACE" "$RUN_DIR/trace-output.jsonl" | tee "$RUN_DIR/pull.log"
fi
if adb_do shell su -c "test -f $DEVICE_ANOMALY" >/dev/null 2>&1; then
    adb_do pull "$DEVICE_ANOMALY" "$RUN_DIR/anomaly.jsonl" | tee "$RUN_DIR/pull-anomaly.log"
fi
if (( NEEDS_GUM == 1 )) && adb_do shell su -c "test -f $DEVICE_GUM_TRACE" >/dev/null 2>&1; then
    adb_do pull "$DEVICE_GUM_TRACE" "$RUN_DIR/gumtrace-compatdemo.log" | tee "$RUN_DIR/pull-gumtrace.log"
fi
adb_do shell su -c "am force-stop $PACKAGE" >/dev/null 2>&1 || true
    adb_do shell su -c "setprop $EXTREME_PROP 0; setprop $LOW_FREQ_PROP 1; setprop $MODE_PROP all; setprop $UPROBE_TARGETS_PROP 32" >/dev/null 2>&1 || true
adb_do logcat -d -v threadtime > "$RUN_DIR/logcat.txt" 2>&1 || true
if ! wait_device_bounded 45; then
    status_warn "运行后设备未在 45s 内恢复，保留当前目录并跳过后置 pstore 拉取"
else
    capture_device_state after
    # 目标可能在 RustFrida 退出后才被 watcher 观察到，恢复设备后再补拉一次。
    if adb_do shell su -c "test -f $DEVICE_ANOMALY" >/dev/null 2>&1; then
        adb_do pull "$DEVICE_ANOMALY" "$RUN_DIR/anomaly.jsonl" >/dev/null 2>&1 || true
    fi
fi

TRACE_LINES=0; HWBP_EVENTS=0; SVC_EVENTS=0; UPROBE_EVENTS=0
if [[ -f "$RUN_DIR/trace-output.jsonl" ]]; then
    # trace-output.jsonl 在极限档可能达到数 GB；一次扫描完成所有计数，
    # 避免 wc + 3 次 awk 让结束后的分析阶段重复读完整文件。
    read -r TRACE_LINES HWBP_EVENTS SVC_EVENTS UPROBE_EVENTS < <(
        awk '
            {
                lines++
                if (index($0, "\"type\":\"hwbp.hit\"")) hwbp++
                if (index($0, "\"type\":\"svc.enter\"")) svc++
                if (index($0, "\"type\":\"uprobe.hit\"")) uprobe++
            }
            END { printf "%d %d %d %d\n", lines+0, hwbp+0, svc+0, uprobe+0 }
        ' "$RUN_DIR/trace-output.jsonl"
    )
fi
# ART 某些版本给不同线程返回不同的 JNIEnv 表；脚本会同时记录直接
# RegisterNatives 回调和 JniProbe 函数指针回调，摘要两种都算作 JNI 验证。
JNI_EVENTS="$(awk '/RegisterNatives class=|\[jni\] registered=|jni#/{n++} END{print n+0}' "$RUN_DIR/rf-output.log" 2>/dev/null || echo 0)"
GUM_EVENTS="$(awk '/GumTrace started/{n++} END{print n+0}' "$RUN_DIR/rf-output.log" 2>/dev/null || echo 0)"
# 这是协议异常的诊断计数，不把它当成业务事件；agent 已经对同类消息限流。
UNKNOWN_FRAME_DIAGNOSTICS="$( (grep -aE '未知 frame kind|未知 agent frame kind' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | wc -l | tr -d ' ' )"
ANOMALY_EVENTS=0
UNEXPECTED_ANOMALIES=0
if [[ -f "$RUN_DIR/anomaly.jsonl" ]]; then
    ANOMALY_EVENTS="$(wc -l < "$RUN_DIR/anomaly.jsonl" | tr -d ' ')"
    # grep 返回 1 表示“没有匹配”；在 pipefail 下要把它转为空输入，
    # 否则无异常的正常运行会在写 SUMMARY 前提前退出。
    UNEXPECTED_ANOMALIES="$( (grep -ao '"expected":false' "$RUN_DIR/anomaly.jsonl" 2>/dev/null || true) | wc -l | tr -d ' ')"
fi
FATAL_LOG_LINES="$( (grep -aE 'FATAL EXCEPTION|Fatal signal|SIGSEGV|SIGABRT|kernel panic|KERNEL PANIC' "$RUN_DIR/logcat.txt" 2>/dev/null || true) | wc -l | tr -d ' ')"
# 日志里最早的 pid 往往是 zygote；优先取 spawn hello 的目标 pid，避免把
# zygote 的无关 fatal/启动信息误归因给本轮 App。
TARGET_PID="$(grep -a -m1 -oE '收到 spawn hello: pid=[0-9]+' "$RUN_DIR/rf-output.log" 2>/dev/null | sed 's/.*pid=//' || true)"
if [[ -n "$TARGET_PID" ]]; then
    FATAL_LOG_LINES="$( (grep -aE " $TARGET_PID .*FATAL EXCEPTION| $TARGET_PID .*Fatal signal| $TARGET_PID .*SIGSEGV| $TARGET_PID .*SIGABRT| $TARGET_PID .*kernel panic| $TARGET_PID .*KERNEL PANIC" "$RUN_DIR/logcat.txt" 2>/dev/null || true) | wc -l | tr -d ' ')"
fi
HEARTBEAT_LINES="$( (grep -a '\[HEARTBEAT\]' "$RUN_DIR/logcat.txt" 2>/dev/null || true) | wc -l | tr -d ' ')"
VERIFY_LINE="$(grep -a '\[VERIFY\] verdict=' "$RUN_DIR/rf-output.log" 2>/dev/null | tail -1 || true)"
verify_field() { printf '%s\n' "$VERIFY_LINE" | sed -n "s/.* $1=\\([^ ]*\\).*/\\1/p"; }
VERIFY_VERDICT="$(verify_field verdict)"
VERIFY_SOURCE_SVC="$(verify_field source_svc)"; VERIFY_OBSERVED_SVC="$(verify_field observed_svc)"
VERIFY_SOURCE_UPROBE="$(verify_field source_uprobe)"; VERIFY_OBSERVED_UPROBE="$(verify_field observed_uprobe)"
VERIFY_SOURCE_HWBP="$(verify_field source_hwbp)"; VERIFY_OBSERVED_HWBP="$(verify_field observed_hwbp)"
VERIFY_SOURCE_C="$(verify_field source_c)"; VERIFY_OBSERVED_C="$(verify_field observed_c)"
VERIFY_SOURCE_JAVA="$(verify_field source_java)"; VERIFY_OBSERVED_JAVA="$(verify_field observed_java)"
VERIFY_SOURCE_DEX="$(verify_field source_dex)"; VERIFY_OBSERVED_DEX="$(verify_field observed_dex)"
VERIFY_SOURCE_DEXPAYLOAD="$(verify_field source_dexPayload)"; VERIFY_OBSERVED_DEXPAYLOAD="$(verify_field observed_dexPayload)"
VERIFY_SOURCE_JNI="$(verify_field source_jni)"; VERIFY_OBSERVED_JNI="$(verify_field observed_jni)"
VERIFY_OBSERVED_JNI_SYSTEM="$(verify_field observed_jni_system)"
VERIFY_SOURCE_METHOD="$(verify_field source_method)"; VERIFY_OBSERVED_METHOD="$(verify_field observed_method)"
VERIFY_GATE_TIMEOUTS="$(verify_field gate_timeouts)"
VERIFY_MISSING="$(verify_field missing)"
: "${VERIFY_SOURCE_SVC:=0}" "${VERIFY_OBSERVED_SVC:=0}"
: "${VERIFY_SOURCE_UPROBE:=0}" "${VERIFY_OBSERVED_UPROBE:=0}"
: "${VERIFY_SOURCE_HWBP:=0}" "${VERIFY_OBSERVED_HWBP:=0}"
: "${VERIFY_SOURCE_C:=0}" "${VERIFY_OBSERVED_C:=0}"
: "${VERIFY_SOURCE_JAVA:=0}" "${VERIFY_OBSERVED_JAVA:=0}"
: "${VERIFY_SOURCE_DEX:=0}" "${VERIFY_OBSERVED_DEX:=0}"
: "${VERIFY_SOURCE_DEXPAYLOAD:=0}" "${VERIFY_OBSERVED_DEXPAYLOAD:=0}"
: "${VERIFY_SOURCE_JNI:=0}" "${VERIFY_OBSERVED_JNI:=0}"
: "${VERIFY_OBSERVED_JNI_SYSTEM:=0}"
: "${VERIFY_SOURCE_METHOD:=0}" "${VERIFY_OBSERVED_METHOD:=0}"
HWBP_MATRIX_LINES="$(grep -a '\[HWBP-MATRIX\]' "$RUN_DIR/rf-output.log" 2>/dev/null || true)"
HWBP_MATRIX_SPEC_COUNT="$(printf '%s\n' "$HWBP_MATRIX_LINES" | sed -n 's/.*\[HWBP-MATRIX\] \([^ ]*\).*/\1/p' | sort -u | sed '/^$/d' | wc -l | tr -d ' ')"
HWBP_MATRIX_FAILURES="$(printf '%s\n' "$HWBP_MATRIX_LINES" | awk '/verdict=FAIL/{n++} END{print n+0}')"
HWBP_MATRIX_PARTIALS="$(printf '%s\n' "$HWBP_MATRIX_LINES" | awk '/verdict=PARTIAL/{n++} END{print n+0}')"
UPROBE_MATRIX_LINES="$(grep -a '\[UPROBE-MATRIX\]' "$RUN_DIR/rf-output.log" 2>/dev/null || true)"
UPROBE_MATRIX_SPEC_COUNT="$(printf '%s\n' "$UPROBE_MATRIX_LINES" | sed -n 's/.*\[UPROBE-MATRIX\] \([^ ]*\).*/\1/p' | sort -u | sed '/^$/d' | wc -l | tr -d ' ')"
UPROBE_MATRIX_FAILURES="$(printf '%s\n' "$UPROBE_MATRIX_LINES" | awk '/verdict=FAIL/{n++} END{print n+0}')"
UPROBE_MATRIX_PARTIALS="$(printf '%s\n' "$UPROBE_MATRIX_LINES" | awk '/verdict=PARTIAL/{n++} END{print n+0}')"
# HWBP 槽位覆盖以 host 的实际 attach 结果和内核统计为准。JS 的
# CALLBACK_LIMITED/CALLBACK_PARTIAL 只表示实时回调预算，不代表断点没挂上。
HWBP_ATTACH_OK="$( (grep -a '\[trace-cmd\] hwbp attached:' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | grep -c 'partial=false' || true )"
HWBP_ATTACH_PARTIAL="$( (grep -a '\[trace-cmd\] hwbp attached:' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | grep -c 'partial=true' || true )"
HWBP_ATTACH_FAILURES="$( (grep -a '\[trace-cmd\] hwbp attach failed' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | wc -l | tr -d ' ' )"
HWBP_STATS_LINE="$( (grep -a '对账 .* hwbp:' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | tail -1 )"
HWBP_KERNEL_RING_DROPS="$(printf '%s\n' "$HWBP_STATS_LINE" | sed -n 's/.*ring丢弃=\([0-9][0-9]*\).*/\1/p')"
HWBP_QUEUE_DROPS="$(printf '%s\n' "$HWBP_STATS_LINE" | sed -n 's/.*队列丢弃=\([0-9][0-9]*\).*/\1/p')"
HWBP_REPORT_DROPS="$(printf '%s\n' "$HWBP_STATS_LINE" | sed -n 's/.*报告丢弃=\([0-9][0-9]*\).*/\1/p')"
HWBP_KERNEL_RING_DROPS="${HWBP_KERNEL_RING_DROPS:-0}"
HWBP_QUEUE_DROPS="${HWBP_QUEUE_DROPS:-0}"
HWBP_REPORT_DROPS="${HWBP_REPORT_DROPS:-0}"
# 轮换模式同时核对 JS 发出的操作和 host 的实际 attach/detach 行。
# `hwbp detached` 才代表 OwnedFd/link 已由 manager 丢弃，不能只看
# `cmd queued`；去重后的 attach 地址用于确认确实切到了下一个位置。
HWBP_ROTATE_LINES="$(grep -a '\[HWBP-ROTATE\]' "$RUN_DIR/rf-output.log" 2>/dev/null || true)"
HWBP_ROTATE_HITS="$(printf '%s\n' "$HWBP_ROTATE_LINES" | awk '/phase=hit/{n++} END{print n+0}')"
HWBP_ROTATE_DETACH_SENT="$(printf '%s\n' "$HWBP_ROTATE_LINES" | awk '/phase=detach/{n++} END{print n+0}')"
HWBP_ROTATE_ATTACH_SENT="$(printf '%s\n' "$HWBP_ROTATE_LINES" | awk '/phase=attach/{n++} END{print n+0}')"
HWBP_ROTATE_HOST_DETACH="$( (grep -a '\[trace-cmd\] hwbp detached:' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | wc -l | tr -d ' ' )"
HWBP_ROTATE_HOST_DETACH_ZERO="$( (grep -aE '\[trace-cmd\] hwbp detached: .*\(0 个规格\)' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | wc -l | tr -d ' ' )"
HWBP_ROTATE_HOST_ATTACH="$( (grep -a '\[trace-cmd\] hwbp attached:' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | wc -l | tr -d ' ' )"
HWBP_ROTATE_HOST_ATTACH_PARTIAL="$( (grep -a '\[trace-cmd\] hwbp attached:' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | grep -c 'partial=true' || true )"
HWBP_ROTATE_HOST_ATTACH_FAILURES="$( (grep -aE 'hwbp attach failed|执行断点槽位已满' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | wc -l | tr -d ' ' )"
HWBP_ROTATE_HOST_TARGETS="$( (grep -a '\[trace-cmd\] hwbp attached:' "$RUN_DIR/rf-output.log" 2>/dev/null || true) | sed -n 's/.* = \(0x[0-9a-fA-F]*\) .*/\1/p' | sort -u | wc -l | tr -d ' ' )"
HWBP_ROTATE_OK=0
HWBP_ROTATE_COVERAGE_FULL=0
if has_lane hwbp-rotate; then
    if (( HWBP_ROTATE_HOST_ATTACH > 0 )) && (( HWBP_ROTATE_HOST_ATTACH_PARTIAL == 0 )); then
        HWBP_ROTATE_COVERAGE_FULL=1
    fi
    if (( HWBP_ROTATE_HITS > 0 )) &&
       (( HWBP_ROTATE_HOST_DETACH > 0 )) &&
       (( HWBP_ROTATE_HOST_DETACH_ZERO == 0 )) &&
       (( HWBP_ROTATE_HOST_ATTACH >= 2 )) &&
       (( HWBP_ROTATE_HOST_TARGETS >= 2 )) &&
       (( HWBP_ROTATE_HOST_ATTACH_FAILURES == 0 )) &&
       (( HWBP_KERNEL_RING_DROPS == 0 )) && (( HWBP_QUEUE_DROPS == 0 )) &&
       (( HWBP_REPORT_DROPS == 0 )); then
        HWBP_ROTATE_OK=1
    fi
fi
HWBP_MATRIX_HOST_OK=0
if has_lane hwbp-matrix; then
    if (( HWBP_ATTACH_OK >= HWBP_MATRIX_SPEC_COUNT )) &&
       (( HWBP_ATTACH_PARTIAL == 0 )) && (( HWBP_ATTACH_FAILURES == 0 )) &&
       (( HWBP_KERNEL_RING_DROPS == 0 )) && (( HWBP_QUEUE_DROPS == 0 )) &&
       (( HWBP_REPORT_DROPS == 0 )) && (( HWBP_EVENTS > 0 )); then
        HWBP_MATRIX_HOST_OK=1
    fi
fi
BOOT_ID_BEFORE="$(tr -d '\r\n ' < "$RUN_DIR/device-before/boot-id.txt" 2>/dev/null || true)"
BOOT_ID_AFTER="$(tr -d '\r\n ' < "$RUN_DIR/device-after/boot-id.txt" 2>/dev/null || true)"
DEVICE_REBOOT=0
if [[ -n "$BOOT_ID_BEFORE" && -n "$BOOT_ID_AFTER" && "$BOOT_ID_BEFORE" != "$BOOT_ID_AFTER" ]]; then
    DEVICE_REBOOT=1
fi
VERIFY_HARD_MISMATCH=0
# 高频下 SVC/uprobe/HWBP/方法回调可能受预算限制；只要观察端仍有事件，
# 这是 partial（背压），不是观察者完全失联。C/Java/JNI 是同步 hook，
# 出现明显源端领先则仍按 hard mismatch 处理。
if has_lane svc && (( VERIFY_SOURCE_SVC > 0 )) && (( VERIFY_OBSERVED_SVC == 0 )); then VERIFY_HARD_MISMATCH=1; fi
if has_lane uprobe && (( VERIFY_SOURCE_UPROBE > 0 )) && (( VERIFY_OBSERVED_UPROBE == 0 )); then VERIFY_HARD_MISMATCH=1; fi
if has_lane hwbp && (( VERIFY_SOURCE_HWBP > 0 )) && (( VERIFY_OBSERVED_HWBP == 0 )); then VERIFY_HARD_MISMATCH=1; fi
if has_lane hwbp && ! has_lane hwbp-rotate && (( VERIFY_SOURCE_METHOD > 0 )) && (( VERIFY_OBSERVED_METHOD == 0 )); then VERIFY_HARD_MISMATCH=1; fi
if has_lane c && (( VERIFY_SOURCE_C > VERIFY_OBSERVED_C + 1 )); then VERIFY_HARD_MISMATCH=1; fi
if has_lane java && (( VERIFY_SOURCE_JAVA > VERIFY_OBSERVED_JAVA + 1 )); then VERIFY_HARD_MISMATCH=1; fi
if has_lane java && (( VERIFY_SOURCE_DEX > 0 )) && (( VERIFY_OBSERVED_DEX == 0 )); then VERIFY_HARD_MISMATCH=1; fi
if has_lane java && (( VERIFY_SOURCE_DEXPAYLOAD > 0 )) && (( VERIFY_OBSERVED_DEXPAYLOAD == 0 )); then VERIFY_HARD_MISMATCH=1; fi
if has_lane jnitrace && (( VERIFY_SOURCE_JNI > VERIFY_OBSERVED_JNI + 1 )); then VERIFY_HARD_MISMATCH=1; fi
if has_lane jnitrace && (( VERIFY_SOURCE_JNI > 0 )) && (( VERIFY_OBSERVED_JNI == 0 )); then VERIFY_HARD_MISMATCH=1; fi
VERIFY_PROBLEM=0
if [[ "$VERIFY_HARD_MISMATCH" == "1" || "$HWBP_MATRIX_FAILURES" != "0" || "$UPROBE_MATRIX_FAILURES" != "0" ]]; then
    VERIFY_PROBLEM=1
fi
if has_lane hwbp-matrix && (( HWBP_MATRIX_HOST_OK == 1 )); then
    # 矩阵模式的 JS 观察端是有界实时视图；槽位/内核链路已经由 host
    # 覆盖率判定，不能因为 CALLBACK_LIMITED 让整轮实验变成失败。
    VERIFY_PROBLEM=0
fi
if [[ "$status" == "0" ]] && [[ "$UNEXPECTED_ANOMALIES" == "0" ]] && [[ "$DEVICE_REBOOT" == "0" ]] &&
   [[ "$VERIFY_PROBLEM" == "0" ]] &&
   [[ "$VERIFY_VERDICT" != "MISMATCH" && "$VERIFY_VERDICT" != "PARTIAL" ]] &&
   ! grep -aqE '\[✗\]|\[失败\]|attach failed|hook failed|FATAL EXCEPTION|SIGSEGV|SIGABRT|kernel panic|KERNEL PANIC' "$RUN_DIR/rf-output.log"; then
    RUN_VERDICT="pass"
elif [[ "$status" == "0" ]] && [[ "$UNEXPECTED_ANOMALIES" == "0" ]] && [[ "$DEVICE_REBOOT" == "0" ]] &&
     [[ "$VERIFY_PROBLEM" == "0" ]] && [[ "$VERIFY_VERDICT" == "MISMATCH" || "$VERIFY_VERDICT" == "PARTIAL" ]]; then
    # PARTIAL 表示源端确实运行了，但 ring/输出预算丢过事件；这与崩溃或
    # “没有安装观察者”不同，单独保留给压力报告，不伪装成 pass。
    RUN_VERDICT="partial"
else
    RUN_VERDICT="fail"
fi
cat > "$RUN_DIR/SUMMARY.txt" <<EOF_SUMMARY
run_id=$RUN_ID
rf_exit_code=$status
run_verdict=$RUN_VERDICT
run_seconds=$RUN_SECS
selected_modes=$MODE_SPEC
stress_mode=$profile
low_frequency=$LOW_FREQ
rustfrida_mode=$RF_MODE
device_serial=${DEVICE_SERIAL_RESOLVED:-${DEVICE_SERIAL:-unknown}}
device_model=${DEVICE_MODEL_RESOLVED:-unknown}
device_kernel=${DEVICE_KERNEL_RESOLVED:-unknown}
apk=$APK
rf_binary=$RF_BIN
script=$JS_FILE
trace_lines=$TRACE_LINES
hwbp_json_events=$HWBP_EVENTS
svc_json_events=$SVC_EVENTS
uprobe_json_events=$UPROBE_EVENTS
jnitrace_register_events=$JNI_EVENTS
gumtrace_started_events=$GUM_EVENTS
unknown_frame_diagnostics=$UNKNOWN_FRAME_DIAGNOSTICS
anomaly_events=$ANOMALY_EVENTS
unexpected_anomalies=$UNEXPECTED_ANOMALIES
fatal_log_lines=$FATAL_LOG_LINES
target_pid=$TARGET_PID
heartbeat_lines=$HEARTBEAT_LINES
logcat_cleared=1
verification_verdict=${VERIFY_VERDICT:-UNAVAILABLE}
verification_missing=${VERIFY_MISSING:-}
source_svc=${VERIFY_SOURCE_SVC:-0}
observed_svc=${VERIFY_OBSERVED_SVC:-0}
source_uprobe=${VERIFY_SOURCE_UPROBE:-0}
observed_uprobe=${VERIFY_OBSERVED_UPROBE:-0}
source_hwbp=${VERIFY_SOURCE_HWBP:-0}
observed_hwbp=${VERIFY_OBSERVED_HWBP:-0}
source_c=${VERIFY_SOURCE_C:-0}
observed_c=${VERIFY_OBSERVED_C:-0}
source_java=${VERIFY_SOURCE_JAVA:-0}
observed_java=${VERIFY_OBSERVED_JAVA:-0}
source_dex=${VERIFY_SOURCE_DEX:-0}
observed_dex=${VERIFY_OBSERVED_DEX:-0}
source_dexPayload=${VERIFY_SOURCE_DEXPAYLOAD:-0}
observed_dexPayload=${VERIFY_OBSERVED_DEXPAYLOAD:-0}
source_jni=${VERIFY_SOURCE_JNI:-0}
observed_jni=${VERIFY_OBSERVED_JNI:-0}
observed_jni_system=${VERIFY_OBSERVED_JNI_SYSTEM:-0}
source_method=${VERIFY_SOURCE_METHOD:-0}
observed_method=${VERIFY_OBSERVED_METHOD:-0}
gate_timeouts=${VERIFY_GATE_TIMEOUTS:-0}
hwbp_matrix_spec_count=${HWBP_MATRIX_SPEC_COUNT:-0}
hwbp_matrix_failures=${HWBP_MATRIX_FAILURES:-0}
hwbp_matrix_partials=${HWBP_MATRIX_PARTIALS:-0}
hwbp_attach_ok=${HWBP_ATTACH_OK:-0}
hwbp_attach_partial=${HWBP_ATTACH_PARTIAL:-0}
hwbp_attach_failures=${HWBP_ATTACH_FAILURES:-0}
hwbp_limit_breakpoints=${HWBP_MAX_BREAKPOINTS:-0}
hwbp_limit_watchpoints=${HWBP_MAX_WATCHPOINTS:-0}
hwbp_kernel_ring_drops=${HWBP_KERNEL_RING_DROPS:-0}
hwbp_queue_drops=${HWBP_QUEUE_DROPS:-0}
hwbp_report_drops=${HWBP_REPORT_DROPS:-0}
hwbp_matrix_host_ok=${HWBP_MATRIX_HOST_OK:-0}
hwbp_rotate_hits=${HWBP_ROTATE_HITS:-0}
hwbp_rotate_detach_sent=${HWBP_ROTATE_DETACH_SENT:-0}
hwbp_rotate_attach_sent=${HWBP_ROTATE_ATTACH_SENT:-0}
hwbp_rotate_host_detach=${HWBP_ROTATE_HOST_DETACH:-0}
hwbp_rotate_host_detach_zero=${HWBP_ROTATE_HOST_DETACH_ZERO:-0}
hwbp_rotate_host_attach=${HWBP_ROTATE_HOST_ATTACH:-0}
hwbp_rotate_host_targets=${HWBP_ROTATE_HOST_TARGETS:-0}
hwbp_rotate_host_attach_partial=${HWBP_ROTATE_HOST_ATTACH_PARTIAL:-0}
hwbp_rotate_host_attach_failures=${HWBP_ROTATE_HOST_ATTACH_FAILURES:-0}
hwbp_rotate_coverage_full=${HWBP_ROTATE_COVERAGE_FULL:-0}
hwbp_rotate_ok=${HWBP_ROTATE_OK:-0}
uprobe_matrix_spec_count=${UPROBE_MATRIX_SPEC_COUNT:-0}
uprobe_matrix_failures=${UPROBE_MATRIX_FAILURES:-0}
uprobe_matrix_partials=${UPROBE_MATRIX_PARTIALS:-0}
boot_id_before=$BOOT_ID_BEFORE
boot_id_after=$BOOT_ID_AFTER
device_reboot=$DEVICE_REBOOT
trace_lib=$TRACE_LIB
rf_output=$RUN_DIR/rf-output.log
trace_output=$RUN_DIR/trace-output.jsonl
anomaly_output=$RUN_DIR/anomaly.jsonl
gumtrace_output=$RUN_DIR/gumtrace-compatdemo.log
logcat=$RUN_DIR/logcat.txt
anomaly_report=$RUN_DIR/ANOMALY_REPORT.txt
EOF_SUMMARY
if [[ -n "$HWBP_MATRIX_LINES" ]]; then
    {
        echo "hwbp_matrix_report_begin"
        printf '%s\n' "$HWBP_MATRIX_LINES"
        echo "hwbp_matrix_report_end"
    } >> "$RUN_DIR/SUMMARY.txt"
fi
if [[ -n "$UPROBE_MATRIX_LINES" ]]; then
    {
        echo "uprobe_matrix_report_begin"
        printf '%s\n' "$UPROBE_MATRIX_LINES"
        echo "uprobe_matrix_report_end"
    } >> "$RUN_DIR/SUMMARY.txt"
fi
# 每轮自动生成一份小报告，避免只保存原始日志而没有异常结论。原始
# anomaly.jsonl/logcat/rf-output 仍然保留，报告只做可复核的关键词计数。
ANOMALY_MARKERS="$( (grep -aE -i 'Fatal signal|FATAL EXCEPTION|SIGABRT|SIGSEGV|JNI DETECTED|target_gone|kernel panic|KERNEL PANIC|未知 frame kind|未知 agent frame kind|attach failed|hook failed' "$RUN_DIR/rf-output.log" "$RUN_DIR/logcat.txt" 2>/dev/null || true) | wc -l | tr -d ' ' )"
EXPECTED_DISCONNECTS="$( (grep -a '"reason":"agent_disconnect".*"expected":true' "$RUN_DIR/anomaly.jsonl" 2>/dev/null || true) | wc -l | tr -d ' ' )"
PSTORE_CHANGED=0
if [[ -f "$RUN_DIR/device-before/console-ramoops-0.txt" &&
      -f "$RUN_DIR/device-after/console-ramoops-0.txt" ]] &&
   ! cmp -s "$RUN_DIR/device-before/console-ramoops-0.txt" "$RUN_DIR/device-after/console-ramoops-0.txt"; then
    PSTORE_CHANGED=1
fi
PSTORE_MARKERS="$( (grep -aE -i 'panic|fatal|oops|watchdog|BUG:' "$RUN_DIR/device-after/console-ramoops-0.txt" "$RUN_DIR/device-after/pmsg-ramoops-0.txt" 2>/dev/null || true) | wc -l | tr -d ' ' )"
ANOMALY_STATUS="PASS"
if (( FATAL_LOG_LINES > 0 || UNEXPECTED_ANOMALIES > 0 || DEVICE_REBOOT == 1 )); then
    ANOMALY_STATUS="FAIL"
elif (( ANOMALY_MARKERS > 0 )); then
    ANOMALY_STATUS="REVIEW"
fi
cat > "$RUN_DIR/ANOMALY_REPORT.txt" <<EOF_ANOMALY
run_id=$RUN_ID
anomaly_status=$ANOMALY_STATUS
fatal_log_lines=$FATAL_LOG_LINES
unexpected_anomalies=$UNEXPECTED_ANOMALIES
device_reboot=$DEVICE_REBOOT
expected_agent_disconnects=$EXPECTED_DISCONNECTS
diagnostic_marker_lines=$ANOMALY_MARKERS
pstore_changed=$PSTORE_CHANGED
pstore_marker_lines=$PSTORE_MARKERS
target_pid=$TARGET_PID

判定说明：
- anomaly_status=PASS：没有目标致命日志、未预期异常或设备重启；预期 agent_disconnect 不算异常。
- anomaly_status=REVIEW：出现诊断关键词，需要回看原始日志，但不自动认定应用崩溃。
- anomaly_status=FAIL：出现致命日志、未预期 anomaly 或 boot_id 改变。
- pstore_changed=1：本轮前后 ramoops 内容发生变化，应结合 console-ramoops-0.txt/pmsg-ramoops-0.txt 查看；旧 pstore 内容不会单独判定本轮失败。

原始文件：
- SUMMARY.txt
- rf-output.log
- trace-output.jsonl
- anomaly.jsonl
- logcat.txt
EOF_ANOMALY
cat "$RUN_DIR/SUMMARY.txt"
cat "$RUN_DIR/ANOMALY_REPORT.txt"

# 这里判定的是“运行链路是否完成”，具体通道是否命中仍以摘要计数为准。
# 未知 frame 已在 agent 侧限流，作为诊断警告显示，不把它误判成业务失败。
unknown_frames="$UNKNOWN_FRAME_DIAGNOSTICS"
if [[ "$RUN_VERDICT" == "pass" ]]; then
    status_ok "实验完成：输出文件和运行摘要已生成"
elif [[ "$RUN_VERDICT" == "partial" ]]; then
    status_warn "实验完成但存在背压丢弃：源端/观察端计数见 SUMMARY.txt，不能当作无损通过"
else
    status_fail "实验未通过：请结合 SUMMARY.txt、rf-output.log 和 logcat.txt 排查"
fi
if [[ "$unknown_frames" != "0" ]]; then
    status_warn "检测到 ${unknown_frames} 组未知 frame 诊断（已限流）；请查看 rf-output.log 中的 len/count/preview"
fi

verify_status() {
    local label="$1" source="$2" observed="$3"
    if [[ -z "$source" || -z "$observed" || ! "$source" =~ ^[0-9]+$ || ! "$observed" =~ ^[0-9]+$ ]]; then
        status_warn "${label}：没有可解析的源端/观察端计数"
    elif (( source == 0 )); then
        status_warn "${label}：源端本轮没有执行，无法判定"
    elif (( observed == source || observed == source + 1 )); then
        status_ok "${label}：源端=${source} 观察端=${observed}，计数一致"
    elif (( observed > 0 )); then
        status_warn "${label}：源端=${source} 观察端=${observed}，存在 $((source-observed)) 条背压/过滤缺口"
    else
        status_fail "${label}：源端=${source} 观察端=0，观察者未命中或已失联"
    fi
}
if [[ -n "$VERIFY_LINE" ]]; then
    if has_lane svc; then verify_status "svc" "$VERIFY_SOURCE_SVC" "$VERIFY_OBSERVED_SVC"; fi
    if has_lane uprobe; then verify_status "uprobe" "$VERIFY_SOURCE_UPROBE" "$VERIFY_OBSERVED_UPROBE"; fi
    if has_lane hwbp && ! has_lane hwbp-rotate; then verify_status "hwbp" "$VERIFY_SOURCE_HWBP" "$VERIFY_OBSERVED_HWBP"; fi
    if has_lane c; then verify_status "C hook" "$VERIFY_SOURCE_C" "$VERIFY_OBSERVED_C"; fi
    if has_lane java; then verify_status "Java hook" "$VERIFY_SOURCE_JAVA" "$VERIFY_OBSERVED_JAVA"; fi
    if has_lane java; then verify_status "Dex load" "$VERIFY_SOURCE_DEX" "$VERIFY_OBSERVED_DEX"; fi
    if has_lane java; then verify_status "Dex payload" "$VERIFY_SOURCE_DEXPAYLOAD" "$VERIFY_OBSERVED_DEXPAYLOAD"; fi
    if has_lane jnitrace; then verify_status "JNI" "$VERIFY_SOURCE_JNI" "$VERIFY_OBSERVED_JNI"; fi
    if has_lane hwbp && ! has_lane hwbp-rotate; then verify_status "method hook" "$VERIFY_SOURCE_METHOD" "$VERIFY_OBSERVED_METHOD"; fi
    if [[ "$VERIFY_VERDICT" == "MISMATCH" ]] && ! (has_lane hwbp-matrix && (( HWBP_MATRIX_HOST_OK == 1 ))); then
        status_fail "功能校验 verdict=MISMATCH：${VERIFY_MISSING:-请查看 VERIFY 行}"
    elif [[ "$VERIFY_VERDICT" == "MISMATCH" ]]; then
        status_warn "功能校验：JS 实时回调有界采样存在缺口；HWBP 槽位和内核链路已由 host 覆盖率确认"
    elif [[ "$VERIFY_VERDICT" == "PARTIAL" ]]; then
        status_warn "功能校验 verdict=PARTIAL：高频档有事件缺口，需结合 ring 丢弃量判断"
    else
        status_ok "功能校验 verdict=${VERIFY_VERDICT:-UNAVAILABLE}"
    fi
    if has_lane hwbp-matrix; then
        if (( HWBP_MATRIX_HOST_OK == 1 )); then
            status_ok "HWBP 矩阵：${HWBP_MATRIX_SPEC_COUNT} 个规格全部挂载，active/target 完整，内核无丢失"
        elif (( HWBP_MATRIX_FAILURES > 0 )); then
            status_fail "HWBP 矩阵：${HWBP_MATRIX_FAILURES} 次出现 source>0 但 observed=0（槽位不足/未挂上/通道失联）"
        elif (( HWBP_MATRIX_PARTIALS > 0 )); then
            status_warn "HWBP 矩阵：${HWBP_MATRIX_SPEC_COUNT} 个规格运行过，存在 ${HWBP_MATRIX_PARTIALS} 次背压缺口"
        elif (( HWBP_MATRIX_SPEC_COUNT > 0 )); then
            status_ok "HWBP 矩阵：${HWBP_MATRIX_SPEC_COUNT} 个规格均有命中记录"
        else
            status_fail "HWBP 矩阵：没有产生规格对账行"
        fi
    fi
    if has_lane hwbp-rotate; then
        if (( HWBP_ROTATE_OK == 1 )); then
            if (( HWBP_ROTATE_COVERAGE_FULL == 1 )); then
                status_ok "HWBP 轮换：命中=${HWBP_ROTATE_HITS}，host 已释放 ${HWBP_ROTATE_HOST_DETACH} 次，切换到 ${HWBP_ROTATE_HOST_TARGETS} 个地址，槽位可复用且线程覆盖完整"
            else
                status_warn "HWBP 轮换：命中=${HWBP_ROTATE_HITS}，host 已释放 ${HWBP_ROTATE_HOST_DETACH} 次，切换到 ${HWBP_ROTATE_HOST_TARGETS} 个地址；槽位已复用，但有短暂线程 partial"
            fi
        elif (( HWBP_ROTATE_HOST_ATTACH_FAILURES > 0 )); then
            status_fail "HWBP 轮换：attach 失败 ${HWBP_ROTATE_HOST_ATTACH_FAILURES} 次；先看槽位/内核错误"
        elif (( HWBP_ROTATE_HOST_DETACH == 0 )); then
            status_fail "HWBP 轮换：没有看到 host 的 hwbp detached，不能证明 bpdel 真正释放槽位"
        else
            status_warn "HWBP 轮换：命中=${HWBP_ROTATE_HITS}，detach=${HWBP_ROTATE_HOST_DETACH}，attach地址=${HWBP_ROTATE_HOST_TARGETS}；证据不完整"
        fi
    fi
    if has_lane uprobe-matrix; then
        if (( UPROBE_MATRIX_FAILURES > 0 )); then
            status_fail "uprobe 矩阵：${UPROBE_MATRIX_FAILURES} 次出现 source>0 但 observed=0（attach/解析/通道失联）"
        elif (( UPROBE_MATRIX_PARTIALS > 0 )); then
            status_warn "uprobe 矩阵：${UPROBE_MATRIX_SPEC_COUNT} 个规格运行过，存在 ${UPROBE_MATRIX_PARTIALS} 次背压缺口"
        elif (( UPROBE_MATRIX_SPEC_COUNT > 0 )); then
            status_ok "uprobe 矩阵：${UPROBE_MATRIX_SPEC_COUNT} 个规格均有命中记录"
        else
            status_fail "uprobe 矩阵：没有产生规格对账行"
        fi
    fi
else
    status_warn "未找到 [VERIFY] 行：可能在观察者安装前退出，或 JS 通道未启动"
fi

# 让调用方可以用退出码自动汇总每一轮结果。终端上的彩色状态仍然保留，
# 但不能再把“实验未通过”伪装成 shell rc=0。
case "$RUN_VERDICT" in
    pass) exit 0 ;;
    partial) exit 3 ;;
    *) exit 1 ;;
esac
