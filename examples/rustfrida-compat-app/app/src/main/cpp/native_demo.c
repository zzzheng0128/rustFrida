#define _GNU_SOURCE

#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jni.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/system_properties.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "syscalls.h"

#define RF_LOG_TAG "RFCompatDemo"
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

typedef struct rf_demo_object {
    uint64_t magic;
    volatile uint64_t read_slot;
    volatile uint64_t write_slot;
    volatile uint64_t read_count;
    volatile uint64_t write_count;
    // C 结构体里的“vtable”函数指针。测试线程会在两个导出方法之间切换；
    // 对这个字段下 8 字节写观察点后，JS 可以从内存中找到新方法地址。
    volatile uintptr_t method_slot;
    volatile uint64_t method_epoch;
    volatile uint32_t method_gate;
    volatile uint32_t method_gate_pad;
    volatile uint64_t method_pending_epoch;
} rf_demo_object_t;

typedef uint64_t (*rf_object_method_t)(rf_demo_object_t *object, uint64_t seed);

uint64_t rf_method_v1(rf_demo_object_t *object, uint64_t seed);
uint64_t rf_method_v2(rf_demo_object_t *object, uint64_t seed);
long rf_agent_hot(long seed);

/* uprobe 极限实验使用一组互不相同的函数入口。重复 attach 同一个地址只能
 * 测到重复事件，不能证明多个软件断点同时生效；这些入口让每个目标都有独立
 * 的 source counter，脚本可以逐目标对账。 */
#define RF_UPROBE_LIMIT_TARGETS 32

static rf_demo_object_t *g_object;
static volatile uint64_t g_init_calls;
static volatile uint64_t g_init_stage;
static volatile long g_init_svc_pid;
static volatile long g_init_svc_tid;
static volatile long g_init_svc_clock_rc;
static volatile long g_init_svc_random_rc;
static volatile uint64_t g_init_svc_byte;
static volatile uint64_t g_object_step_calls;
static volatile uint64_t g_object_read_accesses;
static volatile uint64_t g_object_write_accesses;
static volatile uint64_t g_object_read_slot_reads;
static volatile uint64_t g_object_write_slot_writes;
static volatile uint64_t g_hwbp_counter;
static volatile uint64_t g_hwbp_sink;
static volatile uint64_t g_hwbp_calls;
static volatile uint64_t g_hwbp_read_accesses;
static volatile uint64_t g_hwbp_write_accesses;
static volatile uint64_t g_uprobe_counter;
static volatile uint64_t g_uprobe_calls;
static volatile uint64_t g_agent_counter;
static volatile uint64_t g_agent_calls;
static volatile uint64_t g_native_agent_tick_calls;
static volatile uint64_t g_native_object_exercise_calls;
static volatile uint64_t g_native_method_exercise_calls;
static volatile uint64_t g_native_method_switch_calls;
static volatile uint64_t g_method_calls;
static volatile uint64_t g_method_switches;
static volatile uint64_t g_method_v1_calls;
static volatile uint64_t g_method_v2_calls;
static volatile uint64_t g_method_gate_timeouts;
static volatile uint64_t g_method_hook_ready_calls;
static volatile uint64_t g_method_slot_writes;
static volatile uint64_t g_method_epoch_writes;
static volatile uint64_t g_soft_target_calls[RF_UPROBE_LIMIT_TARGETS];
static volatile int g_jni_probe_registered;
static volatile uint64_t g_jni_register_attempts;
static volatile uint64_t g_jni_register_successes;
static volatile uint64_t g_jni_probe_tick_calls;
static volatile uint64_t g_jni_probe_object_calls;
static volatile uint64_t g_java_oncreate_calls;
static volatile uint64_t g_dex_load_calls;
static volatile uint64_t g_dex_payload_calls;

static inline uint64_t rf_count_load(const volatile uint64_t *counter) {
    return __atomic_load_n(counter, __ATOMIC_RELAXED);
}

/* mkpm 演示使用的固定 marker。它只指向 /data/local/tmp 下的测试文件，
 * 不会触碰应用数据或系统文件；redirect 模式会把它精确替换到另一个文件。 */
#define RF_KPM_MARKER "/data/local/tmp/rfcompat-mkpm-marker"
#define RF_KPM_MAP_PATH "/data/local/tmp/rfcompat-mkpm-map"
#define RF_KPM_READLINK_PATH "/data/user/0/com.rustfrida.compatdemo/rfcompat-readlink"
#define RF_KPM_MAPS_CAP (512u * 1024u)

typedef struct rf_kpm_thread_result {
    long tid;
    long open_rc;
    long read_rc;
} rf_kpm_thread_result_t;

static rf_demo_object_t *rf_object_get(void) {
    rf_demo_object_t *object = __atomic_load_n(&g_object, __ATOMIC_ACQUIRE);
    if (object) return object;

    object = (rf_demo_object_t *) calloc(1, sizeof(*object));
    if (!object) return NULL;
    object->magic = UINT64_C(0x5246434f4d504154); /* RFCOMPAT */
    object->read_slot = UINT64_C(0x1111222233334444);
    object->write_slot = UINT64_C(0xaaaabbbbccccdddd);
    object->method_slot = (uintptr_t) rf_method_v1;
    object->method_epoch = 0;
    object->method_gate = 0;
    object->method_gate_pad = 0;
    object->method_pending_epoch = 0;

    rf_demo_object_t *expected = NULL;
    if (!__atomic_compare_exchange_n(&g_object, &expected, object, 0,
                                     __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
        free(object);
        object = expected;
    }
    return object;
}

/* 这个函数故意放进 .init_array，验证 so 装载最早阶段的行为。
 * VM 处于冻结状态时这里只初始化私有状态，不调用 JNI，也不创建线程。 */
__attribute__((constructor(101))) static void rf_init_array(void) {
    __atomic_add_fetch(&g_init_calls, 1, __ATOMIC_RELAXED);
    g_init_stage = 1;
    /* 在加载器执行 .init_array 时走一遍 raw SVC 路径。
     * 这些调用不触碰 JNI、不启动线程，并把结果保存在 nativeInfo() 中，
     * 这样可以观察应用最早启动窗口是否已经被覆盖。 */
    struct timespec ts;
    unsigned char random_byte = 0;
    memset(&ts, 0, sizeof(ts));
    g_init_svc_pid = rf_getpid();
    g_init_svc_tid = rf_gettid();
    g_init_svc_clock_rc = rf_clock_gettime(CLOCK_MONOTONIC, &ts);
    g_init_svc_random_rc = rf_getrandom(&random_byte, 1, 0);
    g_init_svc_byte = random_byte;
    rf_demo_object_t *object = rf_object_get();
    if (object) {
        object->read_count = 0;
        object->write_count = 0;
        g_init_stage = 2;
    }
    __android_log_print(ANDROID_LOG_INFO, RF_LOG_TAG,
                        "init_array calls=%" PRIu64 " stage=%" PRIu64
                        " svc(pid=%ld tid=%ld clock=%ld random=%ld byte=%" PRIu64 ")",
                        g_init_calls, g_init_stage, g_init_svc_pid,
                        g_init_svc_tid, g_init_svc_clock_rc,
                        g_init_svc_random_rc, g_init_svc_byte);
}

__attribute__((noinline, visibility("default")))
uint64_t rf_object_step(rf_demo_object_t *object, uint64_t seed) {
    if (!object) return 0;
    __atomic_add_fetch(&g_object_step_calls, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_object_read_accesses, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_object_read_slot_reads, 1, __ATOMIC_RELAXED);
    uint64_t value = object->read_slot;
    uint64_t next = value ^ (object->magic + seed);
    __atomic_add_fetch(&g_object_write_accesses, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_object_write_slot_writes, 1, __ATOMIC_RELAXED);
    object->write_slot = next;
    __atomic_add_fetch(&object->read_count, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&object->write_count, 1, __ATOMIC_RELAXED);
    return next;
}

/* 两个真实的 C 函数地址，用来模拟运行时替换结构体方法。 */
__attribute__((noinline, visibility("default")))
uint64_t rf_method_v1(rf_demo_object_t *object, uint64_t seed) {
    if (!object) return 0;
    __atomic_add_fetch(&g_method_v1_calls, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_object_read_slot_reads, 1, __ATOMIC_RELAXED);
    return object->magic ^ object->read_slot ^ (seed + UINT64_C(0x1111));
}

__attribute__((noinline, visibility("default")))
uint64_t rf_method_v2(rf_demo_object_t *object, uint64_t seed) {
    if (!object) return 0;
    __atomic_add_fetch(&g_method_v2_calls, 1, __ATOMIC_RELAXED);
    return (object->magic + object->write_slot) ^ (seed + UINT64_C(0x2222));
}

#define RF_DEFINE_SOFT_TARGET(N) \
    __attribute__((noinline, used, visibility("default"))) \
    uint64_t rf_soft_target_##N(uint64_t seed) { \
        __atomic_add_fetch(&g_soft_target_calls[N], 1, __ATOMIC_RELAXED); \
        return (seed ^ (UINT64_C(0x534f465400000000) + (uint64_t) (N))) + \
               (uint64_t) (N * 17 + 1); \
    }

RF_DEFINE_SOFT_TARGET(0)
RF_DEFINE_SOFT_TARGET(1)
RF_DEFINE_SOFT_TARGET(2)
RF_DEFINE_SOFT_TARGET(3)
RF_DEFINE_SOFT_TARGET(4)
RF_DEFINE_SOFT_TARGET(5)
RF_DEFINE_SOFT_TARGET(6)
RF_DEFINE_SOFT_TARGET(7)
RF_DEFINE_SOFT_TARGET(8)
RF_DEFINE_SOFT_TARGET(9)
RF_DEFINE_SOFT_TARGET(10)
RF_DEFINE_SOFT_TARGET(11)
RF_DEFINE_SOFT_TARGET(12)
RF_DEFINE_SOFT_TARGET(13)
RF_DEFINE_SOFT_TARGET(14)
RF_DEFINE_SOFT_TARGET(15)
RF_DEFINE_SOFT_TARGET(16)
RF_DEFINE_SOFT_TARGET(17)
RF_DEFINE_SOFT_TARGET(18)
RF_DEFINE_SOFT_TARGET(19)
RF_DEFINE_SOFT_TARGET(20)
RF_DEFINE_SOFT_TARGET(21)
RF_DEFINE_SOFT_TARGET(22)
RF_DEFINE_SOFT_TARGET(23)
RF_DEFINE_SOFT_TARGET(24)
RF_DEFINE_SOFT_TARGET(25)
RF_DEFINE_SOFT_TARGET(26)
RF_DEFINE_SOFT_TARGET(27)
RF_DEFINE_SOFT_TARGET(28)
RF_DEFINE_SOFT_TARGET(29)
RF_DEFINE_SOFT_TARGET(30)
RF_DEFINE_SOFT_TARGET(31)

typedef uint64_t (*rf_soft_target_t)(uint64_t seed);
static rf_soft_target_t const g_soft_target_funcs[RF_UPROBE_LIMIT_TARGETS] = {
    rf_soft_target_0, rf_soft_target_1, rf_soft_target_2, rf_soft_target_3,
    rf_soft_target_4, rf_soft_target_5, rf_soft_target_6, rf_soft_target_7,
    rf_soft_target_8, rf_soft_target_9, rf_soft_target_10, rf_soft_target_11,
    rf_soft_target_12, rf_soft_target_13, rf_soft_target_14, rf_soft_target_15,
    rf_soft_target_16, rf_soft_target_17, rf_soft_target_18, rf_soft_target_19,
    rf_soft_target_20, rf_soft_target_21, rf_soft_target_22, rf_soft_target_23,
    rf_soft_target_24, rf_soft_target_25, rf_soft_target_26, rf_soft_target_27,
    rf_soft_target_28, rf_soft_target_29, rf_soft_target_30, rf_soft_target_31,
};

static uint64_t rf_monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t) ts.tv_sec * UINT64_C(1000000000) + (uint64_t) ts.tv_nsec;
}

/* jnitrace 专用实现：函数不导出 JNI 命名符号，稍后由 RegisterNatives
 * 把它们挂到 JniProbe.probeTick/probeObject 上。 */
static jlong rf_jni_probe_tick(JNIEnv *env, jobject thiz, jlong seed) {
    (void) env;
    (void) thiz;
    __atomic_add_fetch(&g_jni_probe_tick_calls, 1, __ATOMIC_RELAXED);
    return (jlong) rf_agent_hot((long) seed);
}

static jlong rf_jni_probe_object(JNIEnv *env, jobject thiz, jint loops) {
    (void) env;
    (void) thiz;
    if (loops < 1) loops = 1;
    if (loops > 100000) loops = 100000;
    __atomic_add_fetch(&g_jni_probe_object_calls, 1, __ATOMIC_RELAXED);
    return (jlong) rf_object_step(rf_object_get(), (uint64_t) loops);
}

/*
 * HWBP 事件通过 ring 异步送到 JS；如果没有同步措施，事件到达时新函数可能
 * 已经执行很多次。这里用 pending_epoch 做一次握手：写指针前先挂起当前
 * epoch，写完立刻等待；JS 从 slot 读出新地址、安装 Interceptor 后调用
 * nativeMethodHookReady() 放行。观察点没装好或 agent 消失时，500ms 超时
 * 自动清 pending，避免测试进程永久卡死。
 */
static void rf_method_wait_for_hook(rf_demo_object_t *object, uint64_t epoch) {
    if (!__atomic_load_n(&object->method_gate, __ATOMIC_ACQUIRE)) return;
    uint64_t deadline = rf_monotonic_ns() + UINT64_C(500000000);
    while (__atomic_load_n(&object->method_pending_epoch, __ATOMIC_ACQUIRE) == epoch) {
        if (rf_monotonic_ns() >= deadline) {
            __atomic_add_fetch(&g_method_gate_timeouts, 1, __ATOMIC_RELAXED);
            __atomic_compare_exchange_n(&object->method_pending_epoch, &epoch, 0, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
            break;
        }
        sched_yield();
    }
}

__attribute__((noinline, visibility("default")))
uint64_t rf_object_method_call(rf_demo_object_t *object, uint64_t seed) {
    if (!object) return 0;
    __atomic_add_fetch(&g_method_calls, 1, __ATOMIC_RELAXED);
    uintptr_t raw = __atomic_load_n(&object->method_slot, __ATOMIC_ACQUIRE);
    rf_object_method_t method = (rf_object_method_t) raw;
    return method ? method(object, seed) : 0;
}

__attribute__((noinline, visibility("default")))
uint64_t rf_object_method_switch(rf_demo_object_t *object, int variant) {
    if (!object) return 0;
    __atomic_add_fetch(&g_method_switches, 1, __ATOMIC_RELAXED);
    uintptr_t next = (variant & 1) ? (uintptr_t) rf_method_v2 : (uintptr_t) rf_method_v1;
    uint64_t epoch = __atomic_add_fetch(&object->method_epoch, 1, __ATOMIC_ACQ_REL);
    __atomic_add_fetch(&g_method_epoch_writes, 1, __ATOMIC_RELAXED);
    if (__atomic_load_n(&object->method_gate, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&object->method_pending_epoch, epoch, __ATOMIC_RELEASE);
    }
    // 保持一次对齐的 8 字节写入，这就是 `KT>w method_slot_addr 8` 观察的
    // 精确地址；不要改成两个 32 位写，否则会产生半指针状态。
    __atomic_add_fetch(&g_method_slot_writes, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&object->method_slot, next, __ATOMIC_RELEASE);
    rf_method_wait_for_hook(object, epoch);
    return rf_object_method_call(object, epoch);
}

__attribute__((noinline, visibility("default")))
long rf_hwbp_hot(void) {
    __atomic_add_fetch(&g_hwbp_calls, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_hwbp_read_accesses, 1, __ATOMIC_RELAXED);
    uint64_t value = g_hwbp_counter;
    __atomic_add_fetch(&g_hwbp_write_accesses, 1, __ATOMIC_RELAXED);
    g_hwbp_sink = value ^ UINT64_C(0x5a5a5a5a);
    g_hwbp_counter = value + 1;
    return (long) value;
}

__attribute__((noinline, visibility("default")))
long rf_uprobe_hot(long seed) {
    __atomic_add_fetch(&g_uprobe_calls, 1, __ATOMIC_RELAXED);
    long value = (long) g_uprobe_counter;
    value += seed + 1;
    g_uprobe_counter = (uint64_t) value;
    return value;
}

__attribute__((noinline, visibility("default")))
long rf_agent_hot(long seed) {
    __atomic_add_fetch(&g_agent_calls, 1, __ATOMIC_RELAXED);
    long value = (long) g_agent_counter;
    value = (value ^ (seed + 0x13579bL)) + 1;
    g_agent_counter = (uint64_t) value;
    return value;
}

static int rf_read_tracer_pid(void) {
    char data[4096];
    long fd = rf_openat(-100, "/proc/self/status", O_RDONLY, 0);
    if (fd < 0) return -1;
    long size = rf_read((int) fd, data, sizeof(data) - 1);
    rf_close((int) fd);
    if (size <= 0) return -1;
    data[size] = 0;
    const char *line = strstr(data, "TracerPid:");
    if (!line) return -1;
    return (int) strtol(line + strlen("TracerPid:"), NULL, 10);
}

static int rf_maps_suspicious(void) {
    char data[8192];
    long fd = rf_openat(-100, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) return -1;
    long size = rf_read((int) fd, data, sizeof(data) - 1);
    rf_close((int) fd);
    if (size <= 0) return -1;
    data[size] = 0;
    for (long i = 0; i < size; i++) {
        if ((i + 5 <= size && strncasecmp(data + i, "frida", 5) == 0) ||
            (i + 7 <= size && strncasecmp(data + i, "gum-js", 6) == 0) ||
            (i + 6 <= size && strncasecmp(data + i, "xposed", 6) == 0)) {
            return 1;
        }
    }
    return 0;
}

static long rf_read_path(const char *path, char *buffer, size_t capacity) {
    if (!buffer || capacity < 2) return -1;
    long fd = rf_openat(-100, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return fd;
    size_t total = 0;
    while (total < capacity - 1) {
        size_t requested = capacity - 1 - total;
        long n = rf_read((int) fd, buffer + total, requested);
        if (n <= 0) break;
        total += (size_t) n;
        /* procfs 经常按页短读；短读不代表 EOF，要继续读到 0。 */
    }
    rf_close((int) fd);
    if (total == 0) return -1;
    buffer[total] = '\0';
    return (long) total;
}

static void *rf_kpm_probe_thread(void *opaque) {
    rf_kpm_thread_result_t *result = (rf_kpm_thread_result_t *) opaque;
    char buffer[96];
    memset(buffer, 0, sizeof(buffer));
    result->tid = rf_gettid();
    result->open_rc = rf_openat(-100, RF_KPM_MARKER, O_RDONLY | O_CLOEXEC, 0);
    result->read_rc = -1;
    if (result->open_rc >= 0) {
        result->read_rc = rf_read((int) result->open_rc, buffer, sizeof(buffer) - 1);
        rf_close((int) result->open_rc);
    }
    return NULL;
}

static unsigned long long rf_maps_target_inode(const char *maps) {
    const char *line = maps;
    while (line && *line) {
        const char *end = strchr(line, '\n');
        size_t length = end ? (size_t) (end - line) : strlen(line);
        if (length > 0 && length < 1024) {
            char copy[1024];
            unsigned long long start = 0, finish = 0, offset = 0, inode = 0;
            unsigned int dev_major = 0, dev_minor = 0;
            char perms[8];
            memcpy(copy, line, length);
            copy[length] = '\0';
            if ((strstr(copy, "rfcompat-mkpm-map") != NULL ||
                 strstr(copy, "libcompatdemo.so") != NULL) &&
                sscanf(copy, "%llx-%llx %7s %llx %x:%x %llu",
                       &start, &finish, perms, &offset,
                       &dev_major, &dev_minor, &inode) == 7) {
                return inode;
            }
        }
        if (!end) break;
        line = end + 1;
    }
    return 0;
}

static uintptr_t rf_module_base(void *address, const char **path_out) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr(address, &info) == 0 || !info.dli_fbase) {
        if (path_out) *path_out = "";
        return 0;
    }
    if (path_out) *path_out = info.dli_fname ? info.dli_fname : "";
    return (uintptr_t) info.dli_fbase;
}

static jstring rf_json(JNIEnv *env, const char *format, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    return (*env)->NewStringUTF(env, buffer);
}

JNIEXPORT jstring JNICALL
Java_com_rustfrida_compatdemo_Native_nativeInfo(JNIEnv *env, jclass clazz) {
    (void) clazz;
    const char *path = "";
    uintptr_t base = rf_module_base((void *) rf_object_step, &path);
    rf_demo_object_t *object = rf_object_get();
    uintptr_t step = (uintptr_t) rf_object_step;
    uintptr_t up = (uintptr_t) rf_uprobe_hot;
    uintptr_t agent = (uintptr_t) rf_agent_hot;
    uintptr_t hwbp = (uintptr_t) rf_hwbp_hot;
    return rf_json(env,
                   "{\"library\":\"%s\",\"base\":\"0x%" PRIxPTR "\","
                   "\"object_addr\":\"0x%" PRIxPTR "\",\"object_size\":%zu,"
                   "\"step_offset\":\"0x%" PRIxPTR "\","
                   "\"uprobe_offset\":\"0x%" PRIxPTR "\","
                   "\"agent_offset\":\"0x%" PRIxPTR "\","
                   "\"hwbp_offset\":\"0x%" PRIxPTR "\","
                   "\"read_offset\":\"0x%zx\",\"write_offset\":\"0x%zx\","
                   "\"read_addr\":\"0x%" PRIxPTR "\"," 
                   "\"write_addr\":\"0x%" PRIxPTR "\"," 
                   "\"method_slot_addr\":\"0x%" PRIxPTR "\"," 
                   "\"method_v1_addr\":\"0x%" PRIxPTR "\"," 
                   "\"method_v2_addr\":\"0x%" PRIxPTR "\"," 
                   "\"method_epoch_addr\":\"0x%" PRIxPTR "\"," 
                   "\"init_calls\":%" PRIu64 ",\"init_stage\":%" PRIu64 ","
                   "\"init_svc_pid\":%ld,\"init_svc_tid\":%ld,"
                   "\"init_svc_clock_rc\":%ld,\"init_svc_random_rc\":%ld,"
                   "\"init_svc_byte\":%" PRIu64 "}",
                   path, base, (uintptr_t) object, sizeof(*object),
                   base ? step - base : 0, base ? up - base : 0,
                   base ? agent - base : 0, base ? hwbp - base : 0,
                   offsetof(rf_demo_object_t, read_slot),
                   offsetof(rf_demo_object_t, write_slot),
                   (uintptr_t) &object->read_slot,
                   (uintptr_t) &object->write_slot,
                   (uintptr_t) &object->method_slot,
                   (uintptr_t) rf_method_v1,
                   (uintptr_t) rf_method_v2,
                   (uintptr_t) &object->method_epoch,
                   g_init_calls, g_init_stage, g_init_svc_pid, g_init_svc_tid,
                   g_init_svc_clock_rc, g_init_svc_random_rc, g_init_svc_byte);
}

/*
 * 返回“触发端”快照。每个字段都是原子读取，避免多个 worker 同时更新时
 * 出现撕裂；脚本把它与 trace/Interceptor 的接收计数做差，缺口会直接显示。
 */
JNIEXPORT jstring JNICALL
Java_com_rustfrida_compatdemo_Native_nativeCounters(JNIEnv *env, jclass clazz) {
    (void) clazz;
    return rf_json(env,
                   "{\"svc_raw\":%" PRIu64 ",\"object_step\":%" PRIu64 ","
                   "\"object_reads\":%" PRIu64 ",\"object_writes\":%" PRIu64 ","
                   "\"read_slot_reads\":%" PRIu64 ",\"write_slot_writes\":%" PRIu64 ","
                   "\"method_slot_writes\":%" PRIu64 ",\"method_epoch_writes\":%" PRIu64 ","
                   "\"uprobe_hot\":%" PRIu64 ",\"hwbp_hot\":%" PRIu64 ","
                   "\"hwbp_reads\":%" PRIu64 ",\"hwbp_writes\":%" PRIu64 ","
                   "\"agent_hot\":%" PRIu64 ",\"native_agent_tick\":%" PRIu64 ","
                   "\"native_object_exercise\":%" PRIu64 ","
                   "\"native_method_exercise\":%" PRIu64 ","
                   "\"native_method_switch\":%" PRIu64 ","
                   "\"method_calls\":%" PRIu64 ",\"method_switches\":%" PRIu64 ","
                   "\"method_v1\":%" PRIu64 ",\"method_v2\":%" PRIu64 ","
                   "\"method_gate_timeouts\":%" PRIu64 ","
                   "\"method_hook_ready\":%" PRIu64 ","
                   "\"soft_target_00\":%" PRIu64 ",\"soft_target_01\":%" PRIu64 ","
                   "\"soft_target_02\":%" PRIu64 ",\"soft_target_03\":%" PRIu64 ","
                   "\"soft_target_04\":%" PRIu64 ",\"soft_target_05\":%" PRIu64 ","
                   "\"soft_target_06\":%" PRIu64 ",\"soft_target_07\":%" PRIu64 ","
                   "\"soft_target_08\":%" PRIu64 ",\"soft_target_09\":%" PRIu64 ","
                   "\"soft_target_10\":%" PRIu64 ",\"soft_target_11\":%" PRIu64 ","
                   "\"soft_target_12\":%" PRIu64 ",\"soft_target_13\":%" PRIu64 ","
                   "\"soft_target_14\":%" PRIu64 ",\"soft_target_15\":%" PRIu64 ","
                   "\"soft_target_16\":%" PRIu64 ",\"soft_target_17\":%" PRIu64 ","
                   "\"soft_target_18\":%" PRIu64 ",\"soft_target_19\":%" PRIu64 ","
                   "\"soft_target_20\":%" PRIu64 ",\"soft_target_21\":%" PRIu64 ","
                   "\"soft_target_22\":%" PRIu64 ",\"soft_target_23\":%" PRIu64 ","
                   "\"soft_target_24\":%" PRIu64 ",\"soft_target_25\":%" PRIu64 ","
                   "\"soft_target_26\":%" PRIu64 ",\"soft_target_27\":%" PRIu64 ","
                   "\"soft_target_28\":%" PRIu64 ",\"soft_target_29\":%" PRIu64 ","
                   "\"soft_target_30\":%" PRIu64 ",\"soft_target_31\":%" PRIu64 ","
                   "\"jni_register_attempts\":%" PRIu64 ","
                   "\"jni_register_successes\":%" PRIu64 ","
                   "\"jni_probe_tick\":%" PRIu64 ",\"jni_probe_object\":%" PRIu64 ","
                   "\"java_oncreate\":%" PRIu64 ",\"dex_load\":%" PRIu64 ","
                   "\"dex_payload\":%" PRIu64 "}",
                   rf_svc_total(), rf_count_load(&g_object_step_calls),
                   rf_count_load(&g_object_read_accesses), rf_count_load(&g_object_write_accesses),
                   rf_count_load(&g_object_read_slot_reads), rf_count_load(&g_object_write_slot_writes),
                   rf_count_load(&g_method_slot_writes), rf_count_load(&g_method_epoch_writes),
                   rf_count_load(&g_uprobe_calls), rf_count_load(&g_hwbp_calls),
                   rf_count_load(&g_hwbp_read_accesses), rf_count_load(&g_hwbp_write_accesses),
                   rf_count_load(&g_agent_calls), rf_count_load(&g_native_agent_tick_calls),
                   rf_count_load(&g_native_object_exercise_calls),
                   rf_count_load(&g_native_method_exercise_calls),
                   rf_count_load(&g_native_method_switch_calls), rf_count_load(&g_method_calls),
                   rf_count_load(&g_method_switches), rf_count_load(&g_method_v1_calls),
                   rf_count_load(&g_method_v2_calls), rf_count_load(&g_method_gate_timeouts),
                   rf_count_load(&g_method_hook_ready_calls),
                   rf_count_load(&g_soft_target_calls[0]), rf_count_load(&g_soft_target_calls[1]),
                   rf_count_load(&g_soft_target_calls[2]), rf_count_load(&g_soft_target_calls[3]),
                   rf_count_load(&g_soft_target_calls[4]), rf_count_load(&g_soft_target_calls[5]),
                   rf_count_load(&g_soft_target_calls[6]), rf_count_load(&g_soft_target_calls[7]),
                   rf_count_load(&g_soft_target_calls[8]), rf_count_load(&g_soft_target_calls[9]),
                   rf_count_load(&g_soft_target_calls[10]), rf_count_load(&g_soft_target_calls[11]),
                   rf_count_load(&g_soft_target_calls[12]), rf_count_load(&g_soft_target_calls[13]),
                   rf_count_load(&g_soft_target_calls[14]), rf_count_load(&g_soft_target_calls[15]),
                   rf_count_load(&g_soft_target_calls[16]), rf_count_load(&g_soft_target_calls[17]),
                   rf_count_load(&g_soft_target_calls[18]), rf_count_load(&g_soft_target_calls[19]),
                   rf_count_load(&g_soft_target_calls[20]), rf_count_load(&g_soft_target_calls[21]),
                   rf_count_load(&g_soft_target_calls[22]), rf_count_load(&g_soft_target_calls[23]),
                   rf_count_load(&g_soft_target_calls[24]), rf_count_load(&g_soft_target_calls[25]),
                   rf_count_load(&g_soft_target_calls[26]), rf_count_load(&g_soft_target_calls[27]),
                   rf_count_load(&g_soft_target_calls[28]), rf_count_load(&g_soft_target_calls[29]),
                   rf_count_load(&g_soft_target_calls[30]), rf_count_load(&g_soft_target_calls[31]),
                   rf_count_load(&g_jni_register_attempts), rf_count_load(&g_jni_register_successes),
                   rf_count_load(&g_jni_probe_tick_calls), rf_count_load(&g_jni_probe_object_calls),
                   rf_count_load(&g_java_oncreate_calls), rf_count_load(&g_dex_load_calls),
                   rf_count_load(&g_dex_payload_calls));
}

/* Java/Dex 源端标记不经过 trace 事件，单独记账，避免把 observer 自身当成结果。 */
JNIEXPORT void JNICALL
Java_com_rustfrida_compatdemo_Native_nativeSourceMark(JNIEnv *env, jclass clazz, jint kind) {
    (void) env;
    (void) clazz;
    switch (kind) {
        case 1: __atomic_add_fetch(&g_java_oncreate_calls, 1, __ATOMIC_RELAXED); break;
        case 2: __atomic_add_fetch(&g_dex_load_calls, 1, __ATOMIC_RELAXED); break;
        case 3: __atomic_add_fetch(&g_dex_payload_calls, 1, __ATOMIC_RELAXED); break;
        default: break;
    }
}

JNIEXPORT jboolean JNICALL
Java_com_rustfrida_compatdemo_Native_nativeExtremeEnabled(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    char value[PROP_VALUE_MAX] = {0};
    int length = __system_property_get("debug.rustfrida.compat.extreme", value);
    return length > 0 &&
           (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 ||
            strcasecmp(value, "yes") == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_rustfrida_compatdemo_Native_nativeLowFrequencyEnabled(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    char value[PROP_VALUE_MAX] = {0};
    int length = __system_property_get("debug.rustfrida.compat.low_freq", value);
    /* 未设置时沿用低频默认值，避免手工启动 demo 意外进入高频档。 */
    if (length <= 0 || value[0] == '\0') return JNI_TRUE;
    return (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 ||
            strcasecmp(value, "yes") == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_rustfrida_compatdemo_Native_nativeDemoMode(JNIEnv *env, jclass clazz) {
    (void) clazz;
    char value[PROP_VALUE_MAX] = {0};
    int length = __system_property_get("debug.rustfrida.compat.mode", value);
    if (length <= 0 || value[0] == '\0') return (*env)->NewStringUTF(env, "all");
    return (*env)->NewStringUTF(env, value);
}

JNIEXPORT jstring JNICALL
Java_com_rustfrida_compatdemo_Native_nativeCrcPhase(JNIEnv *env, jclass clazz) {
    (void) clazz;
    char value[PROP_VALUE_MAX] = {0};
    int length = __system_property_get("debug.rustfrida.compat.crc_phase", value);
    if (length <= 0 || value[0] == '\0') return (*env)->NewStringUTF(env, "all");
    return (*env)->NewStringUTF(env, value);
}

JNIEXPORT jboolean JNICALL
Java_com_rustfrida_compatdemo_Native_nativeRegisterJniProbe(JNIEnv *env, jclass clazz) {
    (void) clazz;
    __atomic_add_fetch(&g_jni_register_attempts, 1, __ATOMIC_RELAXED);
    if (__atomic_load_n(&g_jni_probe_registered, __ATOMIC_ACQUIRE)) return JNI_TRUE;
    __android_log_print(ANDROID_LOG_INFO, RF_LOG_TAG,
                        "RegisterNatives: env=%p fn=%p tid=%ld", (void *) env,
                        (void *) (*env)->RegisterNatives, rf_gettid());
    jclass probe = (*env)->FindClass(env, "com/rustfrida/compatdemo/JniProbe");
    if (probe == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, RF_LOG_TAG,
                            "RegisterNatives: JniProbe class not found");
        return JNI_FALSE;
    }
    JNINativeMethod methods[] = {
        {"probeTick", "(J)J", (void *) rf_jni_probe_tick},
        {"probeObject", "(I)J", (void *) rf_jni_probe_object},
    };
    if ((*env)->RegisterNatives(env, probe, methods,
                                (jint) (sizeof(methods) / sizeof(methods[0]))) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, RF_LOG_TAG,
                            "RegisterNatives: JniProbe registration failed");
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, probe);
        return JNI_FALSE;
    }
    __atomic_store_n(&g_jni_probe_registered, 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&g_jni_register_successes, 1, __ATOMIC_RELAXED);
    __android_log_print(ANDROID_LOG_INFO, RF_LOG_TAG,
                        "RegisterNatives: JniProbe methods registered");
    (*env)->DeleteLocalRef(env, probe);
    return JNI_TRUE;
}

JNIEXPORT jstring JNICALL
Java_com_rustfrida_compatdemo_Native_nativeJniRegisterNativesAddress(JNIEnv *env, jclass clazz) {
    (void) clazz;
    char value[64];
    snprintf(value, sizeof(value), "0x%" PRIxPTR,
             (uintptr_t) (*env)->RegisterNatives);
    return (*env)->NewStringUTF(env, value);
}

JNIEXPORT jboolean JNICALL
Java_com_rustfrida_compatdemo_Native_nativeJniProbeRegistered(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    return __atomic_load_n(&g_jni_probe_registered, __ATOMIC_ACQUIRE) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_rustfrida_compatdemo_Native_nativeJniProbeInfo(JNIEnv *env, jclass clazz) {
    (void) clazz;
    return rf_json(env,
                   "{\"registered\":%d,\"probeTick\":\"0x%" PRIxPTR "\","
                   "\"probeObject\":\"0x%" PRIxPTR "\"}",
                   __atomic_load_n(&g_jni_probe_registered, __ATOMIC_ACQUIRE),
                   (uintptr_t) rf_jni_probe_tick, (uintptr_t) rf_jni_probe_object);
}

JNIEXPORT jstring JNICALL
Java_com_rustfrida_compatdemo_Native_nativeCheck(JNIEnv *env, jclass clazz) {
    (void) clazz;
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    long clock_rc = rf_clock_gettime(CLOCK_MONOTONIC, &ts);
    return rf_json(env,
                   "{\"pid\":%ld,\"tid\":%ld,\"tracer_pid\":%d,"
                   "\"maps_suspicious\":%d,\"clock_rc\":%ld,"
                   "\"clock_ns\":%lld}",
                   rf_getpid(), rf_gettid(), rf_read_tracer_pid(),
                   rf_maps_suspicious(), clock_rc,
                   (long long) ts.tv_sec * 1000000000LL + ts.tv_nsec);
}

/*
 * mkpm 的自包含探针。所有触发动作都在
 * compatdemo 内完成，kpctl 只负责切换内核侧模块：
 *
 *   openat(marker)       -> redirect 精确路径替换的命中点
 *   /proc/self/version    -> syscall/hide 的普通文件读
 *   write(-1, NULL, 1)    -> 错误返回路径（不会写入真实文件）
 *   socket/connect/send/recv -> syscall 事件覆盖
 *   mmap/munmap           -> 内存映射与生命周期
 *   pthread                -> 线程过滤和清理观察
 *
 * 每个返回值都保留 raw SVC 的原始结果（成功为非负，失败为负 errno），方便
 * 对照 `kpctl syscall read` 输出。marker 不存在时 open_marker 通常是 -ENOENT；
 * redirect 开启并准备目标文件后，它会变成可读的 fd。 */
JNIEXPORT jstring JNICALL
Java_com_rustfrida_compatdemo_Native_nativeKpmProbe(JNIEnv *env, jclass clazz) {
    (void) clazz;
    char version[160];
    /* 注入 RustFrida 后 maps 可能超过 64 KiB；使用堆缓冲，避免截断目标行。 */
    char *maps = (char *) calloc(1, RF_KPM_MAPS_CAP);
    memset(version, 0, sizeof(version));
    if (!maps)
        return rf_json(env, "{\"error\":\"maps_alloc_failed\"}");

    long marker_fd = rf_openat(-100, RF_KPM_MARKER, O_RDONLY | O_CLOEXEC, 0);
    long marker_read = -1;
    char marker_data[96];
    memset(marker_data, 0, sizeof(marker_data));
    if (marker_fd >= 0) {
        marker_read = rf_read((int) marker_fd, marker_data, sizeof(marker_data) - 1);
        rf_close((int) marker_fd);
    }

    long version_open = rf_openat(-100, "/proc/self/version", O_RDONLY | O_CLOEXEC, 0);
    long version_read = -1;
    if (version_open >= 0) {
        version_read = rf_read((int) version_open, version, sizeof(version) - 1);
        rf_close((int) version_open);
    }

    /* readlink 对照：KPM 规则只对目标 UID 返回 ENOENT，root shell 读取同一
     * 个应用私有 symlink 仍能拿到原始目标，借此验证 UID 隔离。 */
    char readlink_target[256];
    memset(readlink_target, 0, sizeof(readlink_target));
    long readlink_rc = rf_readlinkat(-100, RF_KPM_READLINK_PATH,
                                     readlink_target, sizeof(readlink_target) - 1);
    if (readlink_rc >= 0 && readlink_rc < (long) sizeof(readlink_target))
        readlink_target[readlink_rc] = 0;

    struct timespec boot_time;
    memset(&boot_time, 0, sizeof(boot_time));
    long boot_time_rc = rf_clock_gettime(CLOCK_BOOTTIME, &boot_time);
    long long boot_time_ns = (long long) boot_time.tv_sec * 1000000000LL + boot_time.tv_nsec;

    /* fd 负值让内核在检查用户指针前直接返回 EBADF，适合稳定压测错误路径。 */
    long invalid_write = rf_write(-1, NULL, 1);

    long socket_fd = rf_socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    long connect_rc = -1;
    long send_rc = -1;
    long recv_rc = -1;
    if (socket_fd >= 0) {
        struct sockaddr_un address;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        const char *socket_path = "/data/local/tmp/rfcompat-mkpm-sock";
        strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);
        size_t address_len = offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1;
        connect_rc = rf_connect((int) socket_fd, &address, address_len);
        const char payload[] = "rfcompat-mkpm";
        send_rc = rf_sendto((int) socket_fd, payload, sizeof(payload) - 1,
                            MSG_DONTWAIT, &address, address_len);
        char recv_buf[32];
        memset(recv_buf, 0, sizeof(recv_buf));
        recv_rc = rf_recvfrom((int) socket_fd, recv_buf, sizeof(recv_buf),
                              MSG_DONTWAIT, NULL, NULL);
        rf_close((int) socket_fd);
    }

    long map_fd = rf_openat(-100, RF_KPM_MAP_PATH, O_RDONLY | O_CLOEXEC, 0);
    long map_rc = -1;
    long unmap_rc = -1;
    if (map_fd >= 0) {
        /* 文件映射会在 /proc/self/maps 留下稳定的测试路径，供 emaps addino
         * 将 inode 改成 1；文件由运行脚本以 root 创建，App 只读。 */
        map_rc = rf_mmap(NULL, 4096, 1, 2, (int) map_fd, 0);
        rf_close((int) map_fd);
    }
    if (map_rc > 0) {
        volatile unsigned char *mapped = (volatile unsigned char *) (uintptr_t) map_rc;
        volatile unsigned char first = mapped[0];
        (void) first;
    }

    /* 必须在映射仍然存在时读取 maps；否则 emaps addino 没有目标行可改。 */
    long maps_read = rf_read_path("/proc/self/maps", maps, RF_KPM_MAPS_CAP);
    int maps_has_demo = 0;
    int maps_has_frida = 0;
    unsigned long long maps_demo_inode = 0;
    if (maps_read > 0) {
        maps_has_demo = strstr(maps, "libcompatdemo.so") != NULL;
        maps_has_frida = strcasestr(maps, "frida") != NULL ||
                         strcasestr(maps, "gum-js") != NULL;
        maps_demo_inode = rf_maps_target_inode(maps);
    }

    /* 对照完成后再释放映射，避免测试文件和 VMA 泄漏到下一轮。 */
    if (map_rc > 0)
        unmap_rc = rf_munmap((void *) (uintptr_t) map_rc, 4096);

    rf_kpm_thread_result_t thread_result;
    memset(&thread_result, 0, sizeof(thread_result));
    pthread_t thread;
    int thread_rc = pthread_create(&thread, NULL, rf_kpm_probe_thread, &thread_result);
    if (thread_rc == 0) pthread_join(thread, NULL);

    jstring result = rf_json(env,
                   "{\"pid\":%ld,\"tid\":%ld,\"marker\":\"%s\","
                   "\"open_marker\":%ld,\"read_marker\":%ld,"
                   "\"open_version\":%ld,\"read_version\":%ld,"
                   "\"readlink_path\":\"%s\",\"readlink_rc\":%ld,\"readlink_target\":\"%s\","
                   "\"boot_time_rc\":%ld,\"boot_time_ns\":%lld,"
                   "\"invalid_write\":%ld,\"socket\":%ld,\"connect\":%ld,"
                   "\"sendto\":%ld,\"recvfrom\":%ld,\"mmap\":%ld,"
                   "\"munmap\":%ld,\"maps_read\":%ld,"
                   "\"map_path\":\"%s\",\"maps_has_demo\":%d,\"maps_target_inode\":%llu,"
                   "\"maps_has_frida\":%d,"
                   "\"thread_create\":%d,\"thread_tid\":%ld,"
                   "\"thread_open_marker\":%ld,\"thread_read_marker\":%ld}",
                   rf_getpid(), rf_gettid(), RF_KPM_MARKER,
                   marker_fd, marker_read, version_open, version_read,
                   RF_KPM_READLINK_PATH, readlink_rc, readlink_target,
                   boot_time_rc, boot_time_ns,
                   invalid_write, socket_fd, connect_rc, send_rc, recv_rc,
                   map_rc, unmap_rc, maps_read, RF_KPM_MAP_PATH, maps_has_demo, maps_demo_inode,
                   maps_has_frida,
                   thread_rc, thread_result.tid, thread_result.open_rc,
                   thread_result.read_rc);
    free(maps);
    return result;
}

JNIEXPORT jlong JNICALL
Java_com_rustfrida_compatdemo_Native_nativeSvcBurst(JNIEnv *env, jclass clazz, jint loops) {
    (void) env;
    (void) clazz;
    if (loops < 1) loops = 1;
    if (loops > 100000) loops = 100000;
    unsigned char random_bytes[8];
    char buffer[32];
    struct timespec ts;
    long checksum = 0;
    for (jint i = 0; i < loops; i++) {
        memset(random_bytes, 0, sizeof(random_bytes));
        memset(&ts, 0, sizeof(ts));
        long pid = rf_getpid();
        long tid = rf_gettid();
        long clock_rc = rf_clock_gettime(CLOCK_MONOTONIC, &ts);
        long fd = rf_openat(-100, "/proc/self/stat", O_RDONLY, 0);
        long n = fd >= 0 ? rf_read((int) fd, buffer, sizeof(buffer)) : -1;
        if (fd >= 0) rf_close((int) fd);
        long random_rc = rf_getrandom(random_bytes, sizeof(random_bytes), 0);
        checksum ^= pid ^ tid ^ clock_rc ^ fd ^ n ^ random_rc ^ random_bytes[0];
    }
    return (jlong) checksum;
}

JNIEXPORT jlong JNICALL
Java_com_rustfrida_compatdemo_Native_nativeUprobeBurst(JNIEnv *env, jclass clazz, jint loops) {
    (void) env;
    (void) clazz;
    if (loops < 1) loops = 1;
    if (loops > 1000000) loops = 1000000;
    long value = 0;
    for (jint i = 0; i < loops; i++) value = rf_uprobe_hot(i);
    return (jlong) value;
}

/* 软件断点矩阵：一次循环依次执行多个不同函数，给每个 KT>brk 目标提供
 * 独立的源端计数。这样可以验证多个 uprobe 同时挂载，而不是把同一函数重复
 * attach 后误认为多个目标都在工作。 */
JNIEXPORT jlong JNICALL
Java_com_rustfrida_compatdemo_Native_nativeUprobeMatrixBurst(JNIEnv *env, jclass clazz, jint loops) {
    (void) env;
    (void) clazz;
    if (loops < 1) loops = 1;
    if (loops > 100000) loops = 100000;
    rf_demo_object_t *object = rf_object_get();
    long value = 0;
    for (jint i = 0; i < loops; i++) {
        value ^= rf_uprobe_hot(i);
        value ^= rf_hwbp_hot();
        value ^= rf_agent_hot(i);
        value ^= (long) rf_object_step(object, (uint64_t) i);
        value ^= (long) rf_method_v1(object, (uint64_t) i);
        value ^= (long) rf_method_v2(object, (uint64_t) i);
    }
    return (jlong) value;
}

/* 软件断点上限实验：默认轮询全部 32 个独立入口。运行器可通过
 * debug.rustfrida.compat.uprobe_targets 选择前 N 个，便于做 4/8/16/32
 * 阶梯测试；N 超出编译进来的目标数时会被安全截断。 */
static int rf_uprobe_target_count(void);

JNIEXPORT jint JNICALL
Java_com_rustfrida_compatdemo_Native_nativeUprobeTargetCount(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    return (jint) rf_uprobe_target_count();
}

static int rf_uprobe_target_count(void) {
    char value[PROP_VALUE_MAX] = {0};
    int length = __system_property_get("debug.rustfrida.compat.uprobe_targets", value);
    if (length <= 0 || value[0] == '\0') return RF_UPROBE_LIMIT_TARGETS;
    long requested = strtol(value, NULL, 10);
    if (requested < 1) requested = 1;
    if (requested > RF_UPROBE_LIMIT_TARGETS) requested = RF_UPROBE_LIMIT_TARGETS;
    return (int) requested;
}

JNIEXPORT jstring JNICALL
Java_com_rustfrida_compatdemo_Native_nativeUprobeMatrixInfo(JNIEnv *env, jclass clazz) {
    (void) clazz;
    char buffer[4096];
    size_t used = 0;
    int written = snprintf(buffer, sizeof(buffer), "{\"count\":%d,\"targets\":[",
                           RF_UPROBE_LIMIT_TARGETS);
    if (written < 0) return (*env)->NewStringUTF(env, "{\"count\":0,\"targets\":[]}");
    used = (size_t) written < sizeof(buffer) ? (size_t) written : sizeof(buffer) - 1;
    for (int i = 0; i < RF_UPROBE_LIMIT_TARGETS && used + 96 < sizeof(buffer); i++) {
        written = snprintf(buffer + used, sizeof(buffer) - used,
                           "%s{\"id\":\"rf_soft_target_%02d\",\"addr\":\"0x%" PRIxPTR
                           "\",\"counter\":\"soft_target_%02d\"}",
                           i == 0 ? "" : ",", i, (uintptr_t) g_soft_target_funcs[i], i);
        if (written < 0) break;
        if ((size_t) written >= sizeof(buffer) - used) {
            used = sizeof(buffer) - 1;
            break;
        }
        used += (size_t) written;
    }
    if (used + 3 < sizeof(buffer)) {
        memcpy(buffer + used, "]}", 3);
        used += 2;
        buffer[used] = '\0';
    } else {
        buffer[sizeof(buffer) - 3] = ']';
        buffer[sizeof(buffer) - 2] = '}';
        buffer[sizeof(buffer) - 1] = '\0';
    }
    return (*env)->NewStringUTF(env, buffer);
}

JNIEXPORT jlong JNICALL
Java_com_rustfrida_compatdemo_Native_nativeUprobeLimitBurst(JNIEnv *env, jclass clazz, jint loops) {
    (void) env;
    (void) clazz;
    if (loops < 1) loops = 1;
    if (loops > 100000) loops = 100000;
    int target_count = rf_uprobe_target_count();
    long value = 0;
    for (jint i = 0; i < loops; i++) {
        int index = (int) ((unsigned int) i % (unsigned int) target_count);
        value ^= (long) g_soft_target_funcs[index]((uint64_t) i);
    }
    return (jlong) value;
}

JNIEXPORT jlong JNICALL
Java_com_rustfrida_compatdemo_Native_nativeHwbpBurst(JNIEnv *env, jclass clazz, jint loops) {
    (void) env;
    (void) clazz;
    if (loops < 1) loops = 1;
    if (loops > 1000000) loops = 1000000;
    long value = 0;
    for (jint i = 0; i < loops; i++) value = rf_hwbp_hot();
    return (jlong) value;
}

JNIEXPORT jlong JNICALL
Java_com_rustfrida_compatdemo_Native_nativeAgentTick(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    __atomic_add_fetch(&g_native_agent_tick_calls, 1, __ATOMIC_RELAXED);
    return (jlong) rf_agent_hot(1);
}

JNIEXPORT jlong JNICALL
Java_com_rustfrida_compatdemo_Native_nativeObjectExercise(JNIEnv *env, jclass clazz, jint loops) {
    (void) env;
    (void) clazz;
    __atomic_add_fetch(&g_native_object_exercise_calls, 1, __ATOMIC_RELAXED);
    if (loops < 1) loops = 1;
    if (loops > 1000000) loops = 1000000;
    rf_demo_object_t *object = rf_object_get();
    uint64_t value = 0;
    for (jint i = 0; i < loops; i++) value = rf_object_step(object, (uint64_t) i);
    return (jlong) value;
}

JNIEXPORT jlong JNICALL
Java_com_rustfrida_compatdemo_Native_nativeMethodExercise(JNIEnv *env, jclass clazz, jint loops) {
    (void) env;
    (void) clazz;
    __atomic_add_fetch(&g_native_method_exercise_calls, 1, __ATOMIC_RELAXED);
    if (loops < 1) loops = 1;
    if (loops > 1000000) loops = 1000000;
    rf_demo_object_t *object = rf_object_get();
    uint64_t value = 0;
    for (jint i = 0; i < loops; i++) value = rf_object_method_call(object, (uint64_t) i);
    return (jlong) value;
}

/* 切换结构体函数指针；开启 gate 后，返回前会等待 JS 完成动态 hook。 */
JNIEXPORT jlong JNICALL
Java_com_rustfrida_compatdemo_Native_nativeMethodSwitch(JNIEnv *env, jclass clazz, jint variant) {
    (void) env;
    (void) clazz;
    __atomic_add_fetch(&g_native_method_switch_calls, 1, __ATOMIC_RELAXED);
    return (jlong) rf_object_method_switch(rf_object_get(), variant);
}

/* 开关无丢失握手。实验脚本在下发 method_slot HWBP 后立即打开它。 */
JNIEXPORT void JNICALL
Java_com_rustfrida_compatdemo_Native_nativeMethodGate(JNIEnv *env, jclass clazz, jboolean enabled) {
    (void) env;
    (void) clazz;
    rf_demo_object_t *object = rf_object_get();
    if (object) __atomic_store_n(&object->method_gate, enabled ? 1U : 0U, __ATOMIC_RELEASE);
}

/* JS 已经完成新方法的 Interceptor 安装，释放正在等待的 writer。 */
JNIEXPORT void JNICALL
Java_com_rustfrida_compatdemo_Native_nativeMethodHookReady(JNIEnv *env, jclass clazz) {
    (void) env;
    (void) clazz;
    __atomic_add_fetch(&g_method_hook_ready_calls, 1, __ATOMIC_RELAXED);
    rf_demo_object_t *object = rf_object_get();
    if (object) __atomic_store_n(&object->method_pending_epoch, 0, __ATOMIC_RELEASE);
}
