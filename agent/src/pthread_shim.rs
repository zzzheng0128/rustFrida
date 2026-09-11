use crate::pthread_tls::{ThreadToken, TlsValueStore};
use libc::{
    c_int, c_long, c_void, clockid_t, mmap, pthread_key_t, pthread_t, timespec, SYS_clock_gettime, SYS_clone, SYS_exit,
    SYS_nanosleep, CLOCK_REALTIME, CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD, CLONE_VM,
    MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE,
};
use std::arch::asm;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

const STACK_SIZE: usize = 1024 * 1024;
const TLS_KEY_COUNT: usize = 128;
const ONCE_IN_PROGRESS: i32 = 1;
const ONCE_DONE: i32 = 2;
const RWLOCK_WRITER: i32 = -1;

struct ShimThreadStart {
    start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
}

static NEXT_TLS_KEY: AtomicU32 = AtomicU32::new(1);
static TLS_KEY_DESTRUCTOR: [AtomicUsize; TLS_KEY_COUNT] = [const { AtomicUsize::new(0) }; TLS_KEY_COUNT];
static TLS_KEY_ACTIVE: [AtomicU32; TLS_KEY_COUNT] = [const { AtomicU32::new(0) }; TLS_KEY_COUNT];
// emutls 依赖 setspecific 后能读回同一个指针；固定容量溢出会让每次 TLS
// 访问都重新分配零值对象。按需扩容，清零/删 key 时回收映射槽位。
static TLS_VALUES: TlsValueStore = TlsValueStore::new();

#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let state = &*(mutex as *const AtomicI32);
    loop {
        if state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return 0;
        }
        asm!("yield", options(nomem, nostack, preserves_flags));
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let state = &*(mutex as *const AtomicI32);
    state.store(0, Ordering::Release);
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_init(mutex: *mut c_void, _attr: *const c_void) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let state = &*(mutex as *const AtomicI32);
    state.store(0, Ordering::Release);
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_destroy(_mutex: *mut c_void) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_init(cond: *mut c_void, _attr: *const c_void) -> c_int {
    if cond.is_null() {
        return libc::EINVAL;
    }
    (*(cond as *const AtomicU32)).store(0, Ordering::Release);
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_destroy(_cond: *mut c_void) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut c_void) -> c_int {
    if cond.is_null() {
        return libc::EINVAL;
    }
    (*(cond as *const AtomicU32)).fetch_add(1, Ordering::Release);
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut c_void) -> c_int {
    pthread_cond_signal(cond)
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_wait(cond: *mut c_void, mutex: *mut c_void) -> c_int {
    wait_on_cond(cond, mutex, std::ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut c_void,
    mutex: *mut c_void,
    abstime: *const timespec,
) -> c_int {
    wait_on_cond(cond, mutex, abstime)
}

#[no_mangle]
pub unsafe extern "C" fn pthread_once(once: *mut c_void, init_routine: Option<unsafe extern "C" fn()>) -> c_int {
    if once.is_null() {
        return libc::EINVAL;
    }
    let state = &*(once as *const AtomicI32);
    loop {
        match state.load(Ordering::Acquire) {
            ONCE_DONE => return 0,
            0 => {
                if state
                    .compare_exchange(0, ONCE_IN_PROGRESS, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    if let Some(f) = init_routine {
                        f();
                    }
                    state.store(ONCE_DONE, Ordering::Release);
                    return 0;
                }
            }
            _ => sleep_for_ns(1_000_000),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_init(lock: *mut c_void, _attr: *const c_void) -> c_int {
    if lock.is_null() {
        return libc::EINVAL;
    }
    (*(lock as *const AtomicI32)).store(0, Ordering::Release);
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_destroy(_lock: *mut c_void) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_rdlock(lock: *mut c_void) -> c_int {
    if lock.is_null() {
        return libc::EINVAL;
    }
    let state = &*(lock as *const AtomicI32);
    loop {
        let current = state.load(Ordering::Acquire);
        if current >= 0
            && state
                .compare_exchange(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            return 0;
        }
        asm!("yield", options(nomem, nostack, preserves_flags));
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_wrlock(lock: *mut c_void) -> c_int {
    if lock.is_null() {
        return libc::EINVAL;
    }
    let state = &*(lock as *const AtomicI32);
    loop {
        if state
            .compare_exchange(0, RWLOCK_WRITER, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return 0;
        }
        asm!("yield", options(nomem, nostack, preserves_flags));
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_unlock(lock: *mut c_void) -> c_int {
    if lock.is_null() {
        return libc::EINVAL;
    }
    let state = &*(lock as *const AtomicI32);
    let current = state.load(Ordering::Acquire);
    if current == RWLOCK_WRITER {
        state.store(0, Ordering::Release);
    } else if current > 0 {
        state.fetch_sub(1, Ordering::Release);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_key_create(
    key: *mut pthread_key_t,
    destructor: Option<unsafe extern "C" fn(*mut c_void)>,
) -> c_int {
    if key.is_null() {
        return libc::EINVAL;
    }
    let id = NEXT_TLS_KEY.fetch_add(1, Ordering::AcqRel);
    if id == 0 || id as usize >= TLS_KEY_COUNT {
        return libc::EAGAIN;
    }
    TLS_KEY_DESTRUCTOR[id as usize].store(destructor.map_or(0, |f| f as usize), Ordering::Relaxed);
    TLS_KEY_ACTIVE[id as usize].store(1, Ordering::Release);
    *key = id as pthread_key_t;
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_key_delete(key: pthread_key_t) -> c_int {
    let id = key as usize;
    if id == 0 || id >= TLS_KEY_COUNT {
        return libc::EINVAL;
    }
    TLS_KEY_ACTIVE[id].store(0, Ordering::Release);
    TLS_VALUES.remove_key(key as u32);
    TLS_KEY_DESTRUCTOR[id].store(0, Ordering::Release);
    0
}

#[no_mangle]
pub unsafe extern "C" fn pthread_getspecific(key: pthread_key_t) -> *mut c_void {
    let id = key as usize;
    if id == 0 || id >= TLS_KEY_COUNT || TLS_KEY_ACTIVE[id].load(Ordering::Acquire) == 0 {
        return std::ptr::null_mut();
    }
    TLS_VALUES.get(current_thread_token(), key as u32) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn pthread_setspecific(key: pthread_key_t, value: *const c_void) -> c_int {
    let id = key as usize;
    if id == 0 || id >= TLS_KEY_COUNT || TLS_KEY_ACTIVE[id].load(Ordering::Acquire) == 0 {
        return libc::EINVAL;
    }
    match TLS_VALUES.set(current_thread_token(), key as u32, value as usize) {
        Ok(()) => 0,
        Err(()) => libc::ENOMEM,
    }
}

/// 只能在当前线程的 agent 调用栈已退出后执行；不得由其它线程代为析构。
pub(crate) unsafe extern "C" fn cleanup_current_thread() {
    TLS_VALUES.destroy_thread_values(current_thread_token(), TLS_KEY_COUNT as u32, |key| {
        let id = key as usize;
        if TLS_KEY_ACTIVE[id].load(Ordering::Acquire) == 0 {
            return None;
        }
        let destructor = TLS_KEY_DESTRUCTOR[id].load(Ordering::Acquire);
        if destructor == 0 {
            None
        } else {
            Some(std::mem::transmute::<usize, crate::pthread_tls::TlsDestructor>(
                destructor,
            ))
        }
    });
}

/// 声明在线程入口最前面，确保其它局部对象先销毁，再执行 TLS 析构。
pub(crate) struct ThreadExitGuard;

impl Drop for ThreadExitGuard {
    fn drop(&mut self) {
        unsafe { cleanup_current_thread() };
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_create(
    thread: *mut pthread_t,
    _attr: *const c_void,
    start: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
    arg: *mut c_void,
) -> c_int {
    let Some(start) = start else {
        return libc::EINVAL;
    };
    let stack = mmap(
        std::ptr::null_mut(),
        STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if stack == libc::MAP_FAILED {
        return libc::ENOMEM;
    }
    let state = Box::into_raw(Box::new(ShimThreadStart { start, arg }));
    let child_stack = (stack as *mut u8).add(STACK_SIZE) as *mut usize;
    let flags = (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM) as u64;
    match raw_clone(shim_thread_entry as *mut usize, state as usize, flags, child_stack) {
        Ok(tid) => {
            if !thread.is_null() {
                *thread = tid as pthread_t;
            }
            0
        }
        Err(errno) => {
            drop(Box::from_raw(state));
            errno
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pthread_detach(_thread: pthread_t) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn nanosleep(req: *const timespec, rem: *mut timespec) -> c_int {
    let mut result: c_long;
    asm!(
        "svc 0x0",
        in("x8") SYS_nanosleep,
        inout("x0") req as usize => result,
        in("x1") rem as usize,
        options(nostack, preserves_flags),
    );
    if result < 0 {
        -1
    } else {
        result as c_int
    }
}

unsafe fn raw_clone(child_func: *mut usize, arg: usize, flags: u64, child_stack: *mut usize) -> Result<i32, c_int> {
    let mut result: i64;

    *(child_stack.sub(1)) = child_func as usize;
    *(child_stack.sub(2)) = arg;

    asm!(
        "svc 0x0",
        "cbnz x0, 1f",
        "ldp x0, x1, [sp], #16",
        "blr x1",
        "mov x8, {exit_syscall}",
        "mov x0, #0",
        "svc 0x0",
        "1:",
        in("x8") SYS_clone,
        inout("x0") flags => result,
        in("x1") child_stack.sub(2),
        in("x2") 0usize,
        in("x3") 0usize,
        in("x4") 0usize,
        exit_syscall = const SYS_exit,
        options(nostack, preserves_flags),
        clobber_abi("C"),
    );

    if result < 0 {
        Err((-result) as c_int)
    } else {
        Ok(result as i32)
    }
}

extern "C" fn shim_thread_entry(arg: usize) -> c_int {
    let _tls_cleanup = ThreadExitGuard;
    let state = unsafe { Box::from_raw(arg as *mut ShimThreadStart) };
    unsafe {
        (state.start)(state.arg);
    }
    0
}

#[inline]
fn current_thread_token() -> ThreadToken {
    let tpidr: u64;
    unsafe { asm!("mrs {}, tpidr_el0", out(reg) tpidr, options(nomem, nostack, preserves_flags)) };
    // 完整保留两部分，避免 TPIDR 复用或 raw clone 继承同一 TPIDR 时串用状态。
    // 受控线程退出时会删除此身份；系统线程仍需配套原生退出通知。
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    ((tpidr as u128) << 32) | tid as u128
}

unsafe fn wait_on_cond(cond: *mut c_void, mutex: *mut c_void, abstime: *const timespec) -> c_int {
    if cond.is_null() || mutex.is_null() {
        return libc::EINVAL;
    }
    let state = &*(cond as *const AtomicU32);
    let observed = state.load(Ordering::Acquire);
    let _ = pthread_mutex_unlock(mutex);
    loop {
        if state.load(Ordering::Acquire) != observed {
            let _ = pthread_mutex_lock(mutex);
            return 0;
        }
        if !abstime.is_null() && realtime_reached(abstime) {
            let _ = pthread_mutex_lock(mutex);
            return libc::ETIMEDOUT;
        }
        sleep_for_ns(1_000_000);
    }
}

fn realtime_reached(abstime: *const timespec) -> bool {
    let mut now = timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        if clock_gettime_raw(CLOCK_REALTIME as clockid_t, &mut now) != 0 {
            return false;
        }
        now.tv_sec > (*abstime).tv_sec || (now.tv_sec == (*abstime).tv_sec && now.tv_nsec >= (*abstime).tv_nsec)
    }
}

fn sleep_for_ns(ns: c_long) {
    let req = timespec { tv_sec: 0, tv_nsec: ns };
    unsafe {
        let _ = nanosleep(&req, std::ptr::null_mut());
    }
}

unsafe fn clock_gettime_raw(clock_id: clockid_t, ts: *mut timespec) -> c_int {
    let mut result: c_long;
    asm!(
        "svc 0x0",
        in("x8") SYS_clock_gettime,
        inout("x0") clock_id as usize => result,
        in("x1") ts as usize,
        options(nostack, preserves_flags),
    );
    result as c_int
}
