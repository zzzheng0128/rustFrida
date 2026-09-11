use super::arm64_analysis::{is_arm64_branch, is_arm64_call, resolve_next_addr};
use super::arm64_codegen::{gen_jump_to_transformer, gen_mov_reg_addr};
use super::ptrace_ops::{attach_to_thread, get_registers, set_reg};
use super::UserRegs;
use crate::arm64_relocator;
use crate::communication::write_stream;
use crate::exec_mem::ExecMem;
use crate::gumlibc::gum_libc_ptrace;
use libc::{
    c_int, mmap, pid_t, CLONE_SETTLS, CLONE_VM, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, PR_SET_NAME,
    PTRACE_DETACH,
};
use once_cell::sync::Lazy;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

type Result<T> = std::result::Result<T, String>;
const TRACE_STACK_SIZE: usize = 0x1100000;
const TRACE_TLS_SIZE: usize = 0x1000;
// __WALL lets the parent reap the CLONE_VM child even though the clone used
// signal 0 instead of SIGCHLD. WNOHANG keeps an unusual kernel wait failure
// from blocking the agent's command thread forever.
const WAIT_ALL: usize = 0x40000000;
const WAIT_NOHANG: usize = 0x1;
const TRACE_REAP_POLLS: usize = 5_000;

// ============== 静态变量 ==============

// The trampoline may be entered by a target thread while the control thread is
// still finishing setup.  A raw mutable static makes that hand-off a data race
// (and is UB even on a single-core test device).  Keep the instruction cursor
// atomic; the executable buffer itself remains serialized by its mutex.
static INSTRUCT_PTR: AtomicUsize = AtomicUsize::new(0);
static EXE_MEM: Lazy<Mutex<ExecMem>> = Lazy::new(|| Mutex::new(ExecMem::new().unwrap()));

// ============== 转换器 ==============

extern "C" {
    pub fn mtransform();
    fn hook_flush_cache(start: *mut std::ffi::c_void, size: usize);
}

/// 返回 mtransform 函数地址，供 arm64_codegen 使用
pub fn mtransform_addr() -> usize {
    mtransform as usize
}

#[no_mangle]
pub extern "C" fn transformer_wrapper_full(ctx: [usize; 32]) -> usize {
    unsafe {
        let mut vall = UserRegs::default();
        for i in 0..31 {
            vall.regs[i] = ctx[31 - i];
        }
        vall.pstate = ctx[0];
        let instruction = INSTRUCT_PTR.load(Ordering::Acquire) as *const u32;
        if instruction.is_null() || (instruction as usize) % 4 != 0 {
            write_stream(b"transformer: instruction cursor is null");
            return 0;
        }
        let Some(addr) = resolve_next_addr(instruction, vall) else {
            write_stream(b"transformer: current instruction is not a supported branch");
            return 0;
        };

        match transformer_global(addr) {
            Ok(addr) => addr,
            Err(error) => {
                write_stream(("transformer failed: ".to_string() + &error).as_bytes());
                0
            }
        }
    }
}

pub fn transformer_global(addr: usize) -> Result<usize> {
    unsafe {
        if addr == 0 {
            return Err("resolved branch target is null".into());
        }
        let mut exe_mem = EXE_MEM.lock().unwrap_or_else(|poison| poison.into_inner());
        let result = (|| {
            let ret_addr = exe_mem.current_addr();
            let current = INSTRUCT_PTR.load(Ordering::Acquire) as *const u32;
            if current.is_null() {
                return Err("instruction cursor is null".into());
            }

            if is_arm64_call(core::ptr::read_volatile(current)) {
                for instr in gen_mov_reg_addr(30, current.add(1) as usize) {
                    exe_mem.write_u32(instr)?;
                }
            }

            let mut next = addr as *const u32;
            let mut relocated = 0usize;
            while relocated < 64 && !is_arm64_branch(core::ptr::read_volatile(next)) {
                arm64_relocator::relocate_one_a64(next as usize, exe_mem.external_write_instruct());
                next = next.add(1);
                relocated += 1;
            }
            if relocated == 64 {
                return Err("branch target scan exceeded 64 instructions".into());
            }
            INSTRUCT_PTR.store(next as usize, Ordering::Release);

            for instruct in gen_jump_to_transformer() {
                exe_mem.write_u32(instruct)?;
            }
            hook_flush_cache(exe_mem.ptr as *mut _, exe_mem.used());
            Ok(ret_addr)
        })();
        if result.is_err() {
            // Do not let a partial trampoline become the prefix for the next
            // branch after a failed write or relocation scan.
            exe_mem.reset();
        }
        result
    }
}

// ============== Trace 入口 ==============

pub fn gum_modify_thread(thread_id: usize) -> Result<pid_t> {
    let stack_base = unsafe {
        mmap(
            null_mut(),
            TRACE_STACK_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if stack_base == libc::MAP_FAILED {
        return Err("trace stack mmap failed".into());
    }
    let stack = unsafe { stack_base.add(TRACE_STACK_SIZE) };
    let tls = unsafe {
        mmap(
            null_mut(),
            TRACE_TLS_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if tls == libc::MAP_FAILED {
        unsafe { libc::munmap(stack_base, TRACE_STACK_SIZE) };
        return Err("trace TLS mmap failed".into());
    }
    let result = crate::gumlibc::gum_libc_clone(
        tracer as *mut usize,
        thread_id,
        (CLONE_VM | CLONE_SETTLS) as u64,
        stack as *mut usize,
        null_mut(),
        null_mut(),
        tls,
    );
    match result {
        Err(error) => {
            unsafe {
                libc::munmap(stack_base, TRACE_STACK_SIZE);
                libc::munmap(tls, TRACE_TLS_SIZE);
            }
            Err(error)
        }
        Ok(child_pid) => {
            // The child shares this address space, so only the parent may
            // reclaim its stack after wait confirms that no instruction can
            // still use it. A bounded poll avoids turning a broken wait
            // implementation into a permanent block; in that case the
            // mappings are intentionally kept.
            let mut status = 0usize;
            for _ in 0..TRACE_REAP_POLLS {
                let waited =
                    crate::gumlibc::gum_libc_waitpid(child_pid, &mut status as *mut _ as usize, WAIT_ALL | WAIT_NOHANG);
                if waited == child_pid {
                    unsafe {
                        libc::munmap(stack_base, TRACE_STACK_SIZE);
                        libc::munmap(tls, TRACE_TLS_SIZE);
                    }
                    break;
                }
                if waited == 0 {
                    crate::raw_thread::sleep_ms(1);
                    continue;
                }
                // Negative errno (including ECHILD/EINTR) means ownership of
                // the mappings is uncertain; retaining them is safer than
                // unmapping a stack that may still be executing.
                break;
            }
            Ok(child_pid)
        }
    }
}

extern "C" fn tracer(thread_id: i32) -> c_int {
    unsafe {
        let _ = libc::prctl(PR_SET_NAME, b"ReferenceQueueD\0".as_ptr(), 0, 0, 0);
        match attach_to_thread(thread_id) {
            Ok(_) => {
                write_stream(b"attach success!! ");
            }
            Err(e) => {
                write_stream(("tracer exit: ".to_string() + &e).as_bytes());
                return -1;
            }
        }
        let mut exe_mem = EXE_MEM.lock().unwrap_or_else(|poison| poison.into_inner());

        let mut regs = match get_registers(thread_id) {
            Ok(regs) => regs,
            Err(error) => {
                write_stream(("trace get registers failed: ".to_string() + &error).as_bytes());
                gum_libc_ptrace(PTRACE_DETACH, thread_id, 0, 0);
                return -1;
            }
        };
        if regs.pc == 0 || regs.pc % 4 != 0 {
            write_stream(("trace invalid PC: ".to_string() + &format!("0x{:x}", regs.pc)).as_bytes());
            gum_libc_ptrace(PTRACE_DETACH, thread_id, 0, 0);
            return -1;
        }
        INSTRUCT_PTR.store(regs.pc, Ordering::Release);
        write_stream(("\nget pc: ".to_string() + &regs.pc.to_string()).as_bytes());

        let mut next = regs.pc as *const u32;
        let mut relocated = 0usize;
        while relocated < 64 && !is_arm64_branch(core::ptr::read_volatile(next)) {
            arm64_relocator::relocate_one_a64(next as usize, exe_mem.external_write_instruct());
            next = next.add(1);
            relocated += 1;
        }
        if relocated == 64 {
            exe_mem.reset();
            write_stream(b"trace compile failed: branch scan exceeded 64 instructions");
            gum_libc_ptrace(PTRACE_DETACH, thread_id, 0, 0);
            return -1;
        }
        INSTRUCT_PTR.store(next as usize, Ordering::Release);

        for instruct in gen_jump_to_transformer() {
            if let Err(error) = exe_mem.write_u32(instruct) {
                exe_mem.reset();
                write_stream(("trace compile failed: ".to_string() + &error).as_bytes());
                gum_libc_ptrace(PTRACE_DETACH, thread_id, 0, 0);
                return -1;
            }
        }
        hook_flush_cache(exe_mem.ptr as *mut _, exe_mem.used());
        write_stream(("\ntrace compile finished :".to_string() + &(regs.pc as u64).to_string()).as_bytes());
        regs.pc = exe_mem.ptr as usize;
        if let Err(error) = set_reg(thread_id, &mut regs) {
            exe_mem.reset();
            write_stream(("trace set registers failed: ".to_string() + &error).as_bytes());
            gum_libc_ptrace(PTRACE_DETACH, thread_id, 0, 0);
            return -1;
        }

        gum_libc_ptrace(PTRACE_DETACH, thread_id, 0, 0);
        write_stream(b"\ndone! detached!");
        1
    }
}
