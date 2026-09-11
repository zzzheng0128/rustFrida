use super::UserRegs;
use crate::gumlibc::{gum_libc_ptrace, gum_libc_waitpid};
use libc::{c_void, iovec, pid_t, PTRACE_ATTACH};
use nix::errno::Errno;
use std::mem::size_of;

type Result<T> = std::result::Result<T, String>;

pub fn get_registers(pid: i32) -> Result<UserRegs> {
    let mut regs = UserRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };
    let result = unsafe {
        gum_libc_ptrace(
            libc::PTRACE_GETREGSET,
            pid as pid_t,
            1, // 通用寄存器
            &mut iov as *mut _ as usize,
        )
    };

    if result < 0 {
        return Err("获取线程 寄存器失败，错误码: ".to_string() + &(-result).to_string());
    }
    Ok(regs)
}

pub(crate) fn set_reg(pid: i32, regs: &mut UserRegs) -> Result<()> {
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len: size_of::<UserRegs>(),
    };

    let ret = gum_libc_ptrace(libc::PTRACE_SETREGSET, pid, 1, &mut iov as *const _ as usize);
    if ret < 0 {
        return Err(format!("设置寄存器失败，错误码: {}", -ret));
    }
    Ok(())
}

pub(crate) fn attach_to_thread(thread_id: i32) -> Result<()> {
    match gum_libc_ptrace(PTRACE_ATTACH, thread_id, 0, 0) {
        res if res >= 0 => {
            let mut status: usize = 0;
            let wait_result = gum_libc_waitpid(thread_id, &mut status as *mut _ as usize, 0x40000000);
            if wait_result < 0 {
                // PTRACE_ATTACH succeeded, so do not leave a tracee stopped
                // and attached when the wait itself fails.
                let _ = gum_libc_ptrace(libc::PTRACE_DETACH, thread_id, 0, 0);
                return Err("waitpid failed!!!!".to_string() + &(-wait_result).to_string());
            }
            // waitpid status low seven bits are 0x7f for a ptrace stop.
            // The previous `!(status & 0xff) == 0x7f` compared a bitwise
            // complement and rejected every normal stop status.
            if (status & 0x7f) != 0x7f {
                let _ = gum_libc_ptrace(libc::PTRACE_DETACH, thread_id, 0, 0);
                return Err("attach failed to stop !!!".to_string());
            }
            Ok(())
        }
        res => {
            let err_msg = match Errno::from_i32(-res) {
                Errno::EPERM => "权限不足，请使用root权限运行 ".to_string(),
                Errno::ESRCH => "目标线程不存在".to_string(),
                _ => "附加到线程失败: ".to_string() + &res.to_string(),
            };
            Err(err_msg)
        }
    }
}
