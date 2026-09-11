//! Small AArch64 instruction formatter for watchpoint reports.
//!
//! The tracer runs on the phone, so invoking a host objdump is not an option.
//! Unknown encodings are returned as .word together with their raw bytes.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Debug)]
pub struct InstructionInfo {
    pub word: u32,
    pub bytes: [u8; 4],
    pub asm: String,
}

static CACHE: OnceLock<Mutex<HashMap<(u32, u64), InstructionInfo>>> = OnceLock::new();
const CACHE_LIMIT: usize = 4096;

/// Read and format the instruction at a user PC. The cache matters because the
/// same load/store PC is normally hit thousands of times.
pub fn read_at(pid: u32, pc: u64) -> Option<InstructionInfo> {
    if pc == 0 || pc & 3 != 0 {
        return None;
    }
    if let Some(info) = cache_get(pid, pc) {
        return Some(info);
    }
    let bytes = crate::argspec::read_mem_pub(pid, pc, 4)?;
    if bytes.len() != 4 {
        return None;
    }
    let raw = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let word = u32::from_le_bytes(raw);
    let info = InstructionInfo {
        word,
        bytes: raw,
        asm: decode(word, pc),
    };
    cache_put(pid, pc, info.clone());
    Some(info)
}

/// Read a consecutive AArch64 instruction window in one `/proc/<pid>/mem`
/// operation. `count` is capped to keep a malformed event from allocating an
/// unbounded buffer. The returned entries start at `pc`, so `count = 16`
/// means the hit instruction plus the following 15 instructions.
pub fn read_window(pid: u32, pc: u64, count: usize) -> Option<Vec<InstructionInfo>> {
    if pc == 0 || pc & 3 != 0 || count == 0 {
        return None;
    }
    let count = count.min(64);
    let mut cached = Vec::with_capacity(count);
    for index in 0..count {
        let address = pc + (index as u64) * 4;
        let Some(info) = cache_get(pid, address) else {
            cached.clear();
            break;
        };
        cached.push(info);
    }
    if cached.len() == count {
        return Some(cached);
    }

    let bytes = crate::argspec::read_mem_pub(pid, pc, count * 4)?;
    let available = (bytes.len() / 4).min(count);
    if available == 0 {
        return None;
    }

    let mut result = Vec::with_capacity(available);
    for index in 0..available {
        let address = pc + (index as u64) * 4;
        let raw = [
            bytes[index * 4],
            bytes[index * 4 + 1],
            bytes[index * 4 + 2],
            bytes[index * 4 + 3],
        ];
        if let Some(info) = cache_get(pid, address) {
            result.push(info);
            continue;
        }
        let word = u32::from_le_bytes(raw);
        let info = InstructionInfo {
            word,
            bytes: raw,
            asm: decode(word, address),
        };
        cache_put(pid, address, info.clone());
        result.push(info);
    }
    Some(result)
}

fn cache_get(pid: u32, pc: u64) -> Option<InstructionInfo> {
    let cache = CACHE.get()?;
    let guard = cache.lock().ok()?;
    guard.get(&(pid, pc)).cloned()
}

fn cache_put(pid: u32, pc: u64, info: InstructionInfo) {
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cache.lock() {
        if guard.len() >= CACHE_LIMIT {
            guard.clear();
        }
        guard.insert((pid, pc), info);
    }
}

fn reg(index: u32, width: u32) -> String {
    if index == 31 {
        if width == 32 {
            "wzr".into()
        } else {
            "xzr".into()
        }
    } else if width == 32 {
        format!("w{index}")
    } else {
        format!("x{index}")
    }
}

fn base_reg(index: u32) -> String {
    if index == 31 {
        "sp".into()
    } else {
        format!("x{index}")
    }
}

fn signed(value: u32, bits: u32) -> i64 {
    let sign = 1u32 << (bits - 1);
    let mask = (1u32 << bits) - 1;
    let value = value & mask;
    if value & sign != 0 {
        value as i64 - (1i64 << bits)
    } else {
        value as i64
    }
}

fn imm(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{:x}", value as u64)
    }
}

fn decode(word: u32, pc: u64) -> String {
    if word & 0xffe0001f == 0xd4000001 {
        return format!("svc #0x{:x}", (word >> 5) & 0xffff);
    }
    if word & 0xffe0001f == 0xd4200000 {
        return format!("brk #0x{:x}", (word >> 5) & 0xffff);
    }
    match word {
        0xd503201f => return "nop".into(),
        0xd65f03c0 => return "ret".into(),
        _ => {}
    }
    if word & 0xfffffc1f == 0xd61f0000 {
        return format!("br {}", reg((word >> 5) & 31, 64));
    }
    if word & 0xfffffc1f == 0xd63f0000 {
        return format!("blr {}", reg((word >> 5) & 31, 64));
    }
    // C11 __atomic_store/load(..., acquire/release) 常被 clang 编译成
    // STLR/LDAR；结构体函数指针的 method_slot 写入就属于这一类。
    let ordered = word & 0x3fff_fc00;
    if ordered == 0x089f_fc00 || ordered == 0x08df_fc00 {
        let width = if word & 0x8000_0000 != 0 { 64 } else { 32 };
        let load = ordered == 0x08df_fc00;
        return format!(
            "{} {}, [{}]",
            if load { "ldar" } else { "stlr" },
            reg(word & 31, width),
            base_reg((word >> 5) & 31)
        );
    }
    if word & 0x7c000000 == 0x14000000 {
        let off = signed(word & 0x03ff_ffff, 26) << 2;
        let target = (pc as i64).wrapping_add(off) as u64;
        return format!("{} 0x{target:x}", if word & 0x8000_0000 != 0 { "bl" } else { "b" });
    }
    if word & 0x7e00_0000 == 0x3400_0000 {
        let width = if word & 0x8000_0000 != 0 { 64 } else { 32 };
        let off = signed((word >> 5) & 0x7ffff, 19) << 2;
        let target = (pc as i64).wrapping_add(off) as u64;
        let op = if word & 0x0100_0000 != 0 { "cbnz" } else { "cbz" };
        return format!("{op} {}, 0x{target:x}", reg(word & 31, width));
    }
    if word & 0x1f00_0000 == 0x1100_0000 {
        let width = if word & 0x8000_0000 != 0 { 64 } else { 32 };
        let op = if word & 0x4000_0000 != 0 { "sub" } else { "add" };
        let set_flags = word & 0x2000_0000 != 0;
        let shift = if word & 0x0040_0000 != 0 { 12 } else { 0 };
        let value = (((word >> 10) & 0xfff) as i64) << shift;
        let mnemonic = if set_flags { format!("{op}s") } else { op.into() };
        return format!(
            "{mnemonic} {}, {}, #{}",
            reg(word & 31, width),
            base_reg((word >> 5) & 31),
            imm(value)
        );
    }
    // MOVZ/MOVK immediate forms used to materialize constants in PIC code.
    if word & 0x7f80_0000 == 0x5280_0000 || word & 0x7f80_0000 == 0x7280_0000 {
        let width = if word & 0x8000_0000 != 0 { 64 } else { 32 };
        let op = if word & 0x0040_0000 != 0 { "movk" } else { "mov" };
        let shift = ((word >> 21) & 3) * 16;
        let value = ((word >> 5) & 0xffff) as u64;
        return if shift == 0 {
            format!("{op} {}, #0x{value:x}", reg(word & 31, width))
        } else {
            format!("{op} {}, #0x{value:x}, lsl #{shift}", reg(word & 31, width))
        };
    }
    if word & 0x1f20_0000 == 0x0b00_0000 {
        let width = if word & 0x8000_0000 != 0 { 64 } else { 32 };
        let op = if word & 0x4000_0000 != 0 { "sub" } else { "add" };
        let set_flags = word & 0x2000_0000 != 0;
        let shift = (word >> 10) & 0x3f;
        let shift_name = match (word >> 22) & 3 {
            0 => "lsl",
            1 => "lsr",
            2 => "asr",
            _ => "ror",
        };
        let suffix = if shift == 0 {
            String::new()
        } else {
            format!(", {shift_name} #{shift}")
        };
        let mnemonic = if set_flags { format!("{op}s") } else { op.into() };
        return format!(
            "{mnemonic} {}, {}, {}{suffix}",
            reg(word & 31, width),
            reg((word >> 5) & 31, width),
            reg((word >> 16) & 31, width)
        );
    }
    if word & 0xff20_0000 == 0x8a00_0000 || word & 0xff20_0000 == 0xaa00_0000 || word & 0xff20_0000 == 0xca00_0000 {
        let width = if word & 0x8000_0000 != 0 { 64 } else { 32 };
        let op = match word & 0xff20_0000 {
            0x8a00_0000 => "and",
            0xaa00_0000 => "orr",
            _ => "eor",
        };
        return format!(
            "{op} {}, {}, {}",
            reg(word & 31, width),
            reg((word >> 5) & 31, width),
            reg((word >> 16) & 31, width)
        );
    }
    if word & 0x3b00_0000 == 0x3900_0000 {
        let size = (word >> 30) & 3;
        let width = 8u32 << size;
        let load = word & 0x0040_0000 != 0;
        let offset = ((word >> 10) & 0xfff) as i64 * (1i64 << size);
        return format!(
            "{} {}, [{}{}]",
            if load { "ldr" } else { "str" },
            reg(word & 31, width),
            base_reg((word >> 5) & 31),
            if offset == 0 {
                String::new()
            } else {
                format!(", #{}", imm(offset))
            }
        );
    }
    if word & 0x3b20_0000 == 0x3800_0000 {
        let size = (word >> 30) & 3;
        let width = 8u32 << size;
        let load = word & 0x0040_0000 != 0;
        let offset = signed((word >> 12) & 0x1ff, 9);
        let mode = word & 3;
        let base = base_reg((word >> 5) & 31);
        let address = match mode {
            3 => format!(", #{}]!", imm(offset)),
            _ => format!(", #{}]", imm(offset)),
        };
        return format!(
            "{} {}, [{}{}",
            if load { "ldur" } else { "stur" },
            reg(word & 31, width),
            base,
            address
        );
    }
    if word & 0x3a00_0000 == 0x2800_0000 {
        let size = (word >> 30) & 3;
        let width = 32u32 << size;
        let load = word & 0x0040_0000 != 0;
        let offset = signed((word >> 15) & 0x7f, 7) * (4i64 << size);
        return format!(
            "{} {}, {}, [{}{}]",
            if load { "ldp" } else { "stp" },
            reg(word & 31, width),
            reg((word >> 10) & 31, width),
            base_reg((word >> 5) & 31),
            if offset == 0 {
                String::new()
            } else {
                format!(", #{}", imm(offset))
            }
        );
    }
    if word & 0x9f00_0000 == 0x1000_0000 || word & 0x9f00_0000 == 0x9000_0000 {
        let page = word & 0x8000_0000 != 0;
        let immlo = (word >> 29) & 3;
        let immhi = (word >> 5) & 0x7ffff;
        let raw = signed((immhi << 2) | immlo, 21);
        let target = if page {
            ((pc & !0xfff) as i64).wrapping_add(raw << 12) as u64
        } else {
            (pc as i64).wrapping_add(raw) as u64
        };
        return format!(
            "{} {}, 0x{target:x}",
            if page { "adrp" } else { "adr" },
            reg(word & 31, 64)
        );
    }
    format!(".word 0x{word:08x}")
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn decodes_compat_demo_watchpoint_accesses() {
        assert_eq!(decode(0xf9400408, 0x1940), "ldr x8, [x0, #0x8]");
        assert_eq!(decode(0xf9000808, 0x1950), "str x8, [x0, #0x10]");
        assert_eq!(decode(0xc89ffd36, 0x1fa0), "stlr x22, [x9]");
    }

    #[test]
    fn retains_unknown_instruction_as_word() {
        assert_eq!(decode(0xffffffff, 0), ".word 0xffffffff");
    }
}
