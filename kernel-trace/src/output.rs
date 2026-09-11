//! 输出格式化:`--dumphex` 把 buffer 输出成 hex+ASCII,`--color` 加 ANSI 着色。

/// 把字节 slice 格式化为 hex+ASCII 行(类似 `xxd` / `hexdump -C` 输出)。
///
/// 每行格式:`OFFSET  HH HH HH HH HH HH HH HH  HH HH HH HH HH HH HH HH  |ASCII|`
/// 默认 16 字节一行。
pub fn dumphex(data: &[u8]) -> String {
    const ROW: usize = 16;
    let mut out = String::with_capacity(data.len() * 4);
    let mut i = 0;
    while i < data.len() {
        let line_start = i;
        let line_end = (i + ROW).min(data.len());
        // offset(8 hex)
        out.push_str(&format!("{:08x}  ", line_start));
        // hex bytes
        for j in line_start..line_end {
            out.push_str(&format!("{:02x} ", data[j]));
            if j == line_start + 7 {
                out.push(' '); // 中间多一个空格
            }
        }
        // 补齐空白(短行)
        let n = line_end - line_start;
        if n < ROW {
            let pad = (ROW - n) * 3 + if n <= 8 { 1 } else { 0 };
            for _ in 0..pad {
                out.push(' ');
            }
        }
        out.push(' ');
        // ASCII
        out.push('|');
        for j in line_start..line_end {
            let c = data[j];
            if (0x20..0x7f).contains(&c) {
                out.push(c as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
        i = line_end;
    }
    out
}

// ============ ANSI 颜色 ============

/// 终端是否支持 ANSI 颜色。检查 `NO_COLOR` 环境变量 + `TERM`。
pub fn color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    match std::env::var("TERM").ok().as_deref() {
        Some("dumb") | Some("") => false,
        _ => true,
    }
}

pub const C_RESET: &str = "\x1b[0m";
pub const C_RED: &str = "\x1b[31m";
pub const C_GREEN: &str = "\x1b[32m";
pub const C_YELLOW: &str = "\x1b[33m";
pub const C_BLUE: &str = "\x1b[34m";
pub const C_MAGENTA: &str = "\x1b[35m";
pub const C_CYAN: &str = "\x1b[36m";
pub const C_BOLD: &str = "\x1b[1m";
pub const C_DIM: &str = "\x1b[2m";

/// 给字符串上色,只在 color_enabled 时返回 ANSI 序列,否则原样。
pub fn paint(s: &str, color: &str, enable: bool) -> String {
    if enable {
        format!("{color}{s}{C_RESET}")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumphex_basic() {
        let s = dumphex(b"hello world\nfoo");
        assert!(s.contains("00000000"));
        assert!(s.contains("hello world"));
        assert!(s.contains("|"));
    }

    #[test]
    fn dumphex_non_ascii() {
        let s = dumphex(&[0u8, 0xff, b'A']);
        assert!(s.contains(".."));
        assert!(s.contains("0xff") || s.contains("ff"));
    }

    #[test]
    fn paint_off() {
        assert_eq!(paint("x", C_RED, false), "x");
    }
}
