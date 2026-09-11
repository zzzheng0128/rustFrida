//! stackplz 风格的 `-f w:/path` / `-f b:/path` / `-f eq:VALUE` / `-f bx:HEX` 过滤规则。
//!
//! 字段语义对齐 stackplz_dev/user/config/config_filter.go。
//!
//! ## 当前实现范围
//! - 路径白/黑名单(`w:/path` / `b:/path`):本 turn 用 `comm` 字符串做前缀匹配作为 fallback,
//!   完整 pathname 匹配依赖 Tier 2 uprobe args 解析(下一 turn 接上)。
//! - LR/buffer 数值比较:`eq:0xVALUE` / `ne:0xVALUE` 需要 regs,接 `read_syscall_regs` 输出。
//!
//! ## 完整规则格式(未来扩展)
//! - `w:/path`      路径白名单(以 /path 为前缀)
//! - `b:/path`      路径黑名单
//! - `eq:0xVALUE`   某寄存器 == VALUE
//! - `ne:0xVALUE`   某寄存器 != VALUE
//! - `bx:HEX`       buffer 前 8 字节 == HEX
//!
//! 全部规则解析后存 `Vec<FilterRule>`,每条事件过一遍,任一不通过则丢弃。

/// 一条过滤规则(token 拆解后的形态)。
#[derive(Debug, Clone)]
pub enum FilterRule {
    /// 路径白名单:`w:/path`
    PathWhitelist(String),
    /// 路径黑名单:`b:/path`
    PathBlacklist(String),
    /// 寄存器/数值等于:`eq:0xVALUE`
    Eq(u64),
    /// 寄存器/数值不等于:`ne:0xVALUE`
    Ne(u64),
    /// buffer hex 匹配(最多 8 字节):`bx:HEX`
    BufferHex(Vec<u8>),
}

/// 解析逗号分隔的规则字符串(`-f w:/system,b:/dev -f eq:0x1234`)。
///
/// 失败返回 `Err(String)`。
pub fn parse_filter_list(spec: &str) -> Result<Vec<FilterRule>, String> {
    let mut out = Vec::new();
    for tok in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(rest) = tok.strip_prefix("w:") {
            out.push(FilterRule::PathWhitelist(rest.to_string()));
        } else if let Some(rest) = tok.strip_prefix("b:") {
            out.push(FilterRule::PathBlacklist(rest.to_string()));
        } else if let Some(rest) = tok.strip_prefix("eq:") {
            let v = parse_hex_u64(rest)?;
            out.push(FilterRule::Eq(v));
        } else if let Some(rest) = tok.strip_prefix("ne:") {
            let v = parse_hex_u64(rest)?;
            out.push(FilterRule::Ne(v));
        } else if let Some(rest) = tok.strip_prefix("bx:") {
            let bytes = parse_hex_bytes(rest, 8)?;
            out.push(FilterRule::BufferHex(bytes));
        } else {
            return Err(format!(
                "unknown filter rule: {tok}; supported: w:/PATH b:/PATH eq:0xHEX ne:0xHEX bx:HEX"
            ));
        }
    }
    Ok(out)
}

fn parse_hex_u64(s: &str) -> Result<u64, String> {
    let t = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|e| format!("bad hex {s:?}: {e}"))
}

fn parse_hex_bytes(s: &str, max: usize) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.len() % 2 != 0 || t.len() > max * 2 {
        return Err(format!("hex bytes {t:?}: must be even-length, <= {max} bytes"));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let h = std::str::from_utf8(&bytes[i..i + 2]).map_err(|e| format!("bad utf8 in hex: {e}"))?;
        let v = u8::from_str_radix(h, 16).map_err(|e| format!("bad hex byte {h:?}: {e}"))?;
        out.push(v);
        i += 2;
    }
    Ok(out)
}

/// 给定事件上下文(comm 字符串 / regs / 待定 path),判断是否通过全部规则。
///
/// 当前实现:`comm` 字符串前缀匹配(因为 path/regs 还没完全接好)。
pub fn event_passes(rules: &[FilterRule], comm: &str, regs: &[(String, u64)]) -> bool {
    for rule in rules {
        match rule {
            FilterRule::PathWhitelist(p) => {
                // fallback:用 comm 前缀匹配;完整版接 args.pathname 后这里换成 path
                if !comm.starts_with(p.as_str()) {
                    return false;
                }
            }
            FilterRule::PathBlacklist(p) => {
                if comm.starts_with(p.as_str()) {
                    return false;
                }
            }
            FilterRule::Eq(v) => {
                if !regs.iter().any(|(_, val)| val == v) {
                    return false;
                }
            }
            FilterRule::Ne(v) => {
                if regs.iter().any(|(_, val)| val == v) {
                    return false;
                }
            }
            FilterRule::BufferHex(_) => {
                // 暂未实现,直接放行;Tier 2 接 args buffer 时再启用
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let v = parse_filter_list("w:/system,b:/dev,eq:0x1234,bx:73ea68").unwrap();
        assert_eq!(v.len(), 4);
    }

    #[test]
    fn parse_bad() {
        assert!(parse_filter_list("bogus:foo").is_err());
        assert!(parse_filter_list("eq:nothex").is_err());
    }

    #[test]
    fn path_whitelist_fallback() {
        let rules = vec![FilterRule::PathWhitelist("/system".into())];
        assert!(event_passes(&rules, "/system/bin", &[]));
        assert!(!event_passes(&rules, "/data/local", &[]));
    }

    #[test]
    fn eq_filter() {
        let rules = vec![FilterRule::Eq(0x1234)];
        assert!(event_passes(&rules, "x", &[("x0".into(), 0x1234)]));
        assert!(!event_passes(&rules, "x", &[("x0".into(), 0x5678)]));
    }
}
