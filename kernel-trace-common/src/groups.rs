//! 进程分组定义(仿 stackplz `-n com.xx,iso` / `--no-uid 10084`)。
//!
//! 分组来源:Android UID 分配惯例 + stackplz_dev/user/module/syscall.go。
//!
//! - `app`     : 普通应用进程(UID >= 10000,且 uid < 20000)
//! - `iso`     : isolated 进程(UID >= 99000 且 < 100000,Android 9+)
//! - `root`    : UID 0
//! - `system`  : UID >= 1000 且 < 2000(老 system_server 等)
//! - `shell`   : UID 2000
//! - `all`     : 全部
//! - `media`   : UID 1013 / 10013(媒体服务)

/// 进程分组 token(用户输入用)。
pub const PROCESS_GROUPS: &[&str] = &["all", "root", "system", "shell", "media", "iso", "app"];

/// 给定 UID,判断它是否落在某个分组里。
pub fn uid_in_group(uid: u32, group: &str) -> bool {
    match group {
        "all" => true,
        "root" => uid == 0,
        "system" => (1000..2000).contains(&uid),
        "shell" => uid == 2000,
        "media" => uid == 1013 || uid == 10013,
        // isolated 进程 UID 范围 Android 9+ 是 99000-99999
        "iso" => (99000..100000).contains(&uid),
        // 普通 app: UID >= 10000 且 < 20000,且不属于 media/iso
        "app" => {
            (10000..20000).contains(&uid) || (1000..10000).contains(&uid) // Android 11+ 部分 app 也走 1xxx 范围
        }
        _ => false,
    }
}

/// 解析逗号分隔的分组 token(`--name com.xx,iso`)。
///
/// 失败时返回 `Err`,包含未识别的 token。
pub fn parse_process_group(spec: &str) -> Result<Vec<&'static str>, String> {
    let mut out = Vec::new();
    for tok in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        // 从静态数组里找 'static 版本,避免生命周期问题
        let known = PROCESS_GROUPS.iter().find(|g| **g == tok).copied();
        match known {
            Some(s) => {
                if !out.contains(&s) {
                    out.push(s);
                }
            }
            None => {
                return Err(format!("unknown process group: {tok}; available: {PROCESS_GROUPS:?}"));
            }
        }
    }
    Ok(out)
}

/// 把一组分组 + 一个 PID list 转成最终"目标 UID 白名单"。
///
/// `extra_uids` 是显式指定的 UID(--no-uid 反向时是黑名单)。
///
/// 返回 true 表示"匹配"。
pub fn uid_matches_groups(uid: u32, groups: &[&str]) -> bool {
    if groups.is_empty() || groups.contains(&"all") {
        return true;
    }
    groups.iter().any(|g| uid_in_group(uid, g))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_classify() {
        assert!(uid_in_group(0, "root"));
        assert!(uid_in_group(1000, "system"));
        assert!(uid_in_group(1013, "media"));
        assert!(uid_in_group(10013, "media"));
        assert!(uid_in_group(99500, "iso"));
        assert!(uid_in_group(10134, "app"));
        assert!(!uid_in_group(2000, "app"));
        assert!(!uid_in_group(0, "iso"));
    }

    #[test]
    fn parse_groups() {
        let v = parse_process_group("app,iso").unwrap();
        assert_eq!(v, vec!["app", "iso"]);
        assert!(parse_process_group("bogus").is_err());
    }
}
