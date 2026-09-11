//! Read-only validation before opening the common text and trace JSONL outputs.
//!
//! Call immediately before opening either file. Like any path-based preflight,
//! this checks the current filesystem; it cannot lock out subsequent renames.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const MAX_SYMLINKS: usize = 40;

/// Reject aliases of one output file before a caller can truncate either path.
/// Neither output path nor its parent directories are created by this check.
pub(crate) fn validate_distinct_outputs(common: Option<&str>, trace: Option<&str>) -> io::Result<()> {
    let (Some(common), Some(trace)) = (common, trace) else {
        return Ok(());
    };
    let collision = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "--output and --trace-output must refer to different files (text and JSONL cannot share one file)",
        )
    };
    if common == trace {
        return Err(collision());
    }

    let common = resolve_output_path(Path::new(common))?;
    let trace = resolve_output_path(Path::new(trace))?;
    if common == trace {
        return Err(collision());
    }

    // Canonical paths alone do not detect hard links. Android and the supported
    // Unix development hosts expose the device/inode pair without opening files.
    let common_metadata = metadata_if_present(&common)?;
    let trace_metadata = metadata_if_present(&trace)?;
    #[cfg(unix)]
    if let (Some(common), Some(trace)) = (common_metadata, trace_metadata) {
        if common.dev() == trace.dev() && common.ino() == trace.ino() {
            return Err(collision());
        }
    }
    #[cfg(not(unix))]
    let _ = (common_metadata, trace_metadata);
    Ok(())
}

fn metadata_if_present(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[derive(Debug)]
enum PathPart {
    Prefix(OsString),
    Root(OsString),
    Parent,
    Name(OsString),
}

fn path_parts(path: &Path) -> VecDeque<PathPart> {
    path.components()
        .filter_map(|component| match component {
            Component::Prefix(prefix) => Some(PathPart::Prefix(prefix.as_os_str().to_owned())),
            Component::RootDir => Some(PathPart::Root(component.as_os_str().to_owned())),
            Component::CurDir => None,
            Component::ParentDir => Some(PathPart::Parent),
            Component::Normal(name) => Some(PathPart::Name(name.to_owned())),
        })
        .collect()
}

/// Resolve existing symlinks even when their final target does not exist yet.
/// Expanding links before handling '..' preserves filesystem path semantics.
fn resolve_output_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut pending = path_parts(&absolute);
    let mut resolved = PathBuf::new();
    let mut followed = 0;
    while let Some(part) = pending.pop_front() {
        match part {
            PathPart::Prefix(prefix) => resolved.push(prefix),
            PathPart::Root(root) => resolved.push(root),
            PathPart::Parent => {
                resolved.pop();
            }
            PathPart::Name(name) => {
                let candidate = resolved.join(&name);
                match fs::symlink_metadata(&candidate) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        followed += 1;
                        if followed > MAX_SYMLINKS {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "too many symbolic links while validating output paths",
                            ));
                        }
                        let target = fs::read_link(&candidate)?;
                        if target.is_absolute() {
                            resolved.clear();
                        }
                        let mut target_parts = path_parts(&target);
                        target_parts.append(&mut pending);
                        pending = target_parts;
                    }
                    Ok(_) => resolved.push(name),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => resolved.push(name),
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "rustfrida-output-paths-{}-{timestamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn validate(common: &Path, trace: &Path) -> io::Result<()> {
        validate_distinct_outputs(common.to_str(), trace.to_str())
    }

    fn assert_collision(common: &Path, trace: &Path) {
        assert_eq!(validate(common, trace).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn one_or_no_explicit_output_needs_no_filesystem_lookup() {
        validate_distinct_outputs(None, None).unwrap();
        validate_distinct_outputs(Some("/missing/common.log"), None).unwrap();
        validate_distinct_outputs(None, Some("/missing/trace.jsonl")).unwrap();
    }

    #[test]
    fn identical_new_paths_are_rejected_without_creating_them() {
        let dir = TempDir::new();
        let output = dir.path("new.log");
        assert_collision(&output, &output);
        assert!(!output.exists());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    }

    #[test]
    fn new_file_parent_components_are_normalized_without_creation() {
        let dir = TempDir::new();
        fs::create_dir(dir.path("child")).unwrap();
        assert_collision(&dir.path("child/.././new.log"), &dir.path("new.log"));
        assert!(!dir.path("new.log").exists());
    }

    #[cfg(unix)]
    #[test]
    fn relative_dot_path_and_absolute_path_identify_the_same_file() {
        let dir = TempDir::new();
        let absolute = dir.path("common.log");
        fs::write(&absolute, "keep this content").unwrap();
        let cwd = std::env::current_dir().unwrap();
        let mut relative = PathBuf::from(".");
        for component in cwd.components() {
            if matches!(component, Component::Normal(_)) {
                relative.push("..");
            }
        }
        relative.push(absolute.strip_prefix("/").unwrap());
        assert_collision(&relative, &absolute);
        assert_eq!(fs::read_to_string(&absolute).unwrap(), "keep this content");
    }

    #[test]
    fn distinct_existing_files_are_allowed_and_unchanged() {
        let dir = TempDir::new();
        let common = dir.path("common.log");
        let trace = dir.path("trace.jsonl");
        fs::write(&common, "plain text\n").unwrap();
        fs::write(&trace, "{\"kind\":\"synthetic\"}\n").unwrap();
        validate(&common, &trace).unwrap();
        assert_eq!(fs::read_to_string(&common).unwrap(), "plain text\n");
        assert_eq!(fs::read_to_string(&trace).unwrap(), "{\"kind\":\"synthetic\"}\n");
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_and_target_are_rejected() {
        let dir = TempDir::new();
        fs::write(dir.path("target.log"), "preserve").unwrap();
        std::os::unix::fs::symlink("target.log", dir.path("alias.log")).unwrap();
        assert_collision(&dir.path("target.log"), &dir.path("alias.log"));
        assert_eq!(fs::read_to_string(dir.path("target.log")).unwrap(), "preserve");
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_and_new_target_are_rejected_without_creation() {
        let dir = TempDir::new();
        std::os::unix::fs::symlink("new.log", dir.path("alias.log")).unwrap();
        assert_collision(&dir.path("new.log"), &dir.path("alias.log"));
        assert!(!dir.path("new.log").exists());
        assert!(fs::symlink_metadata(dir.path("alias.log"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_for_a_new_file_is_resolved_before_parent_traversal() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.path("real/child")).unwrap();
        std::os::unix::fs::symlink("real/child", dir.path("alias")).unwrap();
        assert_collision(&dir.path("alias/new.log"), &dir.path("real/child/new.log"));
        assert_collision(&dir.path("alias/../new.log"), &dir.path("real/new.log"));
        validate(&dir.path("alias/../new.log"), &dir.path("new.log")).unwrap();
        assert!(!dir.path("real/new.log").exists());
        assert!(!dir.path("real/child/new.log").exists());
    }

    #[cfg(unix)]
    #[test]
    fn existing_hardlinks_are_rejected_without_truncation() {
        let dir = TempDir::new();
        fs::write(dir.path("first.log"), "preserve both names").unwrap();
        fs::hard_link(dir.path("first.log"), dir.path("second.log")).unwrap();
        assert_collision(&dir.path("first.log"), &dir.path("second.log"));
        assert_eq!(
            fs::read_to_string(dir.path("first.log")).unwrap(),
            "preserve both names"
        );
        assert_eq!(
            fs::read_to_string(dir.path("second.log")).unwrap(),
            "preserve both names"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cyclic_symlink_fails_instead_of_recursing_forever() {
        let dir = TempDir::new();
        std::os::unix::fs::symlink("second", dir.path("first")).unwrap();
        std::os::unix::fs::symlink("first", dir.path("second")).unwrap();
        assert_eq!(
            validate(&dir.path("first"), &dir.path("unrelated.log"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!dir.path("unrelated.log").exists());
    }
}
