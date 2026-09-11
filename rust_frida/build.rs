use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir.parent().expect("rust_frida must be inside workspace root");
    let target = std::env::var("TARGET").unwrap_or_default();
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());

    // CARGO_TARGET_DIR may point at a separate workspace-local directory.
    // Keep the embedded agent beside the host binary instead of silently
    // reading the legacy workspace `target/` copy.
    let target_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                workspace_root.join(path)
            }
        })
        .unwrap_or_else(|| workspace_root.join("target"));
    let agent_path = target_root.join(&target).join(&profile).join("libagent.so");
    println!("cargo:rustc-env=AGENT_SO_PATH={}", agent_path.display());
    println!("cargo:rerun-if-changed={}", agent_path.display());

    // 当 agent.so 或 helper shellcode 变化时重新编译 host（include_bytes! 缓存问题）
    println!("cargo:rerun-if-changed=../loader/build/bootstrapper.bin");
    println!("cargo:rerun-if-changed=../loader/build/rustfrida-loader.bin");

    let helper_inputs = [
        "loader/build_helpers.py",
        "loader/helpers/bootstrapper.c",
        "loader/helpers/elf-parser.c",
        "loader/helpers/elf-parser.h",
        "loader/helpers/helper.lds",
        "loader/helpers/inject-context.h",
        "loader/helpers/nolibc-compat.h",
        "loader/helpers/rustfrida-loader.c",
        "loader/helpers/syscall.c",
        "loader/helpers/syscall.h",
    ];
    for input in helper_inputs {
        println!("cargo:rerun-if-changed=../{}", input);
    }

    if target == "aarch64-linux-android" && helpers_are_stale(workspace_root) {
        let status = std::process::Command::new("python3")
            .arg(workspace_root.join("loader/build_helpers.py"))
            .current_dir(workspace_root)
            .status()
            .expect("failed to run loader/build_helpers.py");
        if !status.success() {
            panic!("loader/build_helpers.py failed with status {}", status);
        }
    }

    if std::env::var_os("CARGO_FEATURE_QBDI").is_some() {
        let profile = std::env::var("PROFILE").expect("PROFILE not set");
        let helper_path = target_root
            .join(&target)
            .join(if profile == "release" { "release" } else { "debug" })
            .join("libqbdi_helper.so");
        let helper_path = helper_path.display().to_string();
        println!("cargo:rustc-env=QBDI_HELPER_SO_PATH={}", helper_path);
        println!("cargo:rerun-if-changed={}", helper_path);
    }
}

fn helpers_are_stale(workspace_root: &Path) -> bool {
    let inputs = [
        "loader/build_helpers.py",
        "loader/helpers/bootstrapper.c",
        "loader/helpers/elf-parser.c",
        "loader/helpers/elf-parser.h",
        "loader/helpers/helper.lds",
        "loader/helpers/inject-context.h",
        "loader/helpers/nolibc-compat.h",
        "loader/helpers/rustfrida-loader.c",
        "loader/helpers/syscall.c",
        "loader/helpers/syscall.h",
    ];
    let outputs = ["loader/build/bootstrapper.bin", "loader/build/rustfrida-loader.bin"];

    let newest_input = inputs
        .iter()
        .filter_map(|path| modified_time(&workspace_root.join(path)))
        .max();
    let oldest_output = outputs
        .iter()
        .map(|path| modified_time(&workspace_root.join(path)))
        .collect::<Option<Vec<_>>>()
        .and_then(|times| times.into_iter().min());

    match (newest_input, oldest_output) {
        (_, None) => true,
        (Some(input), Some(output)) => input > output,
        (None, Some(_)) => false,
    }
}

fn modified_time(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|metadata| metadata.modified()).ok()
}
