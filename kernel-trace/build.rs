use anyhow::{anyhow, Context as _};

/// 直接调用 cargo 构建 kernel-trace-ebpf（仿 ldmonitor/build.rs）：
/// - 不走 aya_build
/// - 在 CARGO_ENCODED_RUSTFLAGS 里追加 --remap-path-prefix，避免把构建机绝对路径
///   打进嵌入 rustfrida 的 ebpf 对象。
fn main() -> anyhow::Result<()> {
    let out_dir = std::env::var_os("OUT_DIR").ok_or_else(|| anyhow!("OUT_DIR not set"))?;
    let out_dir = std::path::Path::new(&out_dir);
    let home = std::env::var("HOME").unwrap_or_default();

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    let ebpf_root = std::path::Path::new(&manifest_dir)
        .parent()
        .ok_or_else(|| anyhow!("no parent for {manifest_dir}"))?
        .join("kernel-trace-ebpf");

    let proj_root = ebpf_root.parent().unwrap();
    for path in [
        ebpf_root.join("src"),
        ebpf_root.join("Cargo.toml"),
        ebpf_root.join("build.rs"),
        proj_root.join("kernel-trace-common/src"),
        proj_root.join("kernel-trace-common/Cargo.toml"),
        proj_root.join("Cargo.toml"),
        proj_root.join("Cargo.lock"),
        proj_root.join(".cargo"),
    ] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    for name in [
        "AYA_BPF_TARGET_ARCH",
        "BPF_TARGET_ARCH",
        "LLVM_STRIP",
        "CARGO_NET_OFFLINE",
        "CARGO_HOME",
        "HOME",
        "PATH",
        "RUSTUP_HOME",
        "RUSTC_WRAPPER",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let bpf_target_arch = std::env::var("AYA_BPF_TARGET_ARCH")
        .or_else(|_| std::env::var("BPF_TARGET_ARCH"))
        .unwrap_or_else(|_| "aarch64".to_string());

    const SEP: &str = "\x1f";
    let rustflags = [
        format!("--cfg=bpf_target_arch=\"{bpf_target_arch}\""),
        "-Cdebuginfo=2".to_string(),
        "-Clink-arg=--btf".to_string(),
        format!("--remap-path-prefix={}=/rf", proj_root.display()),
        format!("--remap-path-prefix={home}/.cargo/registry/src=/cargo"),
        format!("--remap-path-prefix={home}/.rustup/toolchains=/rustup"),
    ]
    .join(SEP);

    let target_dir = out_dir.join("kernel-trace-ebpf-target");
    // 使用外层 Cargo 已解析的锁文件,避免构建脚本修改工作区依赖。
    // 子进程继承 CARGO_NET_OFFLINE / .cargo 配置,不强制正常构建离线。
    // 外层 --offline 不会传给子 Cargo;整条构建链离线时设置 CARGO_NET_OFFLINE=true。
    let status = std::process::Command::new("cargo")
        .current_dir(&ebpf_root)
        .arg("+nightly")
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--bins",
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .env("CARGO_ENCODED_RUSTFLAGS", &rustflags)
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTFLAGS")
        .status()
        .context("spawn ebpf cargo build")?;
    if !status.success() {
        return Err(anyhow!("ebpf cargo build failed: {status}"));
    }

    let built = target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("kernel-trace");
    let dst = out_dir.join("kernel-trace");
    std::fs::copy(&built, &dst).with_context(|| format!("copy {} -> {}", built.display(), dst.display()))?;

    // strip 调试段（含残余路径）；.BTF 段保留
    let strip = std::env::var("LLVM_STRIP").unwrap_or_else(|_| "llvm-strip".to_string());
    let _ = std::process::Command::new(strip)
        .arg("--strip-debug")
        .arg(&dst)
        .status();

    Ok(())
}
