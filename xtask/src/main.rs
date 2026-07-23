use anyhow::{Context, Result};
use std::process::Command;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("build-ebpf") => build_ebpf(args.contains(&"--release".to_string())),
        _ => {
            eprintln!("Usage: cargo xtask build-ebpf [--release]");
            std::process::exit(1);
        }
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir("vaporwall-ebpf")
        .arg("+nightly")
        .arg("build")
        .arg("-Z")
        .arg("build-std=core");

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context(
        "failed to spawn cargo build for vaporwall-ebpf — is nightly toolchain installed?",
    )?;

    if !status.success() {
        anyhow::bail!("eBPF build failed with status: {status}");
    }

    println!(
        "eBPF bytecode built at: vaporwall-ebpf/target/bpfel-unknown-none/{}/vaporwall",
        if release { "release" } else { "debug" }
    );
    Ok(())
}
