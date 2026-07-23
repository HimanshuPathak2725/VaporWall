use anyhow::Context;
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use clap::Parser;
use log::info;
use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser)]
struct Opt {
    /// Interface to attach XDP program to. In Codespaces, use "lo" — no real NIC available.
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opt = Opt::parse();

    #[cfg(debug_assertions)]
    let bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/vaporwall");
    #[cfg(not(debug_assertions))]
    let bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/release/vaporwall");

    let mut bpf = Ebpf::load(bytes)
        .context("failed to load eBPF object — did you run `cargo xtask build-ebpf` first?")?;

    let program: &mut Xdp = bpf
        .program_mut("vaporwall")
        .context("program 'vaporwall' not found in compiled object — name mismatch with #[xdp] fn?")?
        .try_into()?;

    program
        .load()
        .context("verifier rejected the program — check dmesg/RUST_LOG=debug for details")?;

    // CRITICAL: capture the link_id explicitly. Do NOT discard this with `?` alone.
    // XDP attachment in modern kernels is backed by a bpf_link — its lifetime is
    // tied to *this* handle, not to the process or the Ebpf struct's Drop impl.
    // If we don't hold and explicitly detach this, the program can outlive our
    // process on the interface (as we just saw: `prog/xdp id 103` survived Ctrl-C).
    let link_id = program
        .attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach XDP program — do you have CAP_BPF/CAP_NET_ADMIN? try running with sudo")?;

    info!(
        "VaporWall XDP program attached on '{}' (SKB mode). Ctrl-C to detach and exit.",
        opt.iface
    );

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::SeqCst))
        .context("failed to set Ctrl-C handler")?;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // Explicit detach — do not rely on implicit Drop-on-exit for kernel-resident
    // resources. This is the actual fix: we now deterministically remove the
    // program from the interface before the process exits, rather than hoping
    // Ebpf's destructor runs and cleans up the link for us.
    info!("Detaching XDP program from '{}'...", opt.iface);
    program
        .detach(link_id)
        .context("failed to detach XDP program — you may need to run `sudo ip link set dev <iface> xdp off` manually")?;

    info!("Detached cleanly. Exiting.");
    Ok(())
}