use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use clap::Parser;
use log::info;
use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vaporwall_common::PacketEvent;

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

    // Scoped block: the `&mut Xdp` borrow of `bpf` created here lives only
    // until the end of this block. Once `link_id` is returned out, the borrow
    // is released — this is what lets us call `bpf.take_map(...)` right after,
    // which otherwise conflicts (E0499: cannot borrow `bpf` as mutable twice).
    let link_id = {
        let program: &mut Xdp = bpf
            .program_mut("vaporwall")
            .context(
                "program 'vaporwall' not found in compiled object — name mismatch with #[xdp] fn?",
            )?
            .try_into()?;

        program
            .load()
            .context("verifier rejected the program — check dmesg/RUST_LOG=debug for details")?;

        program.attach(&opt.iface, XdpFlags::SKB_MODE).context(
            "failed to attach XDP program — do you have CAP_BPF/CAP_NET_ADMIN? try running with sudo",
        )?
    };

    info!(
        "VaporWall XDP program attached on '{}' (SKB mode). Ctrl-C to detach and exit.",
        opt.iface
    );

    let mut ring_buf: RingBuf<_> = bpf
        .take_map("EVENTS")
        .context("EVENTS map not found — name must match the #[map] static in vaporwall-ebpf")?
        .try_into()
        .context("EVENTS map is not a RingBuf — type mismatch between kernel and user space")?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || r.store(false, Ordering::SeqCst))
        .context("failed to set Ctrl-C handler")?;

    info!("Polling ring buffer for packet events...");

    while running.load(Ordering::SeqCst) {
        while let Some(item) = ring_buf.next() {
            if item.len() != core::mem::size_of::<PacketEvent>() {
                log::warn!(
                    "ring buffer entry size mismatch: got {} bytes, expected {}",
                    item.len(),
                    core::mem::size_of::<PacketEvent>()
                );
                continue;
            }
            let event: PacketEvent =
                unsafe { core::ptr::read_unaligned(item.as_ptr() as *const PacketEvent) };

            info!(
                "{}:{} -> {}:{} proto={} len={}",
                Ipv4Addr::from(event.src_ip),
                event.src_port,
                Ipv4Addr::from(event.dst_ip),
                event.dst_port,
                event.protocol,
                event.payload_len
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    info!("Detaching XDP program from '{}'...", opt.iface);
    // Fresh borrow of `program` here — the earlier borrow already ended when
    // its enclosing block closed above, so this is a brand new, non-conflicting
    // mutable borrow of `bpf`.
    let program: &mut Xdp = bpf
        .program_mut("vaporwall")
        .context("program disappeared?")?
        .try_into()?;
    program.detach(link_id).context(
        "failed to detach XDP program — you may need to run `sudo ip link set dev <iface> xdp off` manually",
    )?;

    info!("Detached cleanly. Exiting.");
    Ok(())
}
