use aho_corasick::AhoCorasick;
use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use clap::Parser;
use log::{info, warn};
use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use vaporwall_common::PacketEvent;

#[derive(Parser)]
struct Opt {
    /// Interface to attach XDP program to. In Codespaces, use "lo" — no real NIC available.
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

/// Placeholder MVP signature set. These are deliberately generic/testable
/// strings, not real threat signatures — the point of this phase is proving
/// the Aho-Corasick fast path wires up end-to-end (automaton build once,
/// scan every packet's payload snippet in a single pass). Real signatures
/// (SQLi tokens, shellcode NOP sleds, known exploit headers) come from the
/// `rules/signatures.txt` file referenced in the README, which is a later
/// phase's concern — loading and hot-reloading a rules file is a separate
/// piece of work from the matching engine itself.
const TEST_SIGNATURES: &[&str] = &["EVIL_PAYLOAD", "malicious_string", "/etc/passwd"];

/// Builds the Aho-Corasick automaton once at startup. Building is the
/// expensive part (proportional to total pattern bytes); matching against
/// it afterward is fast and does not re-walk the pattern set per packet.
fn build_signature_matcher() -> anyhow::Result<AhoCorasick> {
    AhoCorasick::new(TEST_SIGNATURES).context("failed to build Aho-Corasick automaton")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opt = Opt::parse();

    let matcher = build_signature_matcher()?;
    info!(
        "Signature matcher loaded with {} pattern(s)",
        TEST_SIGNATURES.len()
    );

    #[cfg(debug_assertions)]
    let bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/vaporwall");
    #[cfg(not(debug_assertions))]
    let bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/release/vaporwall");

    let mut bpf = Ebpf::load(bytes)
        .context("failed to load eBPF object — did you run `cargo xtask build-ebpf` first?")?;

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

    let ring_buf: RingBuf<_> = bpf
        .take_map("EVENTS")
        .context("EVENTS map not found — name must match the #[map] static in vaporwall-ebpf")?
        .try_into()
        .context("EVENTS map is not a RingBuf — type mismatch between kernel and user space")?;

    let raw_fd = ring_buf.as_raw_fd();
    let async_fd =
        AsyncFd::new(raw_fd).context("failed to register ring buffer fd with the async reactor")?;
    let mut ring_buf = ring_buf;

    info!("Polling ring buffer for packet events (epoll-driven)...");

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            guard_result = async_fd.readable() => {
                let mut guard = guard_result
                    .context("async_fd reactor error while waiting for ring buffer readiness")?;

                while let Some(item) = ring_buf.next() {
                    if item.len() != core::mem::size_of::<PacketEvent>() {
                        log::warn!(
                            "ring buffer entry size mismatch: got {} bytes, expected {}",
                            item.len(),
                            core::mem::size_of::<PacketEvent>()
                        );
                        continue;
                    }
                    // SAFETY: PacketEvent is #[repr(C)] with no padding
                    // ambiguity, and both vaporwall-ebpf and vaporwall share
                    // this exact definition via vaporwall-common — sound
                    // reinterpretation of kernel-submitted bytes.
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

                    // Fast-path scan: only the captured snippet, only up to
                    // the kernel-reported valid length (trailing bytes in
                    // the fixed-size array are zero-padding, not real data).
                    let snippet_len = (event.snippet_len as usize).min(event.payload_snippet.len());
                    let snippet = &event.payload_snippet[..snippet_len];

                    if let Some(mat) = matcher.find(snippet) {
                        let pattern = TEST_SIGNATURES[mat.pattern().as_usize()];
                        warn!(
                            "SIGNATURE MATCH: pattern=\"{}\" src={}:{} dst={}:{}",
                            pattern,
                            Ipv4Addr::from(event.src_ip),
                            event.src_port,
                            Ipv4Addr::from(event.dst_ip),
                            event.dst_port
                        );
                    }
                }

                guard.clear_ready();
            }
            _ = &mut shutdown => {
                info!("Ctrl-C received, shutting down...");
                break;
            }
        }
    }

    info!("Detaching XDP program from '{}'...", opt.iface);
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
