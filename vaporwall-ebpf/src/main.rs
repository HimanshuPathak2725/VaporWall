#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};
use vaporwall_common::PacketEvent;

// --- Protocol constants (IANA / IEEE assigned numbers, not magic values) ---
const ETH_P_IPV4: u16 = 0x0800;
const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20; // no-options case only, see ihl check below
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// --- Minimal wire-format header structs ---
// repr(C) with explicit byte widths so the layout matches the actual bytes
// on the wire exactly — no compiler-inserted padding is allowed here since
// we're reinterpreting raw packet memory, not a Rust-native struct.
#[repr(C)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    ether_type: u16, // network byte order (big-endian) — must from_be() it
}

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    total_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
}

#[repr(C)]
struct L4Ports {
    src_port: u16,
    dst_port: u16,
}

/// Single-producer (kernel) -> multi-consumer (user-space) lockless ring.
/// 256 KiB, power-of-two sized as required by BPF_MAP_TYPE_RINGBUF.
/// Sized generously relative to a 24-byte PacketEvent so a burst of packets
/// doesn't immediately fill the ring before user-space gets a chance to drain it.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

#[xdp]
pub fn vaporwall(ctx: XdpContext) -> u32 {
    match try_vaporwall(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // malformed/truncated packet: let the
                                        // normal kernel stack decide what to do
                                        // with it, we simply skip telemetry.
    }
}

/// SAFETY: caller must ensure `offset + size_of::<T>()` has already been
/// bounds-checked against `ctx.data_end()` before dereferencing the returned
/// pointer. This function itself performs that check and returns Err(()) if
/// it would go out of bounds — the verifier can statically see this check
/// because it's a simple integer comparison, satisfying its bounds-proof
/// requirement for every subsequent pointer dereference.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_vaporwall(ctx: XdpContext) -> Result<u32, ()> {
    // SAFETY: ptr_at performs the bounds check internally; if it returns Ok,
    // the read of size_of::<EthHdr>() bytes starting at `offset` is proven
    // in-bounds relative to ctx.data_end().
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let ether_type = u16::from_be(unsafe { (*eth_hdr).ether_type });

    // Phase 2 MVP: only IPv4 is parsed. IPv6/ARP/etc. pass through untouched
    // rather than being mis-parsed as IPv4.
    if ether_type != ETH_P_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, ETH_HDR_LEN)? };
    let ihl = unsafe { (*ip_hdr).version_ihl } & 0x0F;

    // ihl == 5 means a 20-byte header with no IPv4 options. Options are not
    // handled in this MVP — passing through here rather than silently
    // misreading option bytes as if they were the L4 header.
    if ihl != 5 {
        return Ok(xdp_action::XDP_PASS);
    }

    let protocol = unsafe { (*ip_hdr).protocol };
    let src_ip = u32::from_be(unsafe { (*ip_hdr).src_addr });
    let dst_ip = u32::from_be(unsafe { (*ip_hdr).dst_addr });

    let (src_port, dst_port) = match protocol {
        IPPROTO_TCP | IPPROTO_UDP => {
            // SAFETY: same bounds-check contract as above, offset now points
            // past the fixed 20-byte IPv4 header (no options, checked above).
            let l4_hdr: *const L4Ports = unsafe { ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN)? };
            (
                u16::from_be(unsafe { (*l4_hdr).src_port }),
                u16::from_be(unsafe { (*l4_hdr).dst_port }),
            )
        }
        _ => (0, 0), // e.g. ICMP: no ports, report zero rather than garbage
    };

    let payload_len = (ctx.data_end() - ctx.data()) as u32;

    let event = PacketEvent {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        payload_len,
        _padding: 0,
    };

    // Reserve space in the ring buffer for this event. If the ring is full
    // (user-space consumer is lagging or has died), `reserve` returns None —
    // we do NOT block the hot path and we do NOT drop the packet itself.
    // Telemetry loss under backpressure is acceptable; adding latency or
    // dropping legitimate traffic to protect telemetry is not.
    if let Some(mut entry) = EVENTS.reserve::<PacketEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
