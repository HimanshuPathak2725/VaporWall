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
const TCP_HDR_MIN_LEN: usize = 20;
const TCP_HDR_MAX_LEN: usize = 60;
const UDP_HDR_LEN: usize = 8;
const PAYLOAD_SNIPPET_LEN: usize = 128;

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

/// Only the fields we need to compute the real TCP header length. The data
/// offset (top 4 bits of byte 12, counted in 32-bit words) tells us where
/// TCP options end and the actual payload begins — without this, a TCP
/// packet with options would have its trailing header bytes miscounted
/// as payload, polluting anything we later try to signature-match against.
#[repr(C)]
struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset_reserved: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent: u16,
}

/// Single-producer (kernel) -> multi-consumer (user-space) lockless ring.
/// 256 KiB, power-of-two sized as required by BPF_MAP_TYPE_RINGBUF.
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

    let l4_offset = ETH_HDR_LEN + IPV4_HDR_LEN;

    let (src_port, dst_port) = match protocol {
        IPPROTO_TCP | IPPROTO_UDP => {
            // SAFETY: same bounds-check contract as above, offset now points
            // past the fixed 20-byte IPv4 header (no options, checked above).
            let l4_hdr: *const L4Ports = unsafe { ptr_at(&ctx, l4_offset)? };
            (
                u16::from_be(unsafe { (*l4_hdr).src_port }),
                u16::from_be(unsafe { (*l4_hdr).dst_port }),
            )
        }
        _ => (0, 0), // e.g. ICMP: no ports, report zero rather than garbage
    };

    // Determine where the real payload starts, protocol-dependent. Getting
    // this wrong means "payload" bytes are actually trailing L4 header/option
    // bytes — silently poisoning any signature matching done downstream.
    let payload_offset: Option<usize> = match protocol {
        IPPROTO_TCP => {
            let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, l4_offset)? };
            let data_offset = ((unsafe { (*tcp_hdr).data_offset_reserved } >> 4) as usize) * 4;

            // A TCP header claiming less than the fixed 20-byte minimum or
            // more than the 60-byte maximum (4-bit field, max value 15 * 4)
            // is malformed — don't trust it as an offset into the packet.
            if !(TCP_HDR_MIN_LEN..=TCP_HDR_MAX_LEN).contains(&data_offset) {
                None
            } else {
                Some(l4_offset + data_offset)
            }
        }
        IPPROTO_UDP => Some(l4_offset + UDP_HDR_LEN),
        _ => None, // ICMP and others: no payload snippet captured in this MVP
    };

    let mut payload_snippet = [0u8; PAYLOAD_SNIPPET_LEN];
    let mut snippet_len: u16 = 0;

    if let Some(start) = payload_offset {
        // SAFETY: bpf_xdp_load_bytes performs its own kernel-side bounds
        // check of [start, start + PAYLOAD_SNIPPET_LEN) against the packet's
        // actual length and simply returns a non-zero error code if that
        // range would go out of bounds -- it never touches memory outside
        // the packet, so no unsafe memory access can occur here regardless
        // of what `start` is.
        //
        // We deliberately request a FIXED, compile-time-constant length
        // (PAYLOAD_SNIPPET_LEN) here rather than a dynamically computed
        // length based on (packet_len - start). That dynamic computation
        // is what caused repeated verifier rejections: LLVM's optimizer
        // proved the computed length was always >= 1 (correctly) and
        // eliminated the explicit lower-bound clamp that was meant to make
        // that fact visible to the verifier -- the verifier's own value-
        // range tracking through the subtraction/min chain did not carry
        // the same refinement, so it saw a possible zero-length read and
        // rejected the call. A fixed constant length sidesteps this
        // entirely: the verifier only needs to prove 128 > 0 (trivial) and
        // that payload_snippet is at least 128 bytes (trivially true by
        // construction), no packet-length arithmetic involved.
        //
        // Trade-off: packets with fewer than PAYLOAD_SNIPPET_LEN payload
        // bytes will fail this call and get snippet_len = 0 (no signature
        // match attempted). This is acceptable for the MVP; revisit if
        // small-payload matching becomes a requirement.
        let ret = unsafe {
            aya_ebpf::helpers::bpf_xdp_load_bytes(
                ctx.ctx,
                start as u32,
                payload_snippet.as_mut_ptr() as *mut core::ffi::c_void,
                PAYLOAD_SNIPPET_LEN as u32,
            )
        };

        if ret == 0 {
            snippet_len = PAYLOAD_SNIPPET_LEN as u16;
        }
    }

    let payload_len = (ctx.data_end() - ctx.data()) as u32;

    let event = PacketEvent {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        _reserved: 0,
        snippet_len,
        payload_len,
        payload_snippet,
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
