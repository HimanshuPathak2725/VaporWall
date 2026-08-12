#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};
use vaporwall_common::PacketEvent;

const ETH_P_IPV4: u16 = 0x0800;
const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const TCP_HDR_MIN_LEN: usize = 20;
const TCP_HDR_MAX_LEN: usize = 60;
const UDP_HDR_LEN: usize = 8;
const PAYLOAD_SNIPPET_LEN: usize = 128;

#[repr(C)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    ether_type: u16,
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

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 18, 0);

#[xdp]
pub fn vaporwall(ctx: XdpContext) -> u32 {
    match try_vaporwall(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

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
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let ether_type = u16::from_be(unsafe { (*eth_hdr).ether_type });

    if ether_type != ETH_P_IPV4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, ETH_HDR_LEN)? };
    let ihl = unsafe { (*ip_hdr).version_ihl } & 0x0F;

    if ihl != 5 {
        return Ok(xdp_action::XDP_PASS);
    }

    let protocol = unsafe { (*ip_hdr).protocol };
    let src_ip = u32::from_be(unsafe { (*ip_hdr).src_addr });
    let dst_ip = u32::from_be(unsafe { (*ip_hdr).dst_addr });

    let l4_offset = ETH_HDR_LEN + IPV4_HDR_LEN;

    let (src_port, dst_port) = match protocol {
        IPPROTO_TCP | IPPROTO_UDP => {
            let l4_hdr: *const L4Ports = unsafe { ptr_at(&ctx, l4_offset)? };
            (
                u16::from_be(unsafe { (*l4_hdr).src_port }),
                u16::from_be(unsafe { (*l4_hdr).dst_port }),
            )
        }
        _ => (0, 0),
    };

    // payload_offset AND seq are both derived from the TCP header, so
    // compute them together to avoid re-fetching/re-bounds-checking the
    // same pointer twice.
    let mut seq: u32 = 0;
    let payload_offset: Option<usize> = match protocol {
        IPPROTO_TCP => {
            let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, l4_offset)? };
            let data_offset = ((unsafe { (*tcp_hdr).data_offset_reserved } >> 4) as usize) * 4;

            if !(TCP_HDR_MIN_LEN..=TCP_HDR_MAX_LEN).contains(&data_offset) {
                None
            } else {
                seq = u32::from_be(unsafe { (*tcp_hdr).seq });
                Some(l4_offset + data_offset)
            }
        }
        IPPROTO_UDP => Some(l4_offset + UDP_HDR_LEN),
        _ => None,
    };

    let mut payload_snippet = [0u8; PAYLOAD_SNIPPET_LEN];
    let mut snippet_len: u16 = 0;

    if let Some(start) = payload_offset {
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
        seq,
        payload_snippet,
    };

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
