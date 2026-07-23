#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

/// Entry point jo kernel XDP hook se call hota hai — har incoming frame ke liye.
/// Return value kernel ko batata hai kya karna hai: PASS, DROP, ABORTED, etc.
#[xdp]
pub fn vaporwall(ctx: XdpContext) -> u32 {
    match try_vaporwall(ctx) {
        Ok(action) => action,
        // SAFETY: verifier ke liye — koi bhi unexpected error path pe
        // hum ABORTED return karte hain, kabhi panic nahi (panic = infinite loop
        // in eBPF context, jo verifier allow nahi karega agar reachable ho without bound).
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Phase 1: sirf PASS. Koi packet parsing abhi nahi — woh Phase 2+ mein aayega
/// jab hume actual header parse karke drop decision lena hoga.
fn try_vaporwall(_ctx: XdpContext) -> Result<u32, ()> {
    Ok(xdp_action::XDP_PASS)
}

// #[panic_handler] REQUIRED hai kyuki hum #![no_std] hain — normal Rust ka
// panic runtime (unwinding, stderr print) kernel space mein exist hi nahi karta.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
