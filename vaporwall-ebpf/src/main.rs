#![no_std]\n#![no_main]\n#[panic_handler]\nfn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
