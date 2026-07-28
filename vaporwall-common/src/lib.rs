#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketEvent {
    pub src_ip: u32,   // offset 0,  size 4
    pub dst_ip: u32,   // offset 4,  size 4
    pub src_port: u16, // offset 8,  size 2
    pub dst_port: u16, // offset 10, size 2
    pub protocol: u8,  // offset 12, size 1
    pub _reserved: u8, // offset 13, size 1  -- explicit, replaces what
    //   would otherwise be invisible compiler padding
    pub snippet_len: u16,           // offset 14, size 2
    pub payload_len: u32,           // offset 16, size 4
    pub payload_snippet: [u8; 128], // offset 20, size 128
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}
