#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub payload_len: u32,
    pub _padding: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}
