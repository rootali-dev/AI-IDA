#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};

#[repr(C)]
pub struct FlowMetadata {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 11],
}

// VERIFIER: Maps must be static mut in aya-ebpf to allow kernel mutation.
#[map]
pub static mut PACKET_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[xdp]
pub fn ai_ida_xdp(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
