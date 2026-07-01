#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};

/// 24-byte flow metadata for Telemetry.
/// Enforced sizing guarantees predictable eBPF map allocation and memory alignment.
#[repr(C)]
pub struct FlowMetadata {
    pub src_ip: u32,      // 4 bytes (Offset 0)
    pub dst_ip: u32,      // 4 bytes (Offset 4)
    pub src_port: u16,    // 2 bytes (Offset 8)
    pub dst_port: u16,    // 2 bytes (Offset 10)
    pub protocol: u8,     // 1 byte  (Offset 12)
    pub _pad: [u8; 11],   // 11 bytes(Offset 13) - Explicit padding for 24-byte boundary
}

// 256KB Ring Buffer for lockless telemetry export.
// Trade-off: Consumes 256KB of locked kernel memory.
#[map]
pub static PACKET_RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[xdp]
pub fn ai_ida_xdp(_ctx: XdpContext) -> u32 {
    // VERIFIER: Phase 1 minimal pass-through. 
    // We are not dereferencing packet pointers yet, so no bounds checks are required.
    // L3/L4 parsing and verifier-safe pointer arithmetic will be added in Phase 2.
    xdp_action::XDP_PASS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // eBPF programs cannot panic normally; we tell the compiler this branch is unreachable.
    unsafe { core::hint::unreachable_unchecked() }
}
