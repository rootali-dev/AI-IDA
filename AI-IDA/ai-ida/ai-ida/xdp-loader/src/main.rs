use aya::{Bpf, programs::{Xdp, XdpFlags}};
use std::convert::TryInto;
use anyhow::Context;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Load the compiled eBPF ELF from the target directory
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/release/ai-ida-ebpf")
        .context("failed to load eBPF object file. Did you run `cargo build` in the workspace root?")?;
    
    // Extract the XDP program defined in our eBPF code
    let program: &mut Xdp = bpf.program_mut("ai_ida_xdp")
        .context("ai_ida_xdp program not found in ELF")?
        .try_into()
        .context("program is not XDP type")?;
        
    // Load the program into the kernel (triggers the Linux Verifier)
    program.load()?;
    
    // Attach to the network interface.
    // Trade-off: DRV_MODE (Native XDP) requires NIC driver support (e.g., ixgbe, i40e, virtio_net).
    // If testing on a VM without SR-IOV/virtio XDP support, fallback to XdpFlags::SKB_MODE.
    let iface = "eth0"; // CHANGE THIS to your actual network interface
    program.attach(iface, XdpFlags::DRV_MODE)
        .context(format!("failed to attach XDP program to {}", iface))?;
        
    println!("AI-IDA Phase 1: XDP Driver attached in DRV_MODE. Intercepting traffic on {}...", iface);
    println!("Press Ctrl+C to detach and exit.");
    
    // Keep the program alive until interrupted
    tokio::signal::ctrl_c().await?;
    
    // Cleanup
    program.detach()?;
    println!("XDP program detached.");
    
    Ok(())
}
