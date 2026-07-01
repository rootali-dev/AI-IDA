use aya::{programs::{Xdp, XdpFlags}, Bpf};
use std::convert::TryInto;
use anyhow::Context;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/release/ai-ida-ebpf")
        .context("failed to load eBPF object file.")?;
    
    let program: &mut Xdp = bpf.program_mut("ai_ida_xdp")
        .context("ai_ida_xdp program not found in ELF")?
        .try_into()
        .context("program is not XDP type")?;
        
    program.load()?;
    
    // CHANGE THIS to your actual interface (e.g., eth0, enp3s0, ens33)
    let iface = "eth0"; 
    program.attach(iface, XdpFlags::DRV_MODE)
        .context(format!("failed to attach XDP program to {}", iface))?;
        
    println!("AI-IDA Phase 1: XDP Driver attached in DRV_MODE. Intercepting traffic on {}...", iface);
    println!("Press Ctrl+C to detach and exit.");
    
    tokio::signal::ctrl_c().await?;
    
    program.detach()?;
    println!("XDP program detached.");
    
    Ok(())
}
