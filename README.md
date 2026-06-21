# 🛡️ AI-IDA: Next-Generation AI-Powered Linux Kernel Firewall

```
    +-----------------------------------------------------------+
    |                    PACKET INGRESS (NIC)                   |
    +-----------------------------------------------------------+
                                  |
                                  v
    +-----------------------------------------------------------+
    | [KERNEL SPACE] - Rust / XDP Driver Layer                  |
    |                                                           |
    |   1. Fast Port Filter & Token Bucket Rate Limiter         |
    |   2. Lookup Static Maps (reputation_map / signature_map)  |
    |      ├── MATCH -> XDP_DROP (Nanoseconds)                  |
    |      └── MISS  -> XDP_PASS                                |
    +-----------------------------------------------------------+
              |                                       ^
    (Ring Buffer: 24B Meta)                 (eBPF Map Updates)
              v                                       |
    +-----------------------------------------------------------+
    | [USER SPACE] - Go Runtime Control Plane                   |
    |                                                           |
    |   ├── 1. High-Speed Ring Buffer Consumer                  |
    |   ├── 2. Flow Aggregator & IAT (Time-Window Variant)      |
    |   └── 3. Concurrent Inference Engine (Worker Pool)        |
    |            │                                              |
    |            ▼ Compiled ML Model (Pure Go if/else)          |
    |          [Anomaly Detected (Probability > 0.85)]          |
    |            │                                              |
    |            ▼ Dynamic Feature Pattern Mining               |
    |          [Extract Structural Attack Signature]            |
    +-----------------------------------------------------------+
```

AI-IDA (Intelligent Defense Architecture) is an ultra-high-performance, programmable Linux kernel firewall subsystem designed to mitigate volumetric and structural cyberattacks (such as DDoS and advanced network scans) at the line rate. 

By leveraging **XDP (eXpress Data Path)** via **Rust (Aya)** at the network driver level and a non-blocking **Go control plane** driven by a compiled machine learning pipeline, AI-IDA drops malicious traffic in **nanoseconds**, keeping host system resources (even on low-tier CPUs like Intel Core i3) completely untouched.

> [!NOTE]
> **Core Engineering Philosophy:** Decouple Computation from the Data Path. Traditional firewalls degrade under high packets-per-second (PPS) due to context switching and `sk_buff` allocation overhead in the Linux network stack. AI-IDA bypasses this entirely using an asynchronous, three-tier architecture.

## ⚡ Core Engineering Features

### 1. In-Driver Ingress Filtering (Rust/eBPF)
* **Zero-Allocation Dropping:** Malicious packets are destroyed using `XDP_DROP` before the kernel allocates an `sk_buff` buffer, providing resilient immunity against infrastructure exhaustion.
* **Stateless Token-Bucket Limiting:** Implemented directly inside the eBPF context to regulate raw burst rates per IP flow with $O(1)$ lookup complexity.
* **Static Layer 4 Port Gating:** Instantly drops traffic targeted at unmapped endpoints, shielding critical OS internal routines.

### 2. High-Throughput Control Plane (Go)
* **Asynchronous Telemetry Layer:** Communicates with the kernel space via lockless `eBPF Ring Buffers` sending a compact, **24-byte** structured metadata schema per packet flow to conserve cross-boundary memory bandwidth.
* **Native Concurrency Engine:** Uses an engineered worker pool pattern with dedicated `Goroutines` to handle flow aggregation, preventing any pipeline stalls.

### 3. Native Matrix-Free ML Inference
* **Zero Runtime Overhead Optimization:** Models are trained offline using gradient-boosted decision trees (**LightGBM**) on standard intrusion datasets (CIC-IDS) and compiled directly into native Go `if/else` conditional primitives via customized parsing pipelines.
* **Microsecond Execution Boundaries:** Eliminates the Python runtime/interpreter from the production environment, reducing floating-point model inference cost down to a few CPU cycles.

## 🔬 Mathematical Feature Engineering & Attack Vector Mitigation

Instead of classifying individual packets, AI-IDA evaluates a dynamic **Time-Window Flow Aggregator** (e.g., 100ms intervals). This enables the firewall to neutralize complex botnets utilizing IP rotation or spoofing.

### Feature Matrix Formulae

**Packet Inter-Arrival Time Standard Deviation ($IAT_{std}$):**

$$\sigma = \sqrt{\frac{1}{N}\sum_{i=1}^{N}(t_i - \mu)^2}$$

> [!TIP]
> Human traffic exhibits natural high variance ($IAT_{std} > 50\text{ms}$), whereas automated script/botnet engines emit tight, mechanical microsecond patterns ($\sigma \approx 0$).

**Asymmetric Flow Density ($Ratio_{flow}$):**

$$Ratio_{flow} = \frac{\text{Packets}_{Inbound}}{\text{Packets}_{Outbound}}$$

> [!TIP]
> Measures TCP handshake state compliance. Volumetric floods show structural divergence ($Ratio_{flow} \gg 100$).

**Shannon Entropy of Destination Ports ($Entropy_{port}$):**

$$H(P) = -\sum_{i=1}^{n} P(p_i) \log_2 P(p_i)$$

### Production Mitigation Vectors

| Target Vector | Detection Metric | Mitigating Kernel Action |
| :--- | :--- | :--- |
| **SYN Flood / Botnets** | Asymmetric ingress $Ratio_{flow}$ + Fixed TCP Windows | Dynamic identification matching -> `signature_map` injection |
| **TCP Port Scanning** | Sharp expansion of $Entropy_{port}$ on local IP | Offending source IP blocked globally via `reputation_map` |
| **DNS/NTP Amplification** | Sudden surge in $Payload_{mean}$ originating from port 53/123 | Adaptive structural match on IP Packet Identification parameters |

## 🛠️ System Roadmap & Current Implementation Milestones

### Phase 1: Zero-Feature Ingress Pipeline (Completed)
- [x] Configure cross-compilation infrastructure for `bpf-linker` & Rust compiler toolchain.
- [x] Implement minimal XDP driver using `Aya` returning generic pass-through (`XDP_PASS`).
- [x] Establish raw telemetry line via lockless `eBPF Ring Buffer` pushing to the Go agent.

### Phase 2: Protocol Parsing & Static Controls (In Progress)
- [ ] Implement robust Layer 3/4 header parsing inside Rust driver space safely passing the eBPF Verifier checks.
- [ ] Add active $O(1)$ Hash Map configurations for port gating and static threshold constraints.
- [ ] Implement kernel-level Token-Bucket tracking primitives for stateless rate limiting.

### Phase 3: ML Integration & Structural Matching (Target: Late Summer 2026)
- [ ] Finalize offline Python training pipeline based on non-linear behavioral profiles.
- [ ] Implement the `m2cgen` code generation pipe translating tree nodes into native Go logic blocks.
- [ ] Deploy the automated pattern extraction routine to convert User-Space AI insights into precise kernel-level eBPF signature constraints.

> [!WARNING]
> **Performance Verification Target:** AI-IDA is architected to perform optimally under severe enterprise networking constraints. Maximum Processing Latency (Kernel Space Match) must remain $< 10$ nanoseconds, and Target Line-Rate Capacity must scale up to 10 Gbps (14.8 Million Packets Per Second) on budget processor layouts like Intel Core i3.

---
*Developed as a high-performance network security research project focused on the convergence of low-level kernel subsystems and real-time behavioral artificial intelligence.*
