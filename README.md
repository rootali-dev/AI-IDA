<div align="center">

# 🛡️ AI-IDA — Intelligent Defense Architecture

**Asynchronous, AI-driven, kernel-space packet filtering for the Linux network stack**

![Kernel](https://img.shields.io/badge/Kernel-XDP%2FeBPF-1793d1?style=flat-square)
![Core](https://img.shields.io/badge/Core-Rust%20(Aya)-dea584?style=flat-square)
![Control Plane](https://img.shields.io/badge/Control%20Plane-Go-00ADD8?style=flat-square)
![ML](https://img.shields.io/badge/Inference-Matrix--Free%20(m2cgen)-2ea44f?style=flat-square)
![Status](https://img.shields.io/badge/Status-Phase%202%20In%20Progress-yellow?style=flat-square)

</div>

---

AI-IDA (**I**ntelligent **D**efense **A**rchitecture) is an ultra-high-performance, programmable Linux kernel firewall subsystem engineered to neutralize volumetric and structural cyberattacks — DDoS floods, port scans, protocol amplification — directly at **line rate**, before they ever touch host CPU cycles.

It fuses **XDP** (eXpress Data Path) interception via **Rust/Aya** at the NIC driver layer with a non-blocking **Go** control plane driven by a matrix-free, compiled machine learning pipeline. Malicious traffic is dropped in nanoseconds, leaving host resources — even on budget hardware (Intel Core i3 class) — completely untouched.

> **Core Engineering Philosophy — Decouple Computation from the Data Path.**
> Traditional firewalls degrade under high PPS due to `sk_buff` allocation overhead and context-switch cost in the Linux network stack. AI-IDA bypasses this entirely via an asynchronous, three-tier architecture: deterministic kernel-space enforcement, lockless telemetry transport, and out-of-band user-space inference.

---

## 🧬 Architecture Overview
+-------------------------------------------------------------+

|                    PACKET INGRESS (NIC)                     |

+-------------------------------------------------------------+

|

v

+-------------------------------------------------------------+

| [KERNEL SPACE] - Rust / XDP Driver Layer (Aya)               |

|                                                               |

|  1. Token-Bucket Rate Limiter    (BPF_MAP_TYPE_PERCPU_HASH)  |

|  2. Static L4 Port Gate          (O(1) lookup)               |

|  3. Reputation / Signature Match (BPF_MAP_TYPE_LPM_TRIE)     |

|       |-- MATCH    -> XDP_DROP / XDP_TX (reflective RST)     |

|       |-- MISS     -> XDP_PASS                               |

|       `-- DISTRIBUTE -> XDP_REDIRECT (RSS-aware steering)    |

+-------------------------------------------------------------+

|                                            ^

(Lockless Ring Buffer: 24B Metadata)      (eBPF Map Update)

v                                            |

+-------------------------------------------------------------+

| [USER SPACE] - Go Runtime Control Plane                      |

|                                                               |

|  1. Lockless Ring Buffer Consumer  (zero-copy reads)         |

|  2. Flow Aggregator - Time-Window IAT Variant (100ms)        |

|  3. Concurrent Inference Engine    (Goroutine Worker Pool)   |

|        |                                                     |

|        v   Compiled ML Model (pure Go if/else, via m2cgen)   |

|      [Anomaly Detected -> P(malicious) > 0.85]                |

|        |                                                     |

|        v   Structural Pattern Extraction                     |

|      [Signature synthesized -> pushed to reputation_map]      |

+-------------------------------------------------------------+

---

## 🗺️ Memory Map Architecture

AI-IDA rejects naive global hash maps to avoid lock contention under concurrent multi-core packet processing:

| Map Type | Purpose | Concurrency Model |
|---|---|---|
| `BPF_MAP_TYPE_PERCPU_HASH` | Per-flow token-bucket rate limiting | Independent per-core state, zero cross-core lock contention |
| `BPF_MAP_TYPE_LPM_TRIE` | Subnet/ASN binary reputation enforcement | Longest-prefix-match, sub-linear lookup, RCU-safe map updates |

---

## ⚡ Core Engineering Features

### 1. In-Driver Ingress Filtering (Rust / eBPF)
- **Zero-Allocation Dropping** — malicious packets are destroyed via `XDP_DROP` before the kernel allocates an `sk_buff`, eliminating allocator pressure under flood conditions.
- **Stateless Token-Bucket Limiting** — implemented natively in eBPF context using `BPF_MAP_TYPE_PERCPU_HASH`, regulating per-flow burst rates with $O(1)$ lookup and no cross-CPU synchronization.
- **Static L4 Port Gating** — instantly drops traffic targeting unmapped endpoints, shielding internal OS routines from exposure.
- **Reflective Mitigation (`XDP_TX`)** — synthesizes TCP RST packets in-driver for stateless connection termination without round-tripping to user space.
- **Multi-Queue Steering (`XDP_REDIRECT`)** — redistributes ingress load across CPU queues/NICs for RSS-aware scaling.

### 2. High-Throughput Control Plane (Go)
- **Asynchronous Telemetry Layer** — consumes a lockless eBPF Ring Buffer carrying a compact **24-byte** structured metadata schema per flow, minimizing cross-boundary memory bandwidth.
- **Native Concurrency Engine** — a dedicated Goroutine worker pool handles flow aggregation and inference dispatch in parallel, preventing pipeline stalls under burst telemetry load.
- **Time-Window Flow Aggregator** — evaluates rolling 100ms windows rather than per-packet classification, enabling detection of distributed/IP-rotated botnet behavior.

### 3. Native Matrix-Free ML Inference
- **Zero Runtime Overhead** — LightGBM gradient-boosted trees are trained offline on CIC-IDS intrusion datasets, then compiled directly into native Go `if/else` conditional trees via a modified `m2cgen` pipeline.
- **Microsecond Execution Boundaries** — eliminates the Python interpreter from the production path entirely; inference cost is reduced to branch evaluation, not floating-point matrix multiplication.
- **Closed-Loop Signature Synthesis** — detected anomalies trigger structural pattern extraction, feeding new entries back into the kernel-space `LPM_TRIE` reputation map.

---

## 🔬 Mathematical Feature Engineering

AI-IDA classifies **flows**, not individual packets, via a dynamic Time-Window Flow Aggregator (100ms intervals) — neutralizing botnets that rely on IP rotation or spoofing to evade per-packet heuristics.

### Packet Inter-Arrival Time Standard Deviation ($IAT_{std}$)

$$\sigma = \sqrt{\frac{1}{N}\sum_{i=1}^{N}(t_i - \mu)^2}$$

> Human traffic exhibits natural high variance ($IAT_{std} > 50\text{ms}$); automated script/botnet engines emit tight, mechanical microsecond-precision patterns ($\sigma \approx 0$).

### Asymmetric Flow Density ($Ratio_{flow}$)

$$Ratio_{flow} = \frac{Packets_{Inbound}}{Packets_{Outbound}}$$

> Measures TCP handshake state compliance. Volumetric floods exhibit structural divergence ($Ratio_{flow} \gg 100$).

### Shannon Entropy of Destination Ports ($Entropy_{port}$)

$$H(P) = -\sum_{i=1}^{n} P(p_i)\log_2 P(p_i)$$

> Sharp entropy expansion on a single source IP signals systematic port enumeration (scanning behavior) rather than organic application traffic.

---

## 🎯 Production Mitigation Matrix

| Target Vector | Detection Metric | Mitigating Kernel Action |
|---|---|---|
| SYN Flood / Botnets | Asymmetric ingress $Ratio_{flow}$ + fixed TCP window anomalies | Dynamic signature → `signature_map` injection, `XDP_DROP` |
| TCP Port Scanning | Sharp $Entropy_{port}$ expansion on a single source IP | Source IP blocked globally via `reputation_map` (`LPM_TRIE`) |
| DNS / NTP Amplification | Surge in $Payload_{mean}$ originating from port 53/123 | Structural match on IP packet identification fields, `XDP_DROP` |

---

## 🛣️ Roadmap & Implementation Milestones

### Phase 1 — Zero-Feature Ingress Pipeline ✅ *Completed*
- [x] Cross-compilation toolchain: `bpf-linker` + Rust compiler target
- [x] Minimal XDP driver (Aya) — generic pass-through (`XDP_PASS`)
- [x] Raw telemetry line via lockless eBPF Ring Buffer → Go agent

### Phase 2 — Protocol Parsing & Static Controls 🔄 *In Progress*
- [ ] Robust L3/L4 header parsing in Rust driver space, verifier-safe
- [ ] $O(1)$ hash map configuration for port gating + static thresholds
- [ ] Kernel-level token-bucket primitives for stateless rate limiting

### Phase 3 — ML Integration & Structural Matching 🎯 *Target: Late Summer 2026*
- [ ] Finalize offline Python training pipeline on non-linear behavioral profiles
- [ ] Implement `m2cgen` code-generation pipe → native Go logic blocks
- [ ] Deploy automated pattern extraction: user-space AI insight → kernel-level eBPF signature constraints

> **Performance Verification Target**
> Maximum Processing Latency (kernel-space match): **< 10 ns**
> Target Line-Rate Capacity: **10 Gbps (14.8M PPS)** sustained on budget processor layouts (Intel Core i3 class)

---

<div align="center">
<sub>High-performance network security research project — convergence of low-level kernel subsystems and real-time behavioral AI.</sub>
</div>
