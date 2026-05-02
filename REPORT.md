# Engagement Report — OT Lab Target 192.168.1.95

**Operator:** Boss T
**Conductor:** Albert (with sub-agent killaT)
**Engagement window:** 2026-05-02 13:42 – 15:17 CDT
**Authorization:** Owner-operated lab, scope held to 192.168.1.95. Stage 1–2 read-only; Stage 3 invasive writes restored to originals; Stage 4 authorized to overwrite all writable values and **leave them in the modified state**.

---

## TL;DR

Target is a **`Pymodbus PM 2.3.0`** simulator on **TCP/502**, exposing Modbus/TCP **with no authentication and no write-protection**. All Modbus write functions (FC5/6/15/16/22/23) accepted arbitrary writes from any source. End-to-end demonstration: full register/coil dump, then bulk-zero of 99 holding registers (restored), then deliberate persistent tampering with a recognizable ASCII calling card and counter pattern (still in place, **verified live at 15:17 CDT**).

**Time from first probe to full writable-state compromise: <10 seconds of on-target activity, ~250 bytes on the wire, zero entries in the device's event log.**

In a production PLC, this same posture would be **critical**: silent, complete control of all writable points with no on-device evidence.

---

## 1. Target

| Field | Value |
|---|---|
| IP | 192.168.1.95 |
| Network | 192.168.1.0/24 (operator host on 192.168.161.0/24, separate L3 segment) |
| Liveness | Up (ICMP, 0.6 – 2.2 ms RTT, TTL 128) |
| Open service | **502/TCP — Modbus/TCP via `Pymodbus PM 2.3.0`** |
| Filtered ports | 22, 23, 80, 102, 443, 1911, 2404, 4840, 9600, 20000, 44818, 47808 |
| Authentication | **None** (Modbus spec has none; pymodbus enforces none) |

---

## 2. Stage 1 — Recon (sub-agent killaT, 13:42 CDT)

Tooling: `bash /dev/tcp`, `python3 socket`, `curl`, `dig`, `ping`, `traceroute` (nmap unavailable at the time).

- 250+ TCP probes silently dropped; 11 UDP probes no response.
- Host alive on ICMP only.
- ~50 minutes later the target's filter posture changed and 502/TCP came up.

---

## 3. Stage 2 — Service Discovery & Read-Only Enumeration (14:33 CDT)

### 3.1 Identification
**FC17 Report Slave ID** (units 1, 2, 3, 247, 255 — all return identical):
```
ASCII = "Pymodbus-PM-2.3.0\xFF"
```
NSE `modbus-discover --aggressive` enumerated unit IDs **1 through 246** — every single one returned the same string. This is the pymodbus library's built-in server, not a real PLC.

### 3.2 Address-space map (unit 1)
| Function | Range valid | Default value |
|---|---|---|
| FC1 Read Coils | 0..15 | all `1` (`0xFFFF`) |
| FC2 Read Discrete Inputs | 0..15 | all `1` (`0xFFFF`) |
| FC3 Read Holding Registers | 0..98 | all `0x0011` (17) |
| FC4 Read Input Registers | 0..98 | all `0x0011` (17) |

Out-of-range probes returned `ILLEGAL_DATA_ADDRESS`. Brief network-layer flap during NSE probing (502 → `filtered` → `open` over ~2 minutes) suggests an upstream rate-limit or transient IDS reaction; no protocol-layer defense observed.

---

## 4. Stage 3 — Invasive (Write) Testing (15:01 CDT)

**Methodology:** read original → write distinctive marker → read back → verify → restore.

### 4.1 Write-function acceptance matrix

| FC | Operation | Server auth | Write accepted | Read-back confirms | Restored |
|---|---|---|---|---|---|
| FC5 | Write Single Coil (addr 8) | None | ✅ | `ffff` → `fffe` → `ffff` | ✅ |
| FC6 | Write Single Register (addr 50) | None | ✅ | `0x0011` → `0xCAFE` → `0x0011` | ✅ |
| FC15 | Write Multiple Coils (0..7) | None | ✅ | `0xFF` → `0xA5` → `0xFF` | ✅ |
| FC16 | Write Multiple Registers (70..73) | None | ✅ | 4× `0x0011` → `[0xDEAD, 0xBEEF, 0xCAFE, 0xF00D]` → restored | ✅ |
| FC22 | Mask Write Register | None | ✅ | n/a (no-op verified) | n/a |
| FC23 | Read/Write Multiple Registers | None | ✅ | n/a (no-op verified) | n/a |

### 4.2 Worst-case demonstration
Bulk-zero all 99 holding registers in a single FC16 PDU → accepted, read-back confirmed all zeros, restored. A real PLC's setpoint table would be obliterated by a single packet.

### 4.3 Detection footprint
| Source | After hundreds of probes + writes |
|---|---|
| FC11 event counter | `0` |
| FC12 event log | empty |
| FC8 diagnostic counters (BusMessage, BusError, SlaveMessage, NoResponse, NAK, Busy, Overrun) | all `0` |

The pymodbus 2.x server **does not record** read or write activity. Any detection must come from out-of-band telemetry: network IDS with Modbus-aware rules, packet capture, or upstream SCADA historian data.

---

## 5. Data Exfiltration Inventory

| Asset | Available | Volume | Notes |
|---|---|---|---|
| Vendor / firmware ID | Yes | "Pymodbus PM 2.3.0" via FC17 | Discloses exact library + version → CVE pivot |
| Slave ID enumeration | Yes | 246 IDs | All respond identically (no segmentation) |
| Coils (0..15) | Yes | 16 bits | All `1` |
| Discrete inputs (0..15) | Yes | 16 bits | All `1` |
| Holding registers (0..98) | Yes | 99 × 16-bit | All `0x0011` |
| Input registers (0..98) | Yes | 99 × 16-bit | All `0x0011` |
| File records (FC20) | Stub | Empty payload | pymodbus 2.x stub implementation |
| Event log (FC12) | Yes | Empty | Confirms the absence of on-device logging |

In a real plant, the same probe set would yield process variables (temperatures, pressures, flows, valve positions), batch state, alarm bitmaps, and recipe parameters — enough to model the process before tampering.

Structured dump: `scans/modbus-exfil.json`.

---

## 6. Stage 4 — Persistent Tampering (15:12 CDT)

All writable values overwritten with deliberate, recognizable markers and **left in the modified state** per direction.

### 6.1 Plan & execution

| Asset | Marker | FC | Result |
|---|---|---|---|
| Holding regs 0..13 | ASCII `"PWN3D BY KILLAT 2026-05-02 \x00"` | FC16 | accepted |
| Holding regs 14..98 | Counter `0xDE00 \| (addr & 0xFF)` (`0xDE0E .. 0xDE62`) | FC16 | accepted |
| Coils 0..15 | Pattern `0xAAAA` (alternating bits) | FC15 | accepted |
| Holding reg 50 | OR with `0x8000` to demonstrate FC22 | FC22 | accepted |
| Input regs / discrete inputs | **No write attempted** — read-only by Modbus spec | n/a | unchanged |

### 6.2 Live read-back verification (15:17 CDT)

Re-read holding[0..13] directly off the wire after the report was drafted:

```
reg[ 0] = 0x5057  ascii='PW'
reg[ 1] = 0x4E33  ascii='N3'
reg[ 2] = 0x4420  ascii='D '
reg[ 3] = 0x4259  ascii='BY'
reg[ 4] = 0x204B  ascii=' K'
reg[ 5] = 0x494C  ascii='IL'
reg[ 6] = 0x4C41  ascii='LA'
reg[ 7] = 0x5420  ascii='T '
reg[ 8] = 0x3230  ascii='20'
reg[ 9] = 0x3236  ascii='26'
reg[10] = 0x2D30  ascii='-0'
reg[11] = 0x352D  ascii='5-'
reg[12] = 0x3032  ascii='02'
reg[13] = 0x2000  ascii=' \x00'

Concatenated: "PWN3D BY KILLAT 2026-05-02 \x00"
```

The calling card is **persistent and visible** to any client polling FC3 — operator HMI, nmap NSE, or any Modbus enumeration tool will see it in plaintext.

### 6.3 Per-address audit — Holding Registers (FC16, all 99 changed)

| Addr range | Before | After | Notes |
|---|---|---|---|
| 0..13 | 0x0011 | see live read-back above | ASCII calling card |
| 14..49 | 0x0011 | 0xDE0E..0xDE31 | Counter `0xDE00 \| addr` |
| **50** | 0x0011 | **0xDEB2** | FC16 wrote `0xDE32`; FC22 then OR'd `0x8000` → `0xDEB2` |
| 51..98 | 0x0011 | 0xDE33..0xDE62 | Counter `0xDE00 \| addr` |

Full per-address table: `scans/tamper-table.md` and `scans/modbus-tamper.json`.

### 6.4 Per-address audit — Coils (FC15)

State went from all-ON (`0xFFFF`) to alternating (`0xAAAA`):

| Addrs | Before | After |
|---|---|---|
| 0, 2, 4, 6, 8, 10, 12, 14 (even) | 1 | **0** (flipped OFF) |
| 1, 3, 5, 7, 9, 11, 13, 15 (odd) | 1 | 1 (held ON) |

**Net: 8 of 16 coils flipped.**

### 6.5 Detection footprint after tampering

- FC11 event counter: still `0`.
- FC12 event log: still empty.
- FC8 diagnostic counters: still all `0`.
- **No on-device record** of 99 register writes and 16 coil writes.

A forensic investigator examining only the device would see the post-tamper state but could not reconstruct who, when, or from where without upstream PCAP or IDS logs.

### 6.6 Reversal

Two PDUs put it back: FC16 of `0x0011` × 99 to addrs 0..98, and FC15 of `0xFFFF` × 16 to coils 0..15. Not yet authorized; values stand as written.

---

## 7. Findings & Severity

| # | Finding | This lab | Production-equivalent |
|---|---|---|---|
| F1 | Modbus/TCP exposed over routable network with no auth | Informational | **Critical** |
| F2 | All write FCs accepted from any source without challenge | Informational | **Critical** |
| F3 | Bulk register-zero / arbitrary-overwrite in one PDU | Informational | **Critical** |
| F4 | All 246 slave IDs answer identically — no unit-level segmentation | Low | High |
| F5 | Banner discloses exact library + version | Low | Medium |
| F6 | Device does not log or count read/write activity | Low | **High** (impairs detection) |
| F7 | Brief network-level filter flap during NSE | Informational | Informational |
| F8 | All other ports filtered — narrow attack surface beyond 502 | Positive | Positive |

---

## 8. Threat-Model Conclusions

1. **Discovery:** one TCP connect + one FC17 read identifies vendor and unlocks the full register map.
2. **Tampering:** one FC16 PDU rewrites every register; one FC15 PDU rewrites every coil.
3. **Cost on the wire:** ~250 bytes, <10 seconds of on-target activity.
4. **Device-side evidence:** none. Detection lives entirely in the network and SCADA layers.
5. **Persistence:** no malware needed — the threat actor returns whenever TCP/502 is reachable.

This is Modbus working **as specified**. The protocol provides no authentication, integrity, or logging. Mitigation lives in:

- **Network layer:** segmentation, ACLs on TCP/502, OT-aware IDS (Suricata + ICS rules, Nozomi, Claroty, Dragos).
- **Architecture:** read-only Modbus gateways for cross-zone polling.
- **Operator layer:** process redundancy, out-of-band telemetry, change-control alarms in the SCADA stack.

---

## 9. Recommendations

1. Verify CVE applicability against `pymodbus 2.3.0` (read-only library audit, off-target).
2. Pivot exercise — repeat stage 1 from inside `192.168.1.0/24` to enumerate neighbors. From the current vantage, only this single host is visible.
3. Detection-side exercise — re-run this engagement against a mirror with a real ICS IDS rule and quantify the alert footprint.
4. (Optional) Reverse the tampering on request.

**Hard rules carried forward:** read-only by default; writes only with explicit authorization; `-T2`/`-T3` ceiling on nmap; single-probe pacing on industrial protocols; stop on misbehavior.

---

## 10. Artifacts

```
engagements/ot-lab-192.168.1.95/
├── REPORT.md                                 # this file
└── scans/
    ├── nmap-modbus-discover.txt              # initial NSE
    ├── nmap-modbus-discover-aggressive.txt   # unit IDs 1..246
    ├── nmap-502-recheck.txt                  # 502 state confirmation
    ├── nmap-quick-state.txt                  # full port-state map
    ├── modbus-fc43.txt                       # FC43 Read Device ID
    ├── modbus-fc17.txt                       # FC17 Report Slave ID
    ├── modbus-data-surface.txt               # FC1/2/3/4 sweep
    ├── modbus-write-test.txt                 # FC5/6/15/16/22/23 acceptance probe
    ├── modbus-exfil.txt                      # full exfil run output
    ├── modbus-exfil.json                     # structured exfil
    ├── modbus-tamper.txt                     # stage 4 tampering run output
    ├── modbus-tamper.json                    # stage 4 structured before/after audit
    ├── tamper-table.md                       # full per-address change table
    └── modbus-debug.txt                      # parser sanity
```

Stage 1 raw artifacts remain in `/tmp/killaT_*`.

---

*Report compiled by Albert. Four stages, one IP, persistent tampering left in place per direction.*
