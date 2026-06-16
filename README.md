# Network Access Control (NAC) Lab — 802.1X with Dynamic VLAN Assignment & Endpoint Posture Enforcement

A from-scratch, fully virtualized NAC solution built on open-source components, reproducing the behaviour of enterprise NAC platforms (Cisco ISE, Aruba ClearPass) on a home lab. The project implements all three pillars of Network Access Control — **authentication**, **posture assessment**, and **enforcement** — and documents not just the working configuration but the real protocol-level problems encountered and how each was diagnosed and solved.

> **Why this exists:** Most NAC tutorials stop at "802.1X authenticates a user." This lab goes further: it enforces network segmentation dynamically via RADIUS, then closes the loop with endpoint posture checks that detect unauthorized remote-access software (AnyDesk, TeamViewer, RustDesk) and quarantine the offending device live via RADIUS Change-of-Authorization.

---

## The three pillars of NAC

A NAC verifies the identity and the state of a device before granting it network access, then applies a decision: full access, restricted (quarantine) access, or block.

| Pillar | Question it answers | Implemented with |
|--------|---------------------|------------------|
| **Authentication** | *Who is this device/user?* | 802.1X (PEAP/MSCHAPv2) + FreeRADIUS |
| **Posture assessment** | *Is this device compliant?* | Endpoint scanners (PowerShell + Bash) detecting prohibited software |
| **Enforcement** | *What access does it get?* | Dynamic VLAN assignment via `Tunnel-Private-Group-Id` + RADIUS CoA / Disconnect |

---

## Architecture

The environment is fully virtualized under VMware Workstation. Four VMs:

| VM | Role |
|----|------|
| **OPNsense 26.1** | Firewall / router. Network control point. RADIUS client. |
| **Ubuntu Server 22.04 — FreeRADIUS** | Centralized authentication. Returns the VLAN per identity. |
| **Ubuntu Server 22.04 — ovs-switch** | 802.1X authenticator: Open vSwitch + hostapd. Relays auth to RADIUS, applies the VLAN. |
| **Windows 10** | Supplicant (the client being authenticated and posture-checked). |

**Network segmentation**
- `VMnet1` (host-only) — internal lab network `192.168.200.0/24`
- `VMnet8` (NAT) — internet access for package installation
- `VMnet3` — the 802.1X access port (no VMware DHCP, so the lab controls addressing)

**VLAN design**
- **VLAN 10 — Production** `192.168.10.0/24` (compliant device, `testuser`)
- **VLAN 99 — Quarantine** `192.168.99.0/24` (non-compliant device, `baduser`)

```
  Windows 10                ovs-switch (Ubuntu)              FreeRADIUS (Ubuntu)
  ┌──────────┐    EAPOL    ┌──────────────────┐   RADIUS   ┌──────────────────┐
  │ Supplicant├───────────►│ hostapd (802.1X) ├───────────►│  Auth + VLAN     │
  │ (PEAP)   │◄───────────┤ + Open vSwitch   │◄───────────┤  decision        │
  └──────────┘  EAP-Success└────────┬─────────┘ Access-    └──────────────────┘
                                     │           Accept +
                            dnsmasq  │           Tunnel-Private-Group-Id
                            (DHCP)   ▼
                          VLAN 10 (prod) / VLAN 99 (quarantine)
```

The authentication flow, step by step:

1. The Windows client connects to the access port (`ens38` on the ovs-switch, via VMnet3).
2. hostapd detects the client and demands 802.1X (EAP) authentication.
3. The client sends credentials (PEAP/MSCHAPv2); hostapd relays them to FreeRADIUS.
4. FreeRADIUS validates and replies `Access-Accept` + the `Tunnel-Private-Group-Id` attribute (the VLAN).
5. hostapd authorizes the port and associates the client with the returned VLAN.
6. dnsmasq assigns an IP address on that VLAN.

---

## Repository layout

```
.
├── README.md                    ← you are here
├── docs/
│   ├── 01-infrastructure-radius.md     Part 1: OPNsense + FreeRADIUS infrastructure & auth
│   ├── 02-8021x-dynamic-vlan.md        Part 2: OVS + hostapd + 802.1X + dynamic VLAN + DHCP
│   ├── 03-posture-enforcement.md       Part 3: endpoint posture + CoA/Disconnect enforcement
│   └── troubleshooting.md              Every bug hit, how it was diagnosed, and the fix
├── detection/
│   ├── windows/detect-remote-tools.ps1     PowerShell endpoint scanner
│   └── linux/detect-remote-tools.sh        Bash endpoint scanner
├── enforcement/
│   ├── coa-quarantine.sh                    Fires RADIUS CoA/Disconnect on a posture failure
│   └── README.md                            CoA vs Disconnect explained + the hostapd limitation
├── configs/
│   ├── freeradius/      users, clients.conf, eap (use_tunneled_reply)
│   ├── hostapd/         hostapd-wired.conf, hostapd.vlan
│   └── dnsmasq/         dnsmasq.conf (DHCP-only)
└── diagrams/
```

---

## What this project demonstrates

- **Protocol-level depth**, not recipe-following: EAPOL transport, the PEAP outer/inner tunnel distinction, the RFC-standard `Tunnel-*` VLAN-assignment attributes, and why each matters.
- **Systematic debugging**: five non-obvious failures were diagnosed with `tcpdump`, hostapd debug output, and `radtest` rather than trial and error. See [`docs/troubleshooting.md`](docs/troubleshooting.md).
- **Honest engineering**: where the open-source stack diverges from enterprise behaviour (notably hostapd's limited dynamic-VLAN CoA support), the limitation is documented and the enterprise equivalent named — see [`enforcement/README.md`](enforcement/README.md).
- **Full NAC loop**: authentication → posture → live enforcement, the same model Cisco ISE and Aruba ClearPass implement.

---

## Status

| Component | State |
|-----------|-------|
| Authentication (Part 1) | ✅ Validated end-to-end (`Access-Accept`) |
| Dynamic VLAN assignment (Part 2) | ✅ Validated (`testuser`→VLAN 10, `baduser`→VLAN 99, confirmed in hostapd debug + client DHCP) |
| Endpoint posture detection (Part 3) | ✅ Windows + Linux scanners |
| CoA/Disconnect enforcement (Part 3) | ⚠️ Disconnect path working; full dynamic-VLAN CoA documented as a hostapd limitation |
| L3 isolation via firewall rules | 🔜 Planned (logical VLAN separation proven; physical L3 isolation is next) |

---


