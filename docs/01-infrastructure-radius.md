# Part 1 — Infrastructure & RADIUS Authentication

**Stack:** OPNsense + FreeRADIUS + VMware

This part covers the infrastructure and the authentication pillar: an OPNsense server as the network control point, and a FreeRADIUS server for centralized authentication. Dynamic VLAN assignment (the 802.1X enforcement pillar) is covered in [Part 2](02-8021x-dynamic-vlan.md).

---

## 1. Objective

The goal is to build a Network Access Control (NAC) solution. A NAC verifies the identity and state of a device before granting network access, then applies a decision: full access, restricted (quarantine) access, or block.

A NAC rests on three pillars:

- **Authentication** — verify who the device is (via 802.1X and a RADIUS server).
- **Posture assessment** — verify the device's compliance state (antivirus, prohibited applications, updates).
- **Enforcement** — apply the decision (VLAN assignment, firewall rules, redirection).

---

## 2. Lab architecture

Fully virtualized under VMware Workstation. Three VMs in this part:

| Virtual machine | Role |
|-----------------|------|
| OPNsense | Firewall / router. Access control point. RADIUS client. |
| Ubuntu Server 22.04 | Hosts the FreeRADIUS server (centralized authentication). |
| Windows 10 | Client used to test network access. |

### 2.1 Addressing plan

| Interface | Address / Network |
|-----------|-------------------|
| OPNsense — WAN (em0) | VMware NAT — 10.10.1.x (internet access) |
| OPNsense — LAN (em1) | 192.168.200.128/24 (lab network) |
| FreeRADIUS — NAT (ens33) | 10.10.1.135/24 (internet for apt) |
| FreeRADIUS — LAN (ens37) | 192.168.200.129/24 (lab network) |
| Lab network (host-only VMnet) | 192.168.200.0/24 |

### 2.2 VMware network configuration

Each internet-facing VM has two NICs: a NAT card (for internet access, e.g. installing packages) and a card on the internal lab network (host-only/VMnet), so the VMs communicate in isolation.

- **WAN** → NAT adapter (VMnet8): provides internet access.
- **LAN** → host-only adapter (VMnet): isolated internal network `192.168.200.0/24`.

> **Note — addressing conflict:** an initial address conflict occurred because the VMware host-only network reused a range that was already occupied. It was resolved by letting DHCP assign a consistent address on the `192.168.200.0/24` segment, then reaching the OPNsense web interface at the address actually obtained (`192.168.200.128`).

---

## 3. OPNsense installation & configuration

OPNsense (version 26.1) was installed as a VM, then configured via the console to correctly assign the network interfaces.

### 3.1 Interface assignment

Two interfaces, `em0` and `em1`, assigned as:

- **WAN = em0** (NAT card, identified by its MAC address in VMware).
- **LAN = em1** (card on the internal lab network).

Console procedure:
- Console menu → option 1 (Assign interfaces)
- LAGGs: no. VLANs: no.
- WAN interface: `em0`
- LAN interface: `em1`

### 3.2 LAN address configuration

The LAN address was adjusted to avoid a conflict with the physical network's gateway:

- Console menu → option 2 (Set interface IP address)
- Select the LAN interface (`em1`)
- Set the address / enable DHCP on the `192.168.200.0/24` segment

Final result:

```
LAN (em1) -> v4: 192.168.200.128/24
WAN (em0) -> v4/DHCP4: 10.10.1.136/24
```

### 3.3 Web interface access

The admin web interface is reachable from the lab network at:

```
https://192.168.200.128
Default credentials:
  login    : root
  password : opnsense
```

---

## 4. FreeRADIUS installation & configuration

FreeRADIUS runs on the Ubuntu Server VM. It performs the authentication: OPNsense forwards requests to it and applies its response (`Access-Accept` or `Access-Reject`).

### 4.1 Installation

```bash
sudo apt update && sudo apt install freeradius -y
```

Verify the service:

```bash
sudo systemctl status freeradius
# expected: Active: active (running)
# Status: "Processing requests"
```

### 4.2 Create a test user

User file: `/etc/freeradius/3.0/users`. Add a line at the top (without modifying the commented examples):

```
testuser Cleartext-Password := "test123"
```

### 4.3 Declare OPNsense as a RADIUS client

File: `/etc/freeradius/3.0/clients.conf`. Add a client block at the end to authorize OPNsense to query the server. The shared secret must be identical on both sides.

```
client opnsense {
    ipaddr = 192.168.200.128
    secret = testing123
}
```

Restart to apply:

```bash
sudo systemctl restart freeradius
```

---

## 5. Validation tests

### 5.1 Local test on the FreeRADIUS server

Before involving OPNsense, authentication is tested locally with `radtest`:

```bash
radtest testuser test123 127.0.0.1 0 testing123
```

Result: `Access-Accept`. Local authentication works.

```
Sent Access-Request Id 113 ...
    User-Name = "testuser"
    User-Password = "test123"
Received Access-Accept Id 113 ...
```

### 5.2 Declare the RADIUS server in OPNsense

Web interface: **System → Access → Servers → Add**.

| Parameter | Value |
|-----------|-------|
| Descriptive name | FreeRADIUS |
| Type | RADIUS |
| Hostname or IP | 192.168.200.129 |
| Shared Secret | testing123 |
| Services offered | Authentication |
| Authentication port | 1812 |

### 5.3 Test from OPNsense

Web interface: **System → Access → Tester**. Entering `testuser` / `test123`, OPNsense queries FreeRADIUS and displays the result:

```
User: testuser authenticated successfully.
```

This confirms the full authentication chain works: **Client → OPNsense → FreeRADIUS → response applied by OPNsense.** The core of the NAC solution is operational.

---

## 6. Part 1 summary

At this stage, the infrastructure and centralized authentication are in place and validated:

- OPNsense installed and configured as the network control point.
- FreeRADIUS operational as the centralized authentication server.
- OPNsense declared and recognized as a RADIUS client.
- Authentication tested and validated end-to-end (`Access-Accept`).

**Next ([Part 2](02-8021x-dynamic-vlan.md)):** enforcement via dynamic VLAN assignment through 802.1X — using an 802.1X switch (Open vSwitch) so an authenticated compliant user is placed in a production VLAN and a non-compliant user in a quarantine VLAN, with the VLAN returned dynamically by RADIUS via the `Tunnel-Private-Group-Id` attribute.
