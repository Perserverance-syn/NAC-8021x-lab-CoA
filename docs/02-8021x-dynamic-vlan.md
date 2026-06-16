# Part 2 — 802.1X Enforcement & Dynamic VLAN Assignment

**Stack:** Open vSwitch + hostapd + FreeRADIUS + dnsmasq

Part 1 set up centralized authentication (OPNsense + FreeRADIUS). Part 2 adds the **enforcement** pillar: port-level network access control via the 802.1X standard, with dynamic VLAN assignment based on user identity.

---

## 1. Objective

The principle: a device that connects to the network gets no access until it authenticates. Once authenticated, the RADIUS server returns a VLAN number, which determines the network segment the device is placed in:

- Compliant user (`testuser`) → **VLAN 10 (production)**
- Non-compliant user (`baduser`) → **VLAN 99 (quarantine)**

This reproduces exactly the behaviour of an enterprise switch (Cisco, Aruba) configured with `dot1x`: the standard RADIUS attribute `Tunnel-Private-Group-Id` carries the VLAN number.

---

## 2. Architecture

A fourth VM is added to the lab: a software switch based on Open vSwitch, acting as the 802.1X authenticator via hostapd.

| Component | Role |
|-----------|------|
| Windows 10 client | 802.1X supplicant (requests authentication). |
| ovs-switch (Ubuntu) | Authenticator: Open vSwitch + hostapd. Relays auth to RADIUS and applies the VLAN. |
| FreeRADIUS (Ubuntu) | Authentication server. Returns the VLAN per identity. |
| dnsmasq (on ovs-switch) | DHCP server: assigns an IP to the client once authenticated. |

### 2.1 Authentication flow

1. The Windows client connects to the access port (interface `ens38` on ovs-switch, via VMnet3).
2. hostapd detects the client and demands 802.1X (EAP) authentication.
3. The client sends credentials (PEAP/MSCHAPv2); hostapd relays them to FreeRADIUS.
4. FreeRADIUS validates and replies `Access-Accept` + the `Tunnel-Private-Group-Id` attribute (the VLAN).
5. hostapd authorizes the port and associates the client with the returned VLAN.
6. dnsmasq assigns an IP address.

### 2.2 Part 2 addressing plan

| Interface / Segment | Address |
|---------------------|---------|
| ovs-switch — ens33 (NAT) | 10.10.1.138/24 (internet for apt) |
| ovs-switch — ens37 (LAN) | 192.168.200.130/24 (management + RADIUS link) |
| ovs-switch — ens38 (access) | 802.1X client port (VMnet3, no VMware DHCP) |
| VLAN 10 — Production | 192.168.10.0/24 (gateway .1) |
| VLAN 99 — Quarantine | 192.168.99.0/24 (gateway .1) |

---

## 3. Open vSwitch setup

A dedicated Ubuntu Server VM (`ovs-switch`) is created with three NICs: NAT (internet), lab LAN (management/RADIUS), and the client access port (VMnet3, no DHCP).

### 3.1 Installation

```bash
sudo apt update
sudo apt install openvswitch-switch hostapd -y
```

Verify:

```bash
sudo ovs-vsctl show
# expected: ovs_version displayed
```

### 3.2 Bridge creation and the access port

An OVS bridge is created to materialize the switch. The management interface (`ens37`) is deliberately left **outside** the bridge so SSH access isn't cut.

```bash
sudo ovs-vsctl add-br br0
sudo ip link set ens38 up
sudo ip link set br0 up
```

> **Important technical note:** during testing it became clear that a port attached to OVS (master `ovs-system`) intercepts Layer 2 frames (EAPOL / 802.1X) *before* hostapd. Since OVS does not natively perform the 802.1X authenticator function, the access port `ens38` is ultimately managed directly by hostapd (outside the OVS datapath) so that the authentication frames reach it.

```bash
sudo ovs-vsctl del-port br0 ens38
sudo ip link set ens38 nomaster
sudo ip link set ens38 up
```

---

## 4. hostapd configuration (802.1X authenticator)

hostapd watches the access port and plays the wired authenticator role: it speaks 802.1X with the client and relays authentication to FreeRADIUS.

### 4.1 Configuration file

File `/etc/hostapd/hostapd-wired.conf`:

```ini
interface=ens38
driver=wired
ieee8021x=1
eap_reauth_period=3600
eapol_version=1

auth_server_addr=192.168.200.129
auth_server_port=1812
auth_server_shared_secret=testing123
use_pae_group_addr=1

dynamic_vlan=1
vlan_file=/etc/hostapd/hostapd.vlan
vlan_tagged_interface=ens38
vlan_bridge=brvlan
```

> **Key gotcha:** Windows emits EAPOL in **version 1**. hostapd must therefore be configured with `eapol_version=1`, otherwise the client's frames are ignored and authentication never starts. (See [troubleshooting](troubleshooting.md#2-windows-eapol-version-mismatch).)

### 4.2 VLAN mapping file

File `/etc/hostapd/hostapd.vlan` — maps each VLAN number to an interface:

```
10 ens38.10
99 ens38.99
```

### 4.3 Create the VLAN interfaces

```bash
sudo modprobe 8021q
sudo ip link add link ens38 name ens38.10 type vlan id 10
sudo ip link add link ens38 name ens38.99 type vlan id 99
sudo ip link set ens38.10 up
sudo ip link set ens38.99 up
```

### 4.4 Launch in debug mode

```bash
sudo hostapd -dd /etc/hostapd/hostapd-wired.conf
```

On correct startup, hostapd prints `AP-ENABLED` and indicates the target RADIUS server (`192.168.200.129:1812`).

---

## 5. Dynamic VLAN assignment via FreeRADIUS

### 5.1 Declare the ovs-switch as a RADIUS client

On the FreeRADIUS VM, add to `/etc/freeradius/3.0/clients.conf` (below the `client opnsense` block):

```
client ovs-switch {
    ipaddr = 192.168.200.130
    secret = testing123
}
```

`192.168.200.130` is the `ens37` IP of the ovs-switch VM (where it talks to FreeRADIUS). Restart:

```bash
sudo systemctl restart freeradius
```

### 5.2 Define users and their VLANs

File `/etc/freeradius/3.0/users` — each user is assigned a VLAN via the standard RFC `Tunnel-*` attributes:

```
testuser Cleartext-Password := "test123"
        Tunnel-Type = VLAN,
        Tunnel-Medium-Type = IEEE-802,
        Tunnel-Private-Group-Id = "10"

baduser Cleartext-Password := "bad123"
        Tunnel-Type = VLAN,
        Tunnel-Medium-Type = IEEE-802,
        Tunnel-Private-Group-Id = "99"
```

What this does:
- `testuser` (compliant) → RADIUS returns **VLAN 10** (production)
- `baduser` (non-compliant) → RADIUS returns **VLAN 99** (quarantine)

The three `Tunnel-*` attributes are the RFC standard for dynamic VLAN assignment.

### 5.3 Forward the VLAN through the PEAP tunnel

> **Key gotcha:** FreeRADIUS with PEAP does **not** forward the `Tunnel-Private-Group-Id` attributes from the inner tunnel to the outer `Access-Accept` by default. The fix is `use_tunneled_reply = yes` in `/etc/freeradius/3.0/mods-available/eap` under the `peap` section. (See [troubleshooting](troubleshooting.md#3-peap-not-forwarding-vlan-attributes).)

---

## 6. DHCP with dnsmasq

dnsmasq runs on the ovs-switch and assigns addresses on each VLAN once the client is authenticated.

> **Key gotcha:** dnsmasq conflicts with `systemd-resolved` on port 53. Resolved by setting `port=0` in the dnsmasq config to disable DNS and run DHCP only. (See [troubleshooting](troubleshooting.md#4-dnsmasq-vs-systemd-resolved-port-53).)

> **Second gotcha:** hostapd's `dynamic_vlan` mode creates bridges named `brvlanXX` and expects tagged traffic, but the Windows client sends *untagged* DHCP on `ens38` (the parent interface). Resolved by pointing dnsmasq at `ens38` directly rather than at the tagged bridge interfaces. (See [troubleshooting](troubleshooting.md#5-untagged-dhcp-on-parent-interface).)

---

## 7. Validation

The validated result:

- FreeRADIUS returns `Tunnel-Private-Group-Id = 10` for `testuser` and `= 99` for `baduser`, confirmed both via `radtest` locally and in hostapd debug logs (`RADIUS: VLAN ID 10` / `RADIUS: VLAN ID 99`).
- End-to-end 802.1X PEAP/MSCHAPv2 authentication with the Windows client triggering a sign-in popup.
- DHCP address assignment after authentication (client receives `192.168.10.x` on the production VLAN).

The VLAN separation is **logically proven** through RADIUS attribute assignment. Physical L3 isolation via firewall rules between segments remains a planned next step.

---

## 8. Why Open vSwitch instead of hostapd-direct?

OVS was chosen over a hostapd-only setup specifically because it mirrors real enterprise switch behaviour (Cisco `dot1x`). Even though the access port ultimately had to be handled outside the OVS datapath (see §3.2), building the lab around a software switch keeps the topology faithful to how a production access layer is structured — a managed switch is the authenticator, RADIUS makes the decision, and the VLAN is pushed to the port.

**Next ([Part 3](03-posture-enforcement.md)):** the posture pillar — detecting unauthorized remote-access software on endpoints and quarantining offending devices live via RADIUS Change-of-Authorization.
