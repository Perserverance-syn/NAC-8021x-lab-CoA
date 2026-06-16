# Troubleshooting — Real Problems Hit & How They Were Solved

This is the most useful document in the repo. Anyone can paste a working config; the value is in the failures. Each of these was a non-obvious bug that silently broke the lab, diagnosed with packet captures and debug output rather than guesswork.

---

## 1. OVS swallows EAPOL frames before hostapd

**Symptom:** With `ens38` attached to the OVS bridge and `driver=wired` in hostapd, the client connects but hostapd shows nothing — no EAP, no auth attempt at all. Dead silence.

**Diagnosis:** A port attached to OVS has its Layer 2 frames handled by the OVS datapath (`master ovs-system`) *before* anything else on the host can see them. EAPOL (EtherType `0x888e`) was being processed by OVS, which doesn't implement the 802.1X authenticator role, so it never reached hostapd.

**Fix:** Take the access port out of the OVS datapath entirely and let hostapd own it directly:

```bash
sudo ovs-vsctl del-port br0 ens38
sudo ip link set ens38 nomaster
sudo ip link set ens38 up
```

**Lesson:** OVS is a switch, not an 802.1X authenticator. The two roles don't compose on the same interface; the authenticator needs raw L2 access to the port.

---

## 2. Windows EAPOL version mismatch

**Symptom:** Client and hostapd are now both on `ens38`, but 802.1X negotiation still never starts. The client sends *something* but hostapd ignores it.

**Diagnosis:** A packet capture on the access port, filtering for EAPOL:

```bash
sudo tcpdump -i ens38 -e ether proto 0x888e
```

…showed the Windows supplicant emitting **EAPOL version 1**, while hostapd was configured with `eapol_version=2`. hostapd silently dropped the version-mismatched frames.

**Fix:** Set `eapol_version=1` in `hostapd-wired.conf` to match what Windows actually sends.

**Lesson:** "Silently ignored" is a protocol-version clue. `tcpdump` filtering on the exact EtherType (`0x888e` for EAPOL) is the fastest way to confirm frames are arriving and inspect their version, rather than assuming the link is dead.

---

## 3. PEAP not forwarding VLAN attributes

**Symptom:** Authentication now succeeds (`Access-Accept`), but no VLAN is assigned — the client lands nowhere useful. `radtest` against the *inner* identity shows the `Tunnel-Private-Group-Id` attribute, but hostapd never receives it.

**Diagnosis:** PEAP establishes a TLS tunnel and authenticates the user *inside* it (the inner tunnel). By default, FreeRADIUS does **not** copy reply attributes from the inner tunnel out to the outer `Access-Accept` that the NAS (hostapd) actually sees. So the VLAN attributes were generated but stayed trapped inside the tunnel.

**Fix:** In `/etc/freeradius/3.0/mods-available/eap`, under the `peap` section:

```
use_tunneled_reply = yes
```

This forwards the inner-tunnel reply attributes (including the `Tunnel-*` VLAN trio) to the outer response.

**Lesson:** With tunneled EAP methods (PEAP, TTLS), there are two RADIUS conversations — inner and outer — and authorization attributes live in the inner one by default. The NAS only acts on the outer reply. `use_tunneled_reply = yes` bridges them.

---

## 4. dnsmasq vs systemd-resolved (port 53)

**Symptom:** dnsmasq fails to start, or starts but DHCP behaves erratically. Logs mention port 53 already in use.

**Diagnosis:** Ubuntu runs `systemd-resolved`, which binds UDP/TCP port 53 for DNS. dnsmasq also wants port 53 by default (it's a DNS + DHCP server). The two collide.

**Fix:** This lab only needs dnsmasq for DHCP, not DNS. Disable dnsmasq's DNS side by setting:

```
port=0
```

in the dnsmasq config. `port=0` turns off the DNS listener entirely while leaving DHCP fully functional, sidestepping the conflict without touching `systemd-resolved`.

**Lesson:** dnsmasq is two services in one. If you only want DHCP, switch DNS off with `port=0` rather than fighting the resolver.

---

## 5. Untagged DHCP on the parent interface

**Symptom:** Authentication and VLAN assignment work (hostapd logs `RADIUS: VLAN ID 10`), but the client never gets a DHCP lease.

**Diagnosis:** hostapd's `dynamic_vlan` mode creates tagged VLAN bridges named `brvlanXX` and expects VLAN-*tagged* traffic on them. But the Windows client is an ordinary access-port supplicant — it sends **untagged** DHCP frames on the parent interface `ens38`, not on a tagged sub-interface. dnsmasq was listening on the tagged bridge interfaces, so it never saw the client's untagged `DHCPDISCOVER`.

**Fix:** Point dnsmasq at the parent interface `ens38` directly, where the untagged client traffic actually arrives, rather than at the `brvlanXX` tagged bridges.

**Lesson:** Dynamic-VLAN tagging on the switch side doesn't mean the *client* sends tagged frames — an access-port supplicant is untagged by definition. The DHCP server has to listen where the frames really land. This is the subtlest bug of the five because every individual component reported success; only the end-to-end "no lease" symptom revealed the interface mismatch.

---

## Debugging toolkit used

| Tool | Used for |
|------|----------|
| `tcpdump -e ether proto 0x888e` | Confirm EAPOL frames arrive; read their version (bugs 1, 2) |
| `hostapd -dd` | Authenticator-side EAP/RADIUS trace; confirmed `RADIUS: VLAN ID` (bugs 2, 3, 5) |
| `radtest` | Isolate RADIUS auth + reply attributes from the 802.1X layer (bug 3) |
| `ovs-vsctl show` / `ip link` | Inspect bridge membership and interface master (bug 1) |
| `systemctl` / journal | Port-conflict diagnosis (bug 4) |

The common thread: **isolate each layer.** `radtest` proves RADIUS independent of 802.1X; `tcpdump` proves frames independent of hostapd; checking the lease independent of the VLAN assignment. Each bug looked like "the whole thing is broken" until the layers were separated.
