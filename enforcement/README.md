# Enforcement — Closing the NAC Loop with RADIUS Dynamic Authorization

Detection alone is passive. A machine running TeamViewer keeps its production-VLAN access while you read the alert. **Enforcement** is what makes it NAC: the posture failure has to *change the device's network access, live.* This is the same model enterprise NAC platforms (Cisco ISE, Aruba ClearPass) implement, and it relies on **RADIUS Dynamic Authorization — RFC 5176**.

## Two messages, two outcomes

RFC 5176 defines two messages the RADIUS server can push to the authenticator (the NAS) for a session that has *already* authenticated:

| Message | What it does | Outcome here |
|---------|-------------|--------------|
| **Disconnect-Message** | Terminates the session. | The device is kicked off the port and must re-authenticate. A posture-aware policy then drops it into the quarantine VLAN on the new auth. |
| **CoA-Request** (Change of Authorization) | Modifies the live session *without* re-authentication — e.g. pushes a new `Tunnel-Private-Group-Id`. | The device is moved from VLAN 10 to VLAN 99 *in place*, no re-auth needed. |

CoA-Request is the "nicer" mechanism — instant, no disruption to the supplicant's auth state. It's why enterprise gear leans on it for live threat response: re-authenticating on a timer (`eap_reauth_period`) is too slow when a prohibited tool just appeared.

## The honest limitation in this lab

**hostapd's wired authenticator does not cleanly support CoA-Request with a new VLAN.**

- **Disconnect-Message** → works. hostapd drops the session, the supplicant re-authenticates, and the quarantine VLAN is applied on the fresh `Access-Accept`. This is the path the demo uses.
- **CoA-Request with `Tunnel-Private-Group-Id`** → unreliable. hostapd's wired driver typically responds `CoA-NAK` or ignores the VLAN-change attributes, because live dynamic-VLAN reassignment isn't implemented the way a hardware switch ASIC handles it.

So the lab-realistic enforcement path is:

```
posture scan fails (exit 1)
        │
        ▼
coa-quarantine.sh <mac> disconnect
        │
        ▼
hostapd drops the session  ──►  supplicant re-authenticates
        │
        ▼
posture-aware RADIUS policy returns VLAN 99  ──►  device quarantined
```

…and `coa-quarantine.sh <mac> coa` is included specifically to **demonstrate the enterprise design and document where the open-source stack diverges from it.** That divergence is the point: a hardware switch + Cisco ISE would issue a true CoA-Request and move the port in place; hostapd makes you fall back to disconnect-and-re-auth. Knowing *why* — and being able to show both — is what distinguishes understanding NAC from copying a config.

## Wiring detection to enforcement

Two realistic ways to connect the posture scan's exit code to this script:

1. **Endpoint-triggered (simplest).** A scheduled task / cron job runs `detect-remote-tools` on the client. On exit 1, the endpoint reports the failure to a small listener on the ovs-switch, which runs `coa-quarantine.sh` for that MAC. (The endpoint reporting its own non-compliance is the weak point — fine for a lab, hardened in production by an agent the user can't trivially disable.)

2. **Server-side policy (closer to enterprise).** The posture result feeds a FreeRADIUS policy (e.g. via an `unlang` check against an external file/SQL the scanner updates, or `rlm_rest` to a posture API). On the *next* auth — forced by the disconnect — FreeRADIUS reads the posture verdict and returns VLAN 10 or VLAN 99 accordingly. This is how ISE/ClearPass structure it: detection updates a posture token, CoA forces re-evaluation, policy decides the VLAN.

The lab implements path 1 for the demo and documents path 2 as the production design.

## Enabling Dynamic Authorization on hostapd

For hostapd to *accept* these messages, the DynAuth listener must be enabled in `hostapd-wired.conf`:

```ini
radius_das_port=3799
radius_das_client=192.168.200.129 testing123
```

`radius_das_client` authorizes the FreeRADIUS host (`192.168.200.129`) to send Disconnect/CoA with the given secret. After adding these, restart hostapd. The script defaults assume this listener on `192.168.200.130:3799`.

## Usage

```bash
# Force re-auth (working path) — quarantines via re-authentication
./coa-quarantine.sh 00:0c:29:ab:cd:ef disconnect

# Attempt live VLAN change (enterprise design; expect hostapd to NAK)
./coa-quarantine.sh 00:0c:29:ab:cd:ef coa
```

Requires `radclient` from `freeradius-utils`:

```bash
sudo apt install freeradius-utils
```
