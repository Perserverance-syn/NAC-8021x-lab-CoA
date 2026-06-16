# Part 3 — Posture Assessment & Live Enforcement

Parts 1 and 2 built **authentication** (who is this device?) and **enforcement infrastructure** (dynamic VLAN assignment). Part 3 adds the missing NAC pillar: **posture assessment** — *is this device compliant?* — and wires a failed posture check back into the enforcement layer so a non-compliant device is quarantined live.

The compliance policy here: **no unauthorized remote-access software.** Tools like AnyDesk, TeamViewer, and RustDesk are a real corporate concern — they're a common shadow-IT vector and a standard initial-access technique in incidents. A device running one of them should not hold a production-VLAN session.

---

## 1. Where posture fits

FreeRADIUS by itself only answers *authentication* and *authorization* questions — it never inspects an endpoint. Posture assessment therefore needs a component that actually looks at the device:

```
Authentication          Posture assessment              Enforcement
(802.1X / RADIUS)        (endpoint scanner)              (VLAN / CoA)
   "valid user"   ──►    "compliant? y/n"      ──►       VLAN 10 or VLAN 99
```

The scanners run **on the endpoint** and emit a single, machine-readable verdict (exit code + JSON). That verdict is the input to enforcement.

---

## 2. The detection scanners

Two scanners, same design, one per OS:

- **Windows:** [`detection/windows/detect-remote-tools.ps1`](../detection/windows/detect-remote-tools.ps1) (PowerShell)
- **Linux:** [`detection/linux/detect-remote-tools.sh`](../detection/linux/detect-remote-tools.sh) (Bash)

### Why four surfaces

A naive "is the process running?" check is trivially evaded — close the app, or rename the binary. Each scanner therefore inspects **four independent surfaces**, and a hit on *any* of them is a violation:

| Surface | Windows | Linux | Catches |
|---------|---------|-------|---------|
| Running processes | `Get-Process` | `ps -eo comm,args` | Tool currently in use |
| Services / units | `Win32_Service` | `systemctl list-unit-files` | Tool installed as a background service (the persistent unattended-access mode) |
| Installed programs | registry uninstall keys (32/64-bit + HKCU) | `dpkg` / `rpm` | Tool installed but not currently running |
| Disk paths | `Program Files`, `AppData`, etc. | `/usr/bin`, `/opt`, desktop entries | Portable/standalone copies with no installer footprint |

Unattended remote access (the dangerous kind — persistent, survives reboot) almost always shows up as a **service**, which is why that surface matters most. A portable AnyDesk that someone runs once shows up as a **process** and a **disk path**. Covering all four means a tool has to hide on every surface simultaneously to evade the check.

### Output contract

Both scanners produce the same contract, which is what makes them pluggable into enforcement:

- **Exit 0** → compliant.
- **Exit 1** → non-compliant; a JSON report lists each violation with its tool, surface, and detail.

```json
{
  "hostname": "DESKTOP-01",
  "user": "synch",
  "scanned_at": "2026-06-16T21:04:29+00:00",
  "compliant": false,
  "violations": [
    {"tool": "TeamViewer", "surface": "service", "detail": "TeamViewer (Running)"},
    {"tool": "TeamViewer", "surface": "installed-program", "detail": "TeamViewer 15.51"}
  ]
}
```

### Detect-only by design

The scanners **never uninstall anything.** Detection and remediation are deliberately separate: a scanner that also deletes software is harder to trust, harder to test, and dangerous to run broadly. Forced remediation (silent uninstall + AV deployment) is a separate Phase 4 step, best handled by a dedicated configuration-management tool rather than the detector.

---

## 3. Enforcement — closing the loop

A failed scan (exit 1) feeds the enforcement layer, which uses **RADIUS Dynamic Authorization (RFC 5176)** to act on the device's *existing* session. Full detail, including the honest hostapd limitation, is in [`enforcement/README.md`](../enforcement/README.md). In short:

- **Disconnect-Message** (working path): hostapd drops the session → device re-authenticates → posture-aware policy returns the quarantine VLAN.
- **CoA-Request** (enterprise design, documented limitation): would move the live session to VLAN 99 in place; hostapd's wired driver doesn't cleanly support this, so the lab falls back to disconnect-and-re-auth and documents why.

```
detect-remote-tools (exit 1)
        │
        ▼
coa-quarantine.sh <mac> disconnect
        │
        ▼
session dropped → re-auth → VLAN 99 (quarantine)
```

---

## 4. The full NAC story, end to end

Putting all three parts together, the lab now implements the complete enterprise NAC model:

1. Device connects → **gets nothing** until it authenticates (802.1X, Part 2).
2. It authenticates → RADIUS returns a VLAN based on identity (Part 1 + 2).
3. A posture scan checks it for prohibited remote-access software (Part 3).
4. If it fails → RADIUS Dynamic Authorization tears down the session and it lands in quarantine (Part 3).

That's authentication, posture, and enforcement — the three pillars — running together, built entirely on open-source tooling, with the gaps between this lab and a production ISE/ClearPass deployment documented rather than hidden.

---

## 5. Roadmap

| Phase | Item | State |
|-------|------|-------|
| 3 | Endpoint posture scanners (Win + Linux) | ✅ Done |
| 3 | CoA/Disconnect enforcement | ✅ Disconnect working; CoA limitation documented |
| 4 | Forced remediation (uninstall + AV push via config-management) | 🔜 Planned |
| 4 | L3 isolation between VLANs via firewall rules | 🔜 Planned |
| 4 | Server-side posture policy in FreeRADIUS (`rlm_rest` to a posture API) | 🔜 Planned |
