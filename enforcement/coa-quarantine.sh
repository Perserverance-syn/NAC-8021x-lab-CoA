#!/usr/bin/env bash
#
# NAC enforcement — quarantine a non-compliant endpoint via RADIUS CoA / Disconnect.
#
# This closes the NAC loop: when a posture check (detect-remote-tools) flags a
# device that already holds a production-VLAN session, this script tells the
# authenticator (hostapd) to tear that session down. The device is forced to
# re-authenticate, at which point a posture-aware RADIUS policy can drop it into
# the quarantine VLAN.
#
# It uses radclient (from the freeradius-utils package) to send the RADIUS
# Dynamic Authorization message defined in RFC 5176.
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ IMPORTANT — read enforcement/README.md before relying on this in a demo. │
# │ hostapd's wired driver handles Disconnect-Message (kick + re-auth) but    │
# │ its support for CoA-Request with a *new* Tunnel-Private-Group-Id (live    │
# │ VLAN change without re-auth) is unreliable. The lab-realistic path is     │
# │ Disconnect -> forced re-auth -> quarantine VLAN. The enterprise           │
# │ equivalent (Cisco ISE / Aruba ClearPass) issues a true CoA-Request.       │
# └─────────────────────────────────────────────────────────────────────────┘
#
# Usage:
#   ./coa-quarantine.sh <client-mac> [mode]
#
#     <client-mac>   the supplicant MAC, e.g. 00:0c:29:ab:cd:ef
#                    (this is the Calling-Station-Id of the session to act on)
#     [mode]         disconnect  (default) — send Disconnect-Message, force re-auth
#                    coa                    — attempt CoA-Request with VLAN 99 (see caveat above)
#
# Environment:
#   NAS_ADDR        authenticator address (hostapd / ovs-switch)   default 192.168.200.130
#   COA_PORT        Dynamic Authorization port                      default 3799
#   COA_SECRET      shared secret for DynAuth                       default testing123
#   QUARANTINE_VLAN VLAN id to assign on CoA mode                   default 99

set -uo pipefail

NAS_ADDR="${NAS_ADDR:-192.168.200.130}"
COA_PORT="${COA_PORT:-3799}"
COA_SECRET="${COA_SECRET:-testing123}"
QUARANTINE_VLAN="${QUARANTINE_VLAN:-99}"

MAC="${1:-}"
MODE="${2:-disconnect}"

if [ -z "$MAC" ]; then
  echo "Usage: $0 <client-mac> [disconnect|coa]" >&2
  exit 2
fi

if ! command -v radclient >/dev/null 2>&1; then
  echo "ERROR: radclient not found. Install with: sudo apt install freeradius-utils" >&2
  exit 3
fi

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [enforce] $1"; }

case "$MODE" in
  disconnect)
    # RFC 5176 Disconnect-Request: terminate the session for this MAC.
    # hostapd will drop the port; the supplicant then re-authenticates.
    log "Sending Disconnect-Message for $MAC to $NAS_ADDR:$COA_PORT"
    printf 'User-Name = "%s"\nCalling-Station-Id = "%s"\n' "$MAC" "$MAC" \
      | radclient -x "$NAS_ADDR:$COA_PORT" disconnect "$COA_SECRET"
    rc=$?
    ;;

  coa)
    # RFC 5176 CoA-Request: ask the NAS to apply a new VLAN to the live session
    # WITHOUT re-authentication. See the caveat at the top — this is the
    # enterprise behaviour, included to document the intended design; on hostapd
    # it may be rejected (CoA-NAK) or silently ignored.
    log "Attempting CoA-Request (VLAN $QUARANTINE_VLAN) for $MAC — see README caveat"
    printf 'User-Name = "%s"\nCalling-Station-Id = "%s"\nTunnel-Type:0 = VLAN\nTunnel-Medium-Type:0 = IEEE-802\nTunnel-Private-Group-Id:0 = "%s"\n' \
      "$MAC" "$MAC" "$QUARANTINE_VLAN" \
      | radclient -x "$NAS_ADDR:$COA_PORT" coa "$COA_SECRET"
    rc=$?
    ;;

  *)
    echo "Unknown mode: $MODE (use 'disconnect' or 'coa')" >&2
    exit 2
    ;;
esac

if [ $rc -eq 0 ]; then
  log "RADIUS dynamic-authorization message accepted (ACK)."
else
  log "RADIUS dynamic-authorization message failed or was NAK'd (rc=$rc)."
  log "If using 'coa' mode, this is the expected hostapd limitation — fall back to 'disconnect'."
fi
exit $rc
