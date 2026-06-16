#!/usr/bin/env bash
#
# NAC posture check — detects unauthorized remote-access software on a Linux endpoint.
#
# Part of the posture-assessment pillar of the NAC lab. Scans four independent
# surfaces so a tool can't hide by only renaming one of them:
#
#   1. Running processes
#   2. systemd units (services)
#   3. Installed packages (dpkg / rpm)
#   4. Common binary locations and desktop entries
#
# On a violation it writes a JSON report and exits 1. A compliant machine exits 0.
# The exit code is what an enforcement layer keys off of.
#
# Detect-and-report by design — never uninstalls anything. Remediation is a
# separate, deliberate Phase 3 step.
#
# Usage:
#   ./detect-remote-tools.sh
#   REPORT_PATH=/var/lib/nac/report.json ./detect-remote-tools.sh

set -uo pipefail

REPORT_PATH="${REPORT_PATH:-/var/lib/nac-posture/report.json}"
LOG_PATH="${LOG_PATH:-/var/lib/nac-posture/posture.log}"

# --- Blacklist: friendly name | space-separated match patterns -------------
# Patterns are matched case-insensitively against process names, unit names,
# package names, and paths.
BLACKLIST=(
  "AnyDesk|anydesk"
  "TeamViewer|teamviewer teamviewerd"
  "RustDesk|rustdesk"
  "Chrome Remote|chrome-remote-desktop remoting_host"
  "UltraVNC|ultravnc uvnc"
  "TightVNC|tightvnc tvnserver"
  "RealVNC|realvnc vncserver-x11"
  "x11vnc|x11vnc"
  "TigerVNC|tigervnc vncserver"
  "NoMachine|nxserver nomachine"
  "Splashtop|splashtop strwinclt"
  "Supremo|supremo"
)

mkdir -p "$(dirname "$REPORT_PATH")" "$(dirname "$LOG_PATH")" 2>/dev/null || true

log() {
  local level="${2:-INFO}"
  local line
  line="$(date '+%Y-%m-%d %H:%M:%S') [$level] $1"
  echo "$line"
  echo "$line" >> "$LOG_PATH" 2>/dev/null || true
}

# lowercase helper
lc() { tr '[:upper:]' '[:lower:]'; }

# returns 0 if haystack ($1) contains any pattern in $2 (space-separated)
match_any() {
  local haystack patterns p
  haystack="$(printf '%s' "$1" | lc)"
  patterns="$2"
  [ -z "$haystack" ] && return 1
  for p in $patterns; do
    case "$haystack" in
      *"$p"*) return 0 ;;
    esac
  done
  return 1
}

log "Starting NAC posture scan on $(hostname)"

# findings accumulate as: tool|surface|detail
declare -a FINDINGS=()
add_finding() { FINDINGS+=("$1|$2|$3"); }

# --- 1. Running processes --------------------------------------------------
# Use ps; comm gives the command name, args gives the full command line.
while IFS= read -r line; do
  comm="$(awk '{print $1}' <<<"$line")"
  full="$line"
  for item in "${BLACKLIST[@]}"; do
    name="${item%%|*}"; pats="${item#*|}"
    if match_any "$comm" "$pats" || match_any "$full" "$pats"; then
      add_finding "$name" "process" "$comm"
    fi
  done
done < <(ps -eo comm,args 2>/dev/null | tail -n +2)

# --- 2. systemd units ------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
  while IFS= read -r unit; do
    [ -z "$unit" ] && continue
    for item in "${BLACKLIST[@]}"; do
      name="${item%%|*}"; pats="${item#*|}"
      if match_any "$unit" "$pats"; then
        state="$(systemctl is-active "$unit" 2>/dev/null || echo unknown)"
        add_finding "$name" "service" "$unit ($state)"
      fi
    done
  done < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1}')
fi

# --- 3. Installed packages -------------------------------------------------
if command -v dpkg-query >/dev/null 2>&1; then
  while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    for item in "${BLACKLIST[@]}"; do
      name="${item%%|*}"; pats="${item#*|}"
      if match_any "$pkg" "$pats"; then
        add_finding "$name" "package" "$pkg"
      fi
    done
  done < <(dpkg-query -W -f='${Package}\n' 2>/dev/null)
elif command -v rpm >/dev/null 2>&1; then
  while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    for item in "${BLACKLIST[@]}"; do
      name="${item%%|*}"; pats="${item#*|}"
      if match_any "$pkg" "$pats"; then
        add_finding "$name" "package" "$pkg"
      fi
    done
  done < <(rpm -qa --qf '%{NAME}\n' 2>/dev/null)
fi

# --- 4. Binary locations & desktop entries ---------------------------------
SCAN_DIRS=(/usr/bin /usr/local/bin /opt /usr/share/applications "$HOME/.local/share/applications")
for base in "${SCAN_DIRS[@]}"; do
  [ -d "$base" ] || continue
  while IFS= read -r entry; do
    bn="$(basename "$entry")"
    for item in "${BLACKLIST[@]}"; do
      name="${item%%|*}"; pats="${item#*|}"
      if match_any "$bn" "$pats"; then
        add_finding "$name" "disk-path" "$entry"
      fi
    done
  done < <(find "$base" -maxdepth 2 \( -type f -o -type l -o -type d \) 2>/dev/null)
done

# --- Deduplicate findings --------------------------------------------------
mapfile -t UNIQUE < <(printf '%s\n' "${FINDINGS[@]}" | awk 'NF' | sort -u)

# --- Build JSON report -----------------------------------------------------
escape_json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

compliant="true"
[ "${#UNIQUE[@]}" -gt 0 ] && compliant="false"

{
  printf '{\n'
  printf '  "hostname": "%s",\n' "$(escape_json "$(hostname)")"
  printf '  "user": "%s",\n' "$(escape_json "${USER:-unknown}")"
  printf '  "scanned_at": "%s",\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf '  "compliant": %s,\n' "$compliant"
  printf '  "violations": ['
  first=1
  for f in "${UNIQUE[@]}"; do
    tool="${f%%|*}"; rest="${f#*|}"; surface="${rest%%|*}"; detail="${rest#*|}"
    [ $first -eq 0 ] && printf ','
    printf '\n    {"tool": "%s", "surface": "%s", "detail": "%s"}' \
      "$(escape_json "$tool")" "$(escape_json "$surface")" "$(escape_json "$detail")"
    first=0
  done
  [ $first -eq 0 ] && printf '\n  '
  printf ']\n}\n'
} > "$REPORT_PATH" 2>/dev/null && log "Report written to $REPORT_PATH"

# --- Exit ------------------------------------------------------------------
if [ "$compliant" = "true" ]; then
  log "COMPLIANT — no prohibited remote-access tools found." "INFO"
  exit 0
else
  names="$(printf '%s\n' "${UNIQUE[@]}" | cut -d'|' -f1 | sort -u | paste -sd', ' -)"
  log "NON-COMPLIANT — detected: $names" "ALERT"
  for f in "${UNIQUE[@]}"; do
    tool="${f%%|*}"; rest="${f#*|}"; surface="${rest%%|*}"; detail="${rest#*|}"
    log "  -> [$surface] $tool: $detail" "ALERT"
  done
  exit 1
fi
