#!/usr/bin/env bash
set -euo pipefail

# ===== patch.sh =====
# Usage:
#   patch.sh <target_binary> <micro_patch.json> <patch_binary> [<PID>|--auto]
#
# Examples:
#   patch.sh ./myapp micro_patch.json patch_program --auto
#   DIBE_PIDFILE=/tmp/dibe.myapp.pid patch.sh ./myapp micro_patch.json patch_program
#
# What it does:
#   1) micro_patch.json -> req.json
#   2) run e9patch against the live PID to plan and map the trampolines
#   3) send APPLY on the target's control FIFO
#
# Notes:
#   - PID auto-resolution order:
#       (a) DIBE_PIDFILE (if present)
#       (b) /proc/*/exe realpath match with $TARGET (most recent)
#       (c) pgrep -f fallback
#   - Set DIBE_PIDFILE when the target is launched through a wrapper script.

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "Usage: $0 <target_program> <micro_patch.json> <patch_binary> [<PID>|--auto]"
  exit 1
fi

TARGET=$1
MICRO_JSON=$2
PATCH=$3
ARG4="${4-}"

realpath_cmd() {
  python3 - "$1" <<'PY'
import os,sys
print(os.path.realpath(sys.argv[1]))
PY
}

TARGET_REAL="$(realpath_cmd "$TARGET")"

log() { echo "[$(date +'%H:%M:%S')] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

read_pidfile_if_exists() {
  local pf="${DIBE_PIDFILE-}"
  if [[ -n "${pf}" && -f "${pf}" ]]; then
    local p
    p="$(tr -d '\n' < "${pf}")" || true
    [[ -n "${p}" ]] && [[ -d "/proc/${p}" ]] && echo "$p"
  fi
}

find_by_exe_symlink() {
  # Find PIDs whose /proc/<pid>/exe resolves to TARGET_REAL
  # Return the most recently started one.
  local target="$1"
  local candidates=()
  for x in /proc/[0-9]*/exe; do
    [[ -e "$x" ]] || continue
    # Fast path: match symlink
    local exe
    exe="$(readlink -f "$x" 2>/dev/null || true)"
    [[ "$exe" == "$target" ]] || continue
    local pid="${x#/proc/}"; pid="${pid%/exe}"
    candidates+=("$pid")
  done
  if [[ ${#candidates[@]} -eq 0 ]]; then
    return 1
  fi
  # Pick the most recent by /proc/<pid>/stat starttime (22nd field)
  # shellcheck disable=SC2002
  local best_pid=""
  local best_start=0
  for pid in "${candidates[@]}"; do
    if [[ -r "/proc/${pid}/stat" ]]; then
      # starttime is the 22nd field; but comm may contain spaces in parentheses.
      # We parse from the right (starttime is stable at index 22)
      local line; line="$(cat "/proc/${pid}/stat")"
      local st
      st="$(awk '{print $(22)}' <<< "$line" 2>/dev/null || echo 0)"
      [[ "$st" =~ ^[0-9]+$ ]] || st=0
      if (( st > best_start )); then
        best_start="$st"
        best_pid="$pid"
      fi
    fi
  done
  [[ -n "$best_pid" ]] && echo "$best_pid"
}

pgrep_fallback() {
  # Last resort: pgrep -f with basename and realpath
  local bn; bn="$(basename "$TARGET_REAL")"
  local cand
  cand="$(pgrep -f -- "$bn" | tail -n1 || true)"
  [[ -n "$cand" ]] && echo "$cand"
}

resolve_pid() {
  local explicit="$1"
  if [[ -n "$explicit" && "$explicit" != "--auto" ]]; then
    echo "$explicit"
    return 0
  fi
  # (a) PIDFILE
  local p
  p="$(read_pidfile_if_exists || true)"
  if [[ -n "$p" ]]; then echo "$p"; return 0; fi
  # (b) exe symlink match
  p="$(find_by_exe_symlink "$TARGET_REAL" || true)"
  if [[ -n "$p" ]]; then echo "$p"; return 0; fi
  # (c) pgrep fallback
  p="$(pgrep_fallback || true)"
  if [[ -n "$p" ]]; then echo "$p"; return 0; fi
  return 1
}

PID=""
if ! PID="$(resolve_pid "$ARG4")"; then
  die "Failed to resolve PID. Consider setting DIBE_PIDFILE or pass an explicit PID."
fi

log "Target     : $TARGET_REAL"
log "Micro JSON : $MICRO_JSON"
log "Patch bin  : $PATCH"
log "PID        : $PID"

objdump -d -w "$TARGET_REAL" > objdump.txt

log "[1/3] Generating req.json from $MICRO_JSON, $PID"
./patch_to_req "$MICRO_JSON" "$TARGET_REAL" "$PATCH" "$PID" > req.json

FIFO="/tmp/dibe_ctrl.${PID}"

# --tactic-T0=false: the runtime expects one 5-byte JMP per site; T0 batching
#   emits a multi-instruction trampoline the runtime cannot replay.
log "[2/3] Planning and mapping trampolines via e9patch"
./e9patch -OCFR --tactic-T0=false --pid "$PID" --input req.json --output resp.json

log "[3/3] Sending APPLY"
echo "APPLY" > "$FIFO"
sleep 1

log "Done."
