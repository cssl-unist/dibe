#!/usr/bin/env bash
# examples/quickstart/run.sh — patch a running process with DIBE, push-button.
#
# What this does, end to end:
#   1. Builds the DIBE toolchain if it is not already built.
#   2. Starts examples/quickstart/target (a tiny long-running program) in the
#      background — an ordinary process, not specially prepared for patching.
#   3. Disassembles it and auto-generates a patch plan covering every jmp/jcc
#      site (src/generate_patches_from_objdump.py).
#   4. Applies that plan to the *running* process via scripts/patch.sh, with
#      DIBE_VALIDATE=1 so the runtime reads back every overwritten byte and
#      reports ALL PASSED only if the live process now matches the plan exactly.
#   5. Prints the S0 / S1 / S2 overwrite-strategy breakdown and the validation
#      result, then cleans up.
#
# Usage: examples/quickstart/run.sh

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

log() { printf '[quickstart] %s\n' "$*"; }
die() { printf '[quickstart] ERROR: %s\n' "$*" >&2; exit 1; }
show_recent_stderr() {
  [[ -f "${STDERR:-}" ]] || return 0
  log "recent patcher stderr:"
  tail -20 "$STDERR" | sed 's/^/[quickstart]   /'
}

cleanup() {
  local rc=$?     # capture before wait/rm below overwrite it, and re-exit with it
  if [[ -n "${TPID:-}" ]] && kill -0 "$TPID" 2>/dev/null; then
    kill "$TPID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$TPID" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$TPID" 2>/dev/null && kill -9 "$TPID" 2>/dev/null
  fi
  wait "$TPID" 2>/dev/null || true   # $TPID was just kill(1)'d; a nonzero wait status is expected, not a script error
  rm -f /tmp/dibe_ctrl.* /tmp/dibe.sock.* /tmp/dibe_map.* 2>/dev/null
  rm -f "$ROOT"/objdump.txt "$ROOT"/micro_patch.json "$ROOT"/req.json "$ROOT"/resp.json \
        "$ROOT"/jmp.jsonl "$ROOT"/patches.jsonl 2>/dev/null
  exit "$rc"
}
trap cleanup EXIT

# 1) Build if needed.
if [[ ! -x "$ROOT/patcher.so" || ! -x "$ROOT/e9patch" || ! -x "$ROOT/patch_to_req" || ! -x "$ROOT/target_program" ]]; then
  log "toolchain not built yet — running 'make -j'"
  make -C "$ROOT" -j"$(nproc)" || die "build failed"
fi

WORK="$(mktemp -d)"
PIDFILE="$WORK/target.pid"
STDERR="$WORK/target.stderr"

# 2) Start the target. patcher.so is loaded via LD_PRELOAD and starts its
#    mapping server / control FIFO in its constructor, before main() runs —
#    the target does not need to know DIBE exists.
log "starting examples/quickstart/target (LD_PRELOAD=patcher.so)..."
DIBE_PIDFILE="$PIDFILE" DIBE_VALIDATE=1 LD_PRELOAD="$ROOT/patcher.so" \
  "$ROOT/target_program" > "$WORK/target.stdout" 2> "$STDERR" &
TPID=$!

for _ in $(seq 1 50); do
  [[ -s "$PIDFILE" ]] && break
  sleep 0.1
done
[[ -s "$PIDFILE" ]] || die "target never published its PID (see $STDERR)"
PID="$(tr -d '\n' < "$PIDFILE")"
log "target running, PID=$PID"

for _ in $(seq 1 50); do
  [[ -S "/tmp/dibe.sock.$PID" ]] && break
  sleep 0.1
done
if [[ ! -S "/tmp/dibe.sock.$PID" ]]; then
  show_recent_stderr
  die "mapping-server socket never appeared; check whether local UNIX socket bind is allowed in this environment (see $STDERR)"
fi

# 3) Auto-generate a patch plan: every jmp/jcc site in the binary.
log "disassembling and generating a patch plan for every jmp/jcc site..."
objdump -d -w "$ROOT/target_program" > "$ROOT/objdump.txt"
python3 "$ROOT/src/generate_patches_from_objdump.py" \
  -i "$ROOT/objdump.txt" -o "$ROOT/micro_patch.json" --pid "$PID" \
  > "$WORK/generate.log" 2>&1
sed 's/^/[quickstart] /' "$WORK/generate.log"

# 4) Apply the plan to the running process.
# NOTE: e9patch internally forks helper processes; redirect to a file rather
# than piping to another live process, or an orphaned grandchild can keep the
# pipe open long after this script has moved on.
log "applying the plan to the running process (patch_address entries below are ELF offsets, not live VAs)..."
"$ROOT/scripts/patch.sh" "$ROOT/target_program" "$ROOT/micro_patch.json" "$WORK/patched_out" "$PID" \
  > "$WORK/patch.log" 2>&1
sed 's/^/[quickstart] /' "$WORK/patch.log"

sleep 2

# 5) Report what happened, straight from the patcher's own log.
echo
log "=== patcher.so report (from the live process) ==="
grep -E 'S0 count|S1 count|int3 count|trap hits|\[validate\]' "$STDERR" | sed 's/^/  /' || true
echo

if grep -q 'ALL PASSED' "$STDERR"; then
  log "SUCCESS: every overwritten byte in the running process was read back and verified."
else
  log "validation did not report ALL PASSED — see $STDERR"
  cat "$STDERR"
  exit 1
fi
