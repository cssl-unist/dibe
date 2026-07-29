#!/usr/bin/env bash
# examples/live-fix/run.sh — fix a bug in a running process, without restarting it.
#
# The point of this example is that you can *see* the patch take effect: the
# service is stuck reporting tick=0, and it starts counting mid-flight, in the
# same process, with the same PID, having never been stopped.
#
# End to end:
#   1. Build the DIBE toolchain (if needed) and examples/live-fix/service.
#   2. Start the service and watch it be stuck at tick=0 for a few seconds.
#   3. Write a one-site patch plan for next_tick's body:
#        mov %edi,%eax ; add $0x1,%eax ; ret     ("return t + 1")
#      i.e. the fix the buggy source line should have had.
#   4. Apply it to the live PID with scripts/patch.sh (DIBE_VALIDATE=1, so the
#      runtime also reads back every overwritten byte).
#   5. Watch the same process start counting.
#
# Usage: examples/live-fix/run.sh

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"   # patch.sh uses ./patch_to_req and ./e9patch, and the patcher reads
             # jmp.jsonl/patches.jsonl from the target's cwd — both are $ROOT.

log() { printf '[live-fix] %s\n' "$*"; }
die() { printf '[live-fix] ERROR: %s\n' "$*" >&2; exit 1; }
show_recent_stderr() {
  [[ -f "${ERR:-}" ]] || return 0
  log "recent patcher stderr:"
  tail -20 "$ERR" | sed 's/^/[live-fix]   /'
}

cleanup() {
  local rc=$?   # capture first: the kill/wait/rm below would clobber it
  if [[ -n "${TPID:-}" ]] && kill -0 "$TPID" 2>/dev/null; then
    kill "$TPID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$TPID" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$TPID" 2>/dev/null && kill -9 "$TPID" 2>/dev/null
  fi
  wait "$TPID" 2>/dev/null || true   # $TPID was just kill(1)'d; a nonzero wait status is expected here, not a script error
  rm -f /tmp/dibe_ctrl.* /tmp/dibe.sock.* /tmp/dibe_map.* 2>/dev/null
  rm -f "$ROOT"/objdump.txt "$ROOT"/req.json "$ROOT"/resp.json \
        "$ROOT"/jmp.jsonl "$ROOT"/patches.jsonl 2>/dev/null
  exit "$rc"
}
trap cleanup EXIT

# 1) Build.
if [[ ! -e "$ROOT/patcher.so" || ! -x "$ROOT/e9patch" || ! -x "$ROOT/patch_to_req" ]]; then
  log "toolchain not built yet — running 'make -j'"
  make -C "$ROOT" -j"$(nproc)" || die "build failed"
fi
[[ -x "$HERE/service" ]] || {
  log "building examples/live-fix/service..."
  gcc -O2 -Wall -Wextra -fpie -pie -o "$HERE/service" "$HERE/service.c"
}

WORK="$(mktemp -d)"
PIDFILE="$WORK/service.pid"
OUT="$WORK/service.out"
ERR="$WORK/service.err"

# 2) Start the service and let it run, buggy, for a few seconds.
log "starting the service (LD_PRELOAD=patcher.so)..."
DIBE_PIDFILE="$PIDFILE" DIBE_VALIDATE=1 LD_PRELOAD="$ROOT/patcher.so" \
  "$HERE/service" > "$OUT" 2> "$ERR" &
TPID=$!

for _ in $(seq 1 50); do [[ -s "$PIDFILE" ]] && break; sleep 0.1; done
[[ -s "$PIDFILE" ]] || die "service never published its PID (see $ERR)"
PID="$(tr -d '\n' < "$PIDFILE")"
for _ in $(seq 1 50); do
  [[ -S "/tmp/dibe.sock.$PID" && -p "/tmp/dibe_ctrl.$PID" ]] && break
  sleep 0.1
done
if [[ ! -S "/tmp/dibe.sock.$PID" ]]; then
  show_recent_stderr
  die "mapping-server socket never appeared; check whether local UNIX socket bind is allowed in this environment (see $ERR)"
fi
log "service running, PID=$PID"

sleep 3
echo
log "=== before the patch (the bug: stuck at tick=0) ==="
grep '^tick=' "$OUT" | sed 's/^/  /'
BEFORE_N="$(grep -c '^tick=' "$OUT" || true)"
[[ "$BEFORE_N" -ge 2 ]] || die "service produced no output (see $ERR)"
grep '^tick=' "$OUT" | grep -qv '^tick=0$' && die "service was not stuck at tick=0 before patching"

# 3) Build the patch plan: the dense .text stream from the generator (e9patch
#    needs it for its pred/succ analysis), with the sites replaced by our one fix.
log "planning the fix for next_tick..."
objdump -d -w "$HERE/service" > "$WORK/objdump.txt"
python3 "$ROOT/src/generate_patches_from_objdump.py" \
  -i "$WORK/objdump.txt" -o "$WORK/plan.json" --pid "$PID" > "$WORK/generate.log" 2>&1

python3 - "$WORK/plan.json" "$WORK/objdump.txt" "$WORK/micro_patch.json" "$PID" <<'PY'
import json, sys

plan_path, objdump_path, out_path, pid = sys.argv[1:5]

# Find next_tick's first body instruction (skipping the endbr64 landing pad).
site = None
in_fn = False
for line in open(objdump_path):
    if line.strip().endswith('<next_tick>:'):
        in_fn = True
        continue
    if in_fn:
        if not line.strip():
            break
        head, _, rest = line.partition(':')
        addr = head.strip()
        # objdump -d -w lines are "<addr>:\t<raw bytes>\t<mnemonic>"; the leading
        # tab yields an empty first field, so drop the blanks before indexing.
        cols = [c.strip() for c in rest.split('\t') if c.strip()]
        if len(cols) < 2:
            continue
        raw, mnemonic = cols[0].split(), cols[1]
        if mnemonic.startswith('endbr64'):
            continue
        site = (addr, raw, mnemonic)
        break

if site is None:
    sys.exit("could not locate next_tick's body in the disassembly")

addr, raw, mnemonic = site

# Fail loudly rather than corrupting the process: the replacement below assumes
# the body is exactly `mov %edi,%eax` (return t), which is what GCC emits at -O2.
if raw != ['89', 'f8']:
    sys.exit("unexpected next_tick body at %s: %s (%s) — expected 89 f8 (mov %%edi,%%eax).\n"
             "This example hard-codes the replacement bytes, so it only supports that form."
             % (addr, ' '.join(raw), mnemonic))

d = json.load(open(plan_path))
d['pid'] = int(pid)
d['patches'] = [{
    'patch_address': addr,
    'target_length': len(raw),                 # bytes at the site, not a count of instructions
    # mov %edi,%eax ; add $0x1,%eax ; ret   ==  "return t + 1", then return
    # straight to main() -- no $break needed, the trampoline ends in ret.
    'patch_bytes': ['0x89', '0xf8', '0x83', '0xc0', '0x01', '0xc3'],
}]
json.dump(d, open(out_path, 'w'))
print("patching next_tick body at 0x%s (%s, %d bytes) -> mov %%edi,%%eax; add $0x1,%%eax; ret"
      % (addr, mnemonic, len(raw)))
PY

# 4) Apply to the live process.
# NOTE: e9patch forks helper processes internally; redirect to a file rather than
# piping to another live process, or an orphaned grandchild can hold the pipe open.
log "applying the fix to PID $PID (live, no restart)..."
"$ROOT/scripts/patch.sh" "$HERE/service" "$WORK/micro_patch.json" "$WORK/patched_out" "$PID" \
  > "$WORK/patch.log" 2>&1 || { sed 's/^/  /' "$WORK/patch.log"; die "patch.sh failed"; }

sleep 4

# 5) Show the same process, now counting.
echo
log "=== after the patch (same PID $PID, never restarted) ==="
grep '^tick=' "$OUT" | tail -n +"$((BEFORE_N + 1))" | sed 's/^/  /'
echo
log "=== patcher.so report (from the live process) ==="
grep -E 'S0 count|S1 count|int3 count|\[validate\]' "$ERR" | sed 's/^/  /' || true
echo

LAST="$(grep '^tick=' "$OUT" | tail -1 | cut -d= -f2)"
if [[ "${LAST:-0}" -gt 0 ]] && grep -q 'ALL PASSED' "$ERR"; then
  log "SUCCESS: next_tick was fixed in the running process — the counter advanced to $LAST,"
  log "         and every overwritten byte read back exactly as planned."
else
  log "expected the counter to advance past 0 and validation to report ALL PASSED"
  log "last tick=${LAST:-<none>}; patcher stderr:"
  sed 's/^/  /' "$ERR"
  exit 1
fi
