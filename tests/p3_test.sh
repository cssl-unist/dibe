#!/usr/bin/env bash
# p3_test.sh — end-to-end behavioral test for DIBE predecessor redirection (P3)
# on the synthetic fixture tests/p3_fixture.
#
# Asserts, with a live patch applied while the program runs:
#   1. e9patch's planner FIRES P3:  "pred-redirect: applied=1 ... pred_entries=1".
#   2. The site converts OFF S2:  the jmp.jsonl entry for sa's predecessor X is a
#      4-byte rel32 rewrite at an S0/S1 offset (no INT3).  We assert the runtime's
#      "int3 count" is 0 (the only patched site is now predecessor-redirected).
#   3. DIBE_VALIDATE byte-readback: "ALL PASSED".
#   4. BEHAVIOR is correct: the fixture keeps returning 201001 after the patch —
#      i.e. X's redirected branch + the replayed [Y, sa) + sa all execute
#      correctly.  A wrong rel32 rewrite or [Y, sa) replay would crash or change
#      the value (e.g. to the 0xBADBAD=12245933 sentinel) and FAIL here.
#   5. Control: with DIBE_NO_PRED_REDIRECT=1, P3 does not fire (applied=0) and
#      the site stays S2 (int3 count = 1).
#
# Exit 0 on PASS, non-zero on FAIL (prints the reason + captured logs).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTS="$ROOT/tests"
GOOD=201001                 # correct p3_compute() return value
SENTINEL=12245933           # 0xBADBAD: the "broken replay" sentinel

fail(){ echo "[p3-test] FAIL: $*"; [ -n "${E9LOG:-}" ] && { echo "--- e9patch stderr ---"; tail -25 "$E9LOG"; }
        [ -n "${TLOG:-}" ] && { echo "--- target stdout ---"; tail -8 "$TLOG"; }
        [ -n "${ELOG:-}" ] && { echo "--- patcher stderr ---"; grep -E 'int3 count|ALL PASSED|FAIL|count:' "$ELOG" | tail -12; }
        cleanup; exit 1; }
cleanup(){ [ -n "${TPID:-}" ] && kill "$TPID" 2>/dev/null; wait "${TPID:-}" 2>/dev/null;
           rm -f /tmp/dibe_ctrl.* /tmp/dibe.sock.* /tmp/dibe_map.* 2>/dev/null; }
trap cleanup EXIT

# --- Build the fixture (PIE, no optimization to preserve the hand-laid layout) ---
gcc -O0 -fPIE -pie "$TESTS/p3_fixture.S" "$TESTS/p3_fixture_main.c" -o "$TESTS/p3_fixture" \
    || { echo "[p3-test] FAIL: fixture build failed"; exit 1; }

# Verify the fixture's unpatched value before involving the patcher.
v0="$(timeout 3 "$TESTS/p3_fixture" | sed -n '2{s/ .*//;p}')"
[ "$v0" = "$GOOD" ] || { echo "[p3-test] FAIL: fixture unpatched value=$v0 (want $GOOD)"; exit 1; }

# run_once <mode-label> <extra-env...> : launch fixture gated, plan, APPLY, observe.
#   echoes "applied=<n> int3=<n> validate=<PASS|FAIL|?> value=<v> rc=<rc>"
run_once(){
    local label="$1"; shift
    local extra_env=("$@")
    local wd; wd="$(mktemp -d)"
    TLOG="$wd/target.out"; ELOG="$wd/patcher.err"; E9LOG="$wd/e9patch.err"
    local pidfile="$wd/dibe.pid"
    rm -f /tmp/dibe_ctrl.* /tmp/dibe.sock.* /tmp/dibe_map.* 2>/dev/null

    # Launch the fixture gated (DIBE_START_GATE holds main() until APPLY completes)
    # so the patch lands deterministically; then it runs and prints values/sec.
    # The patcher ctor writes the live PID to DIBE_PIDFILE before the gate (main's
    # "Process ID:" print is AFTER the gate, so we can't read it from stdout yet).
    ( cd "$wd" && env DIBE_START_GATE=1 DIBE_VALIDATE=1 DIBE_PIDFILE="$pidfile" \
        "${extra_env[@]}" LD_PRELOAD="$ROOT/patcher.so" "$TESTS/p3_fixture" ) \
        >"$TLOG" 2>"$ELOG" &
    TPID=$!
    # Wait for the patcher ctor to publish the PID.
    local i pid=""
    for i in $(seq 1 50); do
        [ -f "$pidfile" ] && pid="$(tr -d '\n' < "$pidfile")" && [ -n "$pid" ] && break
        sleep 0.1
    done
    [ -n "$pid" ] || { echo "applied=? int3=? validate=? value=NOSTART rc=1"; return; }
    # Wait for the mapping-server socket so e9patch can map trampoline pages.
    for i in $(seq 1 50); do [ -S "/tmp/dibe.sock.${pid}" ] && break; sleep 0.1; done

    # Plan: micro_patch (sa only) -> req.json -> e9patch (maps pages into target).
    local od="$wd/od.txt" mp="$wd/full.json" mp2="$wd/mp.json"
    objdump -d -w "$TESTS/p3_fixture" > "$od" 2>/dev/null
    python3 "$ROOT/src/generate_patches_from_objdump.py" -i "$od" -o "$mp" --pid "$pid" >/dev/null 2>&1
    python3 - "$mp" "$mp2" "$pid" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
# Patch ONLY sa (0x118e); leave the predecessor X uninstrumented so P3 can fire.
d['patches']=[{'patch_address':'118e','target_length':5,
               'patch_bytes':['0x90','$instr','$break']}]
d['pid']=int(sys.argv[3])
json.dump(d,open(sys.argv[2],'w'))
PY
    "$ROOT/patch_to_req" "$mp2" "$TESTS/p3_fixture" out "$pid" > "$wd/req.json" 2>>"$E9LOG"
    ( cd "$wd" && env "${extra_env[@]}" "$ROOT/e9patch" -OCFR --tactic-T0=false \
        --pid "$pid" --output-dir "$wd/" --input "$wd/req.json" --output "$wd/resp.json" ) \
        >>"$E9LOG" 2>&1

    # APPLY (patcher reads jmp.jsonl/patches.jsonl from its cwd = $wd).
    local fifo="/tmp/dibe_ctrl.${pid}"
    [ -p "$fifo" ] && echo "APPLY $wd/" > "$fifo"
    sleep 3

    local applied int3 validate value rc=0
    applied="$(sed -n 's/.*pred-redirect: applied=\([0-9]*\).*/\1/p' "$E9LOG" | tail -1)"
    [ -z "$applied" ] && applied="?"
    int3="$(sed -n 's/.*int3 count: \([0-9]*\).*/\1/p' "$ELOG" | tail -1)"
    [ -z "$int3" ] && int3="?"
    if grep -q 'ALL PASSED' "$ELOG"; then validate=PASS
    elif grep -q 'FAIL' "$ELOG"; then validate=FAIL; else validate="?"; fi
    # The value printed AFTER the patch applied (last line).
    value="$(tail -1 "$TLOG" | sed 's/ .*//')"
    [ -z "$value" ] && value="NONE"
    kill "$TPID" 2>/dev/null; wait "$TPID" 2>/dev/null; rc=$?; TPID=""
    echo "applied=$applied int3=$int3 validate=$validate value=$value"
}

echo "[p3-test] fixture unpatched value OK ($GOOD)"

# --- Case A: P3 enabled (default) — must fire, remove the INT3, validate, behave ---
echo "[p3-test] case A: P3 enabled"
RA="$(run_once on)"
echo "  $RA"
ap="$(echo "$RA"|sed 's/.*applied=\([^ ]*\).*/\1/')"
i3="$(echo "$RA"|sed 's/.*int3=\([^ ]*\).*/\1/')"
va="$(echo "$RA"|sed 's/.*validate=\([^ ]*\).*/\1/')"
vl="$(echo "$RA"|sed 's/.*value=\([^ ]*\).*/\1/')"
[ "$ap" = 1 ]        || fail "P3 did not fire (pred-redirect applied=$ap, want 1)"
[ "$i3" = 0 ]        || fail "site did not convert off S2 (int3=$i3, want 0)"
[ "$va" = PASS ]     || fail "DIBE_VALIDATE not ALL PASSED (validate=$va)"
[ "$vl" = "$GOOD" ]  || fail "behavior wrong after P3 (value=$vl, want $GOOD; sentinel=$SENTINEL means broken replay)"
echo "[p3-test] case A OK: P3 fired, int3=0, ALL PASSED, value=$GOOD"

# --- Case B: P3 disabled — must NOT fire; the site stays S2 (int3=1) ---
echo "[p3-test] case B: P3 disabled (control)"
RB="$(run_once off DIBE_NO_PRED_REDIRECT=1)"
echo "  $RB"
apB="$(echo "$RB"|sed 's/.*applied=\([^ ]*\).*/\1/')"
i3B="$(echo "$RB"|sed 's/.*int3=\([^ ]*\).*/\1/')"
vaB="$(echo "$RB"|sed 's/.*validate=\([^ ]*\).*/\1/')"
vlB="$(echo "$RB"|sed 's/.*value=\([^ ]*\).*/\1/')"
[ "$apB" = 0 ] || fail "P3 fired despite DIBE_NO_PRED_REDIRECT=1 (applied=$apB)"
[ "$i3B" = 1 ] || fail "expected site on S2 with P3 disabled (int3=$i3B, want 1)"
[ "$vaB" = PASS ] || fail "DIBE_VALIDATE not ALL PASSED with P3 disabled (validate=$vaB)"
[ "$vlB" = "$GOOD" ] || fail "behavior wrong with P3 disabled (value=$vlB, want $GOOD)"
echo "[p3-test] case B OK: P3 off => int3=1 (S2), still correct"

echo "[p3-test] PASS"
