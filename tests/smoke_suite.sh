#!/usr/bin/env bash
# tests/smoke_suite.sh — reusable DIBE smoke / integration suite.
#
# Fast, deterministic checks. Runs every selected check (does NOT stop at the
# first failure),
# prints PASS/FAIL/SKIP per check, and exits non-zero if any check FAILED.
# Checks SKIP gracefully when a prerequisite is absent (so the suite is portable).
#
# Usage:
#   tests/smoke_suite.sh [--build] [check ...]
#     --build       build the DIBE toolchain first (make -j)
#     (no checks)   run all checks
#     check ...     run only the named checks:
#                   toolchain fork unit p3
#
# Each integration check applies real patches with DIBE_VALIDATE=1 and asserts the
# patcher's own byte-for-byte "ALL PASSED" readback, so a silent apply bug fails here.

set -uo pipefail   # deliberately NOT -e: we want all checks to run
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"

PASS=0; FAIL=0; SKIP=0; FAILED=()
g(){ printf '\033[32m%s\033[0m' "$1"; }; r(){ printf '\033[31m%s\033[0m' "$1"; }; y(){ printf '\033[33m%s\033[0m' "$1"; }
hdr(){ printf '\n=== %s ===\n' "$1"; }
ok(){   PASS=$((PASS+1)); printf '  [%s] %s\n' "$(g PASS)" "$1"; }
bad(){  FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  [%s] %s — %s\n' "$(r FAIL)" "$1" "${2:-}"; [ -n "${3:-}" ] && sed 's/^/        /' "$3" | tail -8; }
skip(){ SKIP=$((SKIP+1)); printf '  [%s] %s — %s\n' "$(y SKIP)" "$1" "${2:-}"; }

cleanup_dibe(){ rm -f /tmp/dibe_ctrl.* /tmp/dibe.sock.* /tmp/dibe_map.* /tmp/dibe.pid 2>/dev/null || true; }

LOG=$(mktemp -d)/log; : > "$LOG"

#############################################################################
check_toolchain(){
  hdr "toolchain"
  local miss=0
  for b in patcher.so e9patch patch_to_req third_party/e9patch/e9tool target_program; do
    if [ -e "$ROOT/$b" ]; then :; else echo "  missing: $b" >>"$LOG"; miss=1; fi
  done
  [ "$miss" = 0 ] && ok "toolchain binaries present" || bad "toolchain" "missing binaries (run with --build)" "$LOG"
}

check_fork(){
  hdr "fork-quiesce levels 0/1/2"
  gcc -O2 -pthread tests/fork_quiesce_test.c -o tests/fork_quiesce_test 2>>"$LOG" || { bad "fork" "test build failed" "$LOG"; return; }
  local allok=1; : >"$LOG.f"
  for lvl in 0 1 2; do
    cleanup_dibe
    # NOTE: env (not a bare prefix) keeps LD_PRELOAD off `timeout` itself — otherwise
    # the patcher loads into timeout, whose fork-to-exec hits the level-2 seccomp
    # trap and dies with SIGSYS. Load the patcher only into the test binary.
    if timeout 60 env DIBE_FORK_QUIESCE=$lvl LD_PRELOAD="$ROOT/patcher.so" tests/fork_quiesce_test 200 >"$LOG" 2>/dev/null && grep -q '^PASS' "$LOG"; then :; else allok=0; echo "  level $lvl failed (rc/marker)" >>"$LOG.f"; fi
  done
  cleanup_dibe
  [ "$allok" = 1 ] && ok "fork microbench: 200 forks re-issued + thread exempt at all levels" || bad "fork" "a quiesce level failed" "${LOG}.f"
}

check_unit(){
  hdr "unit tests (make test)"
  # make test covers: pthread_atfork fork/concurrent, generate_patches (py),
  # and the INT3-avoidance planner-helper cores (test_int3avoid_unit).
  if timeout 120 make test >"$LOG" 2>&1; then ok "make test (pthread_atfork + generate_patches + int3avoid cores)"; else bad "unit" "make test failed" "$LOG"; fi
}

check_p3(){
  hdr "P3 predecessor redirection (synthetic fixture, behavioral)"
  cleanup_dibe
  if [ -f "$ROOT/patcher.so" ] && [ -x "$ROOT/e9patch" ] && [ -x "$ROOT/patch_to_req" ]; then
    if timeout 150 bash "$ROOT/tests/p3_test.sh" >"$LOG" 2>&1 && grep -q '\[p3-test\] PASS' "$LOG"; then
      ok "P3 fires on fixture: site off S2 (int3 0->1), ALL PASSED, behaviour correct"
    else
      bad "p3" "p3_test.sh did not report PASS" "$LOG"
    fi
  else
    skip "p3" "DIBE toolchain not built (run with --build)"
  fi
  cleanup_dibe
}

#############################################################################

ALL="toolchain fork unit p3"
BUILD=0; SELECT=""
for a in "$@"; do
  case "$a" in
    --build) BUILD=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) SELECT="$SELECT $a" ;;
  esac
done
[ -z "${SELECT// }" ] && SELECT="$ALL"

if [ "$BUILD" = 1 ]; then hdr "build (make -j)"; make -j"$(nproc)" >/dev/null 2>&1 && echo "  built" || echo "  build had warnings (continuing)"; fi

echo "DIBE smoke suite — checks:$SELECT"
for c in $SELECT; do
  case "$c" in
    toolchain) check_toolchain ;; fork) check_fork ;;
    unit) check_unit ;; p3) check_p3 ;;
    *) skip "$c" "unknown check" ;;
  esac
done

printf '\n=== summary: %s passed, %s failed, %s skipped ===\n' "$(g $PASS)" "$( [ $FAIL -gt 0 ] && r $FAIL || echo $FAIL )" "$(y $SKIP)"
[ $FAIL -gt 0 ] && { printf 'failed: %s\n' "${FAILED[*]}"; exit 1; }
exit 0
