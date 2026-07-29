# DIBE: Dynamic Incremental Binary Editing

*Language: **English** | [한국어](README.ko.md)*

DIBE patches the machine code of an **already-running** x86-64 Linux process,
without stopping it, restarting it, or requiring it to have been built with any
special support. It confines the cost of every edit to the single thread
executing the patched instruction — never a global pause of the process.

It does this by splitting the work in two: an offline **admin** process reuses
a modified fork of [E9Patch](https://github.com/GJDuck/e9patch) to work out
*what* to change (trampoline placement, patch tactics, the order multi-site
edits must apply in) as metadata, and a lightweight in-process **runtime**
(loaded via `LD_PRELOAD`) replays that plan against the live process through
alignment-aware atomic overwrites.

## Quickstart

```bash
git clone <this-repo> && cd dibe
make -j                        # build patcher.so, the toolchain, and E9Patch
./examples/quickstart/run.sh   # patch an ordinary running process, live
```

`examples/quickstart/run.sh` builds the toolchain if needed, starts a small
long-running program, disassembles it, generates a patch plan covering every
jump/branch site, applies that plan to the *running* process, and prints
DIBE's own byte-for-byte validation of the result:

```
[quickstart] === patcher.so report (from the live process) ===
  [patcher] S0 count: 9
  [patcher] S1 count: 1
  [patcher] int3 count: 0
  [validate] === ALL PASSED ===

[quickstart] SUCCESS: every overwritten byte in the running process was read back and verified.
```

The quickstart exercises the machinery and proves the bytes landed, but its
patches are deliberately behavior-neutral. To watch a patch actually *change
what a running process does*, see [`examples/live-fix/`](examples/live-fix/):
a small service is stuck reporting `tick=0` because of a bug in `next_tick()`,
and DIBE fixes that function in place. The same process — same PID, never
stopped, never restarted — starts counting:

```bash
./examples/live-fix/run.sh
```

```
[live-fix] === before the patch (the bug: stuck at tick=0) ===
  tick=0
  tick=0
[live-fix] === after the patch (same PID 274601, never restarted) ===
  tick=1
  tick=2
  [patcher] S0 count: 1
  [validate] === ALL PASSED ===
```

## How it works

- **Offline planning, online activation.** All heavyweight analysis
  (disassembly, control-flow reasoning, trampoline placement) happens offline,
  in the admin process. The in-process runtime only performs pre-validated,
  already-decided operations — it carries no planning logic of its own.
- **Alignment-aware atomic overwrites.** Three strategies apply a patch
  depending on what alignment guarantees the target site offers: **S0** (a
  single 8-byte aligned store), **S1** (a 16-byte `CMPXCHG16B`), and **S2**
  (an `INT3`-gated two-phase fallback for sites with no atomicity guarantee).
  S0/S1 are invisible to concurrent threads; only S2 can momentarily stall the
  single thread that faults into the gate.
- **Safe multi-site activation.** Some patch tactics rewrite more than one
  instruction (e.g. evicting a neighboring instruction to make room for a
  jump). The admin process resolves the dependency order between such edits
  offline (evictees first) and exports it as metadata, so the runtime applies
  them in an order where every intermediate state observed by a concurrent
  thread is correct — with no ordering logic executing at patch time.
- **Conflict-free trampoline mapping.** Trampoline pages are placed in the
  target's live address space via `memfd` + `SCM_RIGHTS` +
  `MAP_FIXED_NOREPLACE`; a collision (`EEXIST`) triggers a re-plan or a
  clean abort — no live code is ever touched if placement can't be resolved.

## Architecture

```
+-----------------------------+     +-----------------------------------+
|   Admin (scripts/patch.sh)  |     |   Target process                  |
|                             |     |   (LD_PRELOAD=patcher.so)          |
|  micro_patch.json           |     |                                    |
|       |                     |     |  +--------------+                 |
|       v                     |     |  | Mapping       | <- mmap        |
|  patch_to_req -> req.json   |     |  | server        |    trampoline  |
|       |                     |     |  | (UNIX socket) |    pages       |
|       v                     |     |  +--------------+                 |
|  e9patch (modified)         |     |                                    |
|       |                     |     |  +--------------+                 |
|       +-> jmp.jsonl --------+-->--+  | Activation    | <- atomic jmp |
|       +-> patches.jsonl ----+-->--+  | thread        |    overwrites  |
|       +-> resp.json         |     |  +--------------+                 |
|                             |     |                                    |
|  FIFO: "APPLY" -------------+-->--+  FIFO control thread               |
+-----------------------------+     |  (/tmp/dibe_ctrl.<PID>)            |
                                     |                                    |
                                     |  INT3 trap handler (S2 fallback)   |
                                     +-----------------------------------+
```

**Admin side** (`scripts/patch.sh`): converts a patch specification
(`micro_patch.json`) into E9Patch-compatible requests, runs the modified
E9Patch to produce rewrite metadata, and signals the target to apply.

**Target side** (`patcher.so`): loaded via `LD_PRELOAD` at startup, using
`__attribute__((constructor))` (compatible with glibc 2.34+, unlike an
`__libc_start_main` hook). Runs a mapping server for trampoline page
allocation and an activation thread that applies `jmp` overwrites using S0/S1/S2.

## Repository structure

```
src/               runtime + admin-side sources
  patcher.cpp          the in-process runtime (-> patcher.so via LD_PRELOAD)
  patch_to_req.cpp     micro_patch.json -> req.json converter
  dlopen.cpp           signal sender for APPLY/COMMIT control
  generate_patches_from_objdump.py   auto-generate a patch plan from objdump -d
include/           vendored headers (nlohmann/json)
scripts/
  patch.sh             orchestrator: resolves target PID, drives the pipeline
third_party/
  e9patch/             modified E9Patch fork, reused as the offline metadata generator
examples/
  quickstart/          push-button demo: patch every jmp/jcc site, validate (target.c + run.sh)
  live-fix/            fix a bug in a running process and watch the output change
tests/               unit + integration tests (make test, smoke_suite.sh)
docs/                guides and architecture notes
```

Build outputs (`patcher.so`, `e9patch`, `patch_to_req`, `dlopen`,
`target_program`) always land at the repository root, regardless of where
their sources live — see [`docs/guides/scripts.md`](docs/guides/scripts.md)
for the full script/artifact dependency graph.

## Dependencies

- C++17 compiler (`g++`)
- `nlohmann/json` (vendored as `include/json.hpp`)
- `libdl`, `pthread`
- The vendored E9Patch fork additionally needs `libdw`, `libZydis` (or
  `make dev` inside `third_party/e9patch/` to build from vendored contrib), `xxd`

## Build

```bash
make                    # everything: patcher.so, patch_to_req, dlopen,
                         # target_program, and the vendored E9Patch fork
```

Or build components individually:

```bash
make patcher.so         # runtime patcher library
make patch_to_req       # patch-to-request converter
make dlopen             # signal sender utility
make target_program     # quickstart's test target binary
make e9patch             # vendored E9Patch fork (delegates to third_party/e9patch/)
```

## Patching a running process

```bash
scripts/patch.sh <target_binary> <micro_patch.json> <patch_label> [<PID>|--auto]
```

`micro_patch.json` specifies what to patch. This is the plan
[`examples/live-fix/`](examples/live-fix/) applies — it replaces the body of a
two-byte `next_tick()` with `mov %edi,%eax; add $0x1,%eax; ret`, i.e. `return t + 1`:

```json
{
  "patches": [
    {
      "patch_address": "1224",
      "target_length": 2,
      "patch_bytes": ["0x89", "0xf8", "0x83", "0xc0", "0x01", "0xc3"]
    }
  ],
  "pid": 12345
}
```

- `patch_address` — the site's address as printed by `objdump -d`. This is a
  link-time address, not the runtime one: DIBE converts it to a file offset and
  rebases it onto the live process itself, so ASLR and PIE need no handling here.
- `target_length` — the length **in bytes** of the instruction at that address
  (`mov %edi,%eax` above is 2). It is not a count of instructions.
- `patch_bytes` — the trampoline body: what runs in place of that instruction.
  Alongside raw bytes, four tokens are available:

  | Token | Expands to |
  |-------|------------|
  | `$instr` | the original instruction |
  | `$bytes` | the original instruction's raw bytes |
  | `$break` | a jump back to the instruction after the site |
  | `$take` | a jump to the branch target |

  A trampoline ending in `$break` rejoins the normal flow, which is what makes
  `["0x90", "$instr", "$break"]` a behavior-neutral probe. The plan above instead
  ends in a `ret` (`0xc3`), so it returns straight to the caller and the rest of
  the original function is simply never reached.

To generate a plan automatically instead of hand-writing one:

```bash
objdump -d -w target_program > objdump.txt
python3 src/generate_patches_from_objdump.py -i objdump.txt -o micro_patch.json --pid <PID>
```

The generator also emits an `instructions` array beside `patches`: the dense
disassembly of `.text`, which E9Patch needs for the predecessor/successor
analysis behind its trampoline tactics. **A hand-written plan still needs it.**
The practical recipe — used by `examples/live-fix/run.sh` — is to let the
generator produce the plan, then replace only its `patches` array with your own,
keeping `instructions` as-is.

## Environment variables

| Variable | Description |
|----------|--------------|
| `DIBE_PIDFILE` | Path to write a PID file for coordination |
| `DIBE_START_GATE` | If `1`, blocks `main()` until patching completes (cleared after the gate opens) |
| `DIBE_VALIDATE` | If set, validates patches after apply (byte-for-byte correctness check; not for perf runs) |
| `DIBE_FORK_WORKERS` | If `1`, forked children get their own FIFO + mapping server (for multi-process servers) |
| `DIBE_LIVE_PATCH` | If `1`, patches while the target runs (no `START_GATE`) |
| `DIBE_FORCE_S2` | Diagnostic (default off). If `1`, routes every overwrite through the S2 `INT3`-gated path |
| `DIBE_S2_DEBUG_DELAY_US` | Diagnostic (default off). Microseconds to widen the S2 gate window, for deterministic demos |
| `DIBE_FORK_QUIESCE` | Fork hardening (default off). `1` = `pthread_atfork` prepare-quiesce; `2` = also install a seccomp/SIGSYS trap for raw `clone()` |

## Validation mode

DIBE includes a post-apply validation mode that reads back patched memory and
compares it byte-for-byte against the plan. This is for correctness
verification only — do not enable it during performance measurement.

```bash
DIBE_VALIDATE=1 scripts/patch.sh target_program micro_patch.json patched --auto
```

Validation checks that every trampoline page is mapped, and that every
`patches.jsonl` (trampoline bytes) and `jmp.jsonl` (jump overwrite) entry
matches live memory. It can also be triggered on a running process by
creating `/tmp/dibe_validate` (useful for targets that sanitize their
environment before `main()`).

## Testing

```bash
tests/smoke_suite.sh --build     # rebuild, then run every check
tests/smoke_suite.sh toolchain   # run one named check: toolchain, fork, unit, p3
make test-unit                   # C and Python unit tests
make test-integration            # p3 predecessor-redirection integration test
make test                        # full packaged test pass
```

The integration checks apply real patches with `DIBE_VALIDATE=1`, so a silent
apply bug fails the suite. Unit tests (`make test-unit`) cover:

- `tests/test_fork.c` — `pthread_atfork` creates per-worker FIFOs after `fork()`
- `tests/test_generate_patches.py` — jump-mnemonic detection, objdump parsing, subsampling
- `tests/test_int3avoid_unit.c` — the INT3-avoidance planner's core decision logic

Integration tests include:

- `tests/p3_test.sh` — end-to-end predecessor-redirection behavior on a synthetic fixture

## Known issues

- **glibc 2.34+**: the classic `__libc_start_main` hook is incompatible with
  glibc 2.34+ (its internal signature changed). DIBE uses
  `__attribute__((constructor))` + `atexit` instead.
- **C target programs**: `patcher.so` is built as C++ but is commonly loaded
  into pure C programs via `LD_PRELOAD`. All constructor-time code uses
  `fprintf`/POSIX calls rather than `std::cerr`, since iostream may not yet be
  initialized when the constructor runs.

## License

GPLv3 (see [`LICENSE`](LICENSE)) — DIBE's admin/runtime code is offered under
the same license as the vendored E9Patch fork it depends on
(`third_party/e9patch/`, which keeps its own upstream GPLv3 license file).

Developed at UNIST (Ulsan National Institute of Science and Technology).
