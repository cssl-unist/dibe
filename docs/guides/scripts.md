# Scripts Reference

## Summary

| Script | Description |
|--------|-------------|
| `make` / `build.sh` | Builds `patcher.so`, `patch_to_req`, `dlopen`, `target_program`, and the vendored E9Patch fork |
| `third_party/e9patch/build.sh` | Builds the vendored E9Patch fork (`make clean && make debug`, copies the `e9patch`/`e9tool` binaries to the repo root) |
| `scripts/patch.sh` | Applies a patch plan to a running process: resolves its PID, converts the plan to `req.json`, drives `e9patch --pid`, signals APPLY |
| `src/generate_patches_from_objdump.py` | Auto-generates a patch plan from `objdump -d` output (jmp/jcc sites by default; `--a2` for heap-write sites, `--all` for every instruction) |
| `examples/quickstart/run.sh` | Push-button demo: builds if needed, live-patches an ordinary running process, and reports DIBE's own byte-level validation |
| `examples/live-fix/run.sh` | Push-button demo: fixes a bug in a running process (a stuck counter) and shows the output change, same PID, no restart |
| `tests/smoke_suite.sh` | Fast integration checks (toolchain presence, fork-quiesce, unit tests, predecessor-redirection behavior) |

## Dependency graph

```
make / build.sh
  |
  +-- third_party/e9patch/build.sh --> e9patch, e9tool (copied to repo root)
  +-- patcher.so
  +-- patch_to_req
  +-- dlopen
       |
       v
  +------------------+     +---------------------------+
  | scripts/patch.sh |     | examples/quickstart/run.sh |
  +------------------+     +---------------------------+
                                        |
                            src/generate_patches_from_objdump.py
                            (auto-generates the patch plan)

  +--------------------------+
  | examples/live-fix/run.sh |--> scripts/patch.sh (one hand-written patch site)
  +--------------------------+

  +----------------------+
  | tests/smoke_suite.sh |--> make test, tests/p3_test.sh, tests/fork_quiesce_test.c
  +----------------------+
```

### Artifacts

| Artifact | Produced by | Consumed by |
|----------|-------------|-------------|
| `patcher.so` | `make` | `scripts/patch.sh`, both `examples/*/run.sh`, `tests/smoke_suite.sh` |
| `e9patch` | `third_party/e9patch/build.sh` (via `make e9patch`) | `scripts/patch.sh`, and so both `examples/*/run.sh` |
| `e9tool` | `third_party/e9patch/build.sh` (via `make e9patch`) | E9Patch's matcher-driven frontend. The bundled examples do not use it — they write patch plans directly — but it is built and smoke-checked, and is the entry point if you want to select sites by instruction pattern instead. |
| `patch_to_req`, `dlopen` | `make` | `scripts/patch.sh` |
| `target_program` | `make` (from `examples/quickstart/target.c`) | `examples/quickstart/run.sh`, `tests/smoke_suite.sh` |
| `examples/live-fix/service` | `examples/live-fix/run.sh` | `examples/live-fix/run.sh` |

Build outputs (`patcher.so`, `e9patch`, `patch_to_req`, `dlopen`, `target_program`) land at the repository root regardless of where their sources live under `src/` — this keeps every script's relative paths (`./patcher.so`, `../patcher.so` from `tests/`, etc.) unchanged no matter how the source tree is organized.
