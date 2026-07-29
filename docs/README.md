# DIBE documentation

Central map for the DIBE project docs, reachable from the repository
[`../README.md`](../README.md). DIBE is a run-time binary-editing framework for
x86-64 Linux: it patches a program's code while the program keeps running,
instead of requiring an offline rewrite and a restart.

## Guides

- [guides/scripts.md](guides/scripts.md) — what each build/patch script does,
  and how they depend on one another.

## Examples

- [`../examples/quickstart/`](../examples/quickstart/) — the fastest way to see
  DIBE patch a running process; start here.
- [`../examples/live-fix/`](../examples/live-fix/) — fixes a bug in a running
  process, so you can watch a patch change behavior rather than just validate.

## Vendored components

- [`../third_party/e9patch/`](../third_party/e9patch/) — DIBE's modified fork of
  [E9Patch](https://github.com/GJDuck/e9patch), reused as the offline metadata
  generator (trampoline placement, patch tactics, page grouping). It keeps its
  own upstream license (`third_party/e9patch/LICENSE`, GPLv3).
