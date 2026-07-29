.PHONY: test test_fork_run test_patcher_run test_concurrent_run \
        test_int3avoid_run test_py test_p3_run clean

CC       ?= gcc
CXX      ?= g++
CFLAGS   ?= -O2 -Wall -Wextra

PATCHER_SO = ../patcher.so

# DIBE INT3-avoidance planner-helper cores (pure logic; no e9patch.h).
INT3AVOID_DIR  = ../third_party/e9patch/src/e9patch
INT3AVOID_CORE = $(INT3AVOID_DIR)/e9int3avoid_core.cpp
INT3AVOID_HDR  = $(INT3AVOID_DIR)/e9int3avoid.h

test: test_fork_run test_patcher_run test_concurrent_run test_int3avoid_run \
      test_py test_p3_run
	@echo ""
	@echo "=== All tests passed ==="

# Build and run the C fork integration test
test_fork: test_fork.c test_common.h
	$(CC) $(CFLAGS) -o $@ test_fork.c

# DIBE_FORK_WORKERS=1 enables the per-worker FIFO/mapping-server setup in the
# child_after_fork handler. Without it, child_after_fork returns early (it does
# not spawn patcher threads in incidental forks), so the child-FIFO asserts fail.
test_fork_run: test_fork $(PATCHER_SO)
	DIBE_FORK_WORKERS=1 LD_PRELOAD=$(PATCHER_SO) ./test_fork

# Build and run the C patcher core test
test_patcher: test_patcher.c test_common.h
	$(CC) $(CFLAGS) -o $@ test_patcher.c

test_patcher_run: test_patcher $(PATCHER_SO)
	LD_PRELOAD=$(PATCHER_SO) ./test_patcher

# Build and run concurrent execution test
test_concurrent: test_concurrent.c test_common.h
	$(CC) $(CFLAGS) -pthread -o $@ test_concurrent.c

# This test patches WHILE threads execute the target page, which generates
# "deferred traps": a worker hits an INT3 but the SIGTRAP is delivered after the
# gate (int3_in_progress) cleared. The trap handler resumes such post-gate traps
# by checking the fault byte (a completed jmp -> rewind+resume; a still-0xCC
# external INT3 -> re-raise).
test_concurrent_run: test_concurrent $(PATCHER_SO)
	DIBE_FORK_WORKERS=1 LD_PRELOAD=$(PATCHER_SO) ./test_concurrent

# Build and run the INT3-avoidance core unit test.  The core logic lives in a
# C++ TU that depends only on e9int3avoid.h (not e9patch.h), so we compile it
# to an object and link it with the C test.  Pure logic -> no LD_PRELOAD.
e9int3avoid_core.o: $(INT3AVOID_CORE) $(INT3AVOID_HDR)
	$(CXX) -O2 -Wall -Wextra -I$(INT3AVOID_DIR) -c $(INT3AVOID_CORE) -o $@

# Compile the test as C ($(CC)) so its core declarations get C linkage that
# matches the extern "C" symbols in e9int3avoid_core.o.  The core object uses
# no C++ runtime, so gcc links it without libstdc++.
test_int3avoid: test_int3avoid_unit.c test_common.h e9int3avoid_core.o
	$(CC) $(CFLAGS) -I$(INT3AVOID_DIR) -o $@ test_int3avoid_unit.c e9int3avoid_core.o

test_int3avoid_run: test_int3avoid
	./test_int3avoid

# Run Python unit tests
test_py:
	python3 -m unittest test_generate_patches test_generate_patches_stress -v

# DIBE predecessor-redirection (P3) end-to-end behavioral test on the
# synthetic fixture (tests/p3_fixture.S).  Requires the full toolchain
# (patcher.so, e9patch, patch_to_req); SKIPs gracefully if any is absent so
# `make test` still passes in a toolchain-less checkout.  Asserts P3 fires,
# the site converts off S2 (int3 drops), DIBE_VALIDATE ALL PASSED, and the
# fixture behaves correctly (rel32 rewrite + [Y,sa) replay).
test_p3_run:
	@if [ -f ../patcher.so ] && [ -x ../e9patch ] && [ -x ../patch_to_req ]; then \
		echo "[p3] running predecessor-redirection behavioral test"; \
		bash ./p3_test.sh; \
	else \
		echo "[p3] SKIP: DIBE toolchain not built (run ./build.sh)"; \
	fi

clean:
	rm -f test_fork test_patcher test_concurrent test_int3avoid \
        e9int3avoid_core.o p3_fixture
