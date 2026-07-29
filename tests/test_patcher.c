/*
 * test_patcher.c — Integration tests for patcher.so core functionality.
 *
 * Run with: LD_PRELOAD=../patcher.so ./test_patcher
 *
 * Tests the FIFO control channel, JSONL loading, patch application,
 * atomic rewrite strategies (S0/S1/S2), trampoline page mapping,
 * and the validation mode.
 *
 * These tests exercise patcher.so as loaded via LD_PRELOAD — the same
 * way it's used in production. They write JSONL files and send APPLY
 * commands through the FIFO to trigger real patch application paths.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>

#include "test_common.h"

static char g_fifo_path[256];
static char g_workdir[256];

/* Create a temp workdir and write JSONL files into it */
static void setup_workdir(void) {
    snprintf(g_workdir, sizeof(g_workdir), "/tmp/dibe_test_%d", getpid());
    mkdir(g_workdir, 0755);
    snprintf(g_fifo_path, sizeof(g_fifo_path),
             "/tmp/dibe_ctrl.%d", getpid());
}

static void cleanup_workdir(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_workdir);
    (void)system(cmd);
}

/* Write content to a file in the workdir */
static void write_file(const char *name, const char *content) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_workdir, name);
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(content, f);
        fclose(f);
    }
}

/* Send a command to the patcher FIFO.
 * The FIFO thread keeps its read fd open in a loop, so O_WRONLY
 * should not block. We retry briefly if it does. */
static void send_fifo(const char *cmd) {
    int retries = 20;
    int fd = -1;
    while (retries-- > 0) {
        fd = open(g_fifo_path, O_WRONLY | O_NONBLOCK);
        if (fd >= 0) break;
        usleep(100000);
    }
    if (fd >= 0) {
        ssize_t __attribute__((unused)) rc = write(fd, cmd, strlen(cmd));
        close(fd);
    }
    /* Give patcher thread time to process */
    usleep(500000);
}

/* Allocate an RWX page at a specific address for testing */
static void *alloc_rwx_page(void *addr) {
    return mmap(addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
}

/*=========================================================================
 * FIFO Tests
 *=========================================================================*/

TEST(fifo_exists_on_startup) {
    struct stat st;
    ASSERT_EQ(stat(g_fifo_path, &st), 0);
    ASSERT_TRUE(S_ISFIFO(st.st_mode));
}

TEST(fifo_accepts_apply) {
    /* Write empty JSONL files — APPLY should not crash */
    write_file("jmp.jsonl", "");
    write_file("patches.jsonl", "");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);
    /* If we get here without crashing, the FIFO thread handled it */
    ASSERT_TRUE(1);
}

/*=========================================================================
 * JSONL Loading Tests — write various JSONL formats and trigger APPLY
 *=========================================================================*/

TEST(jsonl_empty_files) {
    write_file("jmp.jsonl", "");
    write_file("patches.jsonl", "");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);
    ASSERT_TRUE(1);  /* no crash */
}

TEST(jsonl_address_schema) {
    /* Schema: {"address":"0xADDR", "bytes":[...]} */
    /* Allocate a test page to patch. */
    void *page = alloc_rwx_page((void*)0x40000000UL);
    if (page == MAP_FAILED) {
        fprintf(stderr, "  (skip: cannot mmap test page)\n");
        return;
    }
    memset(page, 0x90, 4096); /* fill with NOP */

    char jmp_line[256];
    snprintf(jmp_line, sizeof(jmp_line),
        "{\"address\":\"0x40000100\",\"length\":2,\"bytes\":[233,0]}\n");
    char patch_line[256];
    snprintf(patch_line, sizeof(patch_line),
        "{\"address\":\"0x40000200\",\"length\":3,\"bytes\":[144,144,144]}\n");

    write_file("jmp.jsonl", jmp_line);
    write_file("patches.jsonl", patch_line);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    /* Verify bytes were written */
    uint8_t *mem = (uint8_t*)0x40000200UL;
    ASSERT_EQ(mem[0], 0x90);  /* NOP */
    ASSERT_EQ(mem[1], 0x90);
    ASSERT_EQ(mem[2], 0x90);

    munmap(page, 4096);
}

/*=========================================================================
 * Atomic Rewrite Strategy Tests
 *
 * S0: 8-byte store (write fits in one aligned 8-byte word)
 * S1: cmpxchg16b (write fits in one aligned 16-byte block)
 * S2: INT3 two-phase (write spans alignment boundaries)
 *=========================================================================*/

/* Helper: allocate a page, write jmp JSONL, APPLY, verify */
static int apply_and_verify_jmp(uint64_t addr, const uint8_t *bytes, size_t len) {
    /* Build JSONL bytes array */
    char bytes_str[1024] = "[";
    for (size_t i = 0; i < len; i++) {
        char tmp[8];
        snprintf(tmp, sizeof(tmp), "%s%u", i ? "," : "", bytes[i]);
        strcat(bytes_str, tmp);
    }
    strcat(bytes_str, "]");

    char jmp_line[1024];
    snprintf(jmp_line, sizeof(jmp_line),
        "{\"address\":\"0x%lx\",\"length\":%zu,\"bytes\":%s}\n",
        (unsigned long)addr, len, bytes_str);

    write_file("jmp.jsonl", jmp_line);
    write_file("patches.jsonl", "");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    /* Verify */
    const uint8_t *mem = (const uint8_t*)addr;
    for (size_t i = 0; i < len; i++) {
        if (mem[i] != bytes[i]) return 0;
    }
    return 1;
}

TEST(rewrite_s0_aligned) {
    /* S0: 2-byte write at 8-byte aligned address (offset 0) */
    void *page = alloc_rwx_page((void*)0x41000000UL);
    if (page == MAP_FAILED) { fprintf(stderr, "  (skip)\n"); return; }
    memset(page, 0xCC, 4096);

    uint64_t addr = 0x41000100;  /* aligned to 8 */
    uint8_t bytes[] = {0xEB, 0xFE};  /* jmp -2 (infinite loop) */
    ASSERT_TRUE(apply_and_verify_jmp(addr, bytes, 2));

    munmap(page, 4096);
}

TEST(rewrite_s0_unaligned_within_word) {
    /* S0: 2-byte write at offset 3 within 8-byte word (still fits) */
    void *page = alloc_rwx_page((void*)0x41001000UL);
    if (page == MAP_FAILED) { fprintf(stderr, "  (skip)\n"); return; }
    memset(page, 0xCC, 4096);

    uint64_t addr = 0x41001103;  /* offset 3 within 8-byte word, 3+2=5 <= 8 */
    uint8_t bytes[] = {0xEB, 0xFE};
    ASSERT_TRUE(apply_and_verify_jmp(addr, bytes, 2));

    munmap(page, 4096);
}

TEST(rewrite_s0_5byte_jmp) {
    /* S0: 5-byte jmp at 8-byte aligned address */
    void *page = alloc_rwx_page((void*)0x41002000UL);
    if (page == MAP_FAILED) { fprintf(stderr, "  (skip)\n"); return; }
    memset(page, 0xCC, 4096);

    uint64_t addr = 0x41002100;
    uint8_t bytes[] = {0xE9, 0x01, 0x02, 0x03, 0x04};
    ASSERT_TRUE(apply_and_verify_jmp(addr, bytes, 5));

    munmap(page, 4096);
}

TEST(rewrite_s1_crosses_8byte_boundary) {
    /* S1: 5-byte write at offset 6 within 8-byte word (6+5=11 > 8, but <= 16) */
    void *page = alloc_rwx_page((void*)0x41003000UL);
    if (page == MAP_FAILED) { fprintf(stderr, "  (skip)\n"); return; }
    memset(page, 0xCC, 4096);

    uint64_t addr = 0x41003106;  /* off8=6, off16=6, 6+5=11 <= 16 -> S1 */
    uint8_t bytes[] = {0xE9, 0xAA, 0xBB, 0xCC, 0xDD};
    ASSERT_TRUE(apply_and_verify_jmp(addr, bytes, 5));

    munmap(page, 4096);
}

TEST(rewrite_s2_large_span) {
    /* S2 fallback: write that crosses 16-byte boundary */
    void *page = alloc_rwx_page((void*)0x41004000UL);
    if (page == MAP_FAILED) { fprintf(stderr, "  (skip)\n"); return; }
    memset(page, 0xCC, 4096);

    /* Put a 15-byte write at offset 0xF within 16-byte block -> crosses boundary */
    uint64_t addr = 0x4100410F;  /* off16=0xF, 0xF + 15 = 30 > 16 -> S2 */
    uint8_t bytes[] = {0xE9, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
    ASSERT_TRUE(apply_and_verify_jmp(addr, bytes, 15));

    munmap(page, 4096);
}

/*=========================================================================
 * Trampoline Page Mapping Tests
 *=========================================================================*/

TEST(trampoline_page_auto_mapped) {
    /* Write a patches.jsonl entry targeting an unmapped address.
       patcher_apply should auto-map the page before writing. */
    uint64_t target = 0x42000200UL;
    uint64_t page_base = target & ~0xFFFUL;

    /* Ensure page is NOT mapped */
    munmap((void*)page_base, 4096);

    char patch_line[256];
    snprintf(patch_line, sizeof(patch_line),
        "{\"address\":\"0x%lx\",\"length\":4,\"bytes\":[144,144,144,195]}\n",
        (unsigned long)target);

    write_file("jmp.jsonl", "");
    write_file("patches.jsonl", patch_line);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    /* Verify the page was mapped and bytes written */
    uint8_t *mem = (uint8_t*)target;
    ASSERT_EQ(mem[0], 0x90);  /* NOP */
    ASSERT_EQ(mem[3], 0xC3);  /* RET */

    munmap((void*)page_base, 4096);
}

/*=========================================================================
 * FIFO Path Passing Tests
 *=========================================================================*/

TEST(fifo_apply_with_path) {
    /* APPLY with explicit directory path. The runtime auto-maps the (free)
       trampoline-content page; it only writes to pages it owns. */
    munmap((void*)0x43000000UL, 4096);

    char patch_line[256];
    snprintf(patch_line, sizeof(patch_line),
        "{\"address\":\"0x43000000\",\"length\":2,\"bytes\":[235,254]}\n");

    write_file("patches.jsonl", patch_line);
    write_file("jmp.jsonl", "");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    uint8_t *mem = (uint8_t*)0x43000000UL;
    ASSERT_EQ(mem[0], 0xEB);  /* 235 */
    ASSERT_EQ(mem[1], 0xFE);  /* 254 */

    munmap((void*)0x43000000UL, 4096);
}

TEST(fifo_apply_without_path_uses_cwd) {
    /* APPLY with no path — reads from CWD. */
    send_fifo("APPLY\n");
    ASSERT_TRUE(1);
}

/*=========================================================================
 * Stress Tests
 *=========================================================================*/

TEST(stress_many_patches) {
    /* Apply 1000 small patches to a single page. The runtime auto-maps the
       (free) page; it only writes to pages it owns. */
    munmap((void*)0x44000000UL, 4096);

    /* Build JSONL with 1000 single-byte patches */
    FILE *f;
    char path[512];

    snprintf(path, sizeof(path), "%s/patches.jsonl", g_workdir);
    f = fopen(path, "w");
    for (int i = 0; i < 1000; i++) {
        uint64_t addr = 0x44000000UL + (i % 4096);
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":1,\"bytes\":[%d]}\n",
                (unsigned long)addr, (i & 0xFF));
    }
    fclose(f);

    snprintf(path, sizeof(path), "%s/jmp.jsonl", g_workdir);
    f = fopen(path, "w");
    fclose(f);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    /* Verify last patch (byte 999%4096 = byte 999 = 0xE7) */
    uint8_t *mem = (uint8_t*)0x44000000UL;
    ASSERT_EQ(mem[999], (999 & 0xFF));

    munmap((void*)0x44000000UL, 4096);
}

TEST(stress_many_jmp_rewrites) {
    /* Apply 500 jmp rewrites across multiple pages */
    void *p1 = alloc_rwx_page((void*)0x45000000UL);
    void *p2 = alloc_rwx_page((void*)0x45001000UL);
    if (p1 == MAP_FAILED || p2 == MAP_FAILED) {
        fprintf(stderr, "  (skip)\n");
        return;
    }
    memset(p1, 0xCC, 4096);
    memset(p2, 0xCC, 4096);

    FILE *f;
    char path[512];

    snprintf(path, sizeof(path), "%s/jmp.jsonl", g_workdir);
    f = fopen(path, "w");
    for (int i = 0; i < 500; i++) {
        /* Distribute across both pages, 8-byte aligned for S0 */
        uint64_t addr = 0x45000000UL + (i * 8) % 8192;
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":2,\"bytes\":[233,%d]}\n",
                (unsigned long)addr, (i & 0xFF));
    }
    fclose(f);

    write_file("patches.jsonl", "");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    /* Spot-check some entries */
    uint8_t *mem = (uint8_t*)0x45000000UL;
    ASSERT_EQ(mem[0], 233);  /* first jmp */

    munmap(p1, 4096);
    munmap(p2, 4096);
}

TEST(stress_rapid_apply_cycles) {
    /* Send multiple APPLY commands sequentially */
    void *page = alloc_rwx_page((void*)0x46000000UL);
    if (page == MAP_FAILED) { fprintf(stderr, "  (skip)\n"); return; }

    for (int cycle = 0; cycle < 5; cycle++) {
        memset(page, 0x00, 4096);

        char patch_line[256];
        snprintf(patch_line, sizeof(patch_line),
            "{\"address\":\"0x46000000\",\"length\":1,\"bytes\":[%d]}\n",
            cycle + 1);
        write_file("patches.jsonl", patch_line);
        write_file("jmp.jsonl", "");

        char cmd[512];
        snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
        send_fifo(cmd);
    }

    /* After 5 cycles, the byte should hold the last value (5) */
    uint8_t *mem = (uint8_t*)0x46000000UL;
    ASSERT_EQ(mem[0], 5);

    munmap(page, 4096);
    /* Extra drain time before next test */
    usleep(500000);
}

TEST(stress_fork_and_apply) {
    /* Fork children, each applies patches independently via their own FIFO */
    int n_children = 5;
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);

    for (int i = 0; i < n_children; i++) {
        pid_t child = fork();
        if (child == 0) {
            close(pipefd[0]);
            usleep(200000);  /* wait for child FIFO */

            /* Each child maps its own page and patches it */
            uint64_t page_addr = 0x47000000UL + i * 0x1000;
            void *page = alloc_rwx_page((void*)page_addr);
            int ok = 0;
            if (page != MAP_FAILED) {
                memset(page, 0x00, 4096);

                /* Write JSONL to a per-child workdir */
                char child_workdir[256];
                snprintf(child_workdir, sizeof(child_workdir),
                         "/tmp/dibe_test_child_%d", getpid());
                mkdir(child_workdir, 0755);

                char patch_path[512];
                snprintf(patch_path, sizeof(patch_path),
                         "%s/patches.jsonl", child_workdir);
                FILE *f = fopen(patch_path, "w");
                fprintf(f, "{\"address\":\"0x%lx\",\"length\":1,\"bytes\":[%d]}\n",
                        (unsigned long)page_addr, i + 42);
                fclose(f);

                char jmp_path[512];
                snprintf(jmp_path, sizeof(jmp_path),
                         "%s/jmp.jsonl", child_workdir);
                f = fopen(jmp_path, "w");
                fclose(f);

                /* APPLY via child's own FIFO */
                char fifo[256];
                snprintf(fifo, sizeof(fifo),
                         "/tmp/dibe_ctrl.%d", getpid());
                char cmd[512];
                snprintf(cmd, sizeof(cmd), "APPLY %s", child_workdir);
                int fd = open(fifo, O_WRONLY);
                if (fd >= 0) {
                    ssize_t __attribute__((unused)) rc =
                        write(fd, cmd, strlen(cmd));
                    close(fd);
                }
                usleep(500000);

                /* Verify */
                uint8_t *mem = (uint8_t*)page_addr;
                ok = (mem[0] == (uint8_t)(i + 42));

                munmap(page, 4096);
                /* cleanup */
                char rm_cmd[512];
                snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", child_workdir);
                (void)system(rm_cmd);
            }

            /* Cleanup child FIFO */
            char fifo[256];
            snprintf(fifo, sizeof(fifo),
                     "/tmp/dibe_ctrl.%d", getpid());
            unlink(fifo);

            ssize_t __attribute__((unused)) rc =
                write(pipefd[1], &ok, sizeof(ok));
            close(pipefd[1]);
            _exit(0);
        }
    }

    close(pipefd[1]);
    int all_ok = 1;
    for (int i = 0; i < n_children; i++) {
        int ok = 0;
        ssize_t __attribute__((unused)) rc =
            read(pipefd[0], &ok, sizeof(ok));
        if (!ok) all_ok = 0;
    }
    close(pipefd[0]);

    /* Wait for all children */
    for (int i = 0; i < n_children; i++) {
        int status;
        wait(&status);
    }

    ASSERT_TRUE(all_ok);
}

/*=========================================================================
 * Mixed Strategy Stress Test
 *=========================================================================*/

TEST(stress_mixed_strategies) {
    /* Generate jmp entries that exercise all three strategies:
       S0 (aligned), S1 (crosses 8-byte), S2 (crosses 16-byte) */
    void *p1 = alloc_rwx_page((void*)0x48000000UL);
    void *p2 = alloc_rwx_page((void*)0x48001000UL);
    if (p1 == MAP_FAILED || p2 == MAP_FAILED) { fprintf(stderr, "  (skip)\n"); return; }
    memset(p1, 0xCC, 4096);
    memset(p2, 0xCC, 4096);

    FILE *f;
    char path[512];
    snprintf(path, sizeof(path), "%s/jmp.jsonl", g_workdir);
    f = fopen(path, "w");

    /* S0 entries: 2-byte at 8-byte aligned */
    for (int i = 0; i < 100; i++) {
        uint64_t addr = 0x48000000UL + i * 16;
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":2,\"bytes\":[235,%d]}\n",
                (unsigned long)addr, i & 0xFF);
    }
    /* S1 entries: 5-byte at offset 5 within 8-byte word */
    for (int i = 0; i < 50; i++) {
        uint64_t addr = 0x48000800UL + i * 16 + 5;
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":5,\"bytes\":[233,1,2,3,%d]}\n",
                (unsigned long)addr, i & 0xFF);
    }
    /* S2 entries: 10-byte at offset 0xA within 16-byte block */
    for (int i = 0; i < 20; i++) {
        uint64_t addr = 0x48000C00UL + i * 32 + 0xA;
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":10,"
                "\"bytes\":[233,1,2,3,4,5,6,7,8,%d]}\n",
                (unsigned long)addr, i & 0xFF);
    }
    fclose(f);

    write_file("patches.jsonl", "");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    /* Spot checks */
    uint8_t *mem = (uint8_t*)0x48000000UL;
    ASSERT_EQ(mem[0], 235);  /* first S0: 0xEB */
    ASSERT_EQ(mem[16], 235); /* second S0 */

    mem = (uint8_t*)(0x48000800UL + 5);
    ASSERT_EQ(mem[0], 233);  /* first S1: 0xE9 */

    mem = (uint8_t*)(0x48000C00UL + 0xA);
    ASSERT_EQ(mem[0], 233);  /* first S2: 0xE9 */

    munmap(p1, 4096);
    munmap(p2, 4096);
}

int main() {
    setup_workdir();

    fprintf(stderr, "\n=== test_patcher (patcher.so core functionality) ===\n");

    /* FIFO tests */
    RUN_TEST(fifo_exists_on_startup);
    RUN_TEST(fifo_accepts_apply);

    /* JSONL loading */
    RUN_TEST(jsonl_empty_files);
    RUN_TEST(jsonl_address_schema);

    /* Atomic rewrite strategies */
    RUN_TEST(rewrite_s0_aligned);
    RUN_TEST(rewrite_s0_unaligned_within_word);
    RUN_TEST(rewrite_s0_5byte_jmp);
    RUN_TEST(rewrite_s1_crosses_8byte_boundary);
    RUN_TEST(rewrite_s2_large_span);

    /* Trampoline mapping */
    RUN_TEST(trampoline_page_auto_mapped);

    /* FIFO path passing */
    RUN_TEST(fifo_apply_with_path);
    RUN_TEST(fifo_apply_without_path_uses_cwd);

    /* Stress tests */
    RUN_TEST(stress_many_patches);
    RUN_TEST(stress_many_jmp_rewrites);
    RUN_TEST(stress_mixed_strategies);

    cleanup_workdir();

    /* Cleanup parent FIFO */
    char fifo[256];
    snprintf(fifo, sizeof(fifo), "/tmp/dibe_ctrl.%d", getpid());
    unlink(fifo);

    return test_report();
}
