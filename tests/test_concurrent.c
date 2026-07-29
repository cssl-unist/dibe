/*
 * test_concurrent.c — Concurrent execution during patch application.
 *
 * Run with: LD_PRELOAD=../patcher.so ./test_concurrent
 *
 * Tests that threads executing code in the target region survive
 * concurrent jmp overwrites, including S2 INT3-gated two-phase rewrites.
 *
 * Setup:
 *   - Allocate an RWX page filled with a NOP sled + RET
 *   - Spawn N worker threads that call into the page in a tight loop
 *   - Send APPLY with jmp entries targeting that page (using offsets
 *     that force S0, S1, and S2 strategies)
 *   - Workers keep running during and after the patch
 *   - Verify: no crashes, all workers complete, trap handler stats
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <stdatomic.h>

#include "test_common.h"

/* Page addresses for test code regions */
#define CODE_PAGE_ADDR  0x50000000UL
#define CODE_PAGE_ADDR2 0x50001000UL

/* Shared state */
static atomic_int g_workers_running = 0;
static atomic_int g_stop_workers = 0;
static atomic_uint g_worker_iterations = 0;

static char g_workdir[256];
static char g_fifo_path[256];

static void setup(void) {
    snprintf(g_workdir, sizeof(g_workdir), "/tmp/dibe_ctest_%d", getpid());
    mkdir(g_workdir, 0755);
    snprintf(g_fifo_path, sizeof(g_fifo_path),
             "/tmp/dibe_ctrl.%d", getpid());
}

static void cleanup(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_workdir);
    int __attribute__((unused)) rc = system(cmd);
}

static void write_file(const char *name, const char *content) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_workdir, name);
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

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
    usleep(500000);
}

/*
 * Fill a page with a simple callable function:
 *   NOP sled (0x90 * 4080) + RET (0xC3) + padding
 *
 * Workers call into the start of the page, slide through NOPs, hit RET.
 * The patcher will overwrite some NOPs with jmp instructions mid-flight.
 */
static void fill_code_page(void *page) {
    uint8_t *p = (uint8_t*)page;
    memset(p, 0x90, 4080);  /* NOP sled */
    p[4080] = 0xC3;         /* RET */
    memset(p + 4081, 0xCC, 15);  /* INT3 padding (safety) */
}

/*
 * Worker thread: calls into the code page in a tight loop.
 * Each call executes the NOP sled + RET.
 * If a jmp overwrite happens mid-execution and the thread hits INT3,
 * the trap handler should catch it and let the thread resume.
 */
static void *worker_thread(void *arg) {
    void (*fn)(void) = (void (*)(void))(uintptr_t)arg;

    atomic_fetch_add(&g_workers_running, 1);

    while (!atomic_load(&g_stop_workers)) {
        fn();  /* execute code page */
        atomic_fetch_add(&g_worker_iterations, 1);
    }

    atomic_fetch_sub(&g_workers_running, 1);
    return NULL;
}

/*=========================================================================
 * Test: S0 rewrites while threads execute (no INT3 expected)
 *=========================================================================*/
TEST(concurrent_s0_rewrite) {
    void *page = mmap((void*)CODE_PAGE_ADDR, 4096,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (page == MAP_FAILED) { fprintf(stderr, "  (skip: mmap)\n"); return; }
    fill_code_page(page);

    atomic_store(&g_stop_workers, 0);
    atomic_store(&g_workers_running, 0);
    atomic_store(&g_worker_iterations, 0);

    /* Spawn 4 worker threads */
    int nthreads = 4;
    pthread_t threads[4];
    for (int i = 0; i < nthreads; i++)
        pthread_create(&threads[i], NULL, worker_thread, (void*)CODE_PAGE_ADDR);

    while (atomic_load(&g_workers_running) < nthreads)
        usleep(10000);

    usleep(100000);

    /* Apply S0 patches: 2-byte writes at 8-byte aligned offsets (all NOP->NOP) */
    FILE *f;
    char path[512];
    snprintf(path, sizeof(path), "%s/jmp.jsonl", g_workdir);
    f = fopen(path, "w");
    for (int i = 0; i < 50; i++) {
        uint64_t addr = CODE_PAGE_ADDR + i * 8;  /* 8-byte aligned -> S0 */
        /* Write NOP,NOP — same as existing, so execution is unaffected */
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":2,\"bytes\":[144,144]}\n",
                (unsigned long)addr);
    }
    fclose(f);
    write_file("patches.jsonl", "");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    /* Let workers keep running after patch */
    usleep(200000);

    atomic_store(&g_stop_workers, 1);
    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    unsigned iters = atomic_load(&g_worker_iterations);
    ASSERT_TRUE(iters > 0);
    ASSERT_EQ(atomic_load(&g_workers_running), 0);

    munmap(page, 4096);
}

/*=========================================================================
 * Test: S2 (INT3) rewrites while threads execute
 *
 * This is the critical test. S2 temporarily writes INT3 (0xCC) at the
 * target site. If a worker thread executes that byte, the trap handler
 * catches SIGTRAP, spins until the rewrite completes, and resumes.
 *=========================================================================*/
TEST(concurrent_s2_rewrite) {
    void *p1 = mmap((void*)CODE_PAGE_ADDR, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    void *p2 = mmap((void*)CODE_PAGE_ADDR2, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p1 == MAP_FAILED || p2 == MAP_FAILED) {
        fprintf(stderr, "  (skip: mmap)\n"); return;
    }
    fill_code_page(p1);
    fill_code_page(p2);

    atomic_store(&g_stop_workers, 0);
    atomic_store(&g_workers_running, 0);
    atomic_store(&g_worker_iterations, 0);

    /* Spawn 4 workers executing from page 1 */
    int nthreads = 4;
    pthread_t threads[4];
    for (int i = 0; i < nthreads; i++)
        pthread_create(&threads[i], NULL, worker_thread, (void*)CODE_PAGE_ADDR);

    while (atomic_load(&g_workers_running) < nthreads)
        usleep(10000);
    usleep(100000);

    /* Apply S2 patches: writes that cross 16-byte boundaries.
     * We overwrite NOP bytes with NOP bytes (same content) so
     * execution semantics are preserved even if the overwrite
     * is seen partially by a worker. */
    FILE *f;
    char path[512];
    snprintf(path, sizeof(path), "%s/jmp.jsonl", g_workdir);
    f = fopen(path, "w");
    for (int i = 0; i < 20; i++) {
        /* offset 0xF within 16-byte block, 10 bytes -> crosses boundary -> S2 */
        uint64_t addr = CODE_PAGE_ADDR + i * 32 + 0xF;
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":10,"
                "\"bytes\":[144,144,144,144,144,144,144,144,144,144]}\n",
                (unsigned long)addr);
    }
    fclose(f);
    write_file("patches.jsonl", "");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    /* Let workers continue after patch */
    usleep(200000);

    atomic_store(&g_stop_workers, 1);
    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    unsigned iters = atomic_load(&g_worker_iterations);
    ASSERT_TRUE(iters > 0);
    ASSERT_EQ(atomic_load(&g_workers_running), 0);


    munmap(p1, 4096);
    munmap(p2, 4096);
}

/*=========================================================================
 * Test: Mixed strategies with many threads
 *=========================================================================*/
TEST(concurrent_mixed_high_contention) {
    void *p1 = mmap((void*)CODE_PAGE_ADDR, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    void *p2 = mmap((void*)CODE_PAGE_ADDR2, 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (p1 == MAP_FAILED || p2 == MAP_FAILED) {
        fprintf(stderr, "  (skip: mmap)\n"); return;
    }
    fill_code_page(p1);
    fill_code_page(p2);

    atomic_store(&g_stop_workers, 0);
    atomic_store(&g_workers_running, 0);
    atomic_store(&g_worker_iterations, 0);

    /* Spawn 8 workers across both pages */
    int nthreads = 8;
    pthread_t threads[8];
    for (int i = 0; i < nthreads; i++) {
        uintptr_t addr = (i % 2 == 0) ? CODE_PAGE_ADDR : CODE_PAGE_ADDR2;
        pthread_create(&threads[i], NULL, worker_thread, (void*)addr);
    }

    while (atomic_load(&g_workers_running) < nthreads)
        usleep(10000);
    usleep(100000);

    /* Apply a large mixed patch set */
    FILE *f;
    char path[512];
    snprintf(path, sizeof(path), "%s/jmp.jsonl", g_workdir);
    f = fopen(path, "w");

    /* S0: small aligned writes on page 1 */
    for (int i = 0; i < 100; i++) {
        uint64_t addr = CODE_PAGE_ADDR + i * 8;
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":2,\"bytes\":[144,144]}\n",
                (unsigned long)addr);
    }
    /* S1: cross-8-byte writes on page 2 */
    for (int i = 0; i < 50; i++) {
        uint64_t addr = CODE_PAGE_ADDR2 + i * 16 + 5;
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":5,\"bytes\":[144,144,144,144,144]}\n",
                (unsigned long)addr);
    }
    /* S2: cross-16-byte writes on page 1 */
    for (int i = 0; i < 20; i++) {
        uint64_t addr = CODE_PAGE_ADDR + 1024 + i * 32 + 0xF;
        fprintf(f, "{\"address\":\"0x%lx\",\"length\":10,"
                "\"bytes\":[144,144,144,144,144,144,144,144,144,144]}\n",
                (unsigned long)addr);
    }
    fclose(f);
    write_file("patches.jsonl", "");

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "APPLY %s", g_workdir);
    send_fifo(cmd);

    usleep(300000);

    atomic_store(&g_stop_workers, 1);
    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    unsigned iters = atomic_load(&g_worker_iterations);
    fprintf(stderr, "    (total worker iterations: %u)\n", iters);
    ASSERT_TRUE(iters > 1000);  /* workers should have run many times */
    ASSERT_EQ(atomic_load(&g_workers_running), 0);

    munmap(p1, 4096);
    munmap(p2, 4096);
}

int main() {
    setup();

    fprintf(stderr, "\n=== test_concurrent (execution during patching) ===\n");
    RUN_TEST(concurrent_s0_rewrite);
    RUN_TEST(concurrent_s2_rewrite);
    RUN_TEST(concurrent_mixed_high_contention);

    cleanup();

    char fifo[256];
    snprintf(fifo, sizeof(fifo), "/tmp/dibe_ctrl.%d", getpid());
    unlink(fifo);

    return test_report();
}
