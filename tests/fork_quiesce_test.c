// fork-quiesce test.
//
// Run under LD_PRELOAD=./patcher.so with DIBE_FORK_QUIESCE in {0,1,2}.
// Validates that, with the seccomp/SIGSYS fork-quiesce installed:
//   (a) address-space-copying fork() still works (trap -> SIGSYS -> re-issue),
//   (b) thread creation (pthread_create -> clone with CLONE_VM) is NOT gated/broken,
//   (c) every child forks and reaps with the expected exit status.
//
// No DIBE APPLY happens here, so g_edit_in_flight stays 0 and the quiesce-wait is
// a no-op; this exercises the fork mechanics under the filter.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>

static volatile int thread_ran = 0;
static void* worker(void* a) { (void)a; thread_ran = 1; return NULL; }

int main(int argc, char** argv) {
    int n = argc > 1 ? atoi(argv[1]) : 200;

    // (b) thread creation must not be gated (clone with CLONE_VM).
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0) { perror("pthread_create"); return 2; }
    pthread_join(t, NULL);
    if (!thread_ran) { fprintf(stderr, "FAIL: worker thread did not run\n"); return 2; }

    // (a)+(c) fork a batch of children; each does trivial work and exits 11/12.
    int ok = 0;
    for (int i = 0; i < n; i++) {
        pid_t p = fork();
        if (p < 0) { perror("fork"); fprintf(stderr, "FAIL at i=%d\n", i); return 3; }
        if (p == 0) {
            volatile long s = 0;
            for (long k = 0; k < 20000; k++) s += k;
            _exit((s & 1) ? 11 : 12);
        }
        int st = 0;
        if (waitpid(p, &st, 0) != p) { perror("waitpid"); return 4; }
        if (WIFEXITED(st) && (WEXITSTATUS(st) == 11 || WEXITSTATUS(st) == 12)) ok++;
        else { fprintf(stderr, "FAIL: child %d bad status 0x%x\n", i, st); return 5; }
    }

    printf("PASS: thread_ran=%d, %d/%d children forked+reaped cleanly\n", thread_ran, ok, n);
    return (ok == n) ? 0 : 6;
}
