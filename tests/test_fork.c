/*
 * test_fork.c — Integration test for patcher.so pthread_atfork support.
 *
 * Run with: LD_PRELOAD=../patcher.so ./test_fork
 *
 * Tests that after fork(), the child process gets its own FIFO control
 * channel at /tmp/dibe_ctrl.<child_pid>, created by the
 * child_after_fork() handler registered via pthread_atfork().
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

#include "test_common.h"

static int fifo_exists(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/dibe_ctrl.%d", pid);
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISFIFO(st.st_mode);
}

static void cleanup_fifo(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/dibe_ctrl.%d", pid);
    unlink(path);
}

/*
 * Test: parent's FIFO exists after patcher.so constructor runs.
 * (patcher.so is loaded via LD_PRELOAD before main)
 */
TEST(parent_fifo_exists) {
    pid_t ppid = getpid();
    ASSERT_TRUE(fifo_exists(ppid));
}

/*
 * Test: after fork(), child gets its own FIFO with a different PID.
 * The child writes its PID to a pipe so the parent can verify.
 */
TEST(child_fifo_created) {
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);

    pid_t child = fork();
    if (child == 0) {
        /* Child process */
        close(pipefd[0]);

        /* Give the atfork handler a moment to run */
        usleep(200000);

        pid_t my_pid = getpid();
        int ok = fifo_exists(my_pid);

        /* Report result to parent via pipe */
        write(pipefd[1], &my_pid, sizeof(my_pid));
        write(pipefd[1], &ok, sizeof(ok));
        close(pipefd[1]);

        /* Cleanup child FIFO before exiting */
        cleanup_fifo(my_pid);
        _exit(0);
    }

    /* Parent process */
    close(pipefd[1]);

    pid_t child_pid = 0;
    int child_fifo_ok = 0;
    read(pipefd[0], &child_pid, sizeof(child_pid));
    read(pipefd[0], &child_fifo_ok, sizeof(child_fifo_ok));
    close(pipefd[0]);

    int status;
    waitpid(child, &status, 0);

    /* Child PID must differ from parent */
    ASSERT_NE(child_pid, getpid());
    ASSERT_NE(child_pid, 0);

    /* Child must have found its own FIFO */
    ASSERT_TRUE(child_fifo_ok);
}

/*
 * Test: multiple forks all get unique FIFOs.
 */
TEST(multiple_children_get_unique_fifos) {
    int n_children = 3;
    pid_t child_pids[3];
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);

    for (int i = 0; i < n_children; i++) {
        pid_t child = fork();
        if (child == 0) {
            close(pipefd[0]);
            usleep(200000);

            pid_t my_pid = getpid();
            int ok = fifo_exists(my_pid);
            write(pipefd[1], &my_pid, sizeof(my_pid));
            write(pipefd[1], &ok, sizeof(ok));
            close(pipefd[1]);
            cleanup_fifo(my_pid);
            _exit(0);
        }
        child_pids[i] = child;
    }

    close(pipefd[1]);

    for (int i = 0; i < n_children; i++) {
        pid_t cpid = 0;
        int ok = 0;
        read(pipefd[0], &cpid, sizeof(cpid));
        read(pipefd[0], &ok, sizeof(ok));

        ASSERT_NE(cpid, getpid());
        ASSERT_TRUE(ok);

        /* Verify uniqueness against parent */
        ASSERT_NE(cpid, getpid());
    }
    close(pipefd[0]);

    for (int i = 0; i < n_children; i++) {
        int status;
        waitpid(child_pids[i], &status, 0);
    }
}

int main() {
    fprintf(stderr, "\n=== test_fork (patcher.so atfork support) ===\n");
    RUN_TEST(parent_fifo_exists);
    RUN_TEST(child_fifo_created);
    RUN_TEST(multiple_children_get_unique_fifos);

    /* Cleanup parent FIFO */
    cleanup_fifo(getpid());

    return test_report();
}
