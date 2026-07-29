/*
 * p3_fixture_main.c — driver for the DIBE P3 synthetic fixture.
 *
 * Calls p3_compute() in a loop (so a live patch lands while it runs), printing
 * the returned value once per second.  Correct value is 201001 (see
 * p3_fixture.S).  P3 redirects sa's predecessor X -> a trampoline that replays
 * [Y, sa) + sa's NOP instrumentation + continues to sa_end; the returned value
 * must stay 201001, since the instrumentation is behaviour-preserving.  A wrong
 * rel32 rewrite or a wrong [Y, sa) replay changes the value or crashes.
 *
 * Output protocol: prints "Process ID: <pid>" once, then "<value> <iter>" each
 * second, so a watcher can confirm the value is correct before and after
 * patching.  The value is invariant across patching (the patch only splices a
 * NOP), so "correct under patch" means it never changes away from 201001 and
 * the program does not crash.
 */
#include <stdio.h>
#include <unistd.h>

extern int p3_compute(void);

int main(void)
{
    fprintf(stdout, "Process ID: %d\n", (int)getpid());
    fflush(stdout);
    for (int i = 0; ; i++)
    {
        int v = p3_compute();
        fprintf(stdout, "%d %d\n", v, i);
        fflush(stdout);
        sleep(1);
    }
    return 0;
}
