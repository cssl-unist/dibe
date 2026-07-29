/* examples/live-fix/service.c — a tiny "service" with a deliberate bug.
 *
 * next_tick() is supposed to advance the counter, but it returns its argument
 * unchanged, so the service is stuck reporting tick=0 forever.  The example
 * fixes this in the *running* process, without stopping or restarting it.
 *
 * Two attributes keep the bug patchable at -O2, and both are load-bearing:
 *   noinline — keeps next_tick a real function with a real call site, instead
 *              of being folded into main().
 *   noipa    — stops GCC from propagating "next_tick returns its argument"
 *              into main() interprocedurally, which would make main() ignore
 *              the return value entirely and no patch to next_tick could ever
 *              be observed.
 * A real service compiled from unrelated translation units gets both for free;
 * they are needed here only because this program is small enough to see through.
 */

#include <stdio.h>
#include <unistd.h>

__attribute__((noinline, noipa))
int next_tick(int t)
{
    return t;              /* BUG: should be t + 1 */
}

int main(void)
{
    int tick = 0;

    setbuf(stdout, NULL);
    printf("Process ID: %d\n", getpid());

    for (;;) {
        tick = next_tick(tick);
        printf("tick=%d\n", tick);
        sleep(1);
    }

    return 0;
}
