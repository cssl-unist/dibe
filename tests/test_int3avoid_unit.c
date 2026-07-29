/*
 * test_int3avoid_unit.c — unit tests for the DIBE INT3-avoidance planner
 * helper cores.
 *
 * These tests link directly against the scalar/array core logic in
 * third_party/e9patch/src/e9patch/e9int3avoid_core.cpp (compiled to an object by
 * the tests/Makefile `test_int3avoid` target).  The cores are the exact logic
 * the C++ wrappers (isS2Site / findUpstreamCand / dominanceClear) delegate to,
 * so testing them tests the planner's decision logic without having to build
 * real e9patch Instr/Binary objects.
 */
#include <stdint.h>
#include "test_common.h"

/* Declarations mirror e9int3avoid.h's extern "C" core block. */
int isS2Site_core(unsigned off16);
int canShiftCand_core(uintptr_t cand_addr);
int findUpstreamCand_core(const uintptr_t *addrs, const unsigned *sizes,
    int n, int sa_idx);
int dominanceClear_core(int ocfr_on, const unsigned char *is_target,
    int n, int cand_idx, int sa_idx);

/*
 * isS2Site truth table: a 5-byte JMP is S2 iff its first byte sits at chunk
 * offset 12, 13, 14, or 15 (off16 + 5 > 16).  Offsets 0..11 are S0/S1.
 */
TEST(is_s2_site_truth_table)
{
    for (unsigned off = 0; off <= 11; off++)
        ASSERT_FALSE(isS2Site_core(off));   /* off+5 <= 16 -> not S2 */
    for (unsigned off = 12; off <= 15; off++)
        ASSERT_TRUE(isS2Site_core(off));    /* off+5 > 16 -> S2 */

    /* The high bits of the address must not matter — only off16 does. */
    ASSERT_TRUE(isS2Site_core((0x4000000u + 13u) & 0xF));   /* off 13 */
    ASSERT_FALSE(isS2Site_core((0x4000000u + 4u) & 0xF));   /* off 4  */
}

/* canShiftCand: offset 11 is the last that fits a 5-byte JMP in its chunk. */
TEST(can_shift_cand_boundary)
{
    ASSERT_TRUE(canShiftCand_core(0x1000 + 0));   /* off 0  -> 0+5<=16 */
    ASSERT_TRUE(canShiftCand_core(0x1000 + 11));  /* off 11 -> 11+5=16 */
    ASSERT_FALSE(canShiftCand_core(0x1000 + 12)); /* off 12 -> 12+5>16 */
    ASSERT_FALSE(canShiftCand_core(0x1000 + 15)); /* off 15 -> S2     */
}

/*
 * findUpstreamCand: a chunk based at 0x1000 with contiguous instructions.
 * sa is at offset 13 (S2).  The latest in-chunk boundary whose 5-byte JMP
 * fits ((addr&0xF)+5<=16, i.e. offset<=11) should be selected.
 *
 *   idx  addr     size   off16  canShift?
 *    0   0x1000     4      0      yes
 *    1   0x1004     4      4      yes
 *    2   0x1008     3      8      yes
 *    3   0x100B     2     11      yes   <- latest qualifying boundary
 *    4   0x100D     3     13      no  (this is sa, S2)
 */
TEST(find_upstream_cand_latest_boundary)
{
    uintptr_t addrs[] = { 0x1000, 0x1004, 0x1008, 0x100B, 0x100D };
    unsigned  sizes[] = {      4,      4,      3,      2,      3 };
    int n = 5, sa_idx = 4;

    int cand = findUpstreamCand_core(addrs, sizes, n, sa_idx);
    ASSERT_EQ(cand, 3);                     /* offset 11 (0x100B) */
    ASSERT_TRUE(canShiftCand_core(addrs[cand]));

    /*
     * If the closest boundary (idx 3) were itself non-shiftable (offset 12),
     * the walk must keep going to the latest *qualifying* earlier boundary.
     */
    uintptr_t addrs2[] = { 0x1000, 0x1006, 0x100C, 0x100D };
    unsigned  sizes2[] = {      6,      6,      1,      3 };
    /* offsets: 0(yes), 6(yes), 12(no), sa=13.  Expect idx 1 (offset 6). */
    int cand2 = findUpstreamCand_core(addrs2, sizes2, 4, 3);
    ASSERT_EQ(cand2, 1);
}

/*
 * findUpstreamCand must STOP at a decode gap (non-contiguous predecessor):
 * addrs[i]+sizes[i] != addrs[i+1] mirrors Instr::pred() returning nullptr.
 */
TEST(find_upstream_cand_stops_at_gap)
{
    /* Gap between idx0 and idx1: 0x1000+4 = 0x1004 != 0x1006. */
    uintptr_t addrs[] = { 0x1000, 0x1006, 0x100D };
    unsigned  sizes[] = {      4,      7,      3 };
    int n = 3, sa_idx = 2;
    /*
     * sa at 0x100D (off 13). pred idx1 @0x1006 (off 6) is contiguous with sa
     * (0x1006+7 = 0x100D) and shiftable -> should be picked immediately.
     */
    ASSERT_EQ(findUpstreamCand_core(addrs, sizes, n, sa_idx), 1);

    /*
     * Now make idx1 non-shiftable (offset 12) so the walk must continue past
     * it to idx0 — but idx0 is across a GAP, so the result is -1 (no cand).
     */
    uintptr_t addrs2[] = { 0x1000, 0x100C, 0x100D };
    unsigned  sizes2[] = {      4,      1,      3 };   /* 0x1000+4=0x1004 != 0x100C */
    /* idx1 @off12 non-shiftable; step to idx0 hits the gap -> stop -> -1. */
    ASSERT_EQ(findUpstreamCand_core(addrs2, sizes2, 3, 2), -1);
}

/* findUpstreamCand: no predecessor at all (sa starts the chunk) -> -1. */
TEST(find_upstream_cand_no_pred)
{
    uintptr_t addrs[] = { 0x1000, 0x100D };   /* idx0 @off0, idx1 sa @off13 */
    unsigned  sizes[] = {     13,      3 };    /* but 0+13 = 13 = sa off ... */
    /*
     * sa_idx=0 (sa starts the chunk, no predecessor index) -> -1.
     */
    ASSERT_EQ(findUpstreamCand_core(addrs, sizes, 2, 0), -1);
}

/*
 * dominanceClear: accept when the interior (cand, sa) is target-free; reject
 * when an interior instruction is a branch target; and return false (closed)
 * when OCFR/targets are unavailable.
 */
TEST(dominance_clear_accept_reject)
{
    /* 5 instructions, cand_idx=1, sa_idx=4 -> interior is {2,3}. */
    int n = 5, cand = 1, sa = 4;

    /* (1) No interior targets -> clear. (cand itself a target is OK.) */
    unsigned char t_clear[5] = { 0, 1, 0, 0, 1 }; /* cand(1) & sa(4) tagged */
    ASSERT_TRUE(dominanceClear_core(1, t_clear, n, cand, sa));

    /* (2) Interior target at idx 3 -> blocked. */
    unsigned char t_block[5] = { 0, 0, 0, 1, 0 };
    ASSERT_FALSE(dominanceClear_core(1, t_block, n, cand, sa));

    /* (3) Interior target at idx 2 -> blocked. */
    unsigned char t_block2[5] = { 0, 0, 1, 0, 0 };
    ASSERT_FALSE(dominanceClear_core(1, t_block2, n, cand, sa));

    /* (4) sa itself a target is irrelevant -> still clear. */
    unsigned char t_sa[5] = { 0, 0, 0, 0, 1 };
    ASSERT_TRUE(dominanceClear_core(1, t_sa, n, cand, sa));

    /* (5) Adjacent cand/sa (no interior) -> trivially clear. */
    ASSERT_TRUE(dominanceClear_core(1, t_block, n, 2, 3));
}

/* dominanceClear must fail closed when OCFR is off / targets == nullptr. */
TEST(dominance_clear_closed_without_targets)
{
    unsigned char t_clear[5] = { 0, 0, 0, 0, 0 };
    /* ocfr_on == 0 -> always false, even with a clear range. */
    ASSERT_FALSE(dominanceClear_core(0, t_clear, 5, 1, 4));
    /* is_target == NULL -> always false. */
    ASSERT_FALSE(dominanceClear_core(1, (const unsigned char *)0, 5, 1, 4));
}

int main(void)
{
    fprintf(stderr, "test_int3avoid_unit:\n");
    RUN_TEST(is_s2_site_truth_table);
    RUN_TEST(can_shift_cand_boundary);
    RUN_TEST(find_upstream_cand_latest_boundary);
    RUN_TEST(find_upstream_cand_stops_at_gap);
    RUN_TEST(find_upstream_cand_no_pred);
    RUN_TEST(dominance_clear_accept_reject);
    RUN_TEST(dominance_clear_closed_without_targets);
    return test_report();
}
