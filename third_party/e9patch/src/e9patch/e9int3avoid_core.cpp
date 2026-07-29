/*
 * e9int3avoid_core.cpp
 *
 * DIBE INT3 (S2) avoidance — scalar/array CORE logic.
 *
 * This TU deliberately depends ONLY on e9int3avoid.h (and <cstdint>), NOT on
 * e9patch.h.  That lets the C unit test (tests/test_int3avoid_unit.c) link
 * against exactly this object and exercise the real planner logic without
 * constructing C++ Instr/Binary objects.  The C++ wrappers that adapt the
 * real e9patch structures onto these cores live in e9int3avoid.cpp.
 */

#define E9INT3AVOID_CORE_ONLY 1
#include "e9int3avoid.h"

/* The 5-byte JMP rel32 that DIBE installs at every shifted/unshifted site. */
#define DIBE_JMP_SIZE   5
#define CHUNK_SIZE      16

extern "C" int isS2Site_core(unsigned off16)
{
    /* Mirror patcher.cpp: S2 iff off16 + len(=5) > 16. */
    return (int)((off16 & 0xF) + DIBE_JMP_SIZE > CHUNK_SIZE);
}

extern "C" int canShiftCand_core(uintptr_t cand_addr)
{
    return (int)(((unsigned)(cand_addr & 0xF) + DIBE_JMP_SIZE) <= CHUNK_SIZE);
}

extern "C" int findUpstreamCand_core(const uintptr_t *addrs,
    const unsigned *sizes, int n, int sa_idx)
{
    if (addrs == nullptr || sizes == nullptr || sa_idx <= 0 || sa_idx >= n)
        return -1;
    uintptr_t sa_chunk = addrs[sa_idx] & ~(uintptr_t)0xF;
    /*
     * Walk predecessors toward lower addresses.  Mirror Instr::pred(): the
     * step is only valid if it is offset-contiguous (no decode gap) and stays
     * within sa's 16-byte chunk.  Return the FIRST (= latest / closest to sa)
     * qualifying boundary, since we walk from sa_idx-1 downward.
     */
    for (int i = sa_idx - 1; i >= 0; i--)
    {
        /* Contiguity with the instruction that follows it (mirror pred()). */
        if (addrs[i] + (uintptr_t)sizes[i] != addrs[i + 1])
            return -1;                      /* decode gap => stop */
        if ((addrs[i] & ~(uintptr_t)0xF) != sa_chunk)
            return -1;                      /* left sa's chunk => stop */
        if (canShiftCand_core(addrs[i]))
            return i;                       /* latest in-chunk boundary */
    }
    return -1;
}

extern "C" int dominanceClear_core(int ocfr_on, const unsigned char *is_target,
    int n, int cand_idx, int sa_idx)
{
    if (!ocfr_on || is_target == nullptr)
        return 0;                           /* conservative: no info */
    if (cand_idx < 0 || sa_idx < 0 || cand_idx >= n || sa_idx > n)
        return 0;
    /* Strictly-interior instructions: (cand_idx, sa_idx). */
    for (int i = cand_idx + 1; i < sa_idx; i++)
        if (is_target[i])
            return 0;                       /* a target lands in range */
    return 1;
}
