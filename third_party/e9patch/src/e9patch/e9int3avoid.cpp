/*
 * e9int3avoid.cpp
 *
 * DIBE INT3 (S2) avoidance — shared planner helpers.
 * See e9int3avoid.h for the contract.
 */

#include "e9int3avoid.h"

#include "e9CFR.h"
#include "e9patch.h"
#include "e9x86_64.h"

/* The 5-byte JMP rel32 that DIBE installs at every shifted/unshifted site. */
#define DIBE_JMP_SIZE   5
#define CHUNK_SIZE      16

/*===========================================================================
 * C++ wrappers over the real e9patch structures.
 *
 * The scalar/array CORE logic these delegate to (isS2Site_core,
 * canShiftCand_core, ...) lives in e9int3avoid_core.cpp so the C unit test can
 * link it without pulling in e9patch.h.
 *===========================================================================*/

bool isS2Site(const Instr *I, unsigned jmp_off)
{
    unsigned off16 = (unsigned)((I->addr + (intptr_t)jmp_off) & 0xF);
    return isS2Site_core(off16) != 0;
}

const Instr *findUpstreamCand(const Instr *I)
{
    uintptr_t sa_chunk = (uintptr_t)I->addr & ~(uintptr_t)0xF;
    for (const Instr *J = I->pred(); J != nullptr; J = J->pred())
    {
        /* pred() already guarantees offset contiguity (no decode gap). */
        if (((uintptr_t)J->addr & ~(uintptr_t)0xF) != sa_chunk)
            break;                          /* left I's chunk => stop */
        if (canShiftCand_core((uintptr_t)J->addr))
            return J;                       /* latest in-chunk boundary */
    }
    return nullptr;
}

bool dominanceClear(const Binary &B, const Instr *cand, const Instr *sa)
{
    if (!option_OCFR || B.targets == nullptr)
        return false;                       /* conservative */
    /*
     * Walk instructions strictly between cand and sa.  cand itself MAY be a
     * branch target; sa is irrelevant.  We use isTarget(&B, offset) which is
     * the OCFR overapproximation (offset-based, matches Instr::offset).
     */
    for (const Instr *J = cand->succ(); J != nullptr && J != sa; J = J->succ())
    {
        if (isTarget(&B, (off_t)J->offset))
            return false;
    }
    return true;
}

/*
 * Does instruction K (bytes/size) carry a LOCK (0xF0) prefix?  Scan the legacy
 * prefix bytes only (LOCK must precede REX/opcode).
 */
static bool hasLockPrefix(const uint8_t *bytes, unsigned size)
{
    for (unsigned i = 0; i < size; i++)
    {
        switch (bytes[i])
        {
            case 0xF0:                          /* LOCK */
                return true;
            /* Other legacy prefixes that may precede LOCK: keep scanning. */
            case 0x66: case 0x67: case 0xF2: case 0xF3:
            case 0x2E: case 0x36: case 0x3E: case 0x26:
            case 0x64: case 0x65:
                continue;
            default:
                return false;                   /* opcode/REX reached */
        }
    }
    return false;
}

bool absorbedRangeClean(const Binary &B, const Instr *origin, const Instr *sa)
{
    if (origin == nullptr || sa == nullptr || origin == sa)
        return false;
    for (const Instr *K = origin; K != nullptr && K != sa; K = K->succ())
    {
        /*
         * CLEAN subset only: every K in [origin, sa) must be a plain,
         * never-instrumented instruction.  Patches are applied in REVERSE
         * address order, so an interior instrumentation site is STATE_QUEUED
         * (not yet patched) at this point; an already-touched one is
         * PATCHED/FREE.  Only STATE_INSTRUCTION is clean.  is_patched catches
         * the (rare) forward-applied case as well.
         */
        if (K->is_patched || K->STATE[0] != STATE_INSTRUCTION)
            return false;                       /* overlap => P1.5, abort */

        const uint8_t *bytes = K->getOrig();
        unsigned ksize = (unsigned)K->size;

        /* Atomicity hazard: a LOCK-prefixed insn must not move. */
        if (hasLockPrefix(bytes, ksize))
            return false;

        /*
         * Indirect / return control flow cannot be replayed verbatim (its
         * target is dynamic).  Direct CALL/JMP/Jcc are relocatable
         * (relocateInstr fixes the rel32); reject only the indirect ones,
         * which getCFTTarget reports as INTPTR_MIN.
         */
        if (isCFT(bytes, ksize, CFT_CALL | CFT_JMP | CFT_JCC | CFT_RET))
        {
            intptr_t tgt = getCFTTarget(K->addr, bytes, ksize,
                CFT_CALL | CFT_JMP | CFT_JCC);
            if (tgt == INTPTR_MIN)
                return false;                   /* indirect/ret => abort */
        }

        /* Final gate: e9patch must be able to relocate it (relax/size mode). */
        if (relocateInstr(K->addr, /*offset32=*/0, bytes, ksize, K->pic,
                /*buf=*/nullptr, /*relax=*/true) < 0)
            return false;
    }
    return true;
}

/*
 * Is instruction K safe to REPLAY (relocate verbatim) inside a
 * composed trampoline?  This is the per-instruction relocation-hazard gate
 * shared by the clean (P1) and overlap (P1.5) paths: it does NOT look at
 * whether K is itself instrumented (that distinction is the caller's job).
 *
 *   - LOCK-prefixed insn  -> false (atomicity: must not move).
 *   - indirect/return CFT -> false (dynamic target, not replayable verbatim).
 *   - relocateInstr fails -> false (e9patch cannot relocate it).
 */
static bool instrReplayable(const Instr *K)
{
    const uint8_t *bytes = K->getOrig();
    unsigned ksize = (unsigned)K->size;

    if (hasLockPrefix(bytes, ksize))
        return false;

    if (isCFT(bytes, ksize, CFT_CALL | CFT_JMP | CFT_JCC | CFT_RET))
    {
        intptr_t tgt = getCFTTarget(K->addr, bytes, ksize,
            CFT_CALL | CFT_JMP | CFT_JCC);
        if (tgt == INTPTR_MIN)
            return false;                   /* indirect/ret => not replayable */
    }

    if (relocateInstr(K->addr, /*offset32=*/0, bytes, ksize, K->pic,
            /*buf=*/nullptr, /*relax=*/true) < 0)
        return false;
    return true;
}

/*
 * absorbedRangeComposable: like absorbedRangeClean, but ALLOWS
 * interior instrumented sites (overlap), composing them into the single
 * shifted trampoline instead of aborting.
 *
 * Every instruction K in [origin, sa) must be REPLAYABLE (instrReplayable):
 * no LOCK, no indirect/return CFT, relocatable.  This holds for BOTH plain
 * instructions and interior sites (a site's load-bearing replay is just its
 * relocated ORIGINAL instruction — for the A1 NOP trampoline that IS its
 * instrumentation).  Interior sites are detected via K->patch (set at parse
 * time for every site, independent of patch order) and collected into
 * `sites_out` (their addresses) so the caller can SUPPRESS their independent
 * patch.  A site that is already absorbed by another shift (B.absorbed) makes
 * the range non-composable (a site may be folded into at most one trampoline).
 *
 * Returns true iff the whole range is composable; sites_out then lists the
 * interior site addresses (possibly empty == the P1 clean case).  On false,
 * sites_out is cleared and the caller keeps S2.
 */
bool absorbedRangeComposable(const Binary &B, const Instr *origin,
    const Instr *sa, std::vector<intptr_t> &sites_out)
{
    sites_out.clear();
    if (origin == nullptr || sa == nullptr || origin == sa)
        return false;
    for (const Instr *K = origin; K != nullptr && K != sa; K = K->succ())
    {
        if (!instrReplayable(K))
            return false;                   /* LOCK/indirect/non-reloc => keep S2 */

        /*
         * Is K itself a patch site?  `patch` is set at parse time for EVERY
         * site (e9api.cpp::parsePatch), so it is reliable here regardless of
         * the reverse patch order (interior sites are STATE_QUEUED now).
         */
        if (K->patch)
        {
            /* A site may be folded into at most one shifted trampoline. */
            if (B.absorbed.find(K->addr) != B.absorbed.end())
            {
                sites_out.clear();
                return false;
            }
            sites_out.push_back(K->addr);
        }
    }
    return true;
}

void buildPredecessorMap(Binary &B)
{
    if (!option_OCFR)
        return;
    B.predecessors.clear();
    for (const Instr *I = B.Is.front(); I != nullptr; I = I->next())
    {
        const uint8_t *bytes = I->getOrig();
        unsigned size = (unsigned)I->size;
        if (!isCFT(bytes, size, CFT_CALL | CFT_JMP | CFT_JCC))
            continue;
        /*
         * getCFTTarget returns the *address*-based direct target, or
         * INTPTR_MIN for indirect branches (jmp/call *r/m) and returns.
         * Indirect edges therefore never enter the map (documented).
         */
        intptr_t target = getCFTTarget(I->addr, bytes, size,
            CFT_CALL | CFT_JMP | CFT_JCC);
        if (target == INTPTR_MIN)
            continue;
        B.predecessors[target].push_back(I->addr);
    }
}
