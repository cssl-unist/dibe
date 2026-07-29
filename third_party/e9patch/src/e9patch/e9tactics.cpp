/*
 * e9tactics.cpp
 * Copyright (C) 2022 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <algorithm>
#include <limits.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <inttypes.h>
#include <unistd.h>
#include <unordered_map>
#include <cctype>
#include <cinttypes>
#include <sys/stat.h>

#include <sys/mman.h>

#include "e9alloc.h"
#include "e9optimize.h"
#include "e9patch.h"
#include "e9tactics.h"
#include "e9trampoline.h"
#include "e9x86_64.h"
#include "e9CFR.h"       // isTarget()
#include "e9io_log.h"
#include "e9int3avoid.h"    // upstream-shift helpers

// No-overlap invariant helpers (defined just above print_patch_info).
static bool emittedRangeOverlaps(const Binary &B, intptr_t lo, intptr_t hi);

// Predecessor-redirection state.  Kept file-scope (NOT in struct
// Binary) on purpose — growing Binary perturbs its layout and trips a
// pre-existing layout-sensitive write elsewhere that corrupts a live std::map.
// Only the
// planner and print_patch_info (both in this TU) consume it; the trampoline pass
// needs only B.shifts[sa]=Y, which already drives the [Y,sa) absorbed-prefix
// replay.  Keyed by sa->addr; records the obstruction Y and the direct rel32
// predecessor branches we redirect Y->trampoline.  e9patch is single-pass over
// one Binary per invocation, so a file-scope map is safe.
struct PredRedirectInfo
{
    const Instr *Y = nullptr;               // dominance obstruction
    std::vector<const Instr *> preds;       // direct rel32 branch sources
};
static std::map<intptr_t, PredRedirectInfo> g_pred_redirects;

// Lazily build the direct-branch predecessor map (P0's
// buildPredecessorMap) the first time P3 needs it.  Building it eagerly at parse
// time is impossible — `instruction` messages stream in reverse address order
// and the set isn't complete until the first `patch` — and P0 never wired the
// call, leaving B.predecessors empty (so every dominance obstruction looked like
// it had 0 direct predecessors).  By the time any `patch`/dominance check runs,
// every `instruction` message has been parsed, so B.Is is complete and
// address-sorted: building here is correct.  e9patch processes one Binary per
// invocation, so a file-scope guard is sufficient.
static bool g_pred_map_built = false;
static void ensurePredecessorMap(Binary &B)
{
    if (g_pred_map_built)
        return;
    g_pred_map_built = true;
    buildPredecessorMap(B);                 // no-op unless option_OCFR
}

#define JMP_REL32_SIZE      sizeof(int32_t)
#define JMP_SIZE            (/*jmpq opcode=*/1 + JMP_REL32_SIZE)
#define PREFIX_MAX          (JMP_SIZE - 1)
#define PATCH_MAX           32

#define SHORT_JMP_MAX       INT8_MAX
#define SHORT_JMP_MIN       INT8_MIN

/*
 * This code uses short variable names.  See here for the key:
 *
 * A     = a virtual address space allocation (Alloc)
 * B     = the input binary to be rewritten (Binary)
 * I,J,K = instructions (Instr)
 * P,Q   = patches (Patch)
 * T,U   = trampoline (Trampoline)
 */

enum Tactic
{
    TACTIC_B0,                          // SIGILL.
    TACTIC_B1,                          // Jump.
    TACTIC_B2,                          // Punned jump.
    TACTIC_T0,                          // Grouping.
    TACTIC_T1,                          // Prefixed punned jump.
    TACTIC_T2,                          // Successor eviction.
    TACTIC_T3                           // Neighbour eviction.
};

/*
 * Representation of a patch.
 */
struct Patch
{
    const Alloc *A;                     // Virtual address space allocation.
    Instr * const I;                    // Instruction.
    Tactic tactic;                      // Tactic used.
    const struct Original
    {
        bool is_patched;                // Original is_patched?
        uint8_t state[PATCH_MAX];       // Original state bytes.
        uint8_t bytes[PATCH_MAX];       // Original data bytes.

        Original(const Instr *I) : is_patched(I->is_patched)
        {
            memcpy(state, I->STATE, PATCH_MAX);
            memcpy(bytes, I->PATCH, PATCH_MAX);
        }
    } original;
    Patch *next = nullptr;              // Next dependent patch.

    // Upstream-shift carry fields (declared for P1; not yet wired
    // into patchJump/print_patch_info/trampoline).  When `shift > 0`, the
    // JMP origin is logged at `origin->addr` instead of `I->addr`, and the
    // absorbed range [origin, I) is replayed by the trampoline.  `shift == 0`
    // (the default) is exactly today's behavior — no regression.
    unsigned shift = 0;                 // Absorbed prefix length (bytes).
    const Instr *origin = nullptr;      // Shifted JMP origin (else nullptr).

    Patch(Instr *I, Tactic t, const Alloc *A = nullptr) :
        A(A), I(I), tactic(t), original(I)
    {
        // TODO: fix stateful update in constructor
        I->is_patched = true;
        if (A != nullptr && A->T == evicteeTrampoline)
            I->is_evicted = true;
    }
};

/*
 * Convert a tactic to a string.
 */
static const char *getTacticName(Tactic tactic)
{
    switch (tactic)
    {
        case TACTIC_B0: return "B0";
        case TACTIC_B1: return "B1";
        case TACTIC_B2: return "B2";
        case TACTIC_T0: return "T0";
        case TACTIC_T1: return "T1";
        case TACTIC_T2: return "T2";
        case TACTIC_T3: return "T3";
        default:        return "???";
    }
}

/*
 * Commit a patch.
 */
static void commit(Binary &B, Patch *P)
{
    switch (P->tactic)
    {
        case TACTIC_B0:
            stat_num_B0++;
            break;
        case TACTIC_B1:
            stat_num_B1++;
            break;
        case TACTIC_B2:
            stat_num_B2++;
            break;
        case TACTIC_T0:
            stat_num_T0++;
            break;
        case TACTIC_T1:
            stat_num_T1++;
            break;
        case TACTIC_T2:
            stat_num_T2++;
            break;
        case TACTIC_T3:
            stat_num_T3++;
            break;
    }
    if (P->tactic == TACTIC_B0)
        B.Traps.push_back(P->A);

    while (P != nullptr)
    {
        if (P->A != nullptr)
            setTrampolineEntry(B.Es, P->I, P->A->lb + P->A->entry);

        // Delete the P (we do not need it anymore)
        Patch *Q = P;
        P = P->next;
        delete Q;
    }
}

/*
 * Undo the application of a patch.
 */
static void undo(Binary &B, Patch *P)
{
    while (P != nullptr)
    {
        P->I->is_patched = P->original.is_patched;
        P->I->is_evicted = false;
        for (unsigned i = 0; i < PATCH_MAX; i++)
        {
            P->I->STATE[i] = P->original.state[i];
            P->I->PATCH[i] = P->original.bytes[i];
        }
        deallocate(&B, P->A);
        Patch *Q = P;
        P = P->next;
        delete Q;
    }
}

// Restore a shifted site's own .text image to ORIGINAL.
//
// When a site `sa` is upstream-shifted (P->origin != nullptr), the 5-byte JMP
// is installed at the ORIGIN, and the trampoline replays [origin, sa_end)
// verbatim — so at runtime the bytes at `sa` itself are LEFT ORIGINAL (never
// rewritten; print_patch_info's shift path emits the JMP at origin, not at sa).
// But the tactic still ran patchJump(P,0)/patchUnused on `sa`, stamping a
// PHANTOM JMP (E9 + rel32, then 0xCC fill) into sa's slot of the shared
// patched.bytes image and marking it STATE_PATCHED/STATE_FREE.  That phantom is
// never emitted, yet it stays live in the image for the REST of the reverse-order
// tactic pass.  A later, LOWER-address neighbour that puns/evicts across sa
// (tactic_T2/T3/T3b, makeBounds Step (1)/(2)) reads sa's PATCH/STATE to size its
// own jmp and to derive the rel32 mask (urel32 = *(I->PATCH + prefix + 1)); it
// then places its trampoline to MATCH the phantom bytes.  At emit the neighbour's
// jmp is clamped to its host size, so the spilled rel32 bytes are taken from the
// real .text (sa's UNCHANGED ORIGINAL bytes) — which disagree with the phantom
// the placement assumed -> the neighbour's jmp targets an unmapped VA -> SIGSEGV.
//
// So: once the shift origin is committed, roll sa's own [sa, sa_end) image
// BYTES back to the pre-patch ORIGINAL (captured in P->original) — the truth the
// runtime presents — so a neighbour's makeBounds rel32 mask (Step 2's
// `urel32 = *(I->PATCH + prefix + 1)`, which reads across the shared
// patched.bytes buffer into sa's region) sees the bytes the runtime will actually
// leave there, not the phantom JMP.  We KEEP sa's STATE (STATE_PATCHED): sa is
// still a claimed site, so no neighbour may pun/extend INTO it (makeBounds Step 1
// only grows the writable window across STATE_FREE), and the no-overlap invariant
// is preserved.  Bytes original + state claimed == exactly what the runtime does:
// leave sa's bytes intact while the trampoline (at origin) replays them.  The
// shift's own JMP (emitted at origin) and the trampoline (replays I->ORIG) never
// read sa's PATCH, so they are unaffected.
static void restoreShiftedSiteBytes(Patch *P)
{
    if (P == nullptr || P->origin == nullptr || P->I == nullptr)
        return;                             // not a shifted site -> nothing to do
    Instr *I = P->I;
    for (unsigned i = 0; i < (unsigned)I->size && i < PATCH_MAX; i++)
        I->PATCH[i] = P->original.bytes[i];  // BYTES only; keep STATE_PATCHED
}

/*
 * Calculate trampoline bounds.
 */
static Bounds makeBounds(Binary &B, const Trampoline *T, const Instr *I,
    const Instr *J, unsigned prefix, bool trap)
{
    // Step (1): Calculate the mask to protect overlapping instructions:
    assert(prefix < I->size || trap);
    size_t size = prefix + 1;
    for (; size < I->size &&
            (I->STATE[size] == STATE_INSTRUCTION ||
             I->STATE[size] == STATE_FREE); size++)
        ;
    assert(prefix < size);
    for (; size < /*sizeof(jmpq)=*/5 && I->STATE[size] == STATE_FREE; size++)
        ;   // overflow
    size_t diff = size - prefix - /*sizeof(jmpq opcode)=*/1;

    // Step (2): Calculate the minimum and maximum jmpq rel32 values:
    int32_t rel32_lo, rel32_hi;
    if (diff >= sizeof(int32_t) || trap)
    {
        rel32_lo = INT32_MIN;
        rel32_hi = INT32_MAX;
    }
    else
    {
        uint32_t mask = 0xFFFFFFFFu << (8 * diff);
        uint32_t urel32 =
          *(uint32_t *)(I->PATCH + prefix + /*sizeof(jmpq opcode)=*/1);
        uint32_t urel32_lo = urel32 & mask;
        uint32_t urel32_hi = urel32_lo | (0xFFFFFFFFu & ~mask);
        rel32_lo = (int32_t)urel32_lo;
        rel32_hi = (int32_t)urel32_hi;
    }

    // Step (3): Calculate the minimum/maximum jump target address:
    intptr_t jmp_from = I->addr + prefix + JMP_SIZE;
    intptr_t jmp_lo = jmp_from + rel32_lo;
    intptr_t jmp_hi = jmp_from + rel32_hi;
    if (jmp_lo > jmp_hi)
    {
        intptr_t tmp = jmp_lo;
        jmp_lo = jmp_hi;
        jmp_hi = tmp;
    }
    intptr_t lo = jmp_lo;
    intptr_t hi = jmp_hi;

    // Step (4): Trampoline must be within a 32bit offset of a return address.
    intptr_t addr_lo = jmp_from - (intptr_t)INT32_MAX;
    intptr_t addr_hi = jmp_from - (intptr_t)INT32_MIN;
    addr_hi -= TRAMPOLINE_MAX;
    lo = std::max(lo, addr_lo);
    hi = std::min(hi, addr_hi);

    // Step (5): The trampoline itself may have bounds.
    Bounds b = getTrampolineBounds(&B, T, J);
    lo = std::max(lo, b.lb);
    hi = std::min(hi, b.ub);

    // Step (6): If the instruction is position-dependent, the trampoline
    // must be withing a 32bit offset of the target address.
    if (I->pcrel32_idx != 0 || I->pcrel8_idx != 0)
    {
        intptr_t pcrel;
        if (I->pcrel32_idx != 0)
            pcrel = *(const int32_t *)(I->ORIG + I->pcrel32_idx);
        else
            pcrel = (int8_t)I->ORIG[I->pcrel32_idx];
        intptr_t target = I->addr + I->size + pcrel;
        intptr_t target_lo = target - (intptr_t)INT32_MAX;
        intptr_t target_hi = target - (intptr_t)INT32_MIN;
        target_hi -= TRAMPOLINE_MAX;
        lo = std::max(lo, target_lo);
        hi = std::min(hi, target_hi);
    }

    // Step (6b): Upstream-shift absorbed-prefix PC-relativity.
    //
    // When I is an upstream-shifted site (B.shifts[I->addr] = origin), the
    // trampoline ALSO replays every instruction in [origin, I) verbatim,
    // relocated (relocateAbsorbedPrefix / ENTRY_INSTR).  Any of those absorbed
    // instructions may be PC-relative (a rel32 branch OR a RIP-relative data
    // reference such as `cmpb $0, disp32(%rip)`).  Step (6) only constrained the
    // trampoline for I's OWN pcrel operand; the absorbed prefix was ignored, so
    // the allocator was free to place the trampoline up to ~2GB from a global
    // referenced by an absorbed instruction.  At emit time relocateInstr then
    // computes a displacement > INT32_MAX and fails with the hard error
    // "absorbed prefix ... could not be relocated" -> e9patch aborts mid-emit
    // (jmp.jsonl truncated, patch never completed).  The planner's relocatability
    // gate (instrReplayable) only checks the instruction IN PLACE (offset 0), so
    // it cannot see this far-placement overflow; the only sound place to enforce
    // it is here, where the placement bounds are decided.  Constrain the
    // trampoline to within int32 of EVERY absorbed-prefix PC-relative target
    // too.  If that makes the window empty, allocate() returns nullptr and the
    // tactic falls back to S2 (INT3) — correct, just unoptimized for this site.
    {
        auto sit = B.shifts.find(I->addr);
        if (sit != B.shifts.end() && sit->second != nullptr)
        {
            const Instr *origin = sit->second;
            for (const Instr *K = origin; K != nullptr && K != I;
                 K = K->succ())
            {
                unsigned idx = getInstrPCRelativeIndex(K->getOrig(),
                    (unsigned)K->size);
                if (idx == 0)
                    continue;               // not PC-relative
                intptr_t pcrel;
                // rel8 branches have a 1-byte field (size - idx < 4); every
                // other PC-relative form (rel32 branch / RIP-rel disp32 data
                // ref) has a 4-byte field.  Mirror parseInstruction's split.
                if (K->size - idx < sizeof(int32_t))
                    pcrel = (int8_t)K->getOrig()[idx];
                else
                    pcrel = *(const int32_t *)(K->getOrig() + idx);
                intptr_t target = K->addr + K->size + pcrel;
                intptr_t target_lo = target - (intptr_t)INT32_MAX;
                intptr_t target_hi = target - (intptr_t)INT32_MIN;
                target_hi -= TRAMPOLINE_MAX;
                lo = std::max(lo, target_lo);
                hi = std::min(hi, target_hi);
            }
        }
    }

    // Step (7): Apply the user-specified bounds (if any).
    lo = std::max(lo, option_mem_lb);
    hi = std::min(hi, option_mem_ub);
    switch (B.mode)
    {
        case MODE_ELF_EXE: case MODE_ELF_DSO:
            // The additional page is for the loader scratch space
            hi = std::min(hi, option_loader_base - (intptr_t)PAGE_SIZE);
        default:
            break;
    }
 
    return {lo, hi};
}

/*
 * Allocate virtual address space for a punned jump.
 */
static const Alloc *allocatePunnedJump(Binary &B, const Instr *I,
    unsigned prefix, const Instr *J, const Trampoline *T)
{
    for (unsigned i = 0; i <= /*sizeof(jmpq)=*/5; i++)
        if (I->STATE[prefix + i] == STATE_QUEUED)
            return nullptr;
    auto b = makeBounds(B, T, I, J, prefix, /*trap=*/false);
    return allocate(&B, b.lb, b.ub, T, J, !option_mem_multi_page);
}

/*
 * Allocate virtual address space for a non-punned jump.
 */
static const Alloc *allocateJump(Binary &B, const Instr *I,
    const Trampoline *T)
{
    return allocatePunnedJump(B, I, /*prefix=*/0, I, T);
}

/*
 * Allocate virtual address space for a trap.
 */
static const Alloc *allocateTrap(Binary &B, const Instr *I,
    const Trampoline *T)
{
    auto b = makeBounds(B, T, I, I, /*prefix=*/0, /*trap=*/true);
    return allocate(&B, b.lb, b.ub, T, I, !option_mem_multi_page);
}

/*
 * Patch in a (redundant) jmp instruction prefix.
 */
static void patchJumpPrefix(Patch *P, unsigned prefix)
{
    // TODO: support other prefixes/encodings/NOPs
    const uint8_t prefixes[] = {0x48, 0x26, 0x36, 0x3E};
    assert(prefix < P->I->size && prefix <= sizeof(prefixes));

    uint8_t *bytes = P->I->PATCH, *state = P->I->STATE;
    for (unsigned i = 0; i < prefix; i++)
    {
        assert(state[i] == STATE_INSTRUCTION ||
               state[i] == STATE_FREE);
        bytes[i] = prefixes[i];
        state[i] = STATE_PATCHED;
    }
}

/*
 * Patch in a jmpq instruction.
 */
static void patchJump(Patch *P, unsigned offset)
{
    assert(offset <= PATCH_MAX - JMP_SIZE);
    assert(offset < P->I->size);
    assert(P->A != nullptr);
     
    intptr_t diff = (P->A->lb + P->A->entry) -
        (P->I->addr + offset + JMP_SIZE);
    assert(diff >= INT32_MIN && diff <= INT32_MAX);
    int32_t rel32 = (int32_t)diff;
    
    uint8_t *bytes = P->I->PATCH + offset,
            *state = P->I->STATE + offset;
    assert(*state == STATE_INSTRUCTION || *state == STATE_FREE);
    *bytes++ = /*jmpq opcode=*/0xE9;
    *state++ = STATE_PATCHED;
    offset++;

    const uint8_t *rel32p8 = (uint8_t *)&rel32;
    unsigned i = 0;
    for (; i < sizeof(rel32) && offset + i < P->I->size; i++)
    {
        assert(state[i] == STATE_INSTRUCTION || state[i] == STATE_FREE ||
            (state[i] == STATE_PATCHED && bytes[i] == rel32p8[i]));
        bytes[i] = rel32p8[i];
        state[i] = STATE_PATCHED;
    }
    for (; i < sizeof(rel32); i++)
    {
        assert(state[i] != STATE_QUEUED);
        if (state[i] == STATE_FREE)
        {
            bytes[i] = rel32p8[i];
            state[i] = STATE_PATCHED;
        }
        else
            state[i] |= STATE_LOCKED;
    }
}

/*
 * Patch in a short jmp instruction.
 */
static void patchShortJump(Patch *P, intptr_t addr)
{
    intptr_t diff = addr - (P->I->addr + /*sizeof(short jmp)=*/2);
    assert(diff >= INT8_MIN && diff <= INT8_MAX);
    int8_t rel8 = (int8_t)diff;

    uint8_t *bytes = P->I->PATCH,
            *state = P->I->STATE;

    assert(*state == STATE_INSTRUCTION || *state == STATE_FREE);
    *bytes++ = /*short jmp opcode=*/0xEB;
    *state++ = STATE_PATCHED;

    assert(*state == STATE_INSTRUCTION || *state == STATE_FREE);
    *bytes++ = (uint8_t)rel8;
    *state++ = STATE_PATCHED;
}

/*
 * Patch in a trap (illegal) instruction.
 */
static void patchTrap(Patch *P)
{
    uint8_t *bytes = P->I->PATCH,
            *state = P->I->STATE;
    assert(*state == STATE_INSTRUCTION || *state == STATE_FREE);
    bytes[0] = 0x27;    // Invalid x86_64 opcode
    state[0] = STATE_PATCHED;
}

/*
 * Patch in unused memory.
 */
static void patchUnused(Patch *P, unsigned offset)
{
    assert(offset <= P->I->size);
    for (unsigned i = offset; i < P->I->size; i++)
    {
        switch (P->I->STATE[i])
        {
            case STATE_INSTRUCTION: case STATE_QUEUED:
                P->I->PATCH[i] = /*int3=*/0xcc;
                P->I->STATE[i] = STATE_FREE;
                break;
            default:
                break;
        }
    }
}

/*
 * Return true if the given instruction can be instrumented.
 */
static bool canPatch(const Instr *I)
{
    switch (I->STATE[0])
    {
        case STATE_INSTRUCTION: case STATE_FREE:
            return true;
        default:
            return false;
    }
}



// 2) Find the offset where the jmp opcode (0xE9) starts in I->PATCH.
//    (Returns 0 if not found -- not an issue for T1 since it provides a prefix hint;
//     used for cases like T2 where internal tactics are mixed)
static unsigned find_jmp_offset(const Instr* I) {
    unsigned limit = (I->size > PATCH_MAX ? PATCH_MAX : (unsigned)I->size);
    for (unsigned i = 0; i + 5 <= limit; i++) {
        if ((I->STATE[i] & STATE_PATCHED) && I->PATCH[i] == 0xE9)
            return i;
    }
    return 0;
}

// Is instruction K an unconditional control-flow break — i.e. does
// control NOT fall through from K into K's successor?  (unconditional JMP, or
// RET).  Used to decide whether an obstruction Y can be entered by fall-through
// (if its predecessor instruction does NOT break, Y is fall-through reachable
// and predecessor redirection cannot cover it).
static bool isUncondBreak(const Instr *K)
{
    if (K == nullptr)
        return false;
    const uint8_t *bytes = K->getOrig();
    unsigned size = (unsigned)K->size;
    // Unconditional JMP (direct or indirect) or RET: no fall-through edge.
    return isCFT(bytes, size, CFT_JMP | CFT_RET);
}

// Classification of a dominance obstruction Y for predecessor
// redirection.  `convertible` is true iff EVERY way control can reach Y is a
// direct branch we can rewrite (no fall-through into Y, >=1 direct predecessor,
// and — checked later by the planner — each predecessor's rel32-rewrite footprint
// is atomic and itself does not need a new S2).  The probe stage only needs the
// CFG facts (fall-through? direct preds? indirect-looking gaps?); the per-pred
// atomic/footprint checks happen in the planner just before emitting.
struct DomObstruction
{
    const Instr *Y = nullptr;       // the first interior branch target
    bool fallthrough_in = false;    // control can fall through INTO Y
    int  direct_preds = 0;          // # of direct branch sources targeting Y
    bool convertible = false;       // P3-convertible (CFG-level)
};

// Find + classify the dominance obstruction for the blocked shift [cand, sa).
// Y = the FIRST instruction strictly inside (cand, sa) that is a branch target.
// Takes a non-const Binary so it can lazily build the predecessor map on first
// use (P0 defined buildPredecessorMap but never called it — see ensurePredecessorMap).
static DomObstruction classifyDomObstruction(Binary &B,
    const Instr *cand, const Instr *sa)
{
    ensurePredecessorMap(B);
    DomObstruction d;
    for (const Instr *J = cand->succ(); J != nullptr && J != sa; J = J->succ())
    {
        if (isTarget(&B, (off_t)J->offset))
        {
            d.Y = J;
            break;
        }
    }
    if (d.Y == nullptr)
        return d;                       // shouldn't happen (dominance said blocked)

    // Fall-through edge into Y: Y's offset-contiguous predecessor instruction
    // exists AND does not unconditionally break.  pred() is null at a decode
    // gap (we cannot prove there is no fall-through) -> treat as fall-through
    // (conservative: NOT convertible).
    const Instr *yp = d.Y->pred();
    if (yp == nullptr)
        d.fallthrough_in = true;        // decode gap before Y -> conservative
    else if (!isUncondBreak(yp))
        d.fallthrough_in = true;        // predecessor falls through into Y

    // Direct predecessors (from the P0 reverse-edge map; indirect invisible).
    auto it = B.predecessors.find(d.Y->addr);
    if (it != B.predecessors.end())
        d.direct_preds = (int)it->second.size();

    // CFG-level convertible: no fall-through into Y AND >=1 direct predecessor.
    // (Indirect predecessors are invisible to the map; the no-fall-through +
    // has-direct-preds heuristic is the design's "all predecessors direct"
    // proxy — an indirect jmp *r lands on Y without a map edge and without a
    // fall-through, so we cannot fully exclude it here; the planner additionally
    // refuses to convert if it cannot account for every entry, see P3 below.)
    d.convertible = (!d.fallthrough_in && d.direct_preds > 0);
    return d;
}

// STEP-1 diagnostic: when a site is dominance-blocked, report
// the obstruction Y and whether predecessor redirection could cover it.  Gated
// by DIBE_SHIFT_PROBE (or DIBE_SHIFT_DEBUG) so it is free in production runs.
static void probeDominanceBlock(Binary &B, const Instr *cand,
    const Instr *sa, unsigned jmp_off)
{
    static const bool probe =
        (getenv("DIBE_SHIFT_PROBE") != nullptr ||
         getenv("DIBE_SHIFT_DEBUG") != nullptr);
    if (!probe)
        return;
    DomObstruction d = classifyDomObstruction(B, cand, sa);
    if (d.Y == nullptr)
    {
        fprintf(stderr, "[p3-probe] sa=0x%lx jmp_off=%u BLOCKED-dominance but "
            "NO interior target found (?)\n",
            (unsigned long)sa->addr, jmp_off);
        return;
    }
    fprintf(stderr, "[p3-probe] sa=0x%lx jmp_off=%u Y=0x%lx fallthrough_in=%d "
        "direct_preds=%d => %s\n",
        (unsigned long)sa->addr, jmp_off, (unsigned long)d.Y->addr,
        d.fallthrough_in? 1: 0, d.direct_preds,
        d.convertible? "P3-CONVERTIBLE" : "NOT-convertible");
}

// Is X a DIRECT rel32 branch we can redirect by rewriting its 4-byte
// immediate (opcode unchanged)?  Returns the in-instruction byte offset of the
// rel32 immediate (so imm_addr = X->addr + *imm_off) and true; false otherwise.
//
// Redirectable forms (the only ones whose target is a 4-byte rel32 at a fixed
// offset, reaching anywhere in ±2GB so a far trampoline is in range):
//   E9 cd            JMP  rel32      (5 bytes, imm at +1)
//   E8 cd            CALL rel32      (5 bytes) -- EXCLUDED (see note)
//   0F 80..8F cd     Jcc  rel32      (6 bytes, imm at +2)
// We EXCLUDE CALL: a CALL pushes a return address and the trampoline ends with a
// JMP to sa_end (not a RET), so the pushed return address would be stale/unbalanced.
// rel8 Jcc (70..7F) and short JMP (EB) reach only ±127 B and cannot target a far
// trampoline -> not redirectable.
static bool isRedirectableRel32Branch(const Instr *X, unsigned *imm_off)
{
    const uint8_t *b = X->getOrig();
    unsigned n = (unsigned)X->size;
    if (n == 5 && b[0] == 0xE9)          // JMP rel32
    {
        if (imm_off) *imm_off = 1;
        return true;
    }
    if (n == 6 && b[0] == 0x0F && (b[1] & 0xF0) == 0x80)   // Jcc rel32
    {
        if (imm_off) *imm_off = 2;
        return true;
    }
    return false;
}

// 4-byte immediate-rewrite footprint is S0/S1-aligned (no new S2)?
// The runtime selects S0 if (a&0x7)+4<=8, S1 if (a&0xF)+4<=16, else S2.  We
// require S0 or S1 (no new INT3): (imm_addr & 0xF) + 4 <= 16.
static bool predFootprintAtomic(intptr_t imm_addr)
{
    return ((uintptr_t)imm_addr & 0xF) + 4 <= 16;
}

// Try predecessor redirection for the dominance-blocked site `sa`.
//
// Pre: an upstream shift to `cand` was just refused because some interior branch
// target Y in (cand, sa) can be entered, bypassing a shifted JMP.  Instead of
// patching sa, redirect Y's DIRECT branch predecessors to a trampoline that
// replays [Y, sa) + sa's instrumentation + continues to sa_end.  `sa` is NOT
// patched.  Convert the site ONLY if EVERY way control can reach sa is via a
// qualifying redirected predecessor:
//   (1) Y is NOT fall-through reachable (its pred instruction unconditionally
//       breaks) and the decode is contiguous (no gap),
//   (2) Y has >=1 direct predecessor in B.predecessors (indirect are invisible),
//   (3) (Y, sa) is dominance-clear (Y is the SOLE obstruction; no second target
//       Z in (Y, sa) could let control reach sa bypassing the trampoline),
//   (4) [Y, sa) is composable (every insn replayable; interior sites absorbed),
//   (5) every predecessor X is a direct rel32 branch (JMP/Jcc-near), is NOT
//       itself a patch site (else two writes collide), its 4-byte immediate
//       footprint is S0/S1-aligned, its rel32 to the trampoline fits int32, and
//       its footprint does not overlap an already-emitted entry.
// If ANY predecessor (or check) fails, leave sa on S2 (return nullptr) — partial
// coverage is expected.  On success: record B.shifts[sa]=Y (drives the trampoline
// replay), g_pred_redirects[sa]={Y,preds} (drives per-pred emit + suppresses the
// sa/Y JMP), absorb interior sites, bump stats, and return Y (so tactic_B1 sets
// P->origin=Y and builds the trampoline).
static const Instr *tryPredRedirect(Binary &B, Instr *I, const Instr *cand,
    unsigned jmp_off)
{
    static const bool disabled =
        (getenv("DIBE_NO_PRED_REDIRECT") != nullptr);
    if (option_no_pred_redirect || disabled)
        return nullptr;

    DomObstruction d = classifyDomObstruction(B, cand, I);
    if (d.Y == nullptr || d.fallthrough_in || d.direct_preds == 0)
        return nullptr;                 // not CFG-convertible (fall-through/indirect)
    const Instr *Y = d.Y;

    // (3) Y must be the SOLE obstruction: nothing in (Y, sa) is a target, else a
    // path entering at that Z bypasses the trampoline's replay and reaches sa.
    if (!dominanceClear(B, Y, I))
        return nullptr;

    // (4) [Y, sa) must be composable (replayable; interior sites absorbable).
    std::vector<intptr_t> absorbed_sites;
    if (!absorbedRangeComposable(B, Y, I, absorbed_sites))
        return nullptr;

    // The shifted JMP footprint guard the upstream path uses (forward-spill past
    // sa) does NOT apply here: we never install a JMP at Y; sa's trampoline ends
    // with $break to sa_end as usual.  But the trampoline's absorbed-prefix MUST
    // be able to replay [Y, sa) — composable already guarantees that.

    // (5) Vet EVERY direct predecessor.  Resolve each address to its Instr and
    // require it be a redirectable rel32 branch, not itself a site, atomic
    // footprint, in-range rel32, and non-overlapping.
    auto it = B.predecessors.find(Y->addr);
    if (it == B.predecessors.end() || it->second.empty())
        return nullptr;

    // The trampoline entry VA is not known until allocate(); but the rel32 range
    // check only needs the *relative* distance, which we cannot know precisely
    // here.  We conservatively require the predecessor and sa to be within int32
    // of each other (the trampoline is allocated near sa); a far predecessor is
    // refused.  print_patch_info re-checks the exact rel32 and asserts in range.
    std::vector<const Instr *> preds;
    std::set<intptr_t> seen;            // de-dup (defensive: no double-emit at X)
    for (intptr_t xaddr : it->second)
    {
        if (!seen.insert(xaddr).second)
            continue;                   // duplicate edge -> skip
        const Instr *X = findInstr(&B, xaddr);
        if (X == nullptr)
            return nullptr;             // map/disasm mismatch -> bail
        // X must live OUTSIDE the absorbed range [Y, sa] (and not be sa itself):
        // a predecessor inside [Y, sa) is replayed by the trampoline AND would
        // have its .text rel32 rewritten — double handling / collision.  Reject.
        if (X->addr >= Y->addr && X->addr <= I->addr)
            return nullptr;
        unsigned imm_off = 0;
        if (!isRedirectableRel32Branch(X, &imm_off))
            return nullptr;             // rel8 / CALL / not a rel32 branch
        if (X->patch)
            return nullptr;             // X is itself a site -> writes would collide
        const intptr_t imm_addr = X->addr + (intptr_t)imm_off;
        if (!predFootprintAtomic(imm_addr))
            return nullptr;             // 4-byte rewrite would be a NEW S2
        // Conservative int32 reachability: |sa - X| must fit (trampoline ~ sa).
        intptr_t dist = (intptr_t)I->addr - imm_addr;
        if (dist < INT32_MIN/2 || dist > INT32_MAX/2)
            return nullptr;             // too far for a safe rel32
        // No-overlap invariant: the 4-byte immediate footprint must be free.
        if (emittedRangeOverlaps(B, imm_addr, imm_addr + 4))
            return nullptr;
        preds.push_back(X);
    }
    if (preds.empty())
        return nullptr;

    // SUCCESS.  Record the shift (drives [Y, sa) replay in the trampoline) and
    // the pred-redirect (drives the per-predecessor emit + suppresses sa/Y JMP).
    B.shifts[I->addr] = Y;
    PredRedirectInfo pr;
    pr.Y = Y;
    pr.preds = preds;
    g_pred_redirects[I->addr] = pr;
    stat_shift_applied++;               // a would-be S2 site is now atomic
    stat_pred_redirect_applied++;
    stat_pred_redirect_preds += preds.size();
    if (!absorbed_sites.empty())
    {
        stat_shift_overlap_applied++;
        for (intptr_t k : absorbed_sites)
        {
            B.absorbed[k] = I->addr;
            stat_shift_absorbed_sites++;
        }
    }
    return Y;
}

// Try to shift the JMP origin of `I` upstream to an in-chunk
// candidate so the 5-byte JMP no longer straddles the 16-byte boundary (S2),
// landing the runtime on S1/S0 instead.  Decides the CLEAN subset only:
//   - I (with the JMP at in-PATCH offset jmp_off) is an S2 site;
//   - a dominance-clear, in-chunk upstream candidate `cand` exists; AND
//   - the absorbed range [cand, I) is clean (no instrumented/LOCK/indirect/
//     non-relocatable instruction).
// On success records B.shifts[I->addr] = cand and returns cand (so callers can
// set P->shift/P->origin for logging); records the appropriate blocked stat and
// returns nullptr otherwise.  MUST be called BEFORE allocate() so the trampoline
// size budget (getTrampolineSize) includes the absorbed-prefix replay.
static const Instr *tryUpstreamShift(Binary &B, Instr *I, unsigned jmp_off)
{
    if (option_no_upstream_shift)
        return nullptr;                 // kill-switch: shift disabled
    // DIBE_SHIFT_ONLY=0xADDR limits the shift to exactly the site at file-VA
    // ADDR; DIBE_SHIFT_MAX=N caps the applied count.
    {
        const char *only = getenv("DIBE_SHIFT_ONLY");
        if (only != nullptr)
        {
            intptr_t want = (intptr_t)strtoll(only, nullptr, 0);
            if (I->addr != want)
                return nullptr;
        }
        const char *mx = getenv("DIBE_SHIFT_MAX");
        if (mx != nullptr && stat_shift_applied >= (size_t)strtoll(mx, nullptr, 0))
            return nullptr;
    }
    if (!isS2Site(I, jmp_off))
        return nullptr;                 // not S2 -> nothing to fix
    static const bool dbg = (getenv("DIBE_SHIFT_DEBUG") != nullptr);
#define SHIFT_DBG(reason) do { if (dbg) fprintf(stderr, \
    "[shift-dbg] sa=0x%lx jmp_off=%u BLOCKED: %s\n", \
    (unsigned long)I->addr, jmp_off, reason); } while (0)

    // Candidate enumeration (latest -> earliest).
    //
    // findUpstreamCand returns the LATEST in-chunk boundary that can hold a
    // 5-byte JMP.  But that latest boundary may sit just past an UPSTREAM short
    // site whose punned JMP spills into ours (the spill-collision below), or may
    // not be dominance-clear.  Picking an EARLIER candidate enlarges the
    // absorbed range so it SWALLOWS the colliding/interior site (composing it,
    // suppressing its independent JMP, so it no longer spills) — this is the
    // punning-group composition the design calls for.  So enumerate ALL valid
    // in-chunk boundaries from latest to earliest (pred() guarantees
    // offset-contiguity) and take the first that passes every gate.
    std::vector<const Instr *> cands;
    {
        uintptr_t sa_chunk = (uintptr_t)I->addr & ~(uintptr_t)0xF;
        for (const Instr *J = I->pred(); J != nullptr; J = J->pred())
        {
            if (((uintptr_t)J->addr & ~(uintptr_t)0xF) != sa_chunk)
                break;                          // left I's chunk
            if (((uintptr_t)J->addr & 0xF) + JMP_SIZE <= 16)
                cands.push_back(J);             // can hold a 5-byte JMP here
        }
    }
    if (cands.empty())
    {
        stat_shift_no_cand++;
        SHIFT_DBG("no_cand");
        return nullptr;
    }

    // `sa`-is-a-branch-target / mid-JMP guard.
    //
    // dominanceClear() checks only instructions STRICTLY BETWEEN cand and sa; it
    // deliberately excludes `sa` itself ("control may legitimately enter at the
    // shifted origin").  That exclusion is unsound for the *crash* case below.
    // Once the JMP origin is shifted upstream to `cand`, the 5-byte JMP occupies
    // the FILE bytes [cand, cand+JMP_SIZE) and the absorbed range [cand, sa) is
    // replayed ONLY inside the trampoline.  A direct control-flow edge whose
    // target is `sa` (e.g. a loop back-edge `jge sa`) lands on the ORIGINAL sa
    // .text address, which after the shift is one of:
    //   (a) cand < sa < cand+JMP_SIZE  -> sa is MID-JMP: the edge decodes the
    //       JMP's rel32 bytes as an instruction -> SIGSEGV (e.g. a back-edge
    //       landing on byte 3 of the shifted JMP).  Whether `sa` is a branch
    //       target is checked with the SAME OCFR over-approximation (isTarget on
    //       I->offset) that dominanceClear consults.
    //   (b) sa >= cand+JMP_SIZE -> sa's original bytes are intact (the JMP fully
    //       precedes them); the edge re-executes the original `sa` instruction.
    //       A back-edge then bypasses the trampoline, so sa's own instrumentation
    //       is skipped on that edge, but it does NOT crash and the program stays
    //       correct.
    // Case (a) is the only crash-causing hazard.  Picking an EARLIER cand
    // grows (sa - cand), moving sa OUT of the JMP footprint (into the safe case
    // (b)), so this is a per-candidate `continue` (try earlier), NOT an abort:
    // we only fall back to S2 if NO in-chunk candidate keeps sa clear of its JMP.
    const bool sa_is_target =
        (option_OCFR && B.targets != nullptr && isTarget(&B, (off_t)I->offset));
    if (getenv("DIBE_SATARGET_PROBE") && sa_is_target) {
        intptr_t latest = cands.front()->addr;  // max cand -> min distance
        fprintf(stderr, "[satarget-probe] sa=0x%lx latest_cand=0x%lx "
            "dist=%ld %s\n", (unsigned long)I->addr, (unsigned long)latest,
            (long)(I->addr - latest),
            (I->addr - latest < JMP_SIZE)? "mid-JMP(crash)": "lost-instr(safe)");
    }

    // Track the "best" blocked reason across candidates for the stat line: we
    // want to report why the OVERALL site stayed S2, preferring the most
    // specific cause from the latest candidate that got furthest.
    enum { BR_NONE, BR_FWDSPILL, BR_SATARGET, BR_SPILL, BR_DOM, BR_OVERLAP,
        BR_RELOC } block_reason = BR_NONE;

    for (const Instr *cand : cands)
    {
        // mid-JMP crash guard (see the sa_is_target note above).
        // If `sa` is a branch target AND this cand puts sa strictly inside the
        // shifted JMP footprint [cand, cand+JMP_SIZE), a direct edge to sa lands
        // mid-JMP -> SIGSEGV.  An EARLIER cand grows (sa-cand) past JMP_SIZE,
        // pulling sa out of the footprint, so try earlier (continue) rather than
        // abort.  If no cand clears it, the site stays S2 (BR_SATARGET).
        if (sa_is_target &&
            cand->addr + (intptr_t)JMP_SIZE > I->addr)   // sa < cand+JMP_SIZE
        {
            if (block_reason < BR_SATARGET) block_reason = BR_SATARGET;
            continue;
        }
        // Forward-spill-past-sa guard.  The shifted JMP at `cand`
        // occupies [cand, cand+JMP_SIZE).  The trampoline reconstructs exactly
        // [cand, sa_end) where sa_end = I->addr + I->size.  If the JMP extends
        // PAST sa_end (sa is a short insn so cand+JMP_SIZE > sa_end), it clobbers
        // the first byte(s) of the instruction after sa (= the $break return).
        // An earlier cand makes this worse, so it is a hard skip (not "try
        // earlier") — but earlier cands are MORE likely to fit, so keep trying.
        if (cand->addr + (intptr_t)JMP_SIZE > I->addr + (intptr_t)I->size)
        {
            if (block_reason < BR_FWDSPILL) block_reason = BR_FWDSPILL;
            continue;
        }
        // No-overlap invariant gate (SOUND, tactic-agnostic).  Our
        // shifted JMP claims the FILE bytes [cand, cand+JMP_SIZE).  Any OTHER
        // already-emitted jmp.jsonl entry whose write-range intersects those
        // bytes would be corrupted at runtime (both writes hit the same .text
        // byte).  Sites are processed in REVERSE address order and entries are
        // emitted as decided, so this catches a higher-address site that already
        // punned/shifted a JMP into cand's bytes (e.g. a backward T3 pun).  An
        // earlier cand has a DIFFERENT footprint and may not collide, so try it
        // (like the spill guard) rather than abort.  NOTE: this is the only
        // gate that needs to be sound vs. NON-contiguous footprints (T3 punning
        // a JMP into cand's chunk from a far site); the pred()-walk spill guard
        // below only sees offset-contiguous upstream sites and is kept as a
        // cheap fast-path.  The symmetric direction (a LATER lower site punning
        // into THIS cand) is handled by the T3 scan querying emittedRangeOverlaps.
        if (emittedRangeOverlaps(B, cand->addr, cand->addr + (intptr_t)JMP_SIZE))
        {
            if (block_reason < BR_SPILL) block_reason = BR_SPILL;
            continue;
        }
        // Upstream-spill collision guard.  Our JMP at `cand` occupies
        // [cand, cand+JMP_SIZE).  An UPSTREAM short site p < cand puns a JMP
        // that may spill into those bytes (sites apply in reverse order, so p is
        // not yet patched and its spill bytes still read STATE_INSTRUCTION).
        // If p collides, an EARLIER candidate (<= p) would absorb p into the
        // range (suppressing its independent JMP, so it no longer spills) —
        // hence `continue` to try earlier, rather than abort.
        {
            const intptr_t cand_lo = cand->addr;
            const intptr_t cand_hi = cand->addr + JMP_SIZE;
            bool spill_collision = false;
            for (const Instr *P = cand->pred();
                 P != nullptr && P->addr + (intptr_t)JMP_SIZE +
                     ((intptr_t)JMP_REL32_SIZE-1) > cand_lo;
                 P = P->pred())
            {
                if (!P->patch)
                    continue;                   // not a site -> no JMP footprint
                intptr_t fp = (intptr_t)P->size;
                intptr_t pun = (intptr_t)JMP_SIZE +
                    (P->size < JMP_SIZE? (JMP_REL32_SIZE-1): 0);
                if (pun > fp) fp = pun;
                const intptr_t p_hi = P->addr + fp;
                if (P->addr < cand_hi && p_hi > cand_lo)
                {
                    spill_collision = true;
                    break;
                }
            }
            if (spill_collision)
            {
                if (block_reason < BR_SPILL) block_reason = BR_SPILL;
                continue;                       // try an earlier cand (absorb p)
            }
        }
        // Dominance: an earlier cand has a LARGER interior range, so if this
        // cand is not dominance-clear, an earlier one cannot be either (its
        // interior is a superset).  Record + give up on earlier cands.
        if (!dominanceClear(B, cand, I))
        {
            if (block_reason < BR_DOM) block_reason = BR_DOM;
            // Diagnose the dominance obstruction Y for this
            // site and report whether it is predecessor-redirect-able.  This is
            // the STEP-1 probe (DIBE_SHIFT_PROBE=1) AND the input to the P3
            // planner below.  We run it on the FIRST (latest) blocking cand,
            // whose interior range is the smallest, so Y is the closest target.
            probeDominanceBlock(B, cand, I, jmp_off);
            // Predecessor redirection: an interior target Y blocks the
            // shift, but if EVERY way control reaches sa is a direct rel32 branch
            // we can re-point Y->trampoline, we convert sa off S2 without patching
            // it.  Returns Y (used as the absorbed-prefix origin) on success.
            const Instr *yorigin = tryPredRedirect(B, I, cand, jmp_off);
            if (yorigin != nullptr)
                return yorigin;         // P3 fired: tactic_B1 builds the tramp
            stat_pred_redirect_blocked++;
            break;
        }
        // Overlap / punning-group composition.  The absorbed range
        // [cand, I) may contain OTHER patch sites K.  Compose: replay each K's
        // original instruction in I's trampoline (the absorbed prefix already
        // does this — for the A1 NOP trampoline that replay IS K's
        // instrumentation) and SUPPRESS K's own independent patch so no
        // dead/conflicting JMP is installed at K.  Composable iff every insn is
        // relocation-safe (no LOCK / indirect / non-relocatable).
        std::vector<intptr_t> absorbed_sites;
        if (!absorbedRangeComposable(B, cand, I, absorbed_sites))
        {
            // A LOCK/indirect/non-relocatable instruction sits in this range.
            // An EARLIER cand's range is a superset, so it also contains that
            // hazard -> cannot improve.  Record + stop.
            bool overlap = false;
            for (const Instr *K = cand; K != nullptr && K != I; K = K->succ())
                if (K->patch) { overlap = true; break; }
            if (block_reason < (overlap? BR_OVERLAP: BR_RELOC))
                block_reason = (overlap? BR_OVERLAP: BR_RELOC);
            break;
        }
        // SUCCESS at this candidate.  Persist the shift for the trampoline pass
        // (Patch is freed at commit()).
        B.shifts[I->addr] = cand;
        stat_shift_applied++;
        // Record absorbed interior sites so queueFlush suppresses their
        // independent patch.  Sites apply in REVERSE address order and every
        // interior site K satisfies cand <= K < I (a lower address), so K is
        // ALWAYS processed AFTER I — the suppression mark is in place in time.
        if (!absorbed_sites.empty())
        {
            stat_shift_overlap_applied++;
            for (intptr_t k : absorbed_sites)
            {
                B.absorbed[k] = I->addr;
                stat_shift_absorbed_sites++;
            }
        }
        return cand;
    }

    // No candidate passed.  Record the most-specific blocked reason.
    switch (block_reason)
    {
        case BR_DOM:      stat_shift_blocked_dominance++;
                          SHIFT_DBG("dominance (interior branch target)");
                          break;
        case BR_RELOC:    stat_shift_blocked_reloc++;
                          SHIFT_DBG("reloc (LOCK/indirect/non-reloc)");
                          break;
        case BR_OVERLAP:  stat_shift_blocked_overlap++;
                          SHIFT_DBG("non-composable (interior site hazard)");
                          break;
        case BR_SPILL:    stat_shift_blocked_overlap++;
                          SHIFT_DBG("upstream-spill-collision (no earlier cand)");
                          break;
        case BR_FWDSPILL: stat_shift_blocked_overlap++;
                          SHIFT_DBG("forward-spill-past-sa");
                          break;
        case BR_SATARGET: stat_shift_blocked_satarget++;
                          SHIFT_DBG("sa-is-branch-target & mid-JMP "
                                    "(no earlier cand clears sa)");
                          break;
        default:          stat_shift_blocked_reloc++;
                          SHIFT_DBG("no-passing-candidate");
                          break;
    }
    return nullptr;
#undef SHIFT_DBG
}

// Undo a shift recorded by tryUpstreamShift for instruction at
// `sa_addr` when the subsequent allocate() fails (so the tactic falls through to
// the next one / S2).  Reverts the shifts side-map, the absorbed-site
// suppression marks, and all the stats so the planner's accounting stays exact.
static void undoUpstreamShift(Binary &B, intptr_t sa_addr)
{
    if (B.shifts.erase(sa_addr) == 0)
        return;                             // nothing was recorded
    stat_shift_applied--;
    bool had_overlap = false;
    for (auto it = B.absorbed.begin(); it != B.absorbed.end(); )
    {
        if (it->second == sa_addr)
        {
            had_overlap = true;
            stat_shift_absorbed_sites--;
            it = B.absorbed.erase(it);
        }
        else
            ++it;
    }
    if (had_overlap)
        stat_shift_overlap_applied--;
    // Roll back a predecessor-redirection recorded for this site.
    auto pri = g_pred_redirects.find(sa_addr);
    if (pri != g_pred_redirects.end())
    {
        stat_pred_redirect_applied--;
        stat_pred_redirect_preds -= pri->second.preds.size();
        g_pred_redirects.erase(pri);
    }
}

// No-overlap invariant helpers.  The runtime applies every jmp.jsonl
// entry independently, so two emitted entries whose FILE-address write-ranges
// [lo, hi) overlap WILL corrupt each other (validated as a byte mismatch, e.g.
// a shifted 0xE9 where another entry expected an original byte).  B.emitted_ranges
// is the single interval set of every emitted entry's [start, end).
//
// emittedRangeOverlaps: does [lo, hi) intersect any already-emitted entry?  Used
// by the upstream-shift candidate gate and the T3 punned-neighbour scan to refuse
// a footprint that would collide.  O(log n): the only candidate overlaps are the
// entry at-or-just-before lo and the entry just after.
static bool emittedRangeOverlaps(const Binary &B, intptr_t lo, intptr_t hi)
{
    if (lo >= hi || B.emitted_ranges.empty())
        return false;
    // First entry whose start >= lo; the one before it may straddle lo.
    auto it = B.emitted_ranges.lower_bound(lo);
    if (it != B.emitted_ranges.begin())
    {
        auto pv = std::prev(it);
        if (pv->second > lo)            // [pv.start, pv.end) extends past lo
            return true;
    }
    if (it != B.emitted_ranges.end() && it->first < hi)   // starts before hi
        return true;
    return false;
}

// recordEmittedRange: register [lo, hi) for an entry about to be written, and
// WARN LOUDLY if it overlaps an already-recorded range — that is the no-overlap
// invariant violation (it must never fire; the gates above keep it silent).
static void recordEmittedRange(Binary &B, const char *tag, intptr_t lo,
    intptr_t hi)
{
    if (lo >= hi)
        return;
    if (emittedRangeOverlaps(B, lo, hi))
    {
        B.stat_overlap_detected++;
        // Find a concrete colliding neighbour for the message.
        auto it = B.emitted_ranges.lower_bound(lo);
        intptr_t olo = 0, ohi = 0;
        if (it != B.emitted_ranges.begin() && std::prev(it)->second > lo)
        { auto pv = std::prev(it); olo = pv->first; ohi = pv->second; }
        else if (it != B.emitted_ranges.end() && it->first < hi)
        { olo = it->first; ohi = it->second; }
        fprintf(stderr, "[e9patch] WARNING: jmp.jsonl OVERLAP (no-overlap "
            "invariant VIOLATED): %s entry [0x%lx,0x%lx) overlaps emitted "
            "[0x%lx,0x%lx) — runtime will corrupt these bytes\n",
            tag, (unsigned long)lo, (unsigned long)hi,
            (unsigned long)olo, (unsigned long)ohi);
    }
    B.emitted_ranges[lo] = hi;
}

// 3) Print patch info (address + bytes)
//    prefix_hint is passed only when the prefix is known (e.g. T1); otherwise set to UINT_MAX for auto-detection
static void print_patch_info(Binary& B, const char* tag, const Patch* P,
                             unsigned prefix_hint = (unsigned)-1,
                             bool do_log = true)
{
    if (!do_log) return;
    if (!P || !P->I) return;

    if (!B.runtime_base_known) {
        uintptr_t found = 0;
        if (detect_runtime_base(&B, B.target_pid, found)) {
            B.runtime_base = found;
            B.runtime_base_known = true;
        }
    }
    unsigned long base = (unsigned long)B.runtime_base;
    unsigned jmp_off = (prefix_hint == (unsigned)-1) ? find_jmp_offset(P->I) : prefix_hint;

    // Predecessor-redirected site: sa (P->I) is NOT patched, and Y's
    // .text bytes are unchanged.  Instead we rewrite each direct predecessor X's
    // 4-byte rel32 immediate (Y -> the trampoline entry).  The trampoline (built
    // via B.shifts[sa]=Y) replays [Y, sa) + sa + $break to sa_end.  Each emitted
    // entry overwrites ONLY 4 bytes (the immediate), opcode byte unchanged, so it
    // is S0/S1 by the predFootprintAtomic gate -> no INT3.
    if (P->A != nullptr) {
        auto pri = g_pred_redirects.find(P->I->addr);
        if (pri != g_pred_redirects.end()) {
            const intptr_t entry = P->A->lb + P->A->entry;   // trampoline entry VA
            for (const Instr *X : pri->second.preds) {
                unsigned imm_off = 0;
                if (!isRedirectableRel32Branch(X, &imm_off))
                    continue;                                // vetted in planner
                const intptr_t imm_addr = X->addr + (intptr_t)imm_off;
                const intptr_t x_next   = X->addr + (intptr_t)X->size;
                // The branch computes target = x_next + rel32; we want target =
                // entry.  Base cancels (both VAs shift by base): rel32 = entry -
                // x_next (file addresses).
                const intptr_t diff = entry - x_next;
                assert(diff >= INT32_MIN && diff <= INT32_MAX);
                int32_t rel32 = (int32_t)diff;
                uint8_t buf[4];
                memcpy(buf, &rel32, sizeof(rel32));
                const unsigned long patch_va =
                    (unsigned long)((intptr_t)base + imm_addr);
                recordEmittedRange(B, tag, imm_addr, imm_addr + 4);
                e9io::append_jmp(patch_va, buf, 4);
            }
            return;
        }
    }

    // Upstream-shifted site: the 5-byte JMP is installed at the
    // candidate origin (P->origin), NOT at I.  The absorbed range [origin, I)
    // is replayed inside the trampoline (see e9trampoline.cpp ENTRY_INSTR), so
    // at .text we ONLY overwrite 5 bytes at origin with the JMP.  Because
    // (origin & 0xF) + 5 <= 16 (guaranteed by findUpstreamCand), the runtime
    // selects S1/S0 instead of S2.  The original bytes at [origin+5, I+...) are
    // jumped over and need no rewrite.
    if (P->shift > 0 && P->origin != nullptr && P->A != nullptr) {
        const intptr_t entry   = P->A->lb + P->A->entry;     // trampoline entry
        const intptr_t jmp_at  = P->origin->addr;            // JMP install addr
        const intptr_t jmp_from = jmp_at + JMP_SIZE;         // addr after JMP
        const intptr_t diff    = entry - jmp_from;
        // rel32 must fit (the trampoline was bounded within int32 of jmp_from-ish
        // via makeBounds on I; origin is within 16 bytes of I, well inside range).
        int32_t rel32 = (int32_t)diff;
        uint8_t buf[JMP_SIZE];
        buf[0] = 0xE9;
        memcpy(buf + 1, &rel32, sizeof(rel32));
        const unsigned long patch_va =
            (unsigned long)((intptr_t)base + jmp_at);
        recordEmittedRange(B, tag, jmp_at, jmp_at + JMP_SIZE);
        e9io::append_jmp(patch_va, buf, JMP_SIZE);
        return;
    }

    size_t bytes_to_dump = jmp_off + JMP_SIZE;
    if (bytes_to_dump > P->I->size) bytes_to_dump = P->I->size;
    if (bytes_to_dump > PATCH_MAX)  bytes_to_dump = PATCH_MAX;
    const unsigned long patch_va = (unsigned long)((intptr_t)base + P->I->addr);
    recordEmittedRange(B, tag, P->I->addr, P->I->addr + (intptr_t)bytes_to_dump);
    e9io::append_jmp(patch_va, P->I->PATCH, bytes_to_dump);
}
/*
 * Tactic B0: replace the instruction with an illegal instruction.
 */
static Patch *tactic_B0(Binary &B, Instr *I, const Trampoline *T)
{
    if (!option_tactic_B0)
        return nullptr;
    const Alloc *A = allocateTrap(B, I, T);
    if (A == nullptr)
        return nullptr;
    Patch *P = new Patch(I, TACTIC_B0, A);
    patchTrap(P);
    patchUnused(P, /*offset=sizeof(illegal)=*/1);
    print_patch_info(B, "B0-main", P);
    return P;
}

/*
 * Tactic B1: replace the instruction with a jump.
 */
static Patch *tactic_B1(Binary &B, Instr *I, const Trampoline *T,
                        Tactic tactic = TACTIC_B1,
                        bool do_log = true)
{
    if (I->size < JMP_SIZE || !option_tactic_B1 || !canPatch(I)) return nullptr;
    // Decide the upstream shift BEFORE allocate so the trampoline
    // size budget (getTrampolineSize) includes the absorbed-prefix replay.
    // Only on the main DIBE path (tactic == TACTIC_B1); not for T0/T2/T3 reuse.
    const Instr *origin = (tactic == TACTIC_B1?
        tryUpstreamShift(B, I, /*jmp_off=*/0): nullptr);
    const Alloc *A = allocateJump(B, I, T);
    if (!A) {
        if (origin) undoUpstreamShift(B, I->addr);
        return nullptr;
    }
    Patch *P = new Patch(I, tactic, A);
    if (origin) { P->origin = origin; P->shift = (unsigned)(I->addr - origin->addr); }
    patchJump(P, /*offset=*/0);
    patchUnused(P, /*offset=*/5);
    if (origin) restoreShiftedSiteBytes(P);   // sa stays original at runtime
    print_patch_info(B, "B1-main", P, /*prefix_hint=*/(unsigned)-1, /*do_log=*/do_log);
    return P;
}

/*
 * Tactic B2: replace the instruction with a punned jump.
 */
static Patch *tactic_B2(Binary &B, Instr *I, const Trampoline *T,
                        Tactic tactic = TACTIC_B2,
                        bool do_log = true)
{
    if (I->size >= JMP_SIZE || !option_tactic_B2 || !canPatch(I)) return nullptr;
    // upstream shift (main path only); jmp_off=0 for B2.
    const Instr *origin = (tactic == TACTIC_B2?
        tryUpstreamShift(B, I, /*jmp_off=*/0): nullptr);
    const Alloc *A = allocatePunnedJump(B, I, /*prefix=*/0, I, T);
    if (!A) {
        if (origin) undoUpstreamShift(B, I->addr);
        return nullptr;
    }
    Patch *P = new Patch(I, tactic, A);
    if (origin) { P->origin = origin; P->shift = (unsigned)(I->addr - origin->addr); }
    patchJump(P, /*offset=*/0);
    if (origin) restoreShiftedSiteBytes(P);   // sa stays original at runtime
    print_patch_info(B, "B2-main", P, /*prefix_hint=*/(unsigned)-1, /*do_log=*/do_log);
    return P;
}

/*
 * Tactic T1: replace the instruction with a prefixed punned jump.
 */
static bool canApplyT1(const Instr *I, unsigned prefix)
{
    switch (I->STATE[prefix])
    {
        case STATE_INSTRUCTION:
            return (prefix < I->size);
        case STATE_FREE:
            return true;
        default:
            return false;
    }
}
static Patch *tactic_T1(Binary &B, Instr *I, const Trampoline *T,
                        Tactic tactic = TACTIC_T1,
                        bool do_log = true)
{
    if (I->size >= JMP_SIZE || !option_tactic_T1 || !canPatch(I)) return nullptr;
    for (unsigned prefix = 1; prefix < JMP_REL32_SIZE && canApplyT1(I, prefix); prefix++) {
        if (prefix >= I->size) break;
        // upstream shift (main path only); jmp_off=prefix for T1.
        const Instr *origin = (tactic == TACTIC_T1?
            tryUpstreamShift(B, I, /*jmp_off=*/prefix): nullptr);
        const Alloc *A = allocatePunnedJump(B, I, prefix, I, T);
        if (A) {
            Patch *P = new Patch(I, tactic, A);
            if (origin) { P->origin = origin; P->shift = (unsigned)(I->addr - origin->addr); }
            patchJumpPrefix(P, prefix);
            patchJump(P, prefix);
            if (origin) restoreShiftedSiteBytes(P);   // sa stays original
            print_patch_info(B, "T1-main", P, /*prefix_hint=*/prefix, /*do_log=*/do_log);
            return P;
        }
        if (origin) undoUpstreamShift(B, I->addr);
    }
    return nullptr;
}

/*
 * Tactic T2: evict the successor instruction.
 */
static Patch *tactic_T2(Binary &B, Instr *I, const Trampoline *T)
{
    if (I->size >= JMP_SIZE || !option_tactic_T2 || !canPatch(I)) return nullptr;

    Instr *J = I->succ();
    if (!J || !canPatch(J)) return nullptr;

    const Trampoline *U = evicteeTrampoline;
    Patch *Q = nullptr;
    Q = (Q ? Q : tactic_B2(B, J, U, TACTIC_T2, /*do_log=*/false));
    Q = (Q ? Q : tactic_T1(B, J, U, TACTIC_T2, /*do_log=*/false));
    if (!Q) return nullptr;

    Patch *P = nullptr;
    P = (P ? P : tactic_B2(B, I, T, TACTIC_T2, /*do_log=*/false));
    P = (P ? P : tactic_T1(B, I, T, TACTIC_T2, /*do_log=*/false));
    if (!P) { undo(B, Q); return nullptr; }

    P->tactic = TACTIC_T2;
    P->next   = Q;

    // Log once at the end only
    print_patch_info(B, "T2-a", Q);
    print_patch_info(B, "T2-b", P);
    return P;
}

/*
 * Tactic T3 (single-byte instruction): evict a neighbour instruction.
 */
static Patch *tactic_T3b(Binary &B, Instr *I, const Trampoline *T, signed long flag = -1)
{
    // We can still use T3 on single-byte instructions, only if the next
    // byte interpreted as a short jmp rel8 happens to land in a suitable
    // location.

    if (I->size != 1 || !option_tactic_T3 || !canPatch(I))
        return nullptr;
    Instr *J = I->succ();
    if (J == nullptr)
        return nullptr;
    switch (J->STATE[0])
    {
        case STATE_INSTRUCTION: case STATE_FREE:
            break;
        default:
            return nullptr;
    }
    int8_t rel8 = (int8_t)J->PATCH[0];
    if (!option_tactic_backward_T3 && rel8 < 1)
        return nullptr;
    intptr_t target = I->addr + /*sizeof(short jmp)=*/2 + (intptr_t)rel8;
    if (target >= I->addr)
    {
        for (; J != nullptr && J->addr + J->size <= target; J = J->next())
            ;
    }
    else
    {
        for (J = I->prev(); J != nullptr && J->addr > target; J = J->prev())
            ;
    }
    if (J == nullptr || target <= J->addr ||
            (J->addr < I->addr && J->addr + J->size > I->addr))
        return nullptr;
    unsigned i = target - J->addr;
    uint8_t state = J->STATE[i];
    Patch *P = nullptr;
    Patch *T3b_a = nullptr;
    int i_t3b_a = -1;
    const Alloc *A = nullptr;
    switch (state)
    {
        case STATE_INSTRUCTION:
        case STATE_FREE:
        {
            // No-overlap invariant gate (see tactic_T3).  The pun's
            // emitted entry covers FILE bytes [J, J+i+JMP_SIZE); refuse it if an
            // upstream shift already claimed any of those bytes.
            if (emittedRangeOverlaps(B, J->addr,
                    J->addr + (intptr_t)i + (intptr_t)JMP_SIZE))
                return nullptr;
            bool save = (bool)J->no_optimize;
            if (target < I->addr)
                J->no_optimize = true;
            A = allocatePunnedJump(B, J, i, I, T);
            if (A == nullptr)
            {
                J->no_optimize = save;
                return nullptr;
            }
            P = new Patch(J, TACTIC_T3, A);
            patchJump(P, i);
            T3b_a = P;
        
            if (state == STATE_FREE)
            {
                // J is already patched. so we are done.
                P->A = nullptr;
                break;
            }
            
            // Step (2b): Attempt to evict J
            const Trampoline *U = evicteeTrampoline;
            Patch *Q = nullptr;
            Q = (Q ? Q : tactic_B1(B, J, U, TACTIC_T3, /*do_log=*/false));
            Q = (Q ? Q : tactic_B2(B, J, U, TACTIC_T3, /*do_log=*/false));
            Q = (Q ? Q : tactic_T1(B, J, U, TACTIC_T3, /*do_log=*/false));
            if (Q == nullptr)
            {
                // Eviction failed...
                J->no_optimize = save;
                undo(B, P);
                return nullptr;
            }
            Q->next = P; // Chain the evict patch + the pun jump we just created
            P->A = nullptr;
            P = Q;
            break;
        }
        default:
            return nullptr;
    }

    assert(A != nullptr);
    Patch *Q = new Patch(I, TACTIC_T3, A);
    // Short jmp (EB) at I, next byte is LOCK

    assert(I->STATE[0] == STATE_INSTRUCTION);
    I->STATE[0] = STATE_PATCHED;
    I->PATCH[0] = /*short jmp opcode=*/0xEB;
    I->next()->STATE[0] |= STATE_LOCKED;

    print_patch_info(B, "T3b-neigh", T3b_a, i_t3b_a);
    print_patch_info(B, "T3b-a",     Q);
    Q->next = P;
    return Q;
}

/*
 * Tactic T3: evict a neighbour instruction.
 */
static Patch *tactic_T3(Binary &B, Instr *I, const Trampoline *T, signed long flag = -1)
{
    if (I->size == 1)
        return tactic_T3b(B, I, T);
    if (I->size >= JMP_SIZE || !option_tactic_T3 || !canPatch(I))
        return nullptr;

    // Step (1): find nearest instruction at +SHORT_JMP_MAX (or
    // -SHORT_JMP_MIN) bytes ahead.
    Instr *J = I;
    while (true)
    {
        Instr *K = J->next();
        if (K == nullptr)
            break;
        if (K->addr - (I->addr + /*sizeof(short jmp)=*/2) > SHORT_JMP_MAX)
            break;
        J = K;
    }

    // Step (2): Iterate through all neighbour instructions:
    Patch *P = nullptr;
    Patch *T3_a = nullptr;
    int i_t3_a = -1;
    const Alloc *A = nullptr;
    intptr_t addr = 0;
    for (; P == nullptr; J = J->prev())
    {
        if (J == I)
            continue;
        if (J == nullptr)
            break;
        if (!option_tactic_backward_T3 && J->addr < I->addr)
            break;
        if ((I->addr + /*sizeof(short jmp)=*/2) - (J->addr + J->size -1) >
                -SHORT_JMP_MIN)
        {
            // Out-of-range, so give up... :(
            break;
        }

        switch (J->STATE[0])
        {
            case STATE_INSTRUCTION: case STATE_FREE:
                break;
            case STATE_PATCHED:
            case STATE_PATCHED | STATE_LOCKED:
            {
                if (J->STATE[J->size-1] == STATE_FREE)
                    break;
                continue;
            }
            default:
                continue;
        }

        for (int i = 0; i < (int)J->size && P == nullptr; i++)
        {
            if (i == 0 && J->STATE[0] != STATE_FREE)
            {
                // if (i == 0) then the instruction must be unused.
                continue;
            }
            if (J->addr > I->addr &&
                (J->addr + i) - (I->addr + /*sizeof(short jmp)=*/2) >
                    SHORT_JMP_MAX)
            {
                // Out-of-range
                continue;
            }
            if (J->addr < I->addr &&
                (I->addr + /*sizeof(short jmp)=*/2) - (J->addr + i) >
                    -SHORT_JMP_MIN)
            {
                // Out-of-range
                break;
            }
            if (J->addr < I->addr &&
                    I->addr - (J->addr + i) < /*sizeof(jmpq)=*/5)
            {
                // Cannot overlap with short jump.
                continue;
            }

            uint8_t state = J->STATE[i];
            switch (state)
            {
                case STATE_FREE:
                case STATE_INSTRUCTION:
                {
                    // Step (2a): Attempt to insert a jump here:
                    // No-overlap invariant gate.  A T3 pun installs a
                    // 5-byte JMP at offset i inside neighbour J; the emitted
                    // entry covers FILE bytes [J, J+i+JMP_SIZE).  An upstream
                    // shift (processed earlier, higher address) may already have
                    // claimed bytes in J's chunk (it shifts a JMP onto an
                    // in-chunk boundary that can fall exactly here).  Refuse this
                    // landing so the two entries cannot overlap; the loop tries
                    // the next offset / neighbour, and T3 falls through to S2 if
                    // none is clean.
                    if (emittedRangeOverlaps(B, J->addr,
                            J->addr + (intptr_t)i + (intptr_t)JMP_SIZE))
                        continue;
                    bool save = J->no_optimize;
                    if (J->addr < I->addr)
                        J->no_optimize = true;
                    A = allocatePunnedJump(B, J, i, I, T);
                    if (A == nullptr)
                    {
                        J->no_optimize = save;
                        continue;
                    }
                    addr = J->addr + i;
                    P = new Patch(J, TACTIC_T3, A);
                    patchJump(P, i);
                    T3_a = P;
                    i_t3_a = i;
                    if (state == STATE_FREE)
                    {
                        // J is already patched. so we are done.
                        P->A = nullptr; // A will be passed to I
                        continue;
                    }
                    
                    // Step (2b): Attempt to evict J
                    const Trampoline *U = evicteeTrampoline;
                    Patch *Q = nullptr;
                    Q = (Q ? Q : tactic_B1(B, J, U, TACTIC_T3, /*do_log=*/false));
                    Q = (Q ? Q : tactic_B2(B, J, U, TACTIC_T3, /*do_log=*/false));
                    Q = (Q ? Q : tactic_T1(B, J, U, TACTIC_T3, /*do_log=*/false));
                    if (Q == nullptr)
                    {
                        // Eviction failed...
                        J->no_optimize = save;
                        undo(B, P);
                        P = nullptr;
                        continue;
                    }
                    Q->next = P;
                    P->A = nullptr;
                    P = Q;
                    continue;
                }
                default:
                    continue;
            }
        }
    }
    if (P == nullptr)
        return nullptr;             // T3 failed

    // Step (3): Insert a short jump to the trampoline jump:
    assert(A != nullptr);
    
    Patch *Q = new Patch(I, TACTIC_T3, A);
    patchShortJump(Q, addr);
    patchUnused(Q, /*sizeof(short jmp)=*/2);

    print_patch_info(B, "T3-jmp", T3_a, i_t3_a);
    print_patch_info(B, "T3-eb",  Q);

    Q->next = P;
    return Q;
}

/*
 * Tactic T0: Batch instructions that are not jump targets.
 *            Assumes (overapproximate) control-flow-recovery
 */
static Patch *tactic_T0(Binary &B, Instr *I, const Trampoline *T,
    Tactic tactic = TACTIC_T0)
{
    if (!option_tactic_T0 || !option_OCFR || !canPatch(I) || I->T != T)
        return nullptr;

    // Step (1): build batch backwards, up to limit or target reached.
    Instr *J = I;
    size_t size = 0;
    for (unsigned limit = T0_LIMIT; !J->target && limit > 0; limit--)
    {
        size += J->size;
        Instr *K = J->pred();
        if (K == nullptr ||
                (K->STATE[0] != STATE_INSTRUCTION &&
                 K->STATE[0] != STATE_QUEUED))
            break;
        J = K;
    }

    // Step (2): Build batch fowards until sizeof(jmpq), or a CFT.
    Instr *L = I;
    bool cft = false;   // isUnconditionalCFT(I);
    while (!cft && size < /*sizeof(jmpq)=*/5)
    {
        Instr *K = L->succ();
        if (K == nullptr || K->target || !canPatch(K) ||
                (K->is_patched && !K->is_evicted))
            break;
        L = K;
        size += L->size;
        cft = isCFT(L->ORIG, L->size, CFT_CALL | CFT_RET | CFT_JMP);
    }
    if (J == L)
        return nullptr; // Batch is a single instruction == T0 failed

    // Step (3): "Free" all batched instructions.
    Patch *P = nullptr;
    for (Instr *K = L; K != nullptr && K->addr >= J->addr; K = K->pred())
    {
        Patch *Q = new Patch(K, TACTIC_T0, nullptr);
        patchUnused(Q, /*offset=*/0);
        Q->next = P;
        P = Q;
    }

    // Step (4): Build batch trampoline.
    Trampoline *U = nullptr;
    {
        size_t num_entries = 1;
        uint8_t *ptr =
            new uint8_t[sizeof(Trampoline) + num_entries * sizeof(Entry)];
        U                    = (Trampoline *)ptr;
        U->prot              = PROT_READ | PROT_EXEC;
        U->num_entries       = num_entries;
        U->preload           = false;
        U->entries[0].kind   = ENTRY_BATCH;
        U->entries[0].length = 0;
        U->entries[0].uint64 = L->addr;
    }

    // Step (5): Apply B1/B2/T1 to the whole batch.
    Patch *Q = nullptr;
    Q = (Q == nullptr? tactic_B1(B, J, U, TACTIC_T0): Q);
    Q = (Q == nullptr? tactic_B2(B, J, U, TACTIC_T0): Q);
    Q = (Q == nullptr? tactic_T1(B, J, U, TACTIC_T0): Q);
    if (Q == nullptr)
    {
        // Failed so clean up:
        delete[] U;
        undo(B, P);
        return nullptr;
    }
    Q->next = P;
    return Q;
}

/*
 * Patch the instruction at the given offset.
 */
bool patch(Binary &B, Instr *I, const Trampoline *T)
{
    switch (I->STATE[0])
    {
        case STATE_INSTRUCTION:
            break;
        default:
            error("failed to patch instruction 0x%lx (%zu) with invalid "
                "state (0x%.2X) (maybe \"patch\" messages are not sent "
                "in reverse order?)", I->addr, I->size, I->STATE[0]);
    }

    // Try all patching tactics in order T0/B1/B2/T1/T2/T3:
    Patch *P = nullptr;
    if (P == nullptr)
        P = tactic_T0(B, I, T);
    if (P == nullptr)
        P = tactic_B1(B, I, T);
    if (P == nullptr)
        P = tactic_B2(B, I, T);
    if (P == nullptr)
        P = tactic_T1(B, I, T);
    if (P == nullptr)
        P = tactic_T2(B, I, T);
    if (P == nullptr)
        P = tactic_T3(B, I, T);
    if (P == nullptr)
        P = tactic_B0(B, I, T);

    if (P == nullptr)
    {
        debug("failed to patch instruction at address 0x%lx (%zu)", I->addr,
            I->size);
        log(COLOR_RED, 'X');
        return false;       // Failed :(
    }

    bool uses_B0 = (P->tactic == TACTIC_B0);
    const char *name = getTacticName(P->tactic);

    commit(B, P);
    if (option_debug)
    {
        intptr_t entry = getTrampolineEntry(B.Es, I);
        intptr_t lb    = entry - getTrampolinePrologueSize(&B, I);
        intptr_t ub    = entry + getTrampolineSize(&B, T, I);
        debug("patched instruction 0x%lx [size=%zu, tactic=%s, "
            "entry=" ADDRESS_FORMAT ", "
            "trampoline=" ADDRESS_FORMAT ".." ADDRESS_FORMAT ", "
            "offset=%zd]",
            I->addr, I->size, name, ADDRESS(entry), ADDRESS(lb), ADDRESS(ub),
            (ssize_t)(entry - lb));
    }
    log((uses_B0? COLOR_YELLOW: COLOR_GREEN),
        (uses_B0? 'T': '.'));
    return true;            // Success!
}

