/*
 * e9int3avoid.h
 *
 * DIBE INT3 (S2) avoidance — shared planner helpers.
 *
 * These helpers convert would-be S2 (INT3-gated) jmp sites into S0/S1 (atomic)
 * sites, by upstream-shift and predecessor/successor redirection.
 *
 * The *logic* of each helper is factored into small, scalar, C-callable "core"
 * functions (declared inside `extern "C"` below) so the C unit test in
 * tests/test_int3avoid_unit.c can exercise the exact same code path without
 * having to construct real C++ `Instr`/`Binary` objects.  The C++ wrappers
 * (declared after the core block) adapt the real e9patch structures onto the
 * cores.
 */

#ifndef __E9INT3AVOID_H
#define __E9INT3AVOID_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Core (scalar, C-callable) logic.  Unit-tested directly.
 *
 * The runtime (patcher.cpp) selects S0/S1/S2 *purely* from
 * (patch_va & 0xF, len):
 *      off8  = va & 0x7;   off16 = va & 0xF;
 *      off8  + len <= 8    -> S0
 *      off16 + len <= 16   -> S1
 *      else                -> S2
 * The planner mirrors this so its prediction agrees with the runtime.  In the
 * planner the 5-byte JMP rel32 starts at (I->addr + jmp_off) within the PATCH,
 * so the JMP's first byte lands at chunk offset ((I->addr + jmp_off) & 0xF).
 */

/*
 * isS2Site_core: would the 5-byte JMP placed at chunk-offset `off16` be S2?
 *   off16 = (I->addr + jmp_off) & 0xF
 * S2 iff off16 + 5 > 16  (i.e. the JMP straddles the 16-byte boundary).
 * Mirrors patcher.cpp's off16 selection EXACTLY for a 5-byte JMP.
 */
int isS2Site_core(unsigned off16);

/*
 * canShiftCand_core: can a candidate JMP origin at chunk-offset `cand_off16`
 * hold a 5-byte JMP within its own 16-byte chunk?  (cand_off16 & 0xF) + 5 <= 16.
 * (Argument is taken as a raw address; only its low 4 bits matter.)
 */
int canShiftCand_core(uintptr_t cand_addr);

/*
 * findUpstreamCand_core: pure logic of findUpstreamCand over a flattened,
 * address-ordered (ascending) instruction array.
 *
 *   addrs[i]      : start address of instruction i (ascending)
 *   sizes[i]      : size in bytes of instruction i
 *   n             : number of instructions
 *   sa_idx        : index of the to-be-shifted instruction `sa` (= I)
 *
 * Walks predecessors (i = sa_idx-1, sa_idx-2, ...) while they stay in sa's
 * 16-byte chunk AND remain offset-contiguous (addrs[i]+sizes[i] == addrs[i+1],
 * mirroring Instr::pred()).  Returns the index of the LATEST such instruction
 * whose address can hold a 5-byte JMP in its own chunk ((addr & 0xF)+5 <= 16),
 * or -1 if none qualifies / a gap is hit before one is found.
 */
int findUpstreamCand_core(const uintptr_t *addrs, const unsigned *sizes,
    int n, int sa_idx);

/*
 * dominanceClear_core: pure logic of dominanceClear over the same flattened
 * array plus a per-instruction "is branch target" flag array `is_target`.
 *
 *   ocfr_on       : nonzero iff OCFR target info is available (else => 0)
 *   cand_idx      : index of the candidate origin
 *   sa_idx        : index of the to-be-shifted instruction `sa`
 *
 * Returns nonzero iff OCFR is on AND no instruction strictly between cand_idx
 * and sa_idx (exclusive both ends) has is_target set.  cand_idx itself may be
 * a target; sa_idx is irrelevant.  Returns 0 when ocfr_on == 0.
 */
int dominanceClear_core(int ocfr_on, const unsigned char *is_target,
    int n, int cand_idx, int sa_idx);

#ifdef __cplusplus
}   // extern "C"
#endif

/*
 * The C++ wrappers below adapt the real e9patch Instr/Binary structures onto
 * the cores above.  Translation units that only need the cores (the unit-test
 * core object, the C test) define E9INT3AVOID_CORE_ONLY to skip the heavy
 * e9patch.h include and the wrapper declarations.
 */
#if defined(__cplusplus) && !defined(E9INT3AVOID_CORE_ONLY)

#include "e9patch.h"

/*
 * isS2Site: would patching instruction `I` (with the 5-byte JMP starting at
 * in-PATCH offset `jmp_off`) land on the runtime S2 path?
 *
 *   ((I->addr + jmp_off) & 0xF) + 5 > 16
 *
 * Mirrors patcher.cpp's off16 selection exactly so planner and runtime agree.
 */
bool isS2Site(const Instr *I, unsigned jmp_off);

/*
 * findUpstreamCand: walk `I->pred()` within the SAME 16-byte chunk as `I`,
 * returning the LATEST (closest-to-I, i.e. highest-address) instruction
 * boundary `J` such that a 5-byte JMP placed at `J->addr` stays inside J's
 * chunk:  (J->addr & 0xF) + 5 <= 16.
 *
 * Stops (returns nullptr for that step) at a null pred() — a decode gap means
 * we cannot prove offset contiguity, so we must not shift across it.  Also
 * stops once pred() leaves I's 16-byte chunk.  Returns nullptr if no in-chunk
 * boundary qualifies (e.g. I itself starts the chunk, or every candidate is
 * still too late).  Never returns `I` itself.
 */
const Instr *findUpstreamCand(const Instr *I);

/*
 * dominanceClear: is the absorbed range [cand, sa) free of branch targets,
 * so that shifting the JMP origin from `sa` to `cand` cannot be bypassed by
 * control entering at an intermediate label?
 *
 * Conservative: returns false if OCFR is off or targets are unavailable.
 * Otherwise returns false iff some instruction STRICTLY between `cand` and
 * `sa` (exclusive on both ends) is an isTarget().  `cand` itself MAY be a
 * branch target (control may legitimately enter at the shifted origin); `sa`
 * is irrelevant to the check.
 *
 * Walks the instruction stream from cand->succ() up to (but not including) sa.
 */
bool dominanceClear(const Binary &B, const Instr *cand, const Instr *sa);

/*
 * absorbedRangeClean: is every instruction in the absorbed range [origin, sa)
 * safe to (a) replay verbatim/relocated in the trampoline prologue and (b)
 * NOT itself already instrumented (CLEAN subset only)?
 *
 * Returns false (=> abort the shift, keep S2) if ANY instruction K in
 * [origin, sa):
 *   - is itself patched (K->is_patched)        -- overlap, out of scope (P1.5)
 *   - carries a LOCK prefix (0xF0)             -- atomicity hazard
 *   - is an indirect/return CFT (jmp/call *m, ret) -- non-replayable target
 *   - fails relocateInstr(K, INTPTR_MIN) < 0   -- e9patch cannot relocate it
 *
 * `origin` and `sa` must be offset-contiguous (origin reachable from sa via
 * pred()); the caller (findUpstreamCand) guarantees this.  `sa` itself is NOT
 * inspected (it becomes the trampoline's ENTRY_INSTR as today).
 */
bool absorbedRangeClean(const Binary &B, const Instr *origin, const Instr *sa);

/*
 * absorbedRangeComposable (P1.5 overlap / punning-group composition): like
 * absorbedRangeClean, but ALLOWS interior instrumented sites by composing them
 * into the single shifted trampoline (their original instruction is replayed in
 * the absorbed prefix; for the A1 NOP trampoline that IS their instrumentation)
 * instead of aborting.
 *
 * Requires every instruction in [origin, sa) to be relocation-safe (no LOCK, no
 * indirect/return CFT, relocatable).  Interior PATCH SITES (K->patch) are
 * permitted and their addresses returned in `sites_out`, so the caller can
 * SUPPRESS each site's independent patch (no dead JMP / wasted jmp.jsonl entry).
 * A site already folded into another shift (B.absorbed) makes the range
 * non-composable.  Returns true iff composable (sites_out then lists the
 * absorbed interior sites — empty == the P1 clean case).
 */
bool absorbedRangeComposable(const Binary &B, const Instr *origin,
    const Instr *sa, std::vector<intptr_t> &sites_out);

/*
 * buildPredecessorMap: one forward pass over B.Is collecting, for each direct
 * branch (CALL/JMP/Jcc with a statically-known immediate target), an inverse
 * edge target_addr -> [source_addr...].  Result stored on B.predecessors.
 *
 * Indirect branches (jmp *r/m, call *r/m, ret) carry no static target and are
 * therefore invisible to this map — documented limitation; such edges must be
 * handled (or conservatively skipped) by later phases.
 *
 * No-op unless option_OCFR is enabled.
 */
void buildPredecessorMap(Binary &B);

#endif /* __cplusplus */

#endif /* __E9INT3AVOID_H */
