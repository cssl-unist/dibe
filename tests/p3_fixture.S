/*
 * p3_fixture.S — synthetic fixture for DIBE predecessor redirection (P3).
 *
 * Hand-laid .text so that exactly ONE patch site `sa` is a DOMINANCE-BLOCKED S2
 * site whose obstruction `Y` has a single DIRECT, S0/S1-alignable, atomic, and
 * NON-instrumented rel32 predecessor `X`.  This is the layout P3 needs to fire;
 * it is rare in real -O2 binaries, whose obstructions are almost always
 * fall-through targets.
 *
 * THE KEY LAYOUT TRICK.  An upstream shift would otherwise pick the LATEST
 * in-chunk JMP-able boundary (offset <= 11) whose [cand, sa) interior is
 * branch-target-free, and absorb that — no P3 needed.  To force the dominance
 * block on EVERY candidate, the obstruction Y sits at chunk offset 12 (which is
 * itself NOT a JMP-able boundary: 12+5 > 16), ending exactly at sa (offset 14).
 * Then Y is inside (cand, sa) for *every* candidate boundary (all <= 11), so the
 * shift is dominance-blocked at all of them and P3 redirects Y's predecessor X.
 *
 * Chunk layout (16-byte aligned chunk_base; offsets shown):
 *   off 0  : nop                         ; cand: an upstream JMP-able boundary
 *   off 1  : jmp dead (rel32, 5B)        ; UNCOND break (dead-code filler)
 *   off 6  : add $7,  %eax  (3B)         ; dead-code filler (never run)
 *   off 9  : jmp p3_Y       (rel8, 2B->0x..)  ; UNCOND break right before Y so Y
 *                                        ;   has NO fall-through entry (off 9..10)
 *   off 11 : nop            (1B)         ; pad to put Y at offset 12
 *   off 12 : Y: add $1,%al  (2B)         ; <-- obstruction Y (branch target via X)
 *                                        ;     ends at offset 14 == sa
 *   off 14 : sa: add $200000,%eax (5B)   ; <-- the patch site; 5B JMP here
 *                                        ;     STRADDLES the 16-byte boundary->S2
 *   after  : ret
 *
 * Reachable control flow (what actually executes):
 *   p3_compute: eax=1000 ; jmp X
 *   X:          jmp Y                     ; rel32 JMP -> Y  (the edge P3 rewrites)
 *   Y:          add $1,%al                ; eax low byte += 1
 *   sa:         add $200000,%eax          ; eax += 200000
 *   after:      ret                       ; returns eax
 *
 * Correct result: eax = 1000 + 1 + 200000 = 201001.  The dead-code chunk top
 * (nop/jmp/add/jmp/nop) is NEVER executed; it exists only so the static
 * disassembly places Y as a branch target at offset 12, blocking the shift.
 * After P3, X's rel32 is repointed at sa's trampoline, which replays [Y, sa)
 * (the `add $1,%al`), runs sa's NOP instrumentation + sa (+200000), then $break
 * to `after`.  A wrong rel32 rewrite or [Y, sa) replay changes the value or
 * crashes.
 */

    .text
    .globl  p3_compute
    .type   p3_compute, @function
p3_compute:
    mov     $1000, %eax              # eax = 1000
    .byte   0xe9                     # JMP rel32 to X (force 5-byte form)
    .long   X - (. + 4)

    .balign 16
chunk_base:
    .globl  p3_cand
p3_cand:
cand:
    nop                              # off 0  (1B) — upstream JMP candidate
    .byte   0xe9                     # off 1  (5B) — JMP rel32 to `dead` (break)
    .long   dead - (. + 4)
filler6:
    add     $7, %eax                 # off 6  (3B) — dead-code filler
    nop                              # off 9  (1B) — pad
    jmp     dead                     # off 10 (2B) — UNCOND break ENDING at off 12,
                                     #               so Y (off 12) has NO
                                     #               fall-through entry.  Targets
                                     #               `dead` (NOT Y) so Y's ONLY
                                     #               predecessor is X (a rel32 JMP)
    .globl  p3_Y
p3_Y:
Y:
    add     $1, %al                  # off 12 (2B) — Y: target via X; ends at sa
    .globl  p3_sa
p3_sa:
sa:
    add     $200000, %eax            # off 14 (5B) — sa: straddles 16B -> S2
after:
    ret                              # returns eax

dead:
    mov     $0xBADBAD, %eax          # sentinel: only reached on a BROKEN replay
    ret

    .balign 16
    .globl  p3_X
p3_X:
X:
    .byte   0xe9                     # JMP rel32 to Y — the edge P3 rewrites
    .long   Y - (. + 4)

    .size   p3_compute, .-p3_compute
    .section .note.GNU-stack,"",@progbits
