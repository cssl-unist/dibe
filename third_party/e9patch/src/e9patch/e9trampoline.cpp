/*
 * e9trampoline.cpp
 * Copyright (C) 2024 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
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
#include <cstring>
#include <ctime>

#include <map>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <cstdio>
#include <sys/socket.h>
#include <sys/un.h>

#include <sys/mman.h>

#include "e9alloc.h"
#include "e9optimize.h"
#include "e9patch.h"
#include "e9trampoline.h"
#include "e9x86_64.h"
#include "e9io_log.h"

#define MACRO_DEPTH_MAX             128
#define SOCK_PATH_FMT "/tmp/dibe.sock.%d"
static pid_t g_target_pid = -1;

/*
    For dynamic physical page grouping
*/

static int my_memfd_create(const char* name) {
#ifdef __NR_memfd_create
    return syscall(__NR_memfd_create, name, MFD_CLOEXEC);
#else
    return -1;
#endif
}

struct VA_PageInfo {
    uint64_t page_base;
    uint8_t  occ[4096];    // occupancy bitmap (1 = occupied)
    size_t lb = 4096, ub = 0;

    struct EntryData {
        size_t       offset; // offset within this VA page
        size_t       size;   // length within this VA page
        const uint8_t* src;  // pointer into original trampoline bytes (A->bytes + local_offset)
    };

    std::vector<EntryData> entries;
    bool finalized = false;
};

struct PhysicalPage {
    int fd;
    uint8_t occ[4096];
    size_t used_lb = 4096, used_ub = 0;

    PhysicalPage(): fd(-1) {
        memset(occ, 0, sizeof(occ));
    }
};

static std::map<uint64_t, VA_PageInfo> g_va_pages;
static std::vector<PhysicalPage> g_pages;
static std::map<uint64_t, size_t> g_va_to_phy;

static bool conflict(const uint8_t* a, const uint8_t* b) {
    for (size_t i = 0; i < 4096; i++) {
        if (a[i] & b[i]) return true;
    }
    return false;
}

/*
 * The general structure of a trampoline is as follows:
 *
 *      +--------------+--------------+--------------+
 *      |              |              |              |
 *      |   PROLOGUE   |  TRAMPOLINE  |   EPILOGUE   |
 *      |              |              |              |
 *      +--------------+--------------+--------------+
 *
 * Where:
 *      - PROLOGUE: are relocated instructions from *before* the patched
 *        instruction.  The prologue essentially serves as a "landing pad" for
 *        the -Opeephole optimization.
 *      - TRAMPOLINE: this is the original "user" trampoline.
 *      - EPILOGUE: are relocated instructions from *after* the patched
 *        instruction.  The epilogue attempts to avoid jumping back to the
 *        main program immediately, and instead waits for some other
 *        control-flow-transfer to do it for "free".  The epilogue is built as
 *        part of the builtin "$break" macro.
 *
 * Ultimately, the prologue/epilogue aim reduce the number of jumps the
 * patched binary uses, which can translate into a significant performance
 * gain.
 */

/*
 * Evictee trampoline template.
 */
const Trampoline *evicteeTrampoline = nullptr;

/*
 * Initialize the evictee trampoline.
 */
void __attribute__((__constructor__(8000))) evicteeTrampolineInit(void)
{
    size_t num_entries = 2;
    uint8_t *ptr =
        new uint8_t[sizeof(Trampoline) + num_entries * sizeof(Entry)];
    Trampoline *T          = (Trampoline *)ptr;
    T->prot                = PROT_READ | PROT_EXEC;
    T->num_entries         = num_entries;
    T->preload             = false;
    T->entries[0].kind     = ENTRY_INSTR;
    T->entries[0].length   = 0;
    T->entries[0].bytes    = nullptr;
    T->entries[1].kind     = ENTRY_BREAK;
    T->entries[1].optimize = true;
    T->entries[1].bytes    = nullptr;

    evicteeTrampoline = T;
}

/*
 * Label set.
 */
struct Label
{
    const intptr_t addr;
    const char * const name;

    Label(const Instr *I, const char *name): addr(I->addr), name(name)
    {
        ;
    }

    bool operator<(const Label &l) const
    {
        if (addr != l.addr)
            return (addr < l.addr);
        return (strcmp(name, l.name) < 0);
    }
};
typedef std::map<Label, intptr_t> LabelSet;

/*
 * Break location information.
 */
typedef std::map<intptr_t, intptr_t> BreakInfo;

/*
 * Lookup a macro value.
 */
static const Trampoline *expandMacro(const Binary *B,
    const Metadata *meta, const char *name)
{
    if (meta != nullptr)
    {
        ssize_t lo = 0, hi = (ssize_t)meta->num_entries-1;
        while (lo <= hi)
        {
            ssize_t mid = (lo + hi) / 2;
            int cmp = strcmp(name, meta->entries[mid].name);
            if (cmp == 0)
                return meta->entries[mid].T;
            else if (cmp < 0)
                hi = mid - 1;
            else
                lo = mid + 1;
        }
    }
    auto i = B->Ts.find(name);
    if (i != B->Ts.end())
        return i->second;
    return nullptr;
}

/*
 * Save a jump instruction for future optimization.
 */
static void saveJump(const Binary *B, intptr_t addr, uint8_t *bytes,
    size_t size)
{
    if (!option_Opeephole || bytes == nullptr || !isCFT(bytes, size, CFT_JMP))
        return;
    B->Js.push_back({addr, bytes, size});
}

/*
 * Relocate an instruction to the given address.
 */
static int relocateInstr(const Instr *I, intptr_t addr, Buffer *buf = nullptr)
{
    bool relax   = (addr == INTPTR_MIN);
    off_t offset = (relax? 0: addr - I->addr);
    return relocateInstr(I->addr, offset, I->ORIG, I->size, I->pic, buf,
        relax);
}

// Defined in e9x86_64.cpp.  When true, CALL relocation keeps the
// original static post-call target.  Set by buildBreak's optimization
// loop around each absorbed-instruction relocateInstr call; reset
// after.  See pushReturnAddress in e9x86_64.cpp.
extern bool g_emit_absorbed_call_target;

/*
 * Build mode for size-vs-bytes passes (used by buildBreak and the DIBE
 * absorbed-prefix replay below).
 */
enum BuildMode
{
    BUILD_SIZE,     // Build size and offsets (buf == nullptr)
    BUILD_BYTES,    // Build bytes (buf != nullptr)
};

/*
 * Upstream-shift: the absorbed-prefix replay.
 *
 * When the JMP origin of `I` was shifted upstream to `origin` (recorded in
 * B->shifts[I->addr]), the bytes in [origin, I) are physically jumped over at
 * .text (the 5-byte JMP now sits at `origin`).  The trampoline must therefore
 * execute those instructions itself, relocated, immediately BEFORE its existing
 * ENTRY_INSTR (which relocates `I`).  This mirrors buildBreak's absorbed-insn
 * loop: each J in [origin, I) is relocateInstr'd, with
 * g_emit_absorbed_call_target set so an absorbed CALL keeps its original static
 * return target.
 *
 * Returns the total relocated size (>=0), or -1 if any instruction in the range
 * cannot be relocated (caller must treat as a hard error: the planner already
 * vetted the range via absorbedRangeClean before recording the shift, so this
 * should not happen, but we fail loudly rather than miscompile).
 *
 * mode==BUILD_SIZE: buf==nullptr, returns worst-case (relax) size.
 * mode==BUILD_BYTES: buf!=nullptr, emits relocated bytes at `addr`.
 */
static const Instr *getShiftOrigin(const Binary *B, const Instr *I)
{
    if (B == nullptr || I == nullptr || B->shifts.empty())
        return nullptr;
    auto it = B->shifts.find(I->addr);
    return (it == B->shifts.end()? nullptr: it->second);
}

static int relocateAbsorbedPrefix(const Binary *B, const Instr *I,
    intptr_t addr, BuildMode mode = BUILD_SIZE, Buffer *buf = nullptr)
{
    const Instr *origin = getShiftOrigin(B, I);
    if (origin == nullptr)
        return 0;                       // not shifted -> nothing to replay

    intptr_t addr_0 = addr;
    for (const Instr *J = origin; J != nullptr && J != I; J = J->succ())
    {
        int len = 0;
        switch (mode)
        {
            case BUILD_SIZE:
                // Worst-case (relax) size when addr is unknown (INTPTR_MIN),
                // else the concrete size at `addr` (no buffer) so buildLabelSet
                // and buildBytes agree byte-for-byte on label positions.
                g_emit_absorbed_call_target = true;
                len = relocateInstr(J, addr, /*buf=*/nullptr);
                g_emit_absorbed_call_target = false;
                break;
            case BUILD_BYTES:
            {
                uint8_t *bytes = (buf != nullptr? buf->bytes(): nullptr);
                g_emit_absorbed_call_target = true;
                len = relocateInstr(J, addr, buf);
                g_emit_absorbed_call_target = false;
                if (len >= 0 && bytes != nullptr)
                    saveJump(B, addr, bytes, len);
                break;
            }
        }
        if (len < 0)
            return -1;                  // un-relocatable (should be pre-vetted)
        addr += (unsigned)len;
    }
    return (int)(addr - addr_0);
}

/*
 * Build a jump instruction that implements an unoptimized $break.
 */
static int buildBreak(const Binary *B, const Instr *I, intptr_t addr,
    BuildMode mode = BUILD_SIZE, const BreakInfo *breaks = nullptr,
    Buffer *buf = nullptr)
{
    if (mode == BUILD_SIZE)
        return /*sizeof(jmpq)=*/5;

    intptr_t target = I->addr + I->size;
    if (breaks != nullptr)
    {
        auto i = breaks->find(I->addr);
        if (i != breaks->end())
            target = i->second;
    }
    off_t rel = target - (addr + /*sizeof(jmpq)=*/5);
    assert(rel >= INT32_MIN && rel <= INT32_MAX);
    int32_t rel32 = (int32_t)rel;
    uint8_t *bytes = buf->bytes();
    buf->push(/*jmpq opcode=*/0xE9);
    buf->push((const uint8_t *)&rel32, sizeof(rel32));

    const Instr *J = I->succ();
    if (option_Opeephole && J != nullptr && buf->bytes() != nullptr)
        saveJump(B, addr, bytes, /*sizeof(jmpq)=*/5);
 
    return /*sizeof(jmpq)=*/5;
}

/*
 * Build a $break/$BREAK operation from a trampoline back to the main code.
 *
 * Note this is heavily optimized.  The Naive way would be to simply use a
 * single jmpq to the next instruction (as per the paper).  However, a far
 * better approach is to clone an "epilogue" containing the succeeding
 * instruction sequence up to and including the next control-flow-transfer
 * (CFT) instruction (including other jumps to unrelated trampolines).  This
 * saves a jump and a lot of overhead (since CPUs like locality).
 *
 * This function has two modes: building the size or building the bytes.
 * The first mode is for information gathering (e.g., determining the size of
 * the trampoline), while the latter actually builds the trampoline bytes.
 * The two modes use the same code to avoid a double maintenance problem.
 */
static int buildBreak(const Binary *B, const Instr *I, intptr_t addr,
    bool fallthrough, bool optimize, BuildMode mode = BUILD_SIZE,
    BreakInfo *breaks = nullptr, Buffer *buf = nullptr)
{
    intptr_t addr_0 = addr;
    if (fallthrough)
        return 0;       // Fallthrough
    if (!optimize || I->no_optimize)
        return buildBreak(B, I, addr, mode, breaks, buf);

    // Determine the epilogue by finding the next unconditional CFT.
    const Instr *J = I;
    unsigned i = 0;
    bool cft = false;
    unsigned size = 0;
    while (!cft && i < option_Oepilogue && size < option_Oepilogue_size)
    {
        const Instr *K = J->succ();
        if (K == nullptr)
            break;
        J = K;
        i++;
        cft = (J->is_patched && !J->is_evicted);
        cft = cft || isCFT(J->ORIG, J->size,
            (option_Ocall? 0x0: CFT_CALL) | CFT_RET | CFT_JMP);
        size += J->size;
    }

    if (!cft)
    {
        // Optimization cannot be applied --> jump to next instruction.
        return buildBreak(B, I, addr, mode, breaks, buf);
    }

    // Build the epilogue:
    J = I->next();
    unsigned start = (mode == BUILD_BYTES? buf->size(): 0);
    bool ok = true;
    for (unsigned j = 0; ok && j < i; j++, J = J->next())
    {
        if (J->is_patched && !J->is_evicted)
        {
            assert(j == i-1);
            addr += buildBreak(B, J->prev(), addr, mode, breaks, buf);
            break;
        }

        int len = 0;
        uint8_t *bytes;
        switch (mode)
        {
            case BUILD_SIZE:
                g_emit_absorbed_call_target = true;
                len = relocateInstr(J, INTPTR_MIN);
                g_emit_absorbed_call_target = false;
                break;
            case BUILD_BYTES:
                bytes = buf->bytes();
                g_emit_absorbed_call_target = true;
                len = relocateInstr(J, addr, buf);
                g_emit_absorbed_call_target = false;
                ok = (len >= 0);
                if (ok)
                    saveJump(B, addr, bytes, len);
                break;
        }
        addr += (unsigned)len;
    }

    if (!ok)
    {
        // Failed to apply optimization --> jump to next instruction.
        if (buf != nullptr)
            buf->reset(start);
        return buildBreak(B, I, addr_0, mode, breaks, buf);
    }

    return addr - addr_0;
}

/*
 * Build a trampoline prologue, which may include instructions before the
 * patched instruction.  The trampoline prologue allows other instructions
 * to jump to the trampoline "early", without having to go back to the main
 * program.  The code is similar to buildBreak().
 */
static int buildPrologue(const Binary *B, const Instr *I,
    intptr_t addr, BuildMode mode = BUILD_SIZE, Buffer *buf = nullptr)
{
    if (!option_Opeephole)
        return 0;
    const Instr *J = getTrampolinePrologueStart(B->Es, I);
    if (J == nullptr || J == I)
        return 0;

    int r = 0;
    unsigned start = (mode == BUILD_BYTES? buf->size(): 0);
    std::vector<std::pair<const Instr *, intptr_t>> entries;
    for (; J != I; J = J->next())
    {
        int len = 0;
        switch (mode)
        {
            case BUILD_SIZE:
                g_emit_absorbed_call_target = true;
                len = relocateInstr(J, INTPTR_MIN);
                g_emit_absorbed_call_target = false;
                break;
            case BUILD_BYTES:
            {
                uint8_t *bytes = buf->bytes();
                intptr_t entry = addr;
                g_emit_absorbed_call_target = true;
                len = relocateInstr(J, addr, buf);
                g_emit_absorbed_call_target = false;
                if (len < 0)
                {
                    buf->reset(start);
                    break;
                }
                saveJump(B, entry, bytes, len);
                entries.push_back({J, entry});
            }
        }
        if (len < 0)
            return 0;
        addr += len;
        r += len;
    }

    for (const auto &entry: entries)
        setTrampolineEntry(B->Es, entry.first, entry.second);

    return r;
}

/*
 * Calculate trampoline size.
 * Returns (-1) if the trampoline cannot be constructed.
 */
static int getTrampolineSize(const Binary *B, const Trampoline *T,
    const Instr *I, bool last, unsigned depth)
{
    if (depth > MACRO_DEPTH_MAX)
        error("failed to get trampoline size; maximum macro expansion depth "
            "(%u) exceeded", MACRO_DEPTH_MAX);
    unsigned size = 0;
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_DEBUG:
                size += (I != nullptr && I->debug? /*sizeof(int3)=*/1: 0);
                continue;
            case ENTRY_BYTES:
            case ENTRY_ZEROES:
                size += entry.length;
                continue;
            case ENTRY_INT8:
                size += sizeof(uint8_t);
                continue;
            case ENTRY_INT16:
                size += sizeof(uint16_t);
                continue;
            case ENTRY_INT32:
                size += sizeof(uint32_t);
                continue;
            case ENTRY_INT64:
                size += sizeof(uint64_t);
                continue;
            case ENTRY_LABEL:
                continue;
            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata,
                    entry.macro);
                if (U == nullptr)
                    error("failed to get trampoline size; metadata for macro "
                        "\"%s\" is missing", entry.macro);
                int r = getTrampolineSize(B, U, I, last, depth+1);
                if (size < 0)
                    return -1;
                size += r;
                continue;
            }
            case ENTRY_REL8:
                size += sizeof(int8_t);
                continue;
            case ENTRY_REL32:
                size += sizeof(int32_t);
                continue;
            case ENTRY_INSTR:
            {
                // Replay the absorbed prefix [origin, I) first.
                int rp = relocateAbsorbedPrefix(B, I, /*addr=*/INTPTR_MIN,
                    BUILD_SIZE);
                if (rp < 0)
                    return -1;
                size += rp;
                int r = relocateInstr(I, INTPTR_MIN);
                if (r < 0)
                    return -1;
                size += r;
                continue;
            }
            case ENTRY_INSTR_BYTES:
                size += I->size;
                continue;
            case ENTRY_BREAK:
            {
                bool fallthrough = !last && (i+1 >= T->num_entries);
                bool optimize    = last && entry.optimize;
                size += buildBreak(B, I, /*addr=*/0, fallthrough, optimize,
                    BUILD_SIZE);
                continue;
            }
            case ENTRY_TAKE:
                size += /*sizeof(jmpq)=*/5;
                continue;
            case ENTRY_BATCH:
            {
                const Instr *J = nullptr;
                while (I != nullptr && I->addr <= (intptr_t)entry.uint64)
                {
                    bool last = (I->addr == (intptr_t)entry.uint64);
                    int r = (I->T != nullptr?
                        getTrampolineSize(B, I->T, I, last, depth+1):
                        relocateInstr(I, INTPTR_MIN));
                    if (r < 0)
                        return -1;
                    size += r;
                    J = I;
                    I = I->next();
                }
                if (J->T == nullptr)
                    size += buildBreak(B, J, /*addr=*/0, false, true,
                        BUILD_SIZE);
                continue;
            }
        }
    }
    return size;
}

/*
 * Calculate trampoline size.
 */
int getTrampolineSize(const Binary *B, const Trampoline *T,
    const Instr *I)
{
    return getTrampolineSize(B, T, I, /*last=*/true, /*depth=*/0);
}

/*
 * Calculate trampoline prologue size.
 */
int getTrampolinePrologueSize(const Binary *B, const Instr *I)
{
    if (I == nullptr)
        return 0;
    return buildPrologue(B, I, /*addr=*/0, BUILD_SIZE);
}

/*
 * Get the address of a "builtin" label, or INTPTR_MIN.
 */
static intptr_t getBuiltinLabelAddress(const Binary *B, const Instr *I,
    const char *label)
{
    if (label[0] != '.' && label[1] != 'L')
        return INTPTR_MIN;

    // Check for "builtin" labels:
    switch (label[2])
    {
        case 'b':
            if (strcmp(label, ".Lbreak") == 0)
                return (intptr_t)I->addr + (intptr_t)I->size;
            break;
        case 'c':
            if (strcmp(label, ".Lconfig") == 0)
                return B->config;
            break;
        case 'i':
            if (strcmp(label, ".Linstr") == 0)
                return (intptr_t)I->addr;
            break;
        case 't':
            if (strcmp(label, ".Ltake") == 0)
            {
                intptr_t target = getCFTTarget(I->addr, I->ORIG, I->size,
                    CFT_JCC);
                if (target == INTPTR_MIN)
                    error("failed to build trampoline; instruction at address "
                        "0x%lx is not a conditional branch (as required by "
                        "\".Ltake\")", I->addr);
                return target;
            }
            break;
    }
    return INTPTR_MIN;
}

/*
 * Calculate trampoline bounds.
 */
static size_t getTrampolineBounds(const Binary *B, const Trampoline *T,
    const Instr *I, unsigned depth, size_t size, bool last, Bounds &b)
{
    if (depth > MACRO_DEPTH_MAX)
        error("failed to get trampoline bounds; maximum macro expansion "
            "depth (%u) exceeded", MACRO_DEPTH_MAX);
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_DEBUG:
                size += (I != nullptr && I->debug? /*sizeof(int3)=*/1: 0);
                continue;
            case ENTRY_BYTES:
            case ENTRY_ZEROES:
                size += entry.length;
                continue;
            case ENTRY_INT8:
                size += sizeof(uint8_t);
                continue;
            case ENTRY_INT16:
                size += sizeof(uint16_t);
                continue;
            case ENTRY_INT32:
                size += sizeof(uint32_t);
                continue;
            case ENTRY_INT64:
                size += sizeof(uint64_t);
                continue;
            case ENTRY_LABEL:
                continue;
            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata,
                    entry.macro);
                if (U == nullptr)
                    error("failed to get trampoline bounds; metadata for "
                        "macro \"%s\" is missing", entry.macro);
                size = getTrampolineBounds(B, U, I, depth+1, size, last, b);
                continue;
            }
            case ENTRY_REL8: case ENTRY_REL32:
            {
                size += (entry.kind == ENTRY_REL8?
                    sizeof(int8_t): sizeof(int32_t));
                intptr_t addr = INTPTR_MIN;
                if (entry.use)
                    addr = getBuiltinLabelAddress(B, I, entry.label);
                else
                    addr = (intptr_t)entry.uint64;
                if (addr != INTPTR_MIN)
                {
                    intptr_t lb = addr - size + 1 +
                        (entry.kind == ENTRY_REL8? INT8_MIN: INT32_MIN);
                    intptr_t ub = addr - size - 1 +
                        (entry.kind == ENTRY_REL8? INT8_MAX: INT32_MAX);
                    b.lb = std::max(b.lb, lb);
                    b.ub = std::min(b.ub, ub);
                }
                continue;
            }
            case ENTRY_INSTR:
            {
                // absorbed prefix contributes to the size used for
                // rel8/rel32 bounds below.
                int rp = relocateAbsorbedPrefix(B, I, /*addr=*/INTPTR_MIN,
                    BUILD_SIZE);
                size += (rp < 0? 0: rp);
                int r = relocateInstr(I, INTPTR_MIN);
                size += (r < 0? 0: r);
                continue;
            }
            case ENTRY_INSTR_BYTES:
                size += I->size;
                continue;
            case ENTRY_BREAK:
            {
                bool fallthrough = !last && (i+1 >= T->num_entries);
                bool optimize    = last && entry.optimize;
                size += buildBreak(B, I, /*addr=*/0, fallthrough, optimize,
                    BUILD_SIZE);
                continue;
            }
            case ENTRY_TAKE:
                size += /*sizeof(jmpq)=*/5;
                continue;
            case ENTRY_BATCH:
            {
                const Instr *J = nullptr;
                while (I != nullptr && I->addr <= (intptr_t)entry.uint64)
                {
                    bool last = (I->addr == (intptr_t)entry.uint64);
                    size += (I->T != nullptr?
                        getTrampolineBounds(B, I->T, I, depth+1, size, last, b):
                        (size_t)relocateInstr(I, INTPTR_MIN));
                    J = I;
                    I = I->next();
                }
                if (J->T == nullptr)
                    size += buildBreak(B, J, /*addr=*/0, false, true,
                        BUILD_SIZE);
                continue;
            }
        }
    }
    return size;
}

/*
 * Calculate trampoline bounds.
 */
Bounds getTrampolineBounds(const Binary *B, const Trampoline *T,
    const Instr *I)
{
    Bounds b = {INTPTR_MIN, INTPTR_MAX};
    if (T == evicteeTrampoline)
        return b;
    getTrampolineBounds(B, T, I, /*depth=*/0, /*size=*/0, /*last=*/true, b);
    return b;
}

/*
 * Build the set of labels.
 */
static intptr_t buildLabelSet(const Binary *B, const Trampoline *T,
    const Instr *I, intptr_t addr, bool last, BreakInfo &breaks,
    LabelSet &labels)
{
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_DEBUG:
                addr += (I != nullptr && I->debug? /*sizeof(int3)=*/1: 0);
            case ENTRY_BYTES:
            case ENTRY_ZEROES:
                addr += entry.length;
                continue;
            case ENTRY_INT8:
                addr += sizeof(uint8_t);
                continue;
            case ENTRY_INT16:
                addr += sizeof(uint16_t);
                continue;
            case ENTRY_INT32:
                addr += sizeof(uint32_t);
                continue;
            case ENTRY_INT64:
                addr += sizeof(uint64_t);
                continue;
            case ENTRY_LABEL:
            {
                Label L(I, entry.label);
                auto i = labels.insert(std::make_pair(L, addr));
                if (!i.second)
                    error("failed to build trampoline; duplicate label "
                        "\"%s\"", entry.label);
                continue;
            }
            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata, entry.macro);
                if (U == nullptr)
                    error("failed to build trampoline; metadata for macro "
                        "\"%s\" is missing", entry.macro);
                addr = buildLabelSet(B, U, I, addr, last, breaks, labels);
                continue;
            }
            case ENTRY_REL8:
                addr += sizeof(int8_t);
                continue;
            case ENTRY_REL32:
                addr += sizeof(int32_t);
                continue;
            case ENTRY_INSTR:
            {
                // absorbed prefix is emitted before I; advance addr
                // so the ENTRY_INSTR (and later labels) land correctly.  Size
                // mode here (no buf) -> worst-case length, matching getTramp*.
                int rp = relocateAbsorbedPrefix(B, I, addr, BUILD_SIZE);
                if (rp > 0)
                    addr += rp;
                addr += relocateInstr(I, addr);
                continue;
            }
            case ENTRY_INSTR_BYTES:
                addr += I->size;
                continue;
            case ENTRY_BREAK:
            {
                bool fallthrough = !last && (i+1 >= T->num_entries);
                bool optimize    = last && entry.optimize;
                addr += buildBreak(B, I, addr, fallthrough, optimize,
                    BUILD_SIZE, &breaks, nullptr);
                continue;
            }
            case ENTRY_TAKE:
                addr += /*sizeof(jmpq)=*/5;
                continue;
            case ENTRY_BATCH:
            {
                const Instr *J = nullptr;
                while (I != nullptr && I->addr <= (intptr_t)entry.uint64)
                {
                    bool last = (I->addr == (intptr_t)entry.uint64);
                    if (I->T != nullptr)
                        addr = buildLabelSet(B, I->T, I, addr, last, breaks,
                            labels);
                    else
                        addr += relocateInstr(I, addr);
                    if (!last)
                        breaks.insert({I->addr, addr});
                    J = I;
                    I = I->next();
                }
                if (J->T == nullptr)
                    addr += buildBreak(B, J, /*addr=*/0, false, true,
                        BUILD_SIZE, &breaks, nullptr);
                continue;
            }
        }
    }
    return addr;
}

/*
 * Lookup a label value.
 */
static off_t lookupLabel(const Binary *B, const char *label,
    const Instr *I, intptr_t addr, const LabelSet &labels)
{
    if (label[0] != '.' && label[1] != 'L')
        error("failed to build trampoline at address 0x%lx; "
            "unknown prefix for \"%s\" label", I->addr, label);

    intptr_t target = getBuiltinLabelAddress(B, I, label);
    if (target != INTPTR_MIN)
        return target - addr;

    // Check for user labels:
    Label L(I, label);
    auto i = labels.find(L);
    if (i == labels.end())
        error("failed to build trampoline at address 0x%lx; "
            "unknown label \"%s\"", I->addr, label); 
    return i->second - addr;
}

/*
 * Build the trampoline bytes.
 */
static void buildBytes(const Binary *B, const Trampoline *T, const Instr *I,
    intptr_t addr, bool last, const BreakInfo &breaks, const LabelSet &labels,
    Buffer &buf)
{
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_DEBUG:
                if (I != nullptr && I->debug)
                    buf.push(/*int3=*/0xcc);
                continue;
            case ENTRY_BYTES:
                buf.push(entry.bytes, entry.length);
                continue;
            case ENTRY_ZEROES:
                for (unsigned i = 0; i < entry.length; i++)
                    buf.push(0x0);
                continue;  
            case ENTRY_INT8: case ENTRY_INT16: case ENTRY_INT32:
            case ENTRY_INT64:
            {
                int64_t val = 0;
                if (entry.use)
                {
                    val = lookupLabel(B, entry.label, I, addr + buf.size(),
                        labels);
                    val += (addr + buf.size());
                }
                else
                    val = (int64_t)entry.uint64;
                switch (entry.kind)
                {
                    case ENTRY_INT8:
                        buf.push((uint8_t)val);
                        break;
                    case ENTRY_INT16:
                        buf.push((uint8_t *)&val, sizeof(uint16_t));
                        break;
                    case ENTRY_INT32:
                        buf.push((uint8_t *)&val, sizeof(uint32_t));
                        break;
                    case ENTRY_INT64:
                        buf.push((uint8_t *)&val, sizeof(uint64_t));
                        break;
                    default:
                        break;
                }
                continue;
            }
 
            case ENTRY_LABEL:
                continue;

            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata,
                    entry.macro);
                assert(U != nullptr);
                buildBytes(B, U, I, addr, last, breaks, labels, buf);
                continue;
            }

            case ENTRY_REL8:
            case ENTRY_REL32:
            {
                off_t rel = 0;
                if (entry.use)
                    rel = lookupLabel(B, entry.label, I, addr + buf.size(),
                        labels);
                else
                    rel = (intptr_t)entry.uint64 - (addr + buf.size());
                rel -= (entry.kind == ENTRY_REL8? sizeof(int8_t):
                                                  sizeof(int32_t));
                if (entry.kind == ENTRY_REL8)
                {
                    if (rel < INT8_MIN || rel > INT8_MAX)
                        error("failed to build trampoline; rel8 value (%zd) "
                            "is out-of-range (%d..%d)", rel, (int)INT8_MIN,
                            INT8_MAX);
                    int8_t rel8 = (int8_t)rel;
                    buf.push((uint8_t)rel8);
                }
                else
                {
                    if (rel < INT32_MIN || rel > INT32_MAX)
                        error("failed to build trampoline; rel32 value (%zd) "
                            "is out-of-range (%zd..%zd)", rel,
                            (ssize_t)INT32_MIN, INT32_MAX);
                    int32_t rel32 = (int32_t)rel;
                    buf.push((const uint8_t *)&rel32, sizeof(rel32));
                    break;
                }
                continue;
            }

            case ENTRY_INSTR:
            {
                // Emit the absorbed prefix [origin, I) before I.
                int rp = relocateAbsorbedPrefix(B, I, addr + buf.size(),
                    BUILD_BYTES, &buf);
                if (rp < 0)
                    error("failed to build trampoline; absorbed prefix for "
                        "instruction at address 0x%lx could not be relocated",
                        I->addr);
                relocateInstr(I, addr + buf.size(), &buf);
                continue;
            }

            case ENTRY_INSTR_BYTES:
                buf.push(I->ORIG, I->size);
                break;
        
            case ENTRY_BREAK:
            {
                bool fallthrough = !last && (i+1 >= T->num_entries);
                bool optimize    = last && entry.optimize;
                (void)buildBreak(B, I, addr + buf.size(), fallthrough,
                    optimize, BUILD_BYTES, (BreakInfo *)&breaks, &buf);
                break;
            }

            case ENTRY_TAKE:
            {
                intptr_t target = getCFTTarget(I->addr, I->ORIG, I->size,
                    CFT_JCC);
                if (target == INTPTR_MIN)
                    error("failed to build trampoline; instruction at address "
                        "0x%lx is not a conditional branch (as required by "
                        "\"$taken\")", I->addr);
                off_t rel = target - (addr + buf.size() + /*sizeof(jmpq)=*/5);

                buf.push(/*jmpq opcode=*/0xE9);
                assert(rel >= INT32_MIN);
                assert(rel <= INT32_MAX);
                int32_t rel32 = (int32_t)rel;
                buf.push((const uint8_t *)&rel32, sizeof(rel32));
                break;
            }

            case ENTRY_BATCH:
            {
                const Instr *J = nullptr;
                while (I != nullptr && I->addr <= (intptr_t)entry.uint64)
                {
                    bool last = (I->addr == (intptr_t)entry.uint64);
                    if (I->T != nullptr)
                        buildBytes(B, I->T, I, addr, last, breaks, labels,
                            buf);
                    else
                    {
                        int r = relocateInstr(I, addr + buf.size(), &buf);
                        if (r < 0)
                            error("failed to relocate instruction at "
                                "address 0x%lx", I->addr);
                    }
                    J = I;
                    I = I->next();
                }
                if (J->T == nullptr)
                {
                    (void)buildBreak(B, J, addr + buf.size(), false, true,
                        BUILD_BYTES, (BreakInfo *)&breaks, &buf);
                }
                I = nullptr;
                continue;
            }
        }
    }
}

/*
 * Flatten a trampoline into a memory buffer.
 */
static void flattenTrampoline(const Binary *B, uint8_t *bytes, size_t size,
    uint8_t fill, intptr_t addr, int32_t offset32, int32_t entry32,
    const Trampoline *T, const Instr *I)
{
    // Note: it is possible for actual size to be smaller than the `size'.
    LabelSet labels;
    BreakInfo breaks;
    intptr_t end = buildLabelSet(B, T, I, addr, true, breaks, labels);
    size_t offset = (size_t)(end - addr);
    
    if (offset > size)
        error("failed to flatten trampoline for instruction at address 0x%lx; "
            "buffer size (%zu) exceeds the trampoline size (%zu)",
            I->addr, offset, size);

    int presize = entry32 - offset32;
    if (presize > 0)
    {
        Buffer buf(bytes, presize);
        (void)buildPrologue(B, I, addr - presize, BUILD_BYTES, &buf);
        assert(buf.size() == (size_t)presize || buf.size() == 0);
        if (buf.size() == 0)
            buf.push(fill, presize);
    }

    bytes += presize;
    size  -= presize;
    {
        Buffer buf(bytes, size);
        buildBytes(B, T, I, addr, true, breaks, labels, buf);
        assert(buf.i <= size);
        buf.push(fill, size - buf.i);
    }
}

/*
 * Save trampoline contents to patches.jsonl
 */
static void dump_trampoline_jsonl(const Alloc *A, const uint8_t *bytes, size_t size, unsigned long base = 0) {
    if (!A) return;
    if (A->I ? (unsigned long)A->I->addr : 0ul) {
        const uint64_t patch_addr = (uint64_t)((intptr_t)A->lb + (intptr_t)base + A->entry);
        e9io::append_patch(patch_addr, bytes, size);
    }
}

static bool send_map_request(uint64_t page_base, int fd) {

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[e9patch] socket");
        return false;
    }

    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), SOCK_PATH_FMT, g_target_pid);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path)-1);

    // Retry connection — the mapping server may not be ready yet.
    // Abort on failure: silent return would leave pages unmapped,
    // causing the target to segfault on patched trampolines.
    static constexpr int MAX_RETRIES = 30;
    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0)
            goto connected;
        struct timespec ts = {0, 100 * 1000 * 1000}; // 100ms
        nanosleep(&ts, NULL);
        // Need a fresh socket after failed connect
        close(sock);
        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("[e9patch] socket");
            abort();
        }
    }
    fprintf(stderr, "[e9patch] FATAL: connect to %s failed after %d retries (3s)\n",
            sock_path, MAX_RETRIES);
    abort();
connected:

    // JSON message
    char json[128];
    snprintf(json, sizeof(json),
             "{\"page_base\":%lu}", page_base);

    // Control message (FD request)
    struct msghdr msg;
    struct iovec iov;
    char cmsgbuf[CMSG_SPACE(sizeof(int))];

    memset(&msg, 0, sizeof(msg));
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    iov.iov_base = json;
    iov.iov_len  = strlen(json);
    msg.msg_iov  = &iov;
    msg.msg_iovlen = 1;

    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));

    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    if (sendmsg(sock, &msg, 0) < 0) {
        perror("[e9patch] sendmsg");
        close(sock);
        return false;
    }

    char ack = 0;
    ssize_t r = recv(sock, &ack, 1, 0);
    close(sock);
    return (r == 1 && ack == 'K');
}

static std::vector<std::pair<uint64_t,int>> g_map_requests_sent;

static void send_map_request_tracked(uint64_t page_base, int fd) {
    if (g_target_pid <= 0)
        return;

    g_map_requests_sent.emplace_back(page_base, fd);
    if (send_map_request(page_base, fd))
        return;

    static constexpr int MAX_ROUNDS = 20;
    for (int round = 1; round <= MAX_ROUNDS; round++) {
        fprintf(stderr, "[e9patch] mapping round rolled back — resending all "
                "%zu pages (round %d/%d)\n",
                g_map_requests_sent.size(), round, MAX_ROUNDS);
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, NULL);
        bool all_ok = true;
        for (const auto &pr : g_map_requests_sent) {
            if (!send_map_request(pr.first, pr.second)) {
                all_ok = false;
                break;
            }
        }
        if (all_ok)
            return;
    }
    fprintf(stderr, "[e9patch] FATAL: trampoline mapping keeps colliding after "
            "%d rounds — aborting so the patch attempt fails cleanly\n",
            MAX_ROUNDS);
    exit(1);
}

static void finalize_va_page(uint64_t page_base) {

    auto &vp = g_va_pages[page_base];
    if (vp.finalized) return;

    // 1. Find physical page
    size_t phy_id = SIZE_MAX;
    for (size_t i = 0; i < g_pages.size(); i++) {
        if (!conflict(g_pages[i].occ, vp.occ)) {
            phy_id = i;
            break;
        }
    }

    // 2. If none found, create new memfd page
    if (phy_id == SIZE_MAX) {
        PhysicalPage newp;
        newp.fd = my_memfd_create("dibe_page");
        if (newp.fd < 0) perror("memfd_create");

        g_pages.push_back(newp);
        phy_id = g_pages.size() - 1;
    }

    PhysicalPage &pg = g_pages[phy_id];

    // 3. Write trampoline chunks into memfd
    for (auto &e : vp.entries) {
        ssize_t w = pwrite(pg.fd, e.src, e.size, e.offset);
        if (w < 0) perror("pwrite");

        memset(pg.occ + e.offset, 1, e.size);

        pg.used_lb = std::min(pg.used_lb, e.offset);
        pg.used_ub = std::max(pg.used_ub, e.offset + e.size);
    }

    // 4. Send map request (VA → FD)
    send_map_request_tracked(page_base, pg.fd);

    g_va_to_phy[page_base] = phy_id;
    vp.finalized = true;
}

/*
 * Flatten all trampolines.
 *
 * - Trampoline bytes are stored only in A->bytes
 * - Split into VA page units and record only metadata in g_va_pages
 * - Safely handle trampolines that cross page boundaries
 * - At the end, log VA page count / physical block count + clean up metadata
 */
void flattenAllTrampolines(Binary *B, unsigned long base) {

    g_target_pid = B->target_pid;
    uint64_t prev_page = UINT64_MAX;

    // Accumulate pages here whenever a page boundary is detected;
    // finalize is performed in the outer loop
    std::vector<uint64_t> pending_finalize_pages;

    for (auto *A : B->allocator) {

        if (!A->T) {
            A->bytes = nullptr;
            continue;
        }

        size_t size = A->ub - A->lb;
        uint8_t *bytes = new uint8_t[size];

        const Instr *I       = A->I;
        int32_t offset32     = (I ? (int32_t)(A->lb - I->addr) : 0);
        int32_t entry32      = offset32 + A->entry;
        intptr_t patch_addr0 = (I ? (intptr_t)I->addr + entry32 : A->lb);

        flattenTrampoline(
            B, bytes, size,
            /*fill=int3=*/0xcc,
            patch_addr0, offset32, entry32,
            A->T, I
        );
        A->bytes = bytes;

        dump_trampoline_jsonl(A, bytes, size, base);

        uint64_t patch_addr = (uint64_t)((intptr_t)A->lb + (intptr_t)base + A->entry);
        if (patch_addr >= 0x800000000000ULL) {
            fprintf(stderr, "[e9patch] FATAL: bogus patch_addr=0x%lx "
                    "(A->lb=0x%lx base=0x%lx entry=0x%x)\n",
                    (unsigned long)patch_addr,
                    (unsigned long)A->lb, (unsigned long)base, A->entry);
            abort();
        }
        const uint8_t *src_ptr = bytes;
        size_t remaining = size;

        while (remaining > 0) {
            uint64_t page_base = patch_addr & ~0xFFFULL;
            size_t   offset    = patch_addr & 0xFFFULL;
            size_t   chunk     = 4096 - offset;
            if (chunk > remaining) chunk = remaining;

            // Page change detected: finalize in the outer loop
            if (prev_page != UINT64_MAX && prev_page != page_base) {
                pending_finalize_pages.push_back(prev_page);
            }
            prev_page = page_base;

            auto &vp = g_va_pages[page_base];
            vp.page_base = page_base;

            memset(vp.occ + offset, 1, chunk);
            vp.lb = std::min(vp.lb, offset);
            vp.ub = std::max(vp.ub, offset + chunk);

            // Save chunk position from the original trampoline
            VA_PageInfo::EntryData ed;
            ed.offset = offset;
            ed.size   = chunk;
            ed.src    = src_ptr;

            vp.entries.push_back(ed);

            patch_addr += chunk;
            src_ptr    += chunk;
            remaining  -= chunk;
        }

        if (!pending_finalize_pages.empty()) {
            for (uint64_t p : pending_finalize_pages)
                finalize_va_page(p);

            pending_finalize_pages.clear();
        }
    }

    if (prev_page != UINT64_MAX)
        finalize_va_page(prev_page);

    fprintf(stderr,
            "[dynpage] VA pages: %zu, physical pages: %zu\n",
            g_va_pages.size(), g_pages.size());
}

/*
 * Trampoline comparison.
 */
bool TrampolineCmp::operator()(const Trampoline *a, const Trampoline *b) const
{
    if (a->num_entries != b->num_entries)
        return (a->num_entries < b->num_entries);
    for (unsigned i = 0; i < a->num_entries; i++)
    {
        const Entry *entry_a = a->entries + i;
        const Entry *entry_b = b->entries + i;
        if (entry_a->kind != entry_b->kind)
            return (entry_a->kind < entry_b->kind);
        int cmp = 0;
        switch (entry_a->kind)
        {
            case ENTRY_BYTES:
                if (entry_a->length != entry_b->length)
                    return (entry_a->length < entry_b->length);
                cmp = memcmp(entry_a->bytes, entry_b->bytes, entry_a->length);
                if (cmp != 0)
                    return (cmp < 0);
                break;
            case ENTRY_ZEROES:
                if (entry_a->length != entry_b->length)
                    return (entry_a->length < entry_b->length);
                break;
            case ENTRY_LABEL:
                cmp = strcmp(entry_a->label, entry_b->label);
                if (cmp != 0)
                    return (cmp < 0);
                break;
            case ENTRY_MACRO:
                cmp = strcmp(entry_a->macro, entry_b->macro);
                if (cmp != 0)
                    return (cmp < 0);
                break;
            case ENTRY_REL8: case ENTRY_REL32:
            case ENTRY_INT8: case ENTRY_INT16: case ENTRY_INT32:
            case ENTRY_INT64:
                if (entry_a->use != entry_b->use)
                    return (entry_a->use < entry_b->use);
                if (entry_a->use)
                {
                    cmp = strcmp(entry_a->label, entry_b->label);
                    if (cmp != 0)
                        return (cmp < 0);
                }
                else
                {
                    if (entry_a->uint64 != entry_b->uint64)
                        return (entry_a->uint64 < entry_b->uint64);
                }
                break;
            case ENTRY_DEBUG: case ENTRY_INSTR:
            case ENTRY_INSTR_BYTES: case ENTRY_BREAK:
            case ENTRY_TAKE:
                break;
            case ENTRY_BATCH:
                if (entry_a->uint64 != entry_b->uint64)
                    return (entry_a->uint64 < entry_b->uint64);
                break;
        }
    }
    return false;
}
