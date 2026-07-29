#!/usr/bin/env python3
"""
generate_patches_from_objdump.py

Usage:
  python3 generate_patches_from_objdump.py -i objdump.txt -o micro_patch.json [--pid 12345]

Description:
  Parse `objdump -d target_program` output (plain text) and collect lines whose
  instruction mnemonic starts with 'j' (jmp/je/jne/ja/.../jmpq). For each such
  instruction emit a patch entry:
    { "patch_address": "<hex-without-0x>", "target_length": <bytes>, "patch_bytes": ["0x90", "$instr", "$break"] }

Notes:
  - Adjust the mnemonic filter in is_jump_mnemonic() if you want to restrict to only unconditional jmp.
  - If you prefer only 'jmp' and 'jmpq', change the check accordingly.
"""

import re
import json
import random
import argparse

# regex to match typical objdump -d instruction lines:
# examples:
#   629e:   e9 12 34 56 00          jmp    62b0 <...>
# 000000000000629e <func+...>:
LINE_RE = re.compile(r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s+(\S+)(?:\s+(.*))?$')

def is_jump_mnemonic(mn):
    # Any mnemonic starting with 'j' is a jump (jmp, jmpq, je, jne, ja, jb, jg, jl, etc.)
    return mn.lower().startswith('j')

def is_heap_write(mnemonic, operands):
    """Detect instructions that may write to heap pointers (A2 site selection).

    All instructions that may write to heap pointers, excluding pure stack
    writes (%rsp-relative) and RIP-relative (global) writes.  %rbp-relative
    writes are INCLUDED (%rbp often accesses local vars that hold heap
    pointers).
    """
    mn = mnemonic.lower()
    if mn.startswith('mov') and operands:
        parts = operands.split(',')
        if len(parts) >= 2:
            dest = parts[-1].strip()
            if '(' in dest:
                # Exclude stack push (%rsp) and globals (%rip)
                if '%rsp' in dest or '%rip' in dest:
                    return False
                return True
        if '(' in operands and mn in ('movl', 'movq', 'movw', 'movb', 'movaps',
                                       'movups', 'movdqa', 'movdqu', 'movsd',
                                       'movss', 'movnti', 'movntdq', 'movntps'):
            mem_part = parts[-1].strip() if len(parts) >= 2 else operands
            if '%rsp' in mem_part or '%rip' in mem_part:
                return False
            return True
    if mn in ('stos', 'stosb', 'stosw', 'stosd', 'stosq'):
        return True
    return False

def parse_heap_writes(path):
    """A2 mode: emit a patch entry for each heap-write site (is_heap_write).

    Site shape is identical to parse_objdump()'s jump sites.  The dense
    instructions[] context is added separately in main().
    """
    patches = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue
            bytes_str = m.group(2).strip()
            byte_tokens = [b for b in bytes_str.split() if re.fullmatch(r'[0-9a-fA-F]{2}', b)]
            if not byte_tokens:
                continue
            if is_heap_write(m.group(3), m.group(4) or ""):
                addr_norm = m.group(1).lstrip('0').lower() or '0'
                patches.append({
                    "patch_address": addr_norm,
                    "target_length": len(byte_tokens),
                    "patch_bytes": ["0x90", "$instr", "$break"]
                })
    return patches

def parse_objdump(path):
    patches = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue
            addr = m.group(1)
            bytes_str = m.group(2).strip()
            mnemonic = m.group(3)
            byte_tokens = [b for b in bytes_str.split() if re.fullmatch(r'[0-9a-fA-F]{2}', b)]
            if not byte_tokens:
                continue
            if is_jump_mnemonic(mnemonic):
                # lower hex, no 0x prefix, no leading zeros
                addr_norm = addr.lstrip('0').lower() or '0'
                entry = {
                    "patch_address": addr_norm,
                    "target_length": len(byte_tokens),
                    "patch_bytes": ["0x90", "$instr", "$break"]
                }
                patches.append(entry)
    return patches

def parse_all_instructions(path):
    """Parse EVERY instruction line in the objdump output (not just jumps).

    Returns a list of {"address": "<hex-no-0x>", "length": N} dicts, one per
    decoded instruction, in objdump (ascending address) order.  This is the
    dense .text instruction stream e9patch needs so its pred()/succ() walk and
    the upstream-shift dominance/relocation analysis have real Instr objects to
    work with (the patch sites alone leave the instruction set sparse).

    NOTE: objdump's linear disassembly can mis-decode data-in-code; such ranges
    just become bogus Instr entries that the planner's clean/reloc gate refuses
    to shift across (it never *patches* a non-site instruction), so a bad decode
    can only LOSE a shift opportunity, never corrupt a site.
    """
    instrs = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue
            bytes_str = m.group(2).strip()
            byte_tokens = [b for b in bytes_str.split() if re.fullmatch(r'[0-9a-fA-F]{2}', b)]
            if not byte_tokens:
                continue
            addr_norm = m.group(1).lstrip('0').lower() or '0'
            instrs.append({
                "address": addr_norm,
                "length": len(byte_tokens),
            })
    return instrs

def parse_all_as_patches(path):
    """ALL mode: emit a patch entry for EVERY decoded instruction line.

    Same shape as parse_objdump() but with NO mnemonic filter — every decoded
    .text instruction becomes a trampoline site (trampoline [0x90,$instr,$break],
    i.e. [144,"$instr","$break"] after patch_to_req).  Short (<5B) instructions
    stress e9patch's tactics (B2/T1/T2/T3 punning/eviction) and some will fail;
    failures are reported rather than forced to succeed.
    """
    patches = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue
            bytes_str = m.group(2).strip()
            byte_tokens = [b for b in bytes_str.split() if re.fullmatch(r'[0-9a-fA-F]{2}', b)]
            if not byte_tokens:
                continue
            addr_norm = m.group(1).lstrip('0').lower() or '0'
            patches.append({
                "patch_address": addr_norm,
                "target_length": len(byte_tokens),
                "patch_bytes": ["0x90", "$instr", "$break"]
            })
    return patches

def main():
    ap = argparse.ArgumentParser(description="Generate patch list JSON from objdump -d text")
    ap.add_argument('-i', '--input', default='objdump.txt', help='objdump text file (objdump -d target > objdump.txt)')
    ap.add_argument('-o', '--output', default='micro_patch.json', help='output json file')
    ap.add_argument('--pid', type=int, default=12345, help='optional pid to include in output (default: 12345)')
    ap.add_argument('--count', type=int, default=0, help='subsample to N patches (0 = all, deterministic seed)')
    ap.add_argument('--all', action='store_true',
                    help='ALL mode: patch EVERY decoded instruction (not just jumps)')
    ap.add_argument('--a2', '--filter-writes', dest='a2', action='store_true',
                    help='A2 mode: patch heap-write sites (mov/stos to memory, '
                         'excluding %%rsp/%%rip) instead of jumps')
    args = ap.parse_args()

    if args.all and args.a2:
        ap.error('--all and --a2 are mutually exclusive')

    if args.all:
        patches = parse_all_as_patches(args.input)
    elif args.a2:
        patches = parse_heap_writes(args.input)
    else:
        patches = parse_objdump(args.input)
    total = len(patches)

    if args.count > 0 and args.count < total:
        random.seed(42)
        patches = random.sample(patches, args.count)

    # Dense .text instruction stream (every decoded instruction), so e9patch's
    # pred()/succ() walk and the upstream-shift analysis have real Instr objects.
    instructions = parse_all_instructions(args.input)

    out = {
        "patches": patches,
        "instructions": instructions,
        "pid": args.pid if args.pid is not None else None
    }
    with open(args.output, 'w', encoding='utf-8') as of:
        json.dump(out, of, indent=2)
    if args.count > 0:
        print(f"Wrote {len(patches)}/{total} patches "
              f"({len(instructions)} instructions) to {args.output}")
    else:
        print(f"Wrote {len(patches)} patches "
              f"({len(instructions)} instructions) to {args.output}")

if __name__ == '__main__':
    main()
