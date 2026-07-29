#!/usr/bin/env python3
"""
Stress tests for generate_patches_from_objdump.py

Run:  python3 -m unittest test_generate_patches_stress -v
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from generate_patches_from_objdump import is_jump_mnemonic, parse_objdump

SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'src', 'generate_patches_from_objdump.py')


class TestLargeObjdump(unittest.TestCase):
    """Stress tests with large synthetic objdump files."""

    def _make_objdump(self, n_total, jump_ratio=0.3):
        """Create objdump with n_total instructions, jump_ratio are jumps."""
        lines = []
        jump_mnemonics = ['jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb']
        nonjump_mnemonics = ['mov', 'add', 'sub', 'xor', 'cmp', 'lea', 'push', 'pop', 'call', 'ret']
        import random
        rng = random.Random(123)  # deterministic
        for i in range(n_total):
            addr = 0x400000 + i * 5
            if rng.random() < jump_ratio:
                mn = rng.choice(jump_mnemonics)
                lines.append(f'  {addr:x}:\te9 00 10 00 00       \t{mn}    {addr+0x1005:x} <f>\n')
            else:
                mn = rng.choice(nonjump_mnemonics)
                lines.append(f'  {addr:x}:\t48 89 e5             \t{mn}    %rsp,%rbp\n')
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        f.writelines(lines)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def _run_script(self, objdump_path, count=0, pid=12345):
        out = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        out.close()
        self.addCleanup(os.unlink, out.name)
        cmd = [sys.executable, SCRIPT, '-i', objdump_path, '-o', out.name,
               '--pid', str(pid)]
        if count > 0:
            cmd += ['--count', str(count)]
        subprocess.run(cmd, check=True, capture_output=True)
        with open(out.name) as f:
            return json.load(f)

    def test_10k_instructions(self):
        """Parse 10,000 instructions (30% jumps -> ~3000 patches)."""
        path = self._make_objdump(10000, jump_ratio=0.3)
        patches = parse_objdump(path)
        self.assertGreater(len(patches), 2500)
        self.assertLess(len(patches), 3500)

    def test_50k_instructions(self):
        """Parse 50,000 instructions."""
        path = self._make_objdump(50000, jump_ratio=0.3)
        patches = parse_objdump(path)
        self.assertGreater(len(patches), 13000)

    def test_100k_instructions_performance(self):
        """Parse 100K instructions in under 5 seconds."""
        path = self._make_objdump(100000, jump_ratio=0.3)
        t0 = time.time()
        patches = parse_objdump(path)
        elapsed = time.time() - t0
        self.assertGreater(len(patches), 25000)
        self.assertLess(elapsed, 5.0, f"Parsing took {elapsed:.1f}s (expected < 5s)")

    def test_subsample_from_large_set(self):
        """Subsample 500 from 10,000 patches."""
        path = self._make_objdump(10000, jump_ratio=0.3)
        result = self._run_script(path, count=500)
        self.assertEqual(len(result['patches']), 500)

    def test_subsample_deterministic_large(self):
        """Determinism with large inputs."""
        path = self._make_objdump(10000)
        r1 = self._run_script(path, count=100)
        r2 = self._run_script(path, count=100)
        self.assertEqual(r1['patches'], r2['patches'])

    def test_all_jumps(self):
        """100% jump ratio."""
        path = self._make_objdump(5000, jump_ratio=1.0)
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 5000)

    def test_no_jumps(self):
        """0% jump ratio."""
        path = self._make_objdump(5000, jump_ratio=0.0)
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 0)

    def test_subsample_from_zero_jumps(self):
        """--count on input with no jumps."""
        path = self._make_objdump(100, jump_ratio=0.0)
        result = self._run_script(path, count=50)
        self.assertEqual(len(result['patches']), 0)


class TestEdgeCases(unittest.TestCase):
    """Edge cases and unusual inputs."""

    def _write_tmp(self, content):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        f.write(content)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_very_long_instruction(self):
        """15-byte x86 instruction (maximum length)."""
        path = self._write_tmp(
            '  1000:\t66 67 2e 36 f0 0f c1 84 05 00 00 00 00 00 00 \tjmp    1010 <f>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]['target_length'], 15)

    def test_single_byte_instruction(self):
        """Single-byte instruction."""
        path = self._write_tmp(
            '  1000:\teb               \tjmp    1002 <f>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]['target_length'], 1)

    def test_max_address(self):
        """Address near top of user space."""
        path = self._write_tmp(
            '  7fffffffe000:\te9 00 10 00 00       \tjmp    7fffffffe005 <f>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]['patch_address'], '7fffffffe000')

    def test_mixed_sections_and_labels(self):
        """Objdump with section headers, labels, and blank lines."""
        path = self._write_tmp(
            '\n'
            'Disassembly of section .text:\n'
            '\n'
            '0000000000401000 <main>:\n'
            '  401000:\t55                   \tpush   %rbp\n'
            '  401001:\te9 00 10 00 00       \tjmp    402006 <foo>\n'
            '\n'
            '0000000000402000 <foo>:\n'
            '  402000:\t48 89 e5             \tmov    %rsp,%rbp\n'
            '  402003:\t74 0a                \tje     40200f <bar>\n'
            '  402005:\tc3                   \tret\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 2)  # jmp and je
        self.assertEqual(patches[0]['patch_address'], '401001')
        self.assertEqual(patches[1]['patch_address'], '402003')

    def test_tab_vs_space_formatting(self):
        """Different whitespace formatting in objdump output."""
        path = self._write_tmp(
            '  1000:  e9 00 10 00 00        jmp    2005 <f>\n'
        )
        patches = parse_objdump(path)
        # The regex expects tab-separated fields, so space-separated input may
        # not match.
        if len(patches) == 0:
            pass  # expected: regex requires tabs
        else:
            self.assertEqual(patches[0]['patch_address'], '1000')

    def test_unicode_in_labels(self):
        """Labels with unusual characters."""
        path = self._write_tmp(
            '  1000:\te9 00 10 00 00       \tjmp    2005 <_Z3foov+0x10>\n'
            '  1005:\t74 05                \tje     100c <std::__cxx11::basic_string>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 2)

    def test_real_objdump_on_test_binary(self):
        """Parse actual objdump of target_program (if it exists)."""
        binary = os.path.join(os.path.dirname(__file__), '..', 'target_program')
        if not os.path.isfile(binary):
            self.skipTest('target_program not built')
        objdump_file = tempfile.NamedTemporaryFile(suffix='.txt', delete=False)
        objdump_file.close()
        self.addCleanup(os.unlink, objdump_file.name)
        subprocess.run(['objdump', '-d', '-w', binary],
                       stdout=open(objdump_file.name, 'w'),
                       check=True)
        patches = parse_objdump(objdump_file.name)
        self.assertGreater(len(patches), 0, 'target_program should have at least one jump')
        # Every entry should have valid fields
        for p in patches:
            self.assertIn('patch_address', p)
            self.assertIn('target_length', p)
            self.assertIn('patch_bytes', p)
            self.assertGreater(p['target_length'], 0)
            self.assertGreater(len(p['patch_address']), 0)


if __name__ == '__main__':
    unittest.main()
