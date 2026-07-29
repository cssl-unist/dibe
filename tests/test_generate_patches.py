#!/usr/bin/env python3
"""
Unit tests for generate_patches_from_objdump.py

Run:  python3 -m unittest test_generate_patches -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

# Add ../src to path so we can import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from generate_patches_from_objdump import is_jump_mnemonic, parse_objdump

SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'src', 'generate_patches_from_objdump.py')


class TestIsJumpMnemonic(unittest.TestCase):
    """Tests for the is_jump_mnemonic() function."""

    def test_unconditional_jumps(self):
        for mn in ('jmp', 'jmpq', 'jmpw'):
            self.assertTrue(is_jump_mnemonic(mn), f'{mn} should be a jump')

    def test_conditional_jumps(self):
        for mn in ('je', 'jne', 'ja', 'jae', 'jb', 'jbe', 'jg', 'jge',
                    'jl', 'jle', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
                    'jcxz', 'jecxz', 'jrcxz'):
            self.assertTrue(is_jump_mnemonic(mn), f'{mn} should be a jump')

    def test_case_insensitive(self):
        self.assertTrue(is_jump_mnemonic('JMP'))
        self.assertTrue(is_jump_mnemonic('Jne'))
        self.assertTrue(is_jump_mnemonic('JGE'))

    def test_non_jumps(self):
        for mn in ('mov', 'call', 'ret', 'nop', 'push', 'pop', 'add',
                    'sub', 'xor', 'lea', 'cmp', 'test', 'movq', 'callq'):
            self.assertFalse(is_jump_mnemonic(mn), f'{mn} should not be a jump')

    def test_empty_string(self):
        self.assertFalse(is_jump_mnemonic(''))


class TestParseObjdump(unittest.TestCase):
    """Tests for parse_objdump() with synthetic objdump output."""

    def _write_tmp(self, content):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        f.write(content)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_simple_jmp(self):
        path = self._write_tmp(
            '  629e:\te9 12 34 56 00       \tjmp    62b0 <foo>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]['patch_address'], '629e')
        self.assertEqual(patches[0]['target_length'], 5)
        self.assertEqual(patches[0]['patch_bytes'], ['0x90', '$instr', '$break'])

    def test_conditional_jump_je(self):
        """Conditional jump je is matched."""
        path = self._write_tmp(
            '  1000:\t74 0a                \tje     100c <bar>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]['patch_address'], '1000')
        self.assertEqual(patches[0]['target_length'], 2)

    def test_conditional_jump_jne(self):
        path = self._write_tmp(
            '  2000:\t75 fe                \tjne    2000 <loop>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 1)

    def test_non_jump_excluded(self):
        path = self._write_tmp(
            '  3000:\t48 89 e5             \tmov    %rsp,%rbp\n'
            '  3003:\te8 fc ff ff ff       \tcall   3004 <fn>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 0)

    def test_mixed_input(self):
        path = self._write_tmp(
            '  1000:\te9 00 10 00 00       \tjmp    2005 <foo>\n'
            '  1005:\t48 89 e5             \tmov    %rsp,%rbp\n'
            '  1008:\t74 0a                \tje     1014 <bar>\n'
            '  100a:\te8 fc ff ff ff       \tcall   100b <fn>\n'
            '  100f:\t0f 85 00 01 00 00    \tjne    1115 <baz>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 3)  # jmp, je, jne

    def test_address_normalization(self):
        """Leading zeros should be stripped, hex should be lowercase."""
        path = self._write_tmp(
            '  0000000000401000:\teb 0a                \tjmp    40100c <f>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]['patch_address'], '401000')

    def test_address_zero(self):
        path = self._write_tmp(
            '  0000:\teb 0a                \tjmp    000c <f>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(patches[0]['patch_address'], '0')

    def test_empty_file(self):
        path = self._write_tmp('')
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 0)

    def test_malformed_lines_skipped(self):
        path = self._write_tmp(
            'this is not objdump output\n'
            '\n'
            '0000000000401000 <main>:\n'
            '  401000:\teb 0a                \tjmp    40100c <f>\n'
        )
        patches = parse_objdump(path)
        self.assertEqual(len(patches), 1)


class TestSubsampling(unittest.TestCase):
    """Tests for the --count CLI flag (deterministic subsampling)."""

    def _make_objdump(self, n_jumps):
        """Create a tmpfile with n_jumps synthetic jump instructions."""
        lines = []
        for i in range(n_jumps):
            addr = 0x1000 + i * 5
            lines.append(f'  {addr:x}:\te9 00 10 00 00       \tjmp    {addr+0x1005:x} <f>\n')
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

    def test_count_zero_returns_all(self):
        path = self._make_objdump(20)
        result = self._run_script(path, count=0)
        self.assertEqual(len(result['patches']), 20)

    def test_count_less_than_total(self):
        path = self._make_objdump(50)
        result = self._run_script(path, count=10)
        self.assertEqual(len(result['patches']), 10)

    def test_count_equal_to_total(self):
        path = self._make_objdump(10)
        result = self._run_script(path, count=10)
        self.assertEqual(len(result['patches']), 10)

    def test_count_greater_than_total(self):
        path = self._make_objdump(5)
        result = self._run_script(path, count=100)
        self.assertEqual(len(result['patches']), 5)

    def test_count_one(self):
        path = self._make_objdump(20)
        result = self._run_script(path, count=1)
        self.assertEqual(len(result['patches']), 1)

    def test_deterministic(self):
        """Same --count on same input should produce identical output."""
        path = self._make_objdump(50)
        r1 = self._run_script(path, count=10)
        r2 = self._run_script(path, count=10)
        self.assertEqual(r1['patches'], r2['patches'])

    def test_pid_in_output(self):
        path = self._make_objdump(5)
        result = self._run_script(path, pid=999)
        self.assertEqual(result['pid'], 999)

    def test_default_pid(self):
        path = self._make_objdump(5)
        result = self._run_script(path)
        self.assertEqual(result['pid'], 12345)


if __name__ == '__main__':
    unittest.main()
