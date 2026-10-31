"""Target-derived kind5 cursor, endian, budget and real-byte corruption controls."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import kind5_reader as k  # noqa: E402


class WordCases(unittest.TestCase):
    def test_nonzero_endian_and_short_payload_cursor(self):
        result, state = k.word_model(k.READER, b'\xfb\x12\x34', 0)
        self.assertEqual(int.from_bytes(result[8:16], 'little'), 0x3412)
        swapped, _ = k.word_model(k.READER, b'\xfb\x12\x34', 255)
        self.assertEqual(int.from_bytes(swapped[8:16], 'little'), 0x1234)
        short, state = k.word_model(k.READER, b'\xfb\x12', 0)
        self.assertEqual(short[0], 0)
        self.assertEqual(int.from_bytes(short[8:16], 'little'), 1)
        self.assertEqual(int.from_bytes(state[:8], 'little'), k.BUFFER + 1)

    def test_wrapper_length_changes_invalid_tag_consumption(self):
        for length, consumed in [(8, 1), (9, 0)]:
            result, state = k.word_model(k.WRAPPER, b'\xfe' + bytes(length - 1), 255)
            self.assertEqual(result[:3], bytes([3, 5, 4]))
            self.assertEqual(int.from_bytes(state[16:24], 'little'), k.BUFFER + consumed)

    def test_limit_charge_order_and_overflow(self):
        result, state = k.word_model(k.WRAPPER, b'', 0, 1, 7, 0)
        self.assertEqual(result, bytes([2]) + bytes([0xa5] * 23))
        self.assertEqual(int.from_bytes(state[32:40], 'little'), 8)
        result, state = k.word_model(k.WRAPPER, b'', 0, 1, k.MASK, k.MASK - 7)
        self.assertEqual(result[0], 2)
        self.assertEqual(int.from_bytes(state[32:40], 'little'), k.MASK - 7)
        # Flag is exactly one; a different nonzero word bypasses this gate.
        result, _ = k.word_model(k.WRAPPER, b'\x07', 0, 2, 0, k.MASK)
        self.assertEqual(result[0], 18)

    def test_native_signed_immediate_display_is_exact(self):
        a = k.Instruction(0x1000, bytes.fromhex('4883f8f7'), 'cmp', (('reg', 'rax'), ('imm', -9)))
        b = k.Instruction(0x1000, a.raw, 'cmp', (('reg', 'rax'), ('imm', k.MASK - 8)))
        self.assertEqual(k.canonical(a), k.canonical(b))
        different = k.Instruction(a.pc, a.raw, 'cmp', (('reg', 'rax'), ('imm', -8)))
        self.assertNotEqual(k.canonical(a), k.canonical(different))


class NativeCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            k.native_tools()
        except (k.bv.EvidenceError, OSError) as exc:
            raise unittest.SkipTest(f'NOT a target comparison PASS: {exc}') from exc
        cls.data = k.bv.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != k.bv.SHA256:
            raise AssertionError('materialized authenticated node94 required')
        cls.sections = k.bv.sections(cls.data)

    def compare(self, data, identity=True):
        with tempfile.TemporaryDirectory(prefix='kind5-test-') as tmp:
            path = Path(tmp) / 'snapshot.elf'
            path.write_bytes(data)
            path.chmod(0o600)
            self.assertEqual(path.stat().st_mode & 0o111, 0)
            return k.collect(data, path, identity=identity)

    def test_full_dual_native_instruction_corpus(self):
        report, ledger, native = self.compare(self.data)
        self.assertEqual(report['fixture_count'], 28992)
        self.assertEqual(report['instruction_count'], 169)
        self.assertEqual(report['instruction_bytes'], 559)
        self.assertEqual(report['visited_instructions'], 169)
        self.assertEqual(report['covered_conditional_outcomes'], 30)
        self.assertEqual(report['missing_conditional_outcomes'], [])
        self.assertEqual(report['mismatches'], 0)
        self.assertTrue(report['authenticated_target'])
        self.assertEqual(len(report['reader_slot_callers']), 4)
        self.assertEqual(len(ledger.splitlines()), 28992)
        self.assertEqual(len(native), 2)

    def test_actual_byte_corruptions_below_identity(self):
        # Every control changes actual authenticated ELF bytes, then BOTH
        # native providers decode that same non-executable mutant. Identity
        # is bypassed only here: the semantic/model or relationship check,
        # rather than a whole-file hash, must reject the changed behavior.
        changes = [
            ('reader threshold', 0x466daf3, 'fb', 'fc'),
            ('reader tag cursor', 0x466dae0, '01', '02'),
            ('reader short width', 0x466db3a, '03', '02'),
            ('reader success tag', 0x466daff, '12', '13'),
            ('reader endian direction', 0x466db88, '44', '45'),
            ('reader expected type', 0x466dbe0, '05', '03'),
            ('error layout', 0x466dac9, '01', '02'),
            ('wrapper charge', 0x466be87, '08', '07'),
            ('wrapper overflow threshold', 0x466be7d, 'f7', 'f8'),
            ('wrapper slow gate', 0x466bea0, '08', '07'),
            ('wrapper endian override', 0x466bf18, '31d2', 'b201'),
        ]
        for name, va, before, after in changes:
            with self.subTest(name=name):
                offset = k.bv.va_to_off(self.sections, va)
                old, new = bytes.fromhex(before), bytes.fromhex(after)
                self.assertEqual(self.data[offset:offset + len(old)], old)
                mutant = bytearray(self.data)
                mutant[offset:offset + len(old)] = new
                with self.assertRaises(k.bv.EvidenceError):
                    self.compare(bytes(mutant), identity=False)

    def test_actual_jump_table_swap_below_identity(self):
        offset = k.bv.va_to_off(self.sections, 0x6f6ee8)
        mutant = bytearray(self.data)
        mutant[offset:offset + 4], mutant[offset + 8:offset + 12] = (
            self.data[offset + 8:offset + 12], self.data[offset:offset + 4])
        with self.assertRaises(k.bv.EvidenceError):
            self.compare(bytes(mutant), identity=False)

    def test_actual_rela_callee_change_below_identity(self):
        section = self.sections['.rela.dyn']
        import struct
        mutant = bytearray(self.data)
        found = 0
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            address, info, target = struct.unpack_from('<QQq', self.data, offset)
            if address == 0x57745e8 and info == 8:
                self.assertEqual(target, k.ERROR)
                struct.pack_into('<q', mutant, offset + 16, k.READER)
                found += 1
        self.assertEqual(found, 1)
        with self.assertRaisesRegex(k.bv.EvidenceError, 'RELATIVE binding'):
            self.compare(bytes(mutant), identity=False)

    def test_wrong_identity_never_admitted(self):
        with self.assertRaisesRegex(k.bv.EvidenceError, 'authenticated node94'):
            self.compare(self.data[:-1])


if __name__ == '__main__':
    unittest.main()
