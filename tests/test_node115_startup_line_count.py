"""Static evidence corruption controls; no captured execution or emulation."""
import importlib.util
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-node115-startup-line-count'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, PACKET / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


v = module('startup_count_verify', 'verify.py')
r = module('startup_count_relations', 'relations.py')


class StartupLineCountEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.spec = v.load(PACKET / 'spec.json')
        cls.secs = v.sections(cls.blob)

    def changed(self, address, replacement):
        sec, = [s for s in self.secs if s['type'] != 8 and s['address'] <= address
                and address + len(replacement) <= s['address'] + s['size']]
        offset = sec['offset'] + address - sec['address']
        mutated = bytearray(self.blob)
        mutated[offset:offset + len(replacement)] = replacement
        return mutated

    def test_authenticated_complete_snapshot(self):
        result = v.collect(self.blob)
        self.assertEqual(result, v.load(PACKET / 'records.json'))
        self.assertEqual(result['metrics'], {'newStaticFDEs': 14, 'newStaticBytes': 6958,
                         'reusedContextFDEs': 1, 'compiledCodeComparisons': 0, 'gateChanges': 0})
        self.assertFalse(result['capturedExecution'])
        self.assertFalse(result['emulation'])

    def test_wrong_identity_precedes_output(self):
        with tempfile.TemporaryDirectory() as folder:
            target, output = Path(folder) / 'wrong', Path(folder) / 'must-not-exist.json'
            target.write_bytes(b'wrong target; not executable')
            p = subprocess.run([sys.executable, '-B', str(PACKET / 'verify.py'),
                                '--target', str(target), '--output', str(output)],
                               capture_output=True, text=True, timeout=30)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('node115 identity mismatch', p.stderr)
            self.assertFalse(output.exists())

    def test_inner_instruction_obligations_without_digest_shortcut(self):
        for address, value, group in [(0x15011bd, b'\x71', 'decimal-sign-width-order'),
                                       (0x1501139, b'\x08', 'decimal-sign-width-order'),
                                       (0x1536827, b'\x01', 'command-construction'),
                                       (0x5c67124, b'\xfe', 'quote-flags'),
                                       (0x595bba6, b'\x00', 'caller-call-tag')]:
            with self.subTest(address=hex(address)):
                # Direct inner guard: whole-file and whole-body hashes are not called.
                with self.assertRaisesRegex(ValueError, 'semantic obligation: ' + group):
                    v.contract(self.changed(address, value), self.spec)

    def test_literal_and_unicode_corruption_without_digest_shortcut(self):
        for address, value, label in [(0x4659f2, b'x', 'wc'), (0x468cca, b'\t', 'join-space'),
                                       (0x479266 + 133, b'\0', 'whitespace-table'),
                                       (0x46ebe7 + 194, b'\0', 'utf8-width-table')]:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, 'literal/table: ' + label):
                    v.contract(self.changed(address, value), self.spec)

    def test_actual_separator_and_suffix_reference_corruptions(self):
        for site in [0x15b052f, 0x595b750]:
            instruction = next(row for rows in self.spec['obligations'].values()
                               for row in rows if row['va'] == hex(site))
            original = bytes.fromhex(instruction['raw'])
            altered = original[:-4] + struct.pack('<i', struct.unpack('<i', original[-4:])[0] + 1)
            # Remove that one exact-byte obligation to exercise displacement/data
            # derivation itself, not the outer digest or duplicate byte guard.
            spec = {**self.spec, 'obligations': {key:[x for x in rows if x['va'] != hex(site)]
                                               for key,rows in self.spec['obligations'].items()}}
            with self.subTest(site=hex(site)):
                with self.assertRaisesRegex(ValueError, 'data reference: ' + hex(site)):
                    v.contract(self.changed(site, altered), spec)

    def test_rela_target_corruption_without_digest_shortcut(self):
        rels = v.relocations(self.blob, self.secs)
        for slot in [0x64e0958, 0x64e0960, 0x64e0a60, 0x64dfca8]:
            row = rels[slot]
            mutated = bytearray(self.blob)
            struct.pack_into('<q', mutated, int(row['fileOffset'], 16) + 16,
                             int(row['addend'], 16) + 1)
            with self.subTest(slot=hex(slot)):
                with self.assertRaisesRegex(ValueError, 'relative binding: ' + hex(slot)):
                    v.contract(mutated, self.spec)

    def test_fde_range_and_duplicate_controls_without_digest_shortcut(self):
        scope = self.spec['scopes'][0]
        # This FDE is DWARF32, pcrel sdata4 start plus udata4 extent.
        mutated = self.changed(scope['fde']['fde'] + 12,
                               struct.pack('<I', int(scope['end'], 16) - int(scope['start'], 16) - 1))
        _, frames, _ = v.fde_extents(mutated)
        index = {}
        for f in frames:
            index.setdefault((f['start'], f['end']), []).append(f)
        with self.assertRaisesRegex(ValueError, 'complete FDE extent'):
            v.checked_frame(index, scope)
        key = int(scope['start'], 16), int(scope['end'], 16)
        with self.assertRaisesRegex(ValueError, 'multiplicity'):
            v.checked_frame({key: [scope['fde'], scope['fde']]}, scope)

    def test_native_export_gap_duplicate_truncation_and_byte_controls(self):
        scope = self.spec['scopes'][0]
        start, end = int(scope['start'], 16), int(scope['end'], 16)
        body = v.span(self.blob, self.secs, start, end-start)
        text = (PACKET / scope['export']).read_text()
        lines = text.splitlines(keepends=True)
        positions = [i for i, line in enumerate(lines) if re.match(r'^\s*[0-9a-f]+:\s+[0-9a-f]{2}\s', line)]
        mid = positions[10]
        altered = [lines[:mid] + lines[mid+1:], lines[:mid] + [lines[mid]] + lines[mid:],
                   lines[:positions[-1]], [line.replace('1500e50:\t55 ', '1500e50:\t54 ') for line in lines]]
        for n, rows in enumerate(altered):
            with self.subTest(control=n):
                with self.assertRaisesRegex(ValueError, 'disassembly|Disassembly'):
                    v.decode_export(''.join(rows), start, end, body)

    def test_native_fde_offset_length_and_cie_controls(self):
        frame = self.spec['scopes'][0]['fde']
        headers = (PACKET / 'fdes.readelf.txt').read_text()
        v.checked_native_frame(self.blob, self.secs, frame, headers)
        first = headers.splitlines()[0]
        for old, new in [('003a4010', '003a4011'), ('0000000000000050', '000000000000004f'),
                         ('0000d8e8', '0000d8e9'), ('cie=0039672c', 'cie=0039672d')]:
            with self.subTest(field=old):
                changed = headers.replace(first, first.replace(old, new), 1)
                with self.assertRaisesRegex(ValueError, 'native FDE offset/length/CIE'):
                    v.checked_native_frame(self.blob, self.secs, frame, changed)

    def test_lsda_protected_numeric_error_cleanup(self):
        body = v.load(PACKET / 'records.json')['bodies'][0]
        sites = body['lsda']['sites']
        self.assertIn({'start':'0x15011d7', 'end':'0x15011df', 'landing':'0x150126d', 'action':0}, sites)
        self.assertEqual(body['callsAndTailJumps'][-1]['target'], '0x63f0a50')
        self.assertEqual(v.contract(self.blob, self.spec)['unwind']['writer']['symbol'], '_Unwind_Resume')

    def test_manual_numeric_boundary_and_error_order_witnesses(self):
        cases = [(b'0', {'value':0}), (b'+00042', {'value':42}),
                 (b'18446744073709551615', {'value':(1<<64)-1}),
                 (b'18446744073709551616', {'numericError':2}),
                 (b'1844674407370955162x', {'numericError':1}),
                 (b'18446744073709551620', {'numericError':2}),
                 (b'18446744073709551616x', {'numericError':2}),
                 (b'00000000000000000000042', {'value':42}),
                 (b'+', {'numericError':1}), (b'-', {'numericError':1}),
                 (b'-0', {'numericError':1}), (b'0x10', {'numericError':1})]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(r.decimal(text), expected)

    def test_manual_status_utf8_and_first_token_witnesses(self):
        cases = [(1, b'12\xff', {'boundaryError':'command-status'}),
                 (0, b'12\xff', {'boundaryError':'utf8'}),
                 (0, b' \r\n', {'boundaryError':'no-token'}),
                 (0, b'  +0042 filename\n', {'value':42}),
                 (0, b'7 9999999999999999999999999\n', {'value':7}),
                 (0, b'7x 9\n', {'numericError':1}),
                 (0, b'7\0 file\n', {'numericError':1})]
        for status, text, expected in cases:
            with self.subTest(status=status, text=text):
                self.assertEqual(r.output_relation(status, text), expected)

    def test_exact_unicode_whitespace_and_python_counterexamples(self):
        for cp in r.WHITE:
            text = chr(cp).encode() + b'9' + chr(cp).encode() + b'ignored'
            self.assertEqual(r.output_relation(0, text), {'value':9})
        for cp in range(0x1c, 0x20):
            self.assertTrue(chr(cp).isspace())
            self.assertNotIn(cp, r.WHITE)
            self.assertEqual(r.output_relation(0, chr(cp).encode() + b'9'), {'numericError':1})

    def test_manual_quote_and_original_path_witnesses(self):
        cases = [(b'file', b'wc -l file'), (b'a b', b"wc -l 'a b'"),
                 (b' file ', b"wc -l ' file '"), (b'\t ', b'wc -l'),
                 (b'a$b', b"wc -l 'a$b'"), (b"a'b", b'wc -l "a\'b"'),
                 (b'^a', b"wc -l '^a'"), (b'a^b', b"wc -l a'^b'"),
                 (b'-x', b'wc -l -x')]
        for path, expected in cases:
            with self.subTest(path=path):
                self.assertEqual(r.command_relation(path), expected)
        self.assertEqual(r.quote(b''), b"''")  # collector filters empty views first
        with self.assertRaisesRegex(ValueError, 'NUL'):
            r.command_relation(b'a\0b')


if __name__ == '__main__':
    unittest.main()
