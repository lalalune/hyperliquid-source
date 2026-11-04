"""Static byte controls and independent search oracles; no captured execution."""
import hashlib
import itertools
import json
import mmap
from pathlib import Path
import re
import runpy
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import node115_wrapped_key56_search as n


class WrappedKey56Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = n.TARGET.open('rb')
        cls.image = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        if len(cls.image) != n.SIZE or hashlib.sha256(cls.image).hexdigest() != n.SHA:
            raise ValueError('materialized pinned node #115 required')
        cls.record = n.extract(cls.image)
        _, offset, read = n.reader(cls.image)
        cls.offset, cls.read = staticmethod(offset), staticmethod(read)
        cls.verifier = runpy.run_path(str(n.PACKET / 'verify.py'))

    @classmethod
    def tearDownClass(cls):
        cls.image.close()
        cls.handle.close()

    def assert_internal_rejects(self, va, raw, message):
        # A private COW mapping dirties only the changed pages, not another image.
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            off = self.offset(va, len(raw))
            changed[off:off+len(raw)] = raw
            with self.assertRaisesRegex(ValueError, message):
                n.extract(changed)

    def test_01_pinned_body_fde_and_complete_instruction_coverage(self):
        w = self.record['window']
        self.assertEqual(w['fde'], n.FDE)
        self.assertEqual(w['size'], n.END-n.START)
        self.assertEqual(w['body_sha256'], n.BODY_SHA)
        rows = w['instructions']
        self.assertEqual(''.join(i['bytes'] for i in rows), w['bytes'])
        self.assertEqual(rows[0]['va'], n.START)
        self.assertEqual(rows[-1]['va']+rows[-1]['size'], n.END)
        for left, right in zip(rows, rows[1:]):
            self.assertEqual(left['va']+left['size'], right['va'])
        starts = {i['va'] for i in rows}
        self.assertTrue(all(i.get('target', n.START) in starts for i in rows))
        self.assertFalse(any(i['op'] == 'call' for i in rows))
        self.assertEqual(w['callees'], [])
        # No supported instruction writes a memory operand in this body.
        for i in rows:
            if i['op'] in ('mov', 'xor', 'add', 'sub', 'adc', 'sbb', 'imul', 'shr', 'movzx') or i['op'].startswith(('cmov', 'set')):
                self.assertEqual(i['operands'][0]['kind'], 'reg')

    def test_02_regeneration_is_byte_identical_without_native_tools(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch('subprocess.run', side_effect=AssertionError('native tool forbidden')), mock.patch('subprocess.check_output', side_effect=AssertionError('native tool forbidden')):
            out = Path(tmp) / 'out'
            n.generate(n.TARGET, out)
            for name in ('records.json', 'README.md', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((out/name).read_bytes(), (n.PACKET/name).read_bytes(), name)

    def test_03_readme_counts_are_exactly_json_metrics(self):
        record = json.loads((n.PACKET/'records.json').read_text())
        readme = (n.PACKET/'README.md').read_text()
        self.assertEqual(readme, n.render_readme(record))
        labels = {'Complete body bytes': 'body_bytes', 'Strictly decoded instructions': 'instructions',
                  'Callees, including tail calls and indirect dispatch': 'callees',
                  'INT3 bytes after body': 'padding_bytes', 'Full .text bytes scanned': 'text_scan_bytes',
                  'E8 rel32 call candidates': 'e8_candidates', 'E9 rel32 tail-jump candidates': 'e9_candidates',
                  'Total direct-call candidate sites': 'call_sites', 'Distinct containing caller FDEs': 'caller_fdes',
                  'Instruction-derived fixture vectors': 'vectors'}
        actual = dict(re.findall(r'^\| ([^|]+?) \| (\d+) \|$', readme, re.M))
        self.assertEqual(set(actual), set(labels))
        for label, key in labels.items():
            self.assertEqual(int(actual[label]), record['metrics'][key])
        m = record['metrics']
        self.assertEqual(m['instructions'], len(record['window']['instructions']))
        self.assertEqual(m['body_bytes'], len(bytes.fromhex(record['window']['bytes'])))
        self.assertEqual(m['call_sites'], len(record['caller_scan']['sites']))
        self.assertEqual(m['vectors'], len(record['vectors']))

    def test_04_frozen_vectors_match_independent_bisect_rule(self):
        for v in self.record['vectors']:
            args = (v['capacity'], v['head'], v['physical_keys'], v['length'], v['needle'])
            want = (v['rax'], v['rdx'])
            self.assertEqual(n.search_model(*args), want, v)
            self.assertEqual(n.decoded_recurrence(*args), want, v)

    def test_05_exhaustive_small_sorted_ring_geometry(self):
        # All sorted logical sequences over this alphabet, every legal head,
        # both raw head encodings, every length, and neighboring needle values.
        for capacity in range(1, 7):
            for length in range(capacity+1):
                for logical in itertools.combinations_with_replacement((0, 2, 4), length):
                    for h in range(capacity):
                        physical = [0] * capacity
                        for i, key in enumerate(logical):
                            physical[(h+i) % capacity] = key
                        for head in (h, h+capacity):
                            for needle in range(6):
                                args = (capacity, head, physical, length, needle)
                                result = n.decoded_recurrence(*args)
                                self.assertEqual(result, n.search_model(*args), args)
                                flag, index = result
                                if flag:
                                    self.assertNotIn(needle, logical)
                                    self.assertEqual(index, sum(k < needle for k in logical))
                                else:
                                    self.assertEqual(logical[index], needle)

    def test_06_pivot_equality_is_neither_uniform_first_nor_last_equal(self):
        self.assertEqual(n.search_model(4, 0, [4]*4, 4, 4), (0, 3))
        self.assertEqual(n.search_model(4, 2, [4]*4, 4, 4), (0, 2))
        self.assertEqual(n.search_model(4, 6, [4]*4, 4, 4), (0, 2))
        self.assertEqual(n.search_model(4, 0, [4]*4, 4, 3), (1, 0))
        self.assertEqual(n.search_model(4, 2, [4]*4, 4, 5), (1, 4))

    def test_07_unsigned_boundaries_and_nonwrap_head_equals_capacity(self):
        keys = [0, (1 << 63)-1, 1 << 63, n.U64]
        for needle, expected in [(0, (0, 0)), (1, (1, 1)), ((1 << 63)-1, (0, 1)),
                                 (1 << 63, (0, 2)), (n.U64-1, (1, 3)), (n.U64, (0, 3))]:
            for head in (0, 4):
                self.assertEqual(n.decoded_recurrence(4, head, keys, 4, needle), expected)
        self.assertEqual(n.decoded_recurrence(3, 3, [5, 0, 0], 1, 5), (0, 0))

    def test_08_actual_midpoint_opcode_mutation_changes_duplicate_choice(self):
        raw = bytearray(self.read(n.START, n.END-n.START))
        raw[0x45518f4-n.START+2] = 0x43  # CMOVA -> CMOVAE at actual opcode.
        p = n.parameters(n.decode(raw, n.START))
        self.assertEqual(p['midpoint_reject'], ['cmova', 'cmovae'])
        args = (4, 0, [4]*4, 4, 4)
        self.assertEqual(n.decoded_recurrence(*args, p=p), (0, 0))
        self.assertEqual(n.search_model(*args), (0, 3))
        self.assert_internal_rejects(0x45518f6, b'\x43', 'semantic parameters')

    def test_09_every_window_byte_mutation_is_rejected_below_identity_gate(self):
        # Test the strict body decoder plus full window hash; no per-case mmap
        # copy or full-image hashing is needed for this all-byte control.
        original = self.read(n.START, n.END-n.START)
        for index in range(len(original)):
            raw = bytearray(original)
            raw[index] ^= 1
            with self.subTest(offset=index), self.assertRaises(ValueError):
                n.bind_body(raw)
        self.assert_internal_rejects(n.START+3, b'\x10', 'window bytes|semantic|unsupported|branch')

    def test_10_fde_start_extent_cie_and_padding_controls(self):
        for va in (n.FDE['fde']+8, n.FDE['fde']+12, n.FDE['cie']+16):
            self.assert_internal_rejects(va, bytes([self.read(va, 1)[0] ^ 1]), 'FDE|CIE|encoding')
        self.assert_internal_rejects(n.END, b'\x90', 'padding')

    def test_11_redirected_actual_caller_target_is_rejected(self):
        site = n.CALL_SITES[0]
        raw = bytearray(self.read(site, 5))
        struct.pack_into('<i', raw, 1, n.START+1-(site+5))
        self.assertEqual(n.decode(raw, site)[0]['target'], n.START+1)
        self.assert_internal_rejects(site, raw, 'caller census/target')
        # The leaf has no callees; incoming call displacement is the real target control.

    def test_12_location_reference_relocation_and_literal_controls(self):
        source = self.record['source_association']
        self.assert_internal_rejects(n.SOURCE_LEA+3, bytes([self.read(n.SOURCE_LEA+3, 1)[0] ^ 1]), 'Location reference')
        self.assert_internal_rejects(source['path_va'], b'L', 'source path')
        self.assert_internal_rejects(n.LOCATION+16, b'\x00', 'Location layout')
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as changed:
            off = source['relocation']['file_offset']+16
            changed[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'Location relocation'):
                n.extract(changed)

    def test_13_public_digest_gate_precedes_extraction_and_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad, out = Path(tmp)/'bad', Path(tmp)/'out'
            bad.write_bytes(b'not node #115')
            with mock.patch.object(n, 'extract', side_effect=AssertionError('no analysis before authentication')):
                with self.assertRaisesRegex(ValueError, 'size/digest'):
                    n.generate(bad, out)
                self.assertFalse(out.exists())
                # Sparse same-size wrong input exercises digest, not just size.
                with bad.open('wb') as handle:
                    handle.truncate(n.SIZE)
                with self.assertRaisesRegex(ValueError, 'size/digest'):
                    n.generate(bad, out)
                self.assertFalse(out.exists())

    def test_14_decoder_truncation_unknown_opcodes_and_branch_displacements(self):
        for raw in (b'\x48', b'\xe8\x00', b'\x0f\x0b', b'\xff\xd0', b'\x48\x8d\xc0', b'\x0f\x97\xc8'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                n.decode(raw, n.START)
        self.assertEqual(n.decode(bytes.fromhex('75fe'), n.START)[0]['target'], n.START)
        self.assertEqual(n.decode(bytes.fromhex('e9fbffffff'), n.START)[0]['target'], n.START)
        self.assertEqual(n.decode(bytes.fromhex('e800000000'), n.START)[0]['target'], n.START+5)
        raw = bytearray(self.read(n.START, n.END-n.START))
        struct.pack_into('<i', raw, 0x4551817-n.START+2, 1)
        with self.assertRaisesRegex(ValueError, 'branch'):
            n.bind_body(raw)

    def test_15_rel32_census_includes_last_possible_position(self):
        text = {'offset': 0, 'size': 10, 'address': 0x1000}
        raw = bytearray(b'\x90'*10)
        raw[5] = 0xe9
        struct.pack_into('<i', raw, 6, 0x1100-0x100a)
        found = n.scan_rel32(raw, text, 0x1100)
        self.assertEqual([(r['va'], r['op']) for r in found], [(0x1005, 'jmp')])
        self.assertEqual(n.scan_rel32(raw, text, 0x1101), [])
        self.assertEqual(tuple(c['call']['va'] for c in self.record['caller_scan']['sites']), n.CALL_SITES)

    def test_16_invalid_model_inputs_are_outside_the_claim(self):
        for args in ((0, 0, [], 0, 0), (2, 4, [0, 1], 2, 0), (2, 0, [0, 1], 3, 0),
                     (2, 0, [1, 0], 2, 0), (1, 0, [-1], 1, 0), (1, 0, [0], 1, 1 << 64)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                n.search_model(*args)

    def test_17_manifest_whitelist_and_regeneration_verifier(self):
        self.assertEqual(self.verifier['verify']()['window']['body_sha256'], n.BODY_SHA)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)/'packet'
            shutil.copytree(n.PACKET, out)
            self.verifier['check_manifest'](out)
            manifest = (out/'MANIFEST.sha256').read_text()
            controls = [manifest+manifest.splitlines()[0]+'\n',
                        '\n'.join(manifest.splitlines()[1:])+'\n',
                        manifest+'0'*64+'  ../../../provenance/artifacts.json\n',
                        manifest.replace('records.json', 'missing.json')]
            for text in controls:
                (out/'MANIFEST.sha256').write_text(text)
                with self.assertRaises(ValueError):
                    self.verifier['check_manifest'](out)
            (out/'MANIFEST.sha256').write_text(manifest)
            (out/'extra').write_text('unlisted')
            with self.assertRaisesRegex(ValueError, 'whitelist'):
                self.verifier['check_manifest'](out)
            (out/'extra').unlink()
            (out/'README.md').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'digest'):
                self.verifier['check_manifest'](out)


if __name__ == '__main__':
    unittest.main()
