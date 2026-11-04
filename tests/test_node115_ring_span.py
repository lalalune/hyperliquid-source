"""Target-grounded static controls for the node #115 ring-span descriptor bind."""
from contextlib import contextmanager
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_ring_span as bind
from elf_index import sections


class RingSpanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = bind.TARGET.open('rb')
        # One private mapping; corruption tests restore tiny patches immediately.
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.secs = sections(cls.data)
        cls.record = bind.analyze(cls.data)
        cls.body = bytes.fromhex(cls.record['window']['body_bytes'])
        cls.check_manifest = staticmethod(runpy.run_path(str(bind.PACKET / 'verify.py'))['check_manifest'])

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def patched(self, offset, replacement):
        original = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(original)] = original

    def offset(self, va, size=1):
        return bind.mapping(self.secs, va, size)

    def test_byte_identical_regeneration(self):
        self.assertEqual(self.record, json.loads((bind.PACKET / 'records.json').read_text()))
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'packet'
            bind.generate(bind.TARGET, out)
            self.assertEqual({p.name for p in out.iterdir()}, {p.name for p in bind.PACKET.iterdir()})
            for p in out.iterdir():
                self.assertEqual(p.read_bytes(), (bind.PACKET / p.name).read_bytes(), p.name)
            self.check_manifest(out, ROOT)

    def test_readme_counts_match_json(self):
        readme = (bind.PACKET / 'README.md').read_text()
        record = json.loads((bind.PACKET / 'records.json').read_text())
        block = re.search(r'<!-- counts:start -->\n(.*?)\n<!-- counts:end -->', readme, re.S)
        self.assertIsNotNone(block)
        actual = dict((key, int(value)) for key, value in re.findall(r'^- (\w+): (\d+)$', block[1], re.M))
        self.assertEqual(actual, record['counts'])
        self.assertEqual(block[1], bind.count_lines(record))
        self.assertEqual(readme, bind.readme_text(record))
        c, ins, scan = record['counts'], record['instructions'], record['caller_scan']
        self.assertEqual(c['body_bytes'], sum(len(bytes.fromhex(r['bytes'])) for r in ins))
        self.assertEqual(c['instructions'], len(ins))
        self.assertEqual(c['callees'], len(record['callees']))
        self.assertEqual(c['call_sites'], len(scan['sites']))
        self.assertEqual(c['caller_owners'], len(scan['owners']))
        self.assertEqual(c['tail_jump_sites'], sum(r['kind'] == 'jmp' for r in scan['sites']))
        self.assertEqual(c['conditional_branches'], sum(r['mnemonic'] in ('jno', 'je', 'ja') for r in ins))
        self.assertEqual(c['unconditional_branches'], sum(r['mnemonic'] == 'jmp' for r in ins))
        self.assertEqual(c['returns'], sum(r['mnemonic'] == 'ret' for r in ins))
        self.assertEqual(c['output_words'], len(record['rule']['output_qwords']))
        self.assertEqual(c['vectors'], len(record['vectors']))
        self.assertEqual(c['padding_bytes'], len(bytes.fromhex(record['window']['padding']['bytes'])))
        self.assertEqual(c['text_bytes_scanned'], scan['end'] - scan['start'])

    def test_complete_leaf_graph_and_stores(self):
        instructions, edges, params = bind.validate_body(self.body)
        self.assertEqual(params, {'word_bits': 64, 'sentinel': 1 << 63, 'stride': 48,
                                  'ring_tag': 2, 'zero_word': 0})
        self.assertEqual(instructions[-1]['va'], bind.END - 1)
        self.assertEqual(instructions[-1]['mnemonic'], 'ret')
        self.assertFalse(any(r['mnemonic'] == 'call' for r in instructions))
        self.assertTrue(all(dst > row['va'] for row in edges for dst in row['successors']))
        stores = [r['operands'][0] for r in instructions
                  if r['mnemonic'] == 'mov' and 'base' in r['operands'][0]]
        self.assertEqual([p['disp'] for p in stores], list(range(0, 72, 8)))
        self.assertTrue(all(p['base'] == 'rax' and p['width'] == 64 for p in stores))
        self.assertEqual(bind.decode(bytes.fromhex('4889f8'), 0)[0]['assembly'], 'mov rax, rdi')
        self.assertTrue(0x2800000 <= bind.START < 0x3c00000)
        self.assertFalse(0x5f00000 <= bind.START < 0x5f20000)

    def test_frozen_instruction_derived_vectors(self):
        for row in self.record['vectors']:
            with self.subTest(case=row['case']):
                self.assertEqual(bind.model(row['input'], self.record['parameters']), row['output'])

    def test_ring_span_matches_independent_circular_positions(self):
        # Enumerate logical circular element positions independently of split equations.
        for capacity in range(1, 17):
            for head in range(2 * capacity):
                for count in range(capacity + 1):
                    base = 4096
                    out = bind.model([capacity, base, head, count])
                    positions = list(range((out[1] - base) // 48, (out[2] - base) // 48))
                    positions += list(range((out[3] - base) // 48, (out[4] - base) // 48))
                    self.assertEqual(positions, [(head + n) % capacity for n in range(count)])
                    self.assertEqual(out[8], len(range((out[3] - base) // 48, (out[4] - base) // 48)))
                    self.assertEqual(out[2], out[6])
                    self.assertEqual(out[3], out[7])

    def test_sentinel_uses_equality_and_full_word_flag(self):
        for base in (0, 1, 1 << 32, 1 << 63, bind.MASK):
            for head in (0, 33, bind.MASK):
                for count in (0, 11, bind.MASK):
                    flag = int(base != 0)
                    self.assertEqual(bind.model([1 << 63, base, head, count]),
                                     [flag, 0, base, head, flag, 0, base, head, count if flag else 0])
        for capacity in ((1 << 63) - 1, (1 << 63) + 1, bind.MASK):
            self.assertEqual(bind.model([capacity, 100, 0, 1]), [2, 100, 148, 100, 100, 0, 148, 100, 0])
        with self.assertRaises(ValueError):
            bind.model([-1, 0, 0, 0])
        with self.assertRaises(ValueError):
            bind.model([0, 0, 0, 1 << 64])

    def test_every_body_byte_corruption_is_rejected_below_digest_gate(self):
        for offset in range(len(self.body)):
            changed = bytearray(self.body)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                bind.validate_body(changed)

    def test_real_stride_operands_change_equation_before_rejection(self):
        changed = bytearray(self.body)
        for site in (0x2d55ba7, 0x2d55bb2, 0x2d55bbd):
            self.assertEqual(changed[site - bind.START], 4)
            changed[site - bind.START] = 3
        extracted = bind.parameters(bind.decode(changed, bind.START))
        self.assertEqual(extracted['stride'], 24)
        words = [8, 4096, 2, 3]
        self.assertNotEqual(bind.model(words, extracted), bind.model(words))
        with self.assertRaisesRegex(ValueError, 'instruction rule changed'):
            bind.validate_body(changed)

    def test_bad_branch_destination_is_rejected(self):
        changed = bytearray(self.body)
        # Actual JNO operand: redirect from ring arm to inside a MOV encoding.
        changed[0x2d55b3d - bind.START] += 1
        rows = bind.decode(changed, bind.START)
        self.assertEqual(rows[4]['operands'], [{'target': 0x2d55b63}])
        with self.assertRaises(ValueError):
            bind.validate_body(changed)

    def test_decoder_fails_on_unsupported_and_truncated_forms(self):
        for code in (b'\x0f\x0b', b'\x48', b'\x48\x8b', b'\x48\x8b\x84\x24',
                     b'\x48\xc7\x00\x00', b'\xe8\x00', b'\x48\xf7\xc2', b'\x66\x90'):
            with self.subTest(code=code.hex()), self.assertRaises(ValueError):
                bind.decode(code, bind.START)
        for length in range(len(self.body)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                bind.validate_body(self.body[:length])

    def test_public_digest_rejects_wrong_or_mutated_capture_before_output(self):
        for data in (b'', b'wrong capture'):
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.analyze(data)
        with self.patched(self.offset(bind.START), b'\x49'):
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.analyze(self.data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wrong.elf'
            path.write_bytes(b'not the authenticated capture')
            output = Path(directory) / 'must-not-exist'
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.generate(path, output)
            self.assertFalse(output.exists())

    def test_actual_fde_shift_and_padding_corruption(self):
        for field in (8, 12):  # encoded initial PC, then encoded range
            offset = self.offset(bind.FDE['fde'] + field, 4)
            value = struct.unpack_from('<i', self.data, offset)[0]
            with self.patched(offset, struct.pack('<i', value + 1)):
                with self.assertRaisesRegex(ValueError, 'FDE changed'):
                    bind.inspect_static(self.data)
        with self.patched(self.offset(bind.END), b'\x90'):
            with self.assertRaisesRegex(ValueError, 'padding'):
                bind.inspect_static(self.data)

    def test_actual_caller_targets_are_checked(self):
        # No callees exist in the leaf: redirect each real incoming CALL instead.
        for site in bind.CALL_SITES:
            offset = self.offset(site + 1, 4)
            old = struct.unpack_from('<i', self.data, offset)[0]
            with self.subTest(site=site), self.patched(offset, struct.pack('<i', old + 1)):
                with self.assertRaisesRegex(ValueError, 'caller target changed'):
                    bind.inspect_static(self.data)

    def test_census_scans_unaligned_e8_e9_and_last_complete_instruction(self):
        # A syntactic hit inside arbitrary data remains in the raw census.
        code = bytearray(b'\x90' * 25)
        section = {'offset': 3, 'address': 0x1000, 'size': 19}
        for file_offset, opcode in ((4, 0xe8), (17, 0xe9)):
            site = section['address'] + file_offset - section['offset']
            code[file_offset:file_offset + 5] = bytes([opcode]) + struct.pack('<i', 0x1100 - site - 5)
        rows = bind.scan_direct(code, section, 0x1100)
        self.assertEqual([(r['file_offset'], r['kind']) for r in rows], [(4, 'call'), (17, 'jmp')])
        self.assertEqual(bind.scan_direct(code, section, 0x1101), [])
        self.assertEqual([r['site'] for r in self.record['caller_scan']['sites']], list(bind.CALL_SITES))

    def test_source_context_reference_location_literal_and_relocation_controls(self):
        offsets = (self.offset(bind.LOCATION_SITE + 3), self.offset(bind.LOCATION_VA + 8),
                   self.offset(bind.LOCATION_VA + 16), self.offset(bind.PATH_VA),
                   self.record['source_context']['relocation']['file_offset'] + 8,
                   self.record['source_context']['relocation']['file_offset'] + 16)
        for offset in offsets:
            with self.subTest(offset=offset), self.patched(offset, bytes([self.data[offset] ^ 1])):
                with self.assertRaisesRegex(ValueError, 'source'):
                    bind.inspect_static(self.data)

    def test_manifest_whitelist_and_corruption_controls(self):
        self.check_manifest(bind.PACKET, ROOT)
        for variant in ('extra-file', 'extra-entry', 'duplicate', 'missing', 'changed-file', 'symlink'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                packet = Path(directory) / 'packet'
                shutil.copytree(bind.PACKET, packet)
                manifest = packet / 'MANIFEST.sha256'
                original = manifest.read_text()
                if variant == 'extra-file':
                    (packet / 'stray.txt').write_text('untracked evidence')
                elif variant == 'extra-entry':
                    manifest.write_text(original + '0' * 64 + '  stray.txt\n')
                elif variant == 'duplicate':
                    manifest.write_text(original + original.splitlines()[0] + '\n')
                elif variant == 'missing':
                    manifest.write_text('\n'.join(original.splitlines()[1:]) + '\n')
                elif variant == 'symlink':
                    manifest.unlink()
                    manifest.symlink_to(bind.PACKET / 'MANIFEST.sha256')
                else:
                    (packet / 'records.json').write_text('{}\n')
                with self.assertRaises(ValueError):
                    self.check_manifest(packet, ROOT)


if __name__ == '__main__':
    unittest.main()
