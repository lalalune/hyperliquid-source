"""Static evidence and corruption controls for the #115 adjacent-key leaf."""
from contextlib import contextmanager
import hashlib
import itertools
import json
import mmap
from pathlib import Path
import random
import re
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_adjacent_key_last as bind


class AdjacentKeyLastTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = bind.TARGET.open('rb')
        # One private mmap, changed/restored in place by controls; no full copies.
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.record = bind.analyze(cls.data)
        cls.secs = bind.sections(cls.data)
        cls.body = bytes.fromhex(cls.record['function']['body_hex'])

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def changed(self, offset, replacement):
        old = self.data[offset:offset + len(replacement)]
        self.data[offset:offset + len(replacement)] = replacement
        try:
            yield
        finally:
            self.data[offset:offset + len(old)] = old

    def offset(self, va, n=1):
        return bind.va_offset(self.secs, va, n)

    @staticmethod
    def row(key, payload):
        return bytes([key]) * 20 + bytes([payload]) * 12

    def test_regeneration_and_manifest(self):
        bind.verify_packet()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'packet'
            bind.generate(bind.TARGET, out)
            for name in (*bind.PACKET_FILES, 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (bind.PACKET / name).read_bytes(), name)

    def test_readme_counts_equal_json(self):
        r = json.loads((bind.PACKET / 'records.json').read_text())
        readme = (bind.PACKET / 'README.md').read_text()
        counts = {name: int(n) for name, n in re.findall(r'^\| ([a-z0-9_]+) \| (\d+) \|$', readme, re.M)}
        self.assertEqual(counts, r['metrics'])
        self.assertIn(f"({r['caller_census']['scan_bytes']} bytes)", readme)
        for field in ('row_bytes', 'key_bytes', 'payload_bytes'):
            self.assertIn(str(r['rule'][field]), readme)
        self.assertEqual(readme, bind.readme_text(r))

    def test_full_instruction_coverage_and_boundaries(self):
        ins = self.record['function']['instructions']
        self.assertEqual(b''.join(bytes.fromhex(r['bytes']) for r in ins), self.body)
        pc = bind.START
        for r in ins:
            self.assertEqual(r['address'], pc)
            pc += len(bytes.fromhex(r['bytes']))
        self.assertEqual(pc, bind.END)
        self.assertEqual({r['target'] for r in ins if 'target' in r} - {r['address'] for r in ins}, set())
        self.assertEqual(self.record['function']['callees'], [])
        self.assertEqual(self.record['function']['indirect_transfers'], [])
        self.assertEqual(self.record['metrics']['ret_sites'], 2)
        self.assertEqual(self.record['metrics']['instructions'], 74)

    def test_comparison_and_copy_operands(self):
        by = {r['address']: r for r in self.record['function']['instructions']}
        for pc, base, index, disp, width in [
            (0x5b2d540, 'rcx', 'rsi', 0, 128),
            (0x5b2d545, 'rcx', 'rsi', 32, 128),
            (0x5b2d54f, 'rcx', 'rsi', 48, 32),
            (0x5b2d555, 'rcx', 'rsi', 16, 32),
            (0x5b2d5e7, 'rsi', None, 0, 128),
            (0x5b2d5eb, 'rcx', 'r9', -32, 128),
            (0x5b2d5f6, 'rsi', None, 16, 32),
            (0x5b2d5fb, 'rcx', 'r9', -16, 32),
        ]:
            mem = by[pc]['operands'][1]
            self.assertEqual((mem['base'], mem['index'], mem['disp'], mem['width']), (base, index, disp, width))
        self.assertEqual(by[0x5b2d568]['operands'][1]['value'], 65535)
        self.assertEqual(by[0x5b2d60f]['operands'][1]['value'], 65535)
        # First and subsequent duplicate routes store all row halves to the
        # keeper AND old read position; they do not merely skip the new row.
        for pc in (0x5b2d592, 0x5b2d597, 0x5b2d59c, 0x5b2d5a1,
                   0x5b2d620, 0x5b2d623, 0x5b2d631, 0x5b2d635):
            self.assertEqual(by[pc]['operands'][0]['kind'], 'mem')
            self.assertEqual(by[pc]['operands'][0]['width'], 128)
        self.assertEqual(by[0x5b2d643]['operands'][0]['disp'], 16)
        self.assertEqual(by[0x5b2d643]['operands'][1]['name'], 'rdx')

    def test_simd_key_mask_all_byte_positions(self):
        a = bytes(32)
        for position in range(32):
            for value in (1, 0x7f, 0x80, 0xff):
                b = a[:position] + bytes([value]) + a[position + 1:]
                mask = bind.equality_mask(a, b)
                self.assertEqual(mask == 65535, position >= 20)
                if position < 20:
                    lane = position if position < 16 else position - 16
                    self.assertEqual(mask, 65535 ^ (1 << lane))
        rng = random.Random(115)
        for _ in range(200):
            a, b = rng.randbytes(32), rng.randbytes(32)
            self.assertEqual(bind.equality_mask(a, b) == 65535, a[:20] == b[:20])

    def test_frozen_instruction_grounded_vectors(self):
        for vector in self.record['vectors']:
            rows = [bytes.fromhex(x) for x in vector['input']]
            memory, n = bind.byte_walk_model(rows)
            self.assertEqual(n, vector['stored_length'])
            self.assertEqual([r.hex() for r in memory], vector['entire_backing_after'])
            self.assertEqual([r.hex() for r in memory[:n]], vector['output_prefix'])
            self.assertEqual(memory[:n], bind.compact_model(rows))

    def test_exhaustive_short_run_patterns(self):
        for n in range(8):
            for keys in itertools.product(range(3), repeat=n):
                rows = [self.row(k, i) for i, k in enumerate(keys)]
                # Independent mathematical oracle: last index before a key
                # change, plus the final row. No mutable write-index algorithm.
                expected = [r for i, r in enumerate(rows) if i + 1 == n or keys[i] != keys[i + 1]]
                memory, count = bind.byte_walk_model(rows)
                self.assertEqual(memory[:count], expected)
                self.assertEqual(bind.compact_model(rows), expected)

    def test_exact_tail_effects_and_no_global_dedup(self):
        a, b, c = self.row(1, 1), self.row(1, 2), self.row(1, 3)
        self.assertEqual(bind.byte_walk_model([a, b, c]), ([c, a, b], 1))
        different = self.row(2, 4)
        self.assertEqual(bind.byte_walk_model([a, b, different]), ([b, different, different], 2))
        separated = [a, different, c]
        self.assertEqual(bind.byte_walk_model(separated), (separated, 3))
        for rows in ([], [a], [a, different]):
            self.assertEqual(bind.byte_walk_model(rows), (rows, len(rows)))
        with self.assertRaises(ValueError):
            bind.compact_model([bytes(31)])

    def test_wrong_digest_and_truncation_fail_before_output(self):
        with self.changed(self.offset(bind.START), b'\x49'):
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                bind.analyze(self.data)
        with tempfile.TemporaryDirectory() as tmp:
            bad, out = Path(tmp) / 'wrong-input', Path(tmp) / 'out'
            bad.write_bytes(b'\x7fELF\x02\x01')
            with mock.patch.object(bind, '_analyze', side_effect=AssertionError('parsed unauthenticated bytes')):
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    bind.generate(bad, out)
            self.assertFalse(out.exists())

    def test_every_body_byte_corruption_rejects(self):
        for i in range(len(self.body)):
            mutant = bytearray(self.body)
            mutant[i] ^= 1
            with self.assertRaisesRegex(ValueError, 'Changed function bytes', msg=f'byte {i}'):
                bind.leaf_instructions(mutant)

    def test_decoder_rejects_unsupported_and_partial_instructions(self):
        for raw in (b'\xff\xd0', b'\xe8', b'\x48\x8b', b'\x48\x8b\x04',
                    b'\x0f\x0b', b'\xf3\xc3', b'\x66\x48\x8b\x00',
                    b'\x0f\x1f\xc0', b'\x66\x0f\xd7\x00'):
            with self.assertRaises(ValueError, msg=raw.hex()):
                bind.decode(raw, bind.START)
        for r in self.record['function']['instructions']:
            raw = bytes.fromhex(r['bytes'])
            for n in range(1, len(raw)):
                with self.assertRaises(ValueError):
                    bind.decode(raw[:n], r['address'])

    def test_actual_key_load_counterfactual(self):
        # Change BOTH remaining-key loads from offsets +16 to +20, keeping
        # the right row bias (+32). Decoded keys now depend on payload bytes.
        mutant = bytearray(self.body)
        for pc in (0x5b2d54f, 0x5b2d555):
            r = next(x for x in self.record['function']['instructions'] if x['address'] == pc)
            mutant[pc - bind.START + len(bytes.fromhex(r['bytes'])) - 1] += 4
        decoded = {r['address']: r for r in bind.decode(mutant, bind.START)}
        left_offset = decoded[0x5b2d555]['operands'][1]['disp']
        right_offset = decoded[0x5b2d54f]['operands'][1]['disp'] - 32
        self.assertEqual((left_offset, right_offset), (20, 20))
        a, b = self.row(1, 1), self.row(1, 2)
        self.assertEqual(bind.equality_mask(a, b), 65535)
        self.assertNotEqual(a[:16] + a[left_offset:left_offset+4], b[:16] + b[right_offset:right_offset+4])
        with self.assertRaises(ValueError):
            bind.leaf_instructions(mutant)

    def test_actual_branch_counterfactual(self):
        mutant = bytearray(self.body)
        mutant[0x5b2d56f - bind.START] = 0x75  # JE -> JNE.
        decoded = {r['address']: r for r in bind.decode(mutant, bind.START)}
        self.assertEqual(decoded[0x5b2d56f]['mnemonic'], 'jne')
        self.assertEqual(decoded[0x5b2d56f]['target'], 0x5b2d57e)
        # With unequal adjacent keys, the original equality edge is false;
        # the changed edge instead enters the swap/delete route.
        equal = bind.equality_mask(self.row(1, 1), self.row(2, 2)) == 65535
        self.assertFalse(equal)
        self.assertTrue(not equal)
        with self.assertRaises(ValueError):
            bind.leaf_instructions(mutant)

    def test_shifted_fde_rejected_below_hash_gate(self):
        offset = self.record['function']['frame']['fde_file_offset'] + 8
        value = struct.unpack_from('<i', self.data, offset)[0]
        with self.changed(offset, struct.pack('<i', value + 1)):
            with self.assertRaisesRegex(ValueError, 'FDE'):
                bind._analyze(self.data)
        with self.changed(offset + 4, struct.pack('<i', bind.END - bind.START - 1)):
            with self.assertRaisesRegex(ValueError, 'FDE'):
                bind._analyze(self.data)

    def test_wrong_callee_target_rejected_below_hash_gate(self):
        off = self.offset(bind.CALL_SITE) + 1
        delta = struct.unpack_from('<i', self.data, off)[0]
        with self.changed(off, struct.pack('<i', delta + 1)):
            changed = bind.decode(self.data[off - 1:off + 4], bind.CALL_SITE)
            self.assertEqual(changed[0]['target'], bind.START + 1)
            with self.assertRaisesRegex(ValueError, 'caller census'):
                bind._analyze(self.data)

    def test_source_and_padding_corruptions_rejected(self):
        relocation = self.record['source_association']['relocation']['file_offset']
        for off, replacement, message in [
            (relocation + 16, struct.pack('<q', bind.PATH_VA + 1), 'relocation'),
            (self.offset(bind.LOCATION) + 16, struct.pack('<I', 139), 'Location'),
            (self.offset(bind.END), b'\x90', 'padding'),
        ]:
            with self.changed(off, replacement):
                with self.assertRaisesRegex(ValueError, message):
                    bind._analyze(self.data)

    def test_caller_scan_covers_text_and_signed_rel32(self):
        c = self.record['caller_census']
        self.assertEqual((c['scan_start'], c['scan_end']), (bind.TEXT_START, bind.TEXT_END))
        self.assertEqual(c['hits'][0]['site'], bind.CALL_SITE)
        self.assertEqual(c['hits'][0]['bytes'], 'e8b1e3d200')
        # Synthetic bytes exercise a backward rel32 and the last possible
        # complete instruction, while excluding an incomplete suffix.
        start = bind.START + 100
        raw = b'\x90' + b'\xe9' + struct.pack('<i', bind.START - (start + 1 + 5))
        text = {'offset': 0, 'address': start, 'size': len(raw)}
        hits = bind.caller_scan(raw, text, [])
        self.assertEqual([(r['site'], r['kind']) for r in hits], [(start + 1, 'tail-jump')])
        self.assertEqual(bind.caller_scan(raw[:-1], {**text, 'size': len(raw) - 1}, []), [])

    def test_manifest_whitelist_and_regeneration_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'packet'
            shutil.copytree(bind.PACKET, out)
            manifest = (out / 'MANIFEST.sha256').read_text()
            for altered in (manifest + manifest.splitlines()[0] + '\n',
                            '\n'.join(manifest.splitlines()[1:]) + '\n',
                            manifest + hashlib.sha256(b'').hexdigest() + '  ../escape\n'):
                (out / 'MANIFEST.sha256').write_text(altered)
                with self.assertRaises(ValueError):
                    bind.verify_packet(out)
            (out / 'MANIFEST.sha256').write_text(manifest)
            (out / 'extra').write_text('')
            with self.assertRaisesRegex(ValueError, 'whitelist'):
                bind.verify_packet(out)
            (out / 'extra').unlink()
            # Rehashing a falsified record still fails byte-identical regeneration.
            r = json.loads((out / 'records.json').read_text())
            r['rule']['keeper'] = 'first'
            (out / 'records.json').write_text(json.dumps(r, indent=2, sort_keys=True) + '\n')
            payloads = {n: (out / n).read_bytes() for n in bind.PACKET_FILES}
            (out / 'MANIFEST.sha256').write_text(bind.manifest_text(payloads))
            with self.assertRaisesRegex(ValueError, 'Regeneration mismatch'):
                bind.verify_packet(out)


if __name__ == '__main__':
    unittest.main()
