"""Static controls for the #115 leaf; never execute the captured node."""
import hashlib
import importlib.util
import mmap
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_slice20_equal as subject


class Slice20EqualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = subject.collect()
        cls.body = bytes.fromhex(cls.record['function']['bytes_hex'])
        spec = importlib.util.spec_from_file_location('slice20_packet_verify', subject.PACKET / 'verify.py')
        cls.verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.verifier)

    def mutate_image(self, offset, replacement, message):
        # Private mmap shares unchanged pages with the artifact; never copy a
        # whole binary into a Python bytes/bytearray or write the actual artifact.
        with subject.TARGET.open('rb') as stream:
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_COPY) as data:
                data[offset:offset + len(replacement)] = replacement
                with self.assertRaisesRegex(ValueError, message):
                    subject.inspect(data)

    def test_exact_target_extent_and_complete_walk(self):
        r = self.record
        f = r['function']
        self.assertEqual(r['target_sha256'], subject.SHA)
        self.assertEqual((f['start'], f['end'], f['size']), (0x5436860, 0x54368b6, 86))
        self.assertEqual(hashlib.sha256(self.body).hexdigest(), subject.BODY_SHA)
        self.assertEqual(f['file_offset'], subject.START - 0x1000)
        self.assertEqual(f['callees'], [])
        self.assertEqual(f['indirect_transfers'], [])
        cursor = f['start']
        for row in f['instructions']:
            self.assertEqual(cursor, row['address'])
            self.assertEqual(len(bytes.fromhex(row['bytes_hex'])), row['size'])
            cursor += row['size']
        self.assertEqual(cursor, f['end'])
        self.assertEqual(b''.join(bytes.fromhex(i['bytes_hex']) for i in f['instructions']), self.body)
        self.assertEqual(sum(i['mnemonic'] == 'ret' for i in f['instructions']), 3)
        graph = {row['address']: row['successors'] for row in f['control_flow']}
        self.assertEqual(graph[0x5436863], [0x5436865, 0x54368b0])
        self.assertEqual(graph[0x5436868], [0x543686a, 0x54368b3])
        self.assertEqual(graph[0x54368a1], [0x54368a3, 0x54368af])
        self.assertEqual(graph[0x54368ad], [0x54368af, 0x5436870])
        self.assertEqual({pc for pc, successors in graph.items() if not successors},
                         {0x54368af, 0x54368b2, 0x54368b5})
        self.assertIsNone(f['unwind']['lsda'])

    def test_full_text_census_and_decoded_caller_bindings(self):
        census = self.record['caller_census']
        self.assertEqual((census['text_start'], census['text_end']), (0x1419300, 0x63f0a00))
        self.assertEqual(census['text_size'], 83719936)
        self.assertEqual([(h['site'], h['opcode'], h['owner_start']) for h in census['hits']],
                         [(0x53791b1, '0xe8', 0x5378220), (0x53791d0, '0xe8', 0x5378220)])
        for h in census['hits']:
            raw = bytes.fromhex(h['bytes_hex'])
            self.assertEqual(h['site'] + 5 + struct.unpack('<i', raw[1:])[0], subject.START)
        rows = self.record['caller_context']['argument_and_call_slice']['instructions']
        self.assertEqual([r['target'] for r in rows if r['mnemonic'] == 'call'], [subject.START] * 2)
        # Exact argument slots at each observed call, not invented source types.
        self.assertEqual([r['displacement'] for r in rows if r['mnemonic'] == 'mov'],
                         [0x10, 0x18, 0x18, 0x20, 0x28, 0x30, 0x30, 0x38])

    def test_scalar_and_simd_vectors(self):
        for v in self.record['vectors']:
            left = [bytes.fromhex(x) for x in v['left']]
            right = [bytes.fromhex(x) for x in v['right']]
            with self.subTest(v['name']):
                self.assertEqual(subject.sequence_equal(left, right), v['al'])
                self.assertEqual(subject.instruction_relation(left, right), v['al'])
        self.assertEqual(len(self.record['vectors']), 69)

    def test_every_lane_and_bit_mismatch(self):
        a = bytes(range(20))
        for offset in range(20):
            for bit in range(8):
                b = bytearray(a)
                b[offset] ^= 1 << bit
                self.assertEqual(subject.lane_mask(a, b), 0xffff ^ (1 << (offset % 16)))
        # Differing head/tail bytes sharing a lane cannot cancel.
        b = bytearray(a)
        b[0] ^= 1
        b[16] ^= 1
        self.assertEqual(subject.lane_mask(a, b), 0xfffe)

    def test_loop_counter_carry_boundaries(self):
        for v in self.record['counter_boundary_vectors']:
            n = v['before_add']
            total = n + subject.U64
            self.assertEqual(v['carry'], total > subject.U64)
            self.assertEqual(v['after_add'], total & subject.U64)
        for n in range(1, 65):
            remaining = n - 1
            for j in range(n):
                self.assertEqual(subject.loop_carry(remaining), j + 1 < n)
                remaining = (remaining - 1) & subject.U64
        for bad in (-1, 1 << 64, True):
            with self.assertRaisesRegex(ValueError, 'u64'):
                subject.loop_carry(bad)

    def test_independent_scalar_boundary_cases(self):
        block = bytes(range(20))
        for count in (0, 1, 2, 4, 17, 65):
            a = [block] * count
            self.assertEqual(subject.sequence_equal(a, a), 1)
            self.assertEqual(subject.instruction_relation(a, a), 1)
            self.assertEqual(subject.instruction_relation(a, a + [block]), 0)
        with self.assertRaisesRegex(ValueError, '20-byte'):
            subject.sequence_equal([b'short'], [b'short'])

    def test_readme_counts_match_json_and_all_generated_text(self):
        text = (subject.PACKET / 'README.md').read_text()
        found = {name: int(value) for name, value in re.findall(r'^\| `([a-z_]+)` \| ([0-9]+) \|$', text, re.M)}
        m = self.record['metrics']
        self.assertEqual(found, m)
        f = self.record['function']
        self.assertEqual(m['body_bytes'], f['end'] - f['start'])
        self.assertEqual(m['instructions'], len(f['instructions']))
        self.assertEqual(m['padding_bytes'], len(bytes.fromhex(f['padding_after']['bytes_hex'])))
        self.assertEqual(m['callees'], len(f['callees']))
        self.assertEqual(m['semantic_vectors'], len(self.record['vectors']))
        self.assertEqual(m['direct_call_sites'], len(self.record['caller_census']['hits']))
        self.assertEqual(subject.readme(self.record), (subject.PACKET / 'README.md').read_bytes())

    def test_byte_identical_regeneration(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'packet'
            subject.generate(subject.TARGET, out)
            for name in ('README.md', 'records.json', 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (subject.PACKET / name).read_bytes(), name)

    def test_wrong_digest_and_mutated_window_reject_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input'
            out = Path(folder) / 'output'
            for data in (b'', b'unrelated ELF capture'):
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    subject.generate(path, out)
                self.assertFalse(out.exists())
            # One disk copy, streamed by shutil; no second in-memory binary.
            shutil.copyfile(subject.TARGET, path)
            with path.open('r+b') as stream:
                stream.seek(self.record['function']['file_offset'])
                stream.write(b'\x49')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                subject.generate(path, out)
            self.assertFalse(out.exists())

    def test_each_body_byte_and_truncated_encoding_rejected(self):
        for i in range(len(self.body)):
            code = bytearray(self.body)
            code[i] ^= 1
            with self.subTest(offset=i), self.assertRaises(ValueError):
                subject.leaf(bytes(code))
        for row in self.record['function']['instructions']:
            raw = bytes.fromhex(row['bytes_hex'])
            for size in range(1, len(raw)):
                with self.subTest(address=row['address'], size=size), self.assertRaises(ValueError):
                    subject.decode(raw[:size], row['address'])
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            subject.decode(b'\x90', subject.START)

    def test_real_operand_counterfactuals(self):
        for site, expected_key, new in ((0x54368a7, 'immediate', 21),
                                        (0x543687c, 'displacement', 17),
                                        (0x5436899, 'immediate', 0xfffe),
                                        (0x54368b3, 'immediate', 0)):
            code = bytearray(self.body)
            if site == 0x5436899:
                struct.pack_into('<I', code, site - subject.START + 1, new)
            else:
                row = next(r for r in self.record['function']['instructions'] if r['address'] == site)
                code[site - subject.START + row['size'] - 1] = new
            changed = next(r for r in subject.decode(bytes(code), subject.START) if r['address'] == site)
            self.assertEqual(changed[expected_key], new)
            with self.assertRaisesRegex(ValueError, 'body changed'):
                subject.leaf(bytes(code))
        # Mask relaxation would falsely accept a mismatch in lane zero.
        a = bytes(20)
        b = b'\x01' + bytes(19)
        self.assertEqual(subject.lane_mask(a, b), 0xfffe)
        self.assertEqual(subject.sequence_equal([a], [b]), 0)
        # The real SETB operand is strict; SETAE cannot enter the decoder.
        code = self.body.replace(b'\x0f\x92\xc1', b'\x0f\x93\xc1')
        with self.assertRaises(ValueError):
            subject.leaf(code)

    def test_shifted_and_shortened_actual_fde(self):
        row = self.record['function']['unwind']['fde_record']
        raw = bytes.fromhex(row['bytes_hex'])
        for relative in (8, 12):
            old = struct.unpack_from('<i', raw, relative)[0]
            changed = old + 1 if relative == 8 else old - 1
            self.mutate_image(row['file_offset'] + relative, struct.pack('<i', changed), 'exact leaf FDE')

    def test_wrong_actual_direct_callee_target(self):
        for site in subject.CALL_SITES:
            offset = site - 0x1000 + 1
            value = subject.START - site - 5 + 16
            self.mutate_image(offset, struct.pack('<i', value), 'caller target changed')

    def test_padding_mutation(self):
        offset = self.record['function']['padding_after']['file_offset']
        self.mutate_image(offset, b'\x90', 'padding changed')

    def test_source_location_and_relocation_controls(self):
        source = self.record['source_association']
        self.mutate_image(source['location']['file_offset'] + 16, struct.pack('<I', 232), 'Location changed')
        self.mutate_image(source['relocation']['file_offset'] + 16,
                          struct.pack('<q', source['relocation']['addend'] + 1), 'relocation changed')
        self.mutate_image(source['instruction']['file_offset'] + 3,
                          struct.pack('<i', subject.LOCATION - subject.SOURCE_SITE - 7 + 1), 'LEA changed')
        self.mutate_image(source['path']['file_offset'], b'x', 'source path changed')

    def test_no_hidden_census_hit(self):
        # Insert an extra E8 in unrelated .text padding to prove no silent filter.
        site = 0x54368b7
        # Call census directly: the full inspect() would reject padding first.
        with subject.TARGET.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            data[site - 0x1000:site - 0x1000 + 5] = b'\xe8' + struct.pack('<i', subject.START - site - 5)
            image = subject.Image(data)
            _, frames = subject.eh_frame_records(data, image.sections)
            with self.assertRaisesRegex(ValueError, 'no FDE owner'):
                subject.caller_census(image, frames)

    def test_verifier_whitelist_hash_and_regenerated_records(self):
        self.assertEqual(self.verifier.verify(), self.record['metrics'])
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / 'packet'
            shutil.copytree(subject.PACKET, packet, ignore=shutil.ignore_patterns('__pycache__'))
            original = (packet / 'MANIFEST.sha256').read_bytes()
            for bad in (original + original.splitlines(keepends=True)[0],
                        original + b'0' * 64 + b'  ../escape\n',
                        b''.join(original.splitlines(keepends=True)[1:])):
                (packet / 'MANIFEST.sha256').write_bytes(bad)
                with self.assertRaisesRegex(ValueError, 'whitelist'):
                    self.verifier.verify(packet, ROOT)
            (packet / 'MANIFEST.sha256').write_bytes(original)
            (packet / 'records.json').write_bytes(b'{}\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                self.verifier.verify(packet, ROOT)
            (packet / 'MANIFEST.sha256').write_bytes(subject.manifest(packet))
            with self.assertRaisesRegex(ValueError, 'regeneration mismatch'):
                self.verifier.verify(packet, ROOT)
            (packet / 'unexpected').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'file whitelist'):
                self.verifier.verify(packet, ROOT)


if __name__ == '__main__':
    unittest.main()
