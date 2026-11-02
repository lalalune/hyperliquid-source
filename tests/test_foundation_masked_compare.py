"""Target-grounded rule, decoder, metadata and corruption controls; no objdump."""
import copy
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import random
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import foundation_masked_compare as bind


class MaskedCompareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = (ROOT / bind.TARGET).open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        cls.image = bind.Image(cls.data)
        cls.records, cls.walk, cls.callers = bind.collect(cls.image)
        cls.body = cls.image.read(bind.START, bind.END-bind.START)
        cls.instructions = bind.decode(cls.body, bind.START)
        cls.packet = ROOT / bind.PACKET

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def test_authentic_packet_reproduces(self):
        bind.check_packet(ROOT / bind.TARGET, self.packet)

    def test_generator_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            bind.generate(ROOT / bind.TARGET, out)
            for name in (*bind.PACKET_FILES, 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (self.packet / name).read_bytes(), name)

    def test_readme_counts_equal_json(self):
        records = json.loads((self.packet / 'records.json').read_text())
        self.assertEqual(records, self.records)
        self.assertEqual((self.packet / 'README.md').read_text(), bind.readme(records))
        counts = records['counts']
        self.assertEqual(counts['instructions'], len(self.instructions))
        self.assertEqual(counts['body_bytes'], sum(i['size'] for i in self.instructions))
        self.assertEqual(counts['vectors'], len(records['rule']['vectors']))
        self.assertEqual(counts['direct_call_sites'], len(records['incoming']['sites']))
        self.assertEqual(counts['callees'], len(records['callees']))

    def test_all_control_flow_is_internal_and_no_callees(self):
        reachable = bind.validate_cfg(self.instructions)
        self.assertEqual(len(reachable), self.records['counts']['reachable_instructions'])
        self.assertTrue(all(i['op'] == 'nop' or i['va'] in reachable for i in self.instructions))
        self.assertFalse(any(i['op'] in ('call', 'call_slot') for i in self.instructions))
        self.assertEqual(self.records['function']['padding_bytes'], 0)

    def test_fixed_target_grounded_vectors(self):
        for v in self.records['rule']['vectors']:
            with self.subTest(name=v['name']):
                args = (bytes.fromhex(v['haystack_hex']), bytes.fromhex(v['needle_hex']),
                        v['offset'], v['mask'], v['guard'])
                self.assertEqual(bind.interpret(self.instructions, *args)['al'], v['expected_al'])
                self.assertEqual(int(bind.predicate(*args)), v['expected_al'])

    def test_every_candidate_bit_and_length_boundary(self):
        for length in range(18):
            needle = bytes(range(1, length+1))
            for bit in range(16):
                hay = bytearray(b'\xff' * (32+length))
                hay[bit+1:bit+1+length] = needle
                with self.subTest(length=length, bit=bit):
                    result = bind.interpret(self.instructions, bytes(hay), needle, 0, 1 << bit)
                    self.assertEqual(result['al'], 1)
                    if length:
                        self.assertEqual(result['reads'][3][0], 0x100000+bit+1)

    def test_each_needle_byte_is_compared_without_overread(self):
        for length in range(1, 34):
            needle = bytes(range(length))
            for position in range(length):
                hay = bytearray(b'!' + needle)
                hay[position+1] ^= 0x80
                # The only readable haystack bytes end exactly at the candidate
                # end: a rounded-up terminal word load would fail this test.
                result = bind.interpret(self.instructions, bytes(hay), needle, 0, 1)
                self.assertEqual(result['al'], 0, (length, position))
            self.assertEqual(bind.interpret(self.instructions, b'!'+needle, needle, 0, 1)['al'], 1)

    def test_sparse_mask_order_and_later_match(self):
        hay = b'x'*6 + b'abc' + b'x'*30
        result = bind.interpret(self.instructions, hay, b'abc', 0, (1 << 1) | (1 << 5) | (1 << 15))
        self.assertEqual(result['al'], 1)
        candidate_reads = [address for address, _ in result['reads'] if 0x100000 <= address < 0x200000]
        self.assertEqual(candidate_reads, [0x100002, 0x100006, 0x100007, 0x100008])

    def test_random_rule_crosscheck_and_instruction_coverage(self):
        rng, visited = random.Random(1407), set()
        for _ in range(600):
            length = rng.randrange(34)
            needle = bytes(rng.randrange(4) for _ in range(length))
            hay = bytearray(rng.randrange(4) for _ in range(90))
            offset, mask, guard = rng.randrange(5), rng.getrandbits(32), rng.randrange(5) == 0
            if rng.randrange(2):
                bit = rng.randrange(16)
                mask |= 1 << bit
                hay[offset+1+bit:offset+1+bit+length] = needle
            result = bind.interpret(self.instructions, bytes(hay), needle, offset, mask, int(guard))
            self.assertEqual(result['al'], int(bind.predicate(bytes(hay), needle, offset, mask, int(guard))))
            visited.update(result['visited'])
        for v in self.records['rule']['vectors']:
            result = bind.interpret(self.instructions, bytes.fromhex(v['haystack_hex']),
                                    bytes.fromhex(v['needle_hex']), v['offset'], v['mask'], v['guard'])
            visited.update(result['visited'])
        self.assertEqual(visited, bind.validate_cfg(self.instructions))

    def test_guard_returns_without_any_memory_reads(self):
        result = bind.interpret(self.instructions, b'', b'abcdef', -100, 0, 1)
        self.assertEqual((result['al'], result['rax'], result['reads']), (0, 0, []))

    def test_empty_needle_only_reads_descriptor(self):
        result = bind.interpret(self.instructions, b'', b'', 0, 0)
        self.assertEqual(result['al'], 1)
        self.assertEqual(result['reads'], [(0x300000, 8), (0x300010, 8), (0x300018, 8)])

    def test_true_result_is_not_canonical_rax_boolean(self):
        result = bind.interpret(self.instructions, b'xabc', b'abc', 0, 1)
        self.assertEqual(result['al'], 1)
        self.assertNotEqual(result['rax'], 1)

    def test_unreadable_model_memory_fails(self):
        with self.assertRaisesRegex(ValueError, 'unmapped synthetic read'):
            bind.interpret(self.instructions, b'x', b'abc', 0, 1)
        with self.assertRaisesRegex(ValueError, 'not readable'):
            bind.predicate(b'x', b'abc', 0, 1)

    def test_wrong_digest_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'digest/size'):
            bind.Image(b'\x7fELFwrong')

    def test_mutated_window_in_copy_on_write_binary_is_rejected(self):
        # A second virtual mapping dirties a page, not a copied 90 MB bytearray.
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as damaged:
            off = int(self.records['function']['file_offset'], 16)
            damaged[off] ^= 1
            with self.assertRaisesRegex(ValueError, 'digest/size'):
                bind.Image(damaged)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), bind.DIGEST)

    def test_body_digest_is_checked_below_artifact_gate(self):
        original = self.image.read
        def damaged(va, size):
            raw = original(va, size)
            return bytes([raw[0] ^ 1]) + raw[1:] if va == bind.START else raw
        with patch.object(self.image, 'read', damaged):
            with self.assertRaisesRegex(ValueError, 'body digest'):
                bind.collect(self.image)

    def test_decoder_refuses_unknown_and_truncated_encodings(self):
        for bad in (b'\x90', b'\xe8\x00', b'\x0f\x84', b'\x66\xb8', b'\x48\x8b', b'\x0f\x0b'):
            with self.subTest(raw=bad.hex()), self.assertRaises(ValueError):
                bind.decode(bad, bind.START)

    def test_shifted_branch_into_instruction_is_rejected(self):
        damaged = bytearray(self.body)
        damaged[3] += 1  # entry JE now lands inside mov rax,[rdi]
        with self.assertRaisesRegex(ValueError, 'boundaries|target'):
            bind.validate_cfg(bind.decode(damaged, bind.START))

    def test_wrong_caller_target_is_rejected(self):
        original = self.image.read
        def damaged(va, size):
            raw = original(va, size)
            if va == bind.CONTEXTS[0][0]:
                raw = bytearray(raw)
                raw[-4] ^= 1
                return bytes(raw)
            return raw
        with patch.object(self.image, 'read', damaged):
            with self.assertRaisesRegex(ValueError, 'caller target'):
                bind.collect(self.image)

    def test_shifted_fde_start_is_rejected(self):
        frames = [dict(f) for f in self.image.frames]
        next(f for f in frames if f['start'] == bind.START)['start'] += 1
        with patch.object(self.image, 'frames', frames):
            with self.assertRaisesRegex(ValueError, 'FDE start'):
                bind.collect(self.image)

    def test_shifted_fde_end_is_rejected(self):
        frames = [dict(f) for f in self.image.frames]
        next(f for f in frames if f['start'] == bind.START)['end'] += 1
        with patch.object(self.image, 'frames', frames):
            with self.assertRaisesRegex(ValueError, 'FDE extent'):
                bind.collect(self.image)

    def test_wrong_cie_association_is_rejected(self):
        frames = [dict(f) for f in self.image.frames]
        replacement = next(f['cie'] for f in frames if f['cie'] != 0xCE1518)
        next(f for f in frames if f['start'] == bind.START)['cie'] = replacement
        with patch.object(self.image, 'frames', frames):
            with self.assertRaisesRegex(ValueError, 'FDE/CIE'):
                bind.collect(self.image)

    def test_wrong_location_relocation_is_rejected(self):
        original = self.image.relocation
        def damaged(slot):
            record = original(slot)
            record['addend_va'] = hex(int(record['addend_va'], 16)+1)
            return record
        with patch.object(self.image, 'relocation', damaged):
            with self.assertRaisesRegex(ValueError, 'source path'):
                bind.collect(self.image)

    def test_full_text_call_scan_and_last_possible_site(self):
        calls = bind.scan_callers(self.data, self.image.section('.text'), bind.START)
        self.assertEqual(calls, self.records['incoming']['sites'])
        synthetic = b'junk' + b'\xe8' + struct.pack('<i', 100-(4+5))
        self.assertEqual(bind.scan_callers(synthetic, {'offset': 0, 'address': 0, 'size': 9}, 100),
                         [{'site_va': '0x4', 'opcode': '0xe8', 'target_va': '0x64'}])

    def test_semantic_record_corruption_even_with_updated_manifest(self):
        for change in ('callee', 'caller', 'fde', 'body', 'vector'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                packet = Path(tmp) / 'packet'
                shutil.copytree(self.packet, packet, ignore=shutil.ignore_patterns('__pycache__'))
                record = copy.deepcopy(self.records)
                if change == 'callee':
                    record['callees'] = [{'target_va': '0x1'}]
                elif change == 'caller':
                    record['incoming']['sites'].pop()
                elif change == 'fde':
                    record['function']['fde_section_offset'] = '0x7a71'
                elif change == 'body':
                    record['function']['sha256'] = '0'*64
                else:
                    record['rule']['vectors'][0]['expected_al'] = 0
                (packet / 'records.json').write_bytes(bind.canonical_json(record))
                (packet / 'MANIFEST.sha256').write_bytes(bind.manifest(packet))
                with self.assertRaisesRegex(ValueError, 'records.json mismatch'):
                    bind.check_packet(ROOT / bind.TARGET, packet)

    def test_readme_and_instruction_edits_are_rejected(self):
        for name in ('README.md', 'instructions.txt', 'callers.txt'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                packet = Path(tmp) / 'packet'
                shutil.copytree(self.packet, packet, ignore=shutil.ignore_patterns('__pycache__'))
                with (packet / name).open('ab') as handle:
                    handle.write(b'edited\n')
                (packet / 'MANIFEST.sha256').write_bytes(bind.manifest(packet))
                with self.assertRaisesRegex(ValueError, 'regenerated'):
                    bind.check_packet(ROOT / bind.TARGET, packet)

    def test_manifest_whitelist_rejects_omission_duplicate_and_traversal(self):
        spec = importlib.util.spec_from_file_location('masked_verify', self.packet / 'verify.py')
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        original = (self.packet / 'MANIFEST.sha256').read_text()
        for text in (original.split('\n', 1)[1], original+original.splitlines()[0]+'\n',
                     original+'0'*64+'  ../escape\n', original.replace(original[:64], '0'*64, 1)):
            with tempfile.TemporaryDirectory() as tmp:
                packet = Path(tmp)
                (packet / 'MANIFEST.sha256').write_text(text)
                with patch.object(verifier, 'PACKET', packet):
                    with self.assertRaises(ValueError):
                        verifier.verify_manifest()

    def test_extra_packet_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / 'packet'
            shutil.copytree(self.packet, packet, ignore=shutil.ignore_patterns('__pycache__'))
            (packet / 'unexpected').write_text('x')
            with self.assertRaisesRegex(ValueError, 'whitelist'):
                bind.check_packet(ROOT / bind.TARGET, packet)


if __name__ == '__main__':
    unittest.main()
