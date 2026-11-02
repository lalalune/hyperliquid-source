"""Static controls for the node #94 addition bind; never execute the artifact."""
import copy
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import u256_add_carry as bind


class U256AddCarryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = bind.BINARY.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        cls.records, cls.instructions, cls.context, _ = bind.derive(cls.data)
        cls.generated = bind.artifact_bytes(cls.data)
        cls.secs = bind.sections(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    def fixture(self, a, b, output=192, left=32, right=96):
        memory = bytearray(b'\xa5' * 288)
        memory[left:left + 32] = a.to_bytes(32, 'little')
        memory[right:right + 32] = b.to_bytes(32, 'little')
        before = bytes(memory)
        registers, writes = bind.execute_leaf(self.instructions, memory, output, left, right)
        return memory, before, registers, writes

    def compare(self, a, b):
        total, overflow = bind.add256(a, b)
        memory, before, registers, writes = self.fixture(a, b)
        self.assertEqual(memory[32:64], total.to_bytes(32, 'little'))
        self.assertEqual(memory[96:128], b.to_bytes(32, 'little'))
        self.assertEqual(memory[192:225], total.to_bytes(32, 'little') + bytes([overflow]))
        self.assertEqual(registers[0], total >> 192)
        self.assertEqual(writes, [(32, 8), (40, 8), (48, 8), (56, 8),
                                  (192, 16), (208, 8), (216, 8), (224, 1)])
        changed = set(range(32, 64)) | set(range(192, 225))
        self.assertTrue(all(memory[i] == before[i] for i in range(len(memory)) if i not in changed))

    def test_byte_identical_regeneration(self):
        for name, contents in self.generated.items():
            with self.subTest(name=name):
                self.assertEqual((bind.PACKET / name).read_bytes(), contents)

    def test_complete_packet_verifies(self):
        bind.verify_packet(bind.PACKET)

    def test_readme_counts_equal_json(self):
        records = json.loads((bind.PACKET / 'records.json').read_text())
        text = (bind.PACKET / 'README.md').read_text()
        self.assertEqual(text, bind.readme(records))
        counts = records['counts']
        rows = dict(re.findall(r'^\| ([^|]+?) \| (\d+) \|$', text, re.MULTILINE))
        names = {'Body bytes': 'body_bytes', 'Decoded instructions': 'instructions',
                 'Padding bytes': 'padding_bytes', 'Callees': 'callees',
                 'Direct call sites': 'direct_calls', 'Direct tail-jump sites': 'direct_tail_jumps',
                 'Model vectors': 'vectors'}
        self.assertEqual({names[k]: int(v) for k, v in rows.items()}, counts)
        self.assertEqual(counts['body_bytes'], sum(len(i.raw) for i in self.instructions))
        self.assertEqual(counts['instructions'], len(self.instructions))
        self.assertEqual(counts['callees'], len(records['callees']))
        self.assertEqual(counts['vectors'], len(records['vectors']))
        for kind, key in [('call', 'direct_calls'), ('jmp', 'direct_tail_jumps')]:
            self.assertEqual(counts[key], sum(s['kind'] == kind for s in records['incoming']['sites']))

    def test_instruction_stream_covers_whole_fde(self):
        cursor = bind.START
        for instruction in self.instructions:
            self.assertEqual(instruction.va, cursor)
            cursor += len(instruction.raw)
        self.assertEqual(cursor, bind.END)
        self.assertEqual(self.instructions[-1].op, 'ret')
        self.assertFalse(any(i.op in ('call', 'jmp', 'jne') for i in self.instructions))

    def test_target_grounded_vectors(self):
        for vector in self.records['vectors']:
            with self.subTest(case=vector['case']):
                a, b = int(vector['left'], 16), int(vector['right'], 16)
                self.assertEqual(bind.add256(a, b),
                                 (int(vector['sum_mod_2_256'], 16), vector['overflow']))
                self.compare(a, b)

    def test_all_zero_or_maximal_limb_pairs(self):
        values = [sum(limb << (64 * i) for i, limb in enumerate(parts))
                  for parts in itertools.product((0, bind.MASK64), repeat=4)]
        for a, b in itertools.product(values, repeat=2):
            self.compare(a, b)

    def test_reproducible_broader_operands(self):
        rng = random.Random(0x1EB3C40)
        for _ in range(256):
            self.compare(rng.getrandbits(256), rng.getrandbits(256))

    def test_unaligned_disjoint_regions(self):
        a, b = bind.MASK256, 1
        memory, _, _, _ = self.fixture(a, b, output=193, left=33, right=97)
        self.assertEqual(memory[33:65], bytes(32))
        self.assertEqual(memory[193:226], bytes(32) + b'\x01')

    def test_equal_input_addresses_machine_control(self):
        a = (1 << 255) + 0x5555
        memory, _, _, _ = self.fixture(a, a, left=32, right=32)
        total, carry = bind.add256(a, a)
        self.assertEqual(memory[192:225], total.to_bytes(32, 'little') + bytes([carry]))

    def test_output_equal_left_machine_control(self):
        memory, _, _, _ = self.fixture(bind.MASK256, 1, output=32)
        self.assertEqual(memory[32:65], bytes(32) + b'\x01')

    def test_output_equal_right_machine_control(self):
        memory, _, _, _ = self.fixture(bind.MASK256, 1, output=96)
        self.assertEqual(memory[96:129], bytes(32) + b'\x01')

    def test_partial_overlap_is_outside_integer_rule(self):
        a = sum(limb << (64 * i) for i, limb in enumerate((1, 2, 3, 4)))
        memory, _, _, _ = self.fixture(a, 0, output=40)
        self.assertNotEqual(memory[40:72], a.to_bytes(32, 'little'))
        self.assertEqual(struct.unpack('<QQQQ', memory[40:72]), (1, 2, 2, 2))

    def test_model_rejects_non_u256_inputs(self):
        for value in (-1, 1 << 256, True, 1.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bind.add256(value, 0)

    def test_decoder_rejects_unknown_and_truncated_forms(self):
        for raw in (b'\x90', b'\x48', b'\x48\x8b', b'\x48\x8b\x42',
                    b'\x0f\x92\xe0', b'\x88\xe0', b'\x88\x20', b'\x48\x8b\x04\x00',
                    b'\x48\xe8\x00\x00\x00\x00', b'\x0f\x0b'):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                bind.decode(raw, bind.START)

    def test_every_instruction_truncation_fails_closed(self):
        for instruction in self.instructions + self.context:
            for length in range(1, len(instruction.raw)):
                with self.subTest(va=hex(instruction.va), length=length), self.assertRaises(ValueError):
                    bind.decode(instruction.raw[:length], instruction.va)

    def test_scan_signed_edges_and_last_possible_site(self):
        # A nonzero section file offset distinguishes VA from file coordinates.
        text = {'offset': 7, 'address': 0x1000, 'size': 27}
        blob = bytearray(b'\x90' * 34)
        for offset, opcode in ((0, 0xE8), (10, 0xE9), (22, 0xE8)):
            blob[7 + offset:12 + offset] = bytes([opcode]) + struct.pack('<i', 0x100F - (0x1000 + offset + 5))
        result = bind.scan_incoming(blob, text, 0x100F)
        self.assertEqual([(x['site'], x['kind']) for x in result],
                         [('0x1000', 'call'), ('0x100a', 'jmp'), ('0x1016', 'call')])

    def test_wrong_binary_digest(self):
        with self.assertRaisesRegex(ValueError, 'digest/size'):
            bind.authenticate(b'wrong artifact')

    def changed_image(self, offset, raw):
        # Copy-on-write mmap changes a page, never duplicates the entire image.
        image = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        image[offset:offset + len(raw)] = raw
        self.addCleanup(image.close)
        return image

    def test_mutated_window_byte_even_valid_opcode_rejected(self):
        text = next(s for s in self.secs if s['name'] == '.text')
        off = text['offset'] + bind.START - text['address'] + 11
        self.assertEqual(self.data[off], 0x11)  # ADC becomes ADD, losing low-limb carry.
        image = self.changed_image(off, b'\x01')
        with self.assertRaisesRegex(ValueError, 'digest/size'):
            bind.derive(image)
        raw = bind.read_va(image, self.secs, bind.START, bind.END - bind.START)
        memory = bytearray(288)
        memory[32:64] = bind.MASK64.to_bytes(32, 'little')
        memory[96:128] = (1).to_bytes(32, 'little')
        bind.execute_leaf(bind.decode(raw, bind.START), memory, 192, 32, 96)
        self.assertNotEqual(int.from_bytes(memory[192:224], 'little'), bind.MASK64 + 1)

    def test_shifted_actual_fde(self):
        frame = next(s for s in self.secs if s['name'] == '.eh_frame')
        off = frame['offset'] + int(self.records['function']['fde_section_offset'], 16) + 8
        delta = struct.unpack_from('<i', self.data, off)[0]
        image = self.changed_image(off, struct.pack('<i', delta + 1))
        _, fdes = bind.eh_frame_records(image, self.secs)
        with self.assertRaisesRegex(ValueError, 'FDE start'):
            bind.frame_record(image, self.secs, fdes, bind.START)
        with self.assertRaisesRegex(ValueError, 'digest/size'):
            bind.derive(image)

    def test_wrong_callee_target_in_actual_call(self):
        text = next(s for s in self.secs if s['name'] == '.text')
        off = text['offset'] + bind.CALL_SITE - text['address']
        raw = bytes([0xE8]) + struct.pack('<i', bind.START + 16 - bind.CALL_SITE - 5)
        image = self.changed_image(off, raw)
        self.assertEqual(bind.decode(raw, bind.CALL_SITE)[0].operands[0].value, bind.START + 16)
        context = bind.read_va(image, self.secs, bind.CONTEXT_START,
                               bind.CONTEXT_END - bind.CONTEXT_START)
        with self.assertRaisesRegex(ValueError, 'wrong callee target'):
            bind.decode_context(context)
        with self.assertRaisesRegex(ValueError, 'digest/size'):
            bind.derive(image)

    def temporary_packet(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        packet = Path(directory.name)
        for name in bind.PACKET_FILES | {'MANIFEST.sha256'}:
            shutil.copyfile(bind.PACKET / name, packet / name)
        return packet

    def rehash_changed_file(self, packet, name):
        manifest = packet / 'MANIFEST.sha256'
        lines = manifest.read_text().splitlines()
        manifest.write_text('\n'.join(f'{bind.digest((packet / name).read_bytes())}  {name}'
                                      if line.endswith('  ' + name) else line for line in lines) + '\n')

    def test_semantic_corruption_rejected_even_with_rehashed_manifest(self):
        paths = [(['target', 'sha256'], '0' * 64),
                 (['function', 'fde_section_offset'], '0x438c1'),
                 (['function', 'cie_section_offset'], '0x2dc714'),
                 (['function', 'end_exclusive'], hex(bind.END + 1)),
                 (['function', 'body_sha256'], 'f' * 64),
                 (['function', 'padding', 'bytes'], 8),
                 (['incoming', 'sites', 0, 'target'], hex(bind.START + 16)),
                 (['incoming', 'sites'], []),
                 (['caller', 'location', 'line'], 159),
                 (['rule', 'input_left_mutated'], False),
                 (['vectors', 3, 'overflow'], 0)]
        packet = self.temporary_packet()
        for path, value in paths:
            with self.subTest(path=path):
                records = copy.deepcopy(self.records)
                node = records
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
                (packet / 'records.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n')
                self.rehash_changed_file(packet, 'records.json')
                with self.assertRaisesRegex(ValueError, 'regenerated evidence differs'):
                    bind.verify_packet(packet)

    def test_readme_corruption_rejected_even_with_rehashed_manifest(self):
        packet = self.temporary_packet()
        path = packet / 'README.md'
        path.write_text(path.read_text().replace('| Body bytes | 103 |', '| Body bytes | 104 |'))
        self.rehash_changed_file(packet, 'README.md')
        with self.assertRaisesRegex(ValueError, 'regenerated evidence differs'):
            bind.verify_packet(packet)

    def test_manifest_whitelist_rejects_injection_omission_duplicate(self):
        packet = self.temporary_packet()
        path = packet / 'MANIFEST.sha256'
        good = path.read_text()
        for bad in (good + '0' * 64 + '  ../../unexpected\n',
                    '\n'.join(good.splitlines()[1:]) + '\n',
                    good + good.splitlines()[0] + '\n'):
            with self.subTest(manifest=bad[-80:]):
                path.write_text(bad)
                with self.assertRaises(ValueError):
                    bind.verify_manifest(packet)

    def test_extra_packet_file_rejected(self):
        packet = self.temporary_packet()
        (packet / 'untracked.txt').write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'filename whitelist'):
            bind.verify_packet(packet)

    def test_exported_evidence_has_no_local_environment_strings(self):
        for name, raw in self.generated.items():
            with self.subTest(name=name):
                self.assertNotIn(b'/workspace/', raw)
                self.assertNotIn(b'/home/', raw)
                self.assertNotIn(b'PATH=', raw)
                self.assertNotRegex(raw.decode(), r'\b20\d\d-\d\d-\d\d[T ]\d\d:')


if __name__ == '__main__':
    unittest.main()
