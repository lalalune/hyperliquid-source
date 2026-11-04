"""Focused static and synthetic controls for the node 115 result path."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_result_digest115 as m
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

MASK = (1 << 64) - 1
ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def reference_round_constants():
    """Generate Keccak iota constants from the independent 8-bit LFSR rule."""
    lfsr = 1
    constants = []
    for _ in range(24):
        word = 0
        for j in range(7):
            if lfsr & 1:
                word ^= 1 << ((1 << j) - 1)
            lfsr = ((lfsr << 1) ^ (0x71 if lfsr & 0x80 else 0)) & 0xff
        constants.append(word)
    return constants


def rol(value, count):
    return ((value << count) | (value >> (64 - count))) & MASK if count else value


def synthetic_keccak256(message):
    """Independent mathematical model, not execution of any target instruction."""
    rate = 136
    padded = bytearray(message)
    padded.append(1)
    padded.extend(bytes((-len(padded)) % rate))
    padded[-1] ^= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], 'little')
        for rc in reference_round_constants():
            parity = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                      for x in range(5)]
            for x in range(5):
                d = parity[(x - 1) % 5] ^ rol(parity[(x + 1) % 5], 1)
                for y in range(5):
                    state[x + 5 * y] ^= d
            rotated = [0] * 25
            for x in range(5):
                for y in range(5):
                    rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rol(state[x + 5 * y], ROT[x][y])
            for y in range(5):
                for x in range(5):
                    state[x + 5 * y] = rotated[x + 5 * y] ^ (
                        (~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y])
            state[0] ^= rc
    return b''.join(v.to_bytes(8, 'little') for v in state)[:32]


class StaticEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing artifacts are test errors, never skips.
        cls.data = bytearray(m.TARGET.read_bytes())
        cls.secs, cls.indices = unwind_index(cls.data)
        _, cls.fdes = eh_frame_records(cls.data, cls.secs)
        cls.artifacts = m.analyze(cls.data)
        cls.facts = json.loads(cls.artifacts['facts.json'])
        cls.schema = cls.facts['serializer']

    def test_target_and_inventory(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.DIGEST)
        summary = json.loads(self.artifacts['summary.json'])
        self.assertEqual(summary['selected_fde_count'], 15)
        self.assertEqual(summary['round_constant_count'], 24)
        self.assertEqual(summary['context_window_count'], 21)
        self.assertEqual(summary['literal_count'], 3)

    def test_bad_digest_has_no_output(self):
        with tempfile.TemporaryDirectory() as td:
            destination = Path(td) / 'evidence'
            self.data[0] ^= 1
            try:
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    m.generate(self.data, destination)
            finally:
                self.data[0] ^= 1
            self.assertFalse(destination.exists())

    def test_truncated_input_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as td:
            destination = Path(td) / 'evidence'
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                m.generate(self.data[:-1], destination)
            self.assertFalse(destination.exists())

    def test_every_pinned_window_detects_byte_corruption(self):
        for label, _, start, _, _ in m.WINDOWS:
            off = m.map_range(self.secs, start, 1, True)
            self.data[off] ^= 1
            try:
                with self.subTest(window=label), self.assertRaises(ValueError):
                    m.validate_windows(self.data, self.secs)
            finally:
                self.data[off] ^= 1

    def test_body_corruption_outside_selected_window_is_detected(self):
        # The last byte of this FDE is outside its selected windows.
        _, _, end, _ = m.FUNCTIONS[0]
        off = m.map_range(self.secs, end - 1, 1, True)
        self.data[off] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, 'extent hash'):
                m.function_records(self.data, self.secs, self.indices, self.fdes)
        finally:
            self.data[off] ^= 1

    def test_fde_extent_mismatch_is_rejected(self):
        start = m.FUNCTIONS[0][1]
        changed = [dict(f) if f['start'] == start else f for f in self.fdes]
        next(f for f in changed if f['start'] == start)['end'] -= 1
        with self.assertRaisesRegex(ValueError, 'FDE/header'):
            m.function_records(self.data, self.secs, self.indices, changed)

    def test_foreign_overlapping_fde_is_rejected(self):
        start = m.FUNCTIONS[0][1]
        other = {'start': start + 1, 'end': start + 3, 'fde': 0xffff, 'cie': 0, 'lsda': None}
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            m.function_records(self.data, self.secs, self.indices, self.fdes + [other])

    def test_selected_unwind_header_link_mismatch_is_rejected(self):
        start = m.FUNCTIONS[0][1]
        changed = [dict(e) if e['start'] == start else e for e in self.indices]
        next(e for e in changed if e['start'] == start)['fde'] += 4
        with self.assertRaisesRegex(ValueError, 'FDE/header'):
            m.function_records(self.data, self.secs, changed, self.fdes)

    def test_section_mapping_rejects_nobits_ambiguity_and_boundaries(self):
        section = {'type': 1, 'flags': 4, 'address': 100, 'offset': 20, 'size': 10}
        self.assertEqual(m.map_range([section], 109, 1, True), 29)
        for address, size in ((99, 1), (109, 2), (100, 0), (-1, 1)):
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                m.map_range([section], address, size, True)
        nobits = dict(section, type=8)
        with self.assertRaises(ValueError):
            m.map_range([nobits], 100, 1)
        with self.assertRaises(ValueError):
            m.map_range([section, dict(section)], 100, 1)
        with self.assertRaises(ValueError):
            m.map_range([dict(section, flags=2)], 100, 1, True)

    def test_relocation_duplicate_wrong_type_and_truncation(self):
        good = struct.pack('<QQq', 0x100, 8, 0x200)
        desc = {'type': 4, 'offset': 0, 'size': len(good)}
        self.assertEqual(m.read_relative_relocations(good, desc, {0x100: 0x200})[0x100]['addend'], 0x200)
        for payload, sec, expected in (
            (good + good, dict(desc, size=48), {0x100: 0x200}),
            (struct.pack('<QQq', 0x100, 7, 0x200), desc, {0x100: 0x200}),
            (struct.pack('<QQq', 0x100, (1 << 32) | 8, 0x200), desc, {0x100: 0x200}),
            (good[:-1], desc, {0x100: 0x200}),
            (good, dict(desc, size=23), {0x100: 0x200}),
            (good, desc, {0x100: 0x201}),
            (good, desc, {0x101: 0x200}),
            (good, dict(desc, type=8), {0x100: 0x200}),
        ):
            with self.subTest(payload=payload.hex(), size=sec['size'], expected=expected), self.assertRaises(ValueError):
                m.read_relative_relocations(payload, sec, expected)

    def test_wrong_transfer_opcode_is_rejected(self):
        site = 0x4e36b48
        off = m.map_range(self.secs, site, 1, True)
        self.data[off] = 0xe9
        try:
            with self.assertRaisesRegex(ValueError, 'opcode'):
                m.relative_target(self.data, self.secs, site, 'e8')
        finally:
            self.data[off] = 0xe8

    def test_wrong_branch_opcode_is_rejected(self):
        site = 0x5a6ec82
        off = m.map_range(self.secs, site, 1, True)
        self.data[off] = 0x77
        try:
            with self.assertRaisesRegex(ValueError, 'opcode'):
                m.branch_target(self.data, self.secs, site, '76')
        finally:
            self.data[off] = 0x76

    def test_periodic_predicate_against_remainder_and_neighbours(self):
        pred = self.facts['period_predicate']
        multiplier, limit = int(pred['multiplier'], 16), int(pred['unsigned_limit'], 16)
        self.assertEqual(multiplier * pred['period'] & MASK, 1)
        self.assertEqual(limit, MASK // pred['period'])
        values = list(range(100_000)) + list(range(MASK - 100_000, MASK + 1))
        for k in (0, 1, 2, 99, 10000, MASK // 11 - 1, MASK // 11):
            values.extend(v for v in (11 * k - 1, 11 * k, 11 * k + 1) if 0 <= v <= MASK)
        for value in values:
            self.assertEqual(m.is_periodic(value, multiplier, limit), value % 11 == 0, value)
        with self.assertRaises(ValueError):
            m.is_periodic(-1, multiplier, limit)
        with self.assertRaises(ValueError):
            m.is_periodic(1 << 64, multiplier, limit)
        self.assertNotEqual(m.is_periodic(11, multiplier ^ 1, limit), 11 % 11 == 0)

    def test_array_header_boundaries(self):
        cases = {
            0: '90', 1: '91', 15: '9f', 16: 'dc0010', 17: 'dc0011',
            65535: 'dcffff', 65536: 'dd00010000', 0xffffffff: 'ddffffffff',
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(m.header_bytes(value, self.schema).hex(), expected)
        for invalid in (-1, 1 << 32):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                m.header_bytes(invalid, self.schema)

    def test_array_header_negative_control(self):
        bad = dict(self.schema, array16_marker=self.schema['array16_marker'] ^ 1)
        self.assertNotEqual(m.header_bytes(16, bad), bytes.fromhex('dc0010'))

    def test_postblock_collection_layout(self):
        item = self.facts['postblock_state_collection']
        self.assertEqual(item['callback_subobject_offset'], 0x2a0)
        self.assertEqual(item['owner_state_slot_offset'], 0xb00)
        self.assertEqual((item['owner_guard_offset'], item['owner_guard_value']), (0x128, 1000000000))
        self.assertEqual((item['first_state_container_offset'], item['second_state_container_offset']),
                         (0x1a48, 0x1940))
        self.assertEqual((item['first_source_stride'], item['second_source_stride']), (32, 80))
        self.assertEqual((item['first_collected_stride'], item['second_collected_stride']), (32, 64))
        self.assertEqual((item['first_watermark_in_callback'], item['second_watermark_in_callback']),
                         (0x570, 0x578))
        self.assertEqual(item['callback_subobject_offset'] + item['first_watermark_in_subobject'],
                         item['first_watermark_in_callback'])
        self.assertEqual(item['callback_subobject_offset'] + item['second_watermark_in_subobject'],
                         item['second_watermark_in_callback'])

    def test_postblock_watermark_prefix_models(self):
        # Synthetic model for the second stream; the first stream corresponds
        # to all rows being present. Later keys are not considered after stop.
        def update(old, rows):
            selected = []
            for key, present in rows:
                if key <= old:
                    break
                if present:
                    selected.append(key)
            return max(selected, default=old)
        cases = [
            (10, [], 10),
            (10, [(10, True), (99, True)], 10),
            (10, [(12, True), (15, True), (10, True), (99, True)], 15),
            (10, [(15, False), (12, True), (11, False)], 12),
            (10, [(15, False), (12, False)], 10),
            (MASK, [(MASK, True)], MASK),
            (MASK - 2, [(MASK, True), (MASK - 1, True)], MASK),
        ]
        for old, rows, expected in cases:
            with self.subTest(old=old, rows=rows):
                self.assertEqual(update(old, rows), expected)
        self.assertNotEqual(update(10, [(12, True), (9, True), (99, True)]), 99)
        self.assertNotEqual(update(10, [(15, False)]), 15)

    def test_unequal_qword_order_selects_larger_key(self):
        # The two comparators' first-key bytes produce -1, 0, or 1. The
        # remaining tie-breaker can change which row wins, not its first key.
        for left in (0, 1, 11, 1 << 63, MASK):
            for right in (0, 1, 11, 1 << 63, MASK):
                order = int(left > right) - int(left < right)
                chosen = right if order <= 0 else left
                self.assertEqual(chosen, max(left, right))

    def test_context_to_result_offsets(self):
        flow = self.facts['height_handoff']
        self.assertEqual(flow['owner_state_slot_offset'], 0xb00)
        self.assertEqual(flow['expanded_state_height_offset'], 0x28)
        self.assertEqual(flow['upper_stack_height_offset'] - flow['upper_stack_record_base'],
                         flow['outer_result_height_offset'])
        self.assertEqual(flow['worker_height_load_stack_offset'] - flow['worker_output_stack_base'],
                         flow['outer_result_height_offset'])
        self.assertEqual(flow['outer_result_height_offset'], 0x18)
        self.assertEqual(flow['worker_vector_save_stack_offset'], 0x180)

    def test_configuration_and_nested_projection(self):
        s = self.schema
        self.assertEqual(s['configuration_bytes'], '0004000100')
        self.assertEqual((s['vector_pointer_offset'], s['vector_count_offset']), (8, 16))
        self.assertEqual((s['outer_row_stride'], s['nested_row_stride']), (56, 64))
        self.assertEqual((s['nested_pointer_offset'], s['nested_count_offset']), (40, 48))
        self.assertEqual((s['identifier_input_bytes'], s['identifier_rendered_bytes']), (32, 66))
        self.assertEqual((s['identifier_prefix_hex'], s['identifier_alphabet'], s['string8_marker']),
                         ('3078', '0123456789abcdef', 0xd9))
        self.assertEqual(s['outer_row_pair_marker'], 0x92)
        self.assertEqual((s['response_optional_user_offset'], s['response_absent_user_marker']), (40, 0xc0))

    def test_static_round_constants_match_independent_lfsr(self):
        _, observed, _ = m.facts(self.data, self.secs)
        self.assertEqual(observed, reference_round_constants())
        self.assertNotEqual([observed[0] ^ 1] + observed[1:], reference_round_constants())

    def test_independent_keccak_model_known_vectors(self):
        self.assertEqual(synthetic_keccak256(b'').hex(),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(synthetic_keccak256(b'abc').hex(),
                         '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
        self.assertNotEqual(synthetic_keccak256(b''), hashlib.sha3_256(b'').digest())
        self.assertEqual((self.facts['sponge']['rate_bytes'], self.facts['sponge']['domain_byte'],
                          self.facts['sponge']['output_bytes']), (136, 1, 32))

    def test_synthetic_empty_and_single_row_preimage(self):
        # Synthetic consequences of the checked serializer path; not target outputs.
        empty = m.header_bytes(0, self.schema)
        self.assertEqual(empty.hex(), self.schema['empty_outer_array_preimage_hex'])
        key = bytes(range(32))
        prefix = bytes([self.schema['outer_row_pair_marker'], 0xd9, 0x42])
        one = m.header_bytes(1, self.schema) + prefix + b'0x' + key.hex().encode('ascii') + m.header_bytes(0, self.schema)
        self.assertEqual(one.hex(), '9192d9423078' + key.hex().encode('ascii').hex() + '90')
        self.assertEqual(len(one), 71)
        self.assertNotEqual(synthetic_keccak256(empty), synthetic_keccak256(one))
        changed = one[:-2] + bytes([one[-2] ^ 1]) + one[-1:]
        self.assertNotEqual(synthetic_keccak256(one), synthetic_keccak256(changed))

    def test_historical_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'historical artifact SHA-256'):
            m.check_historical(b'not the retired artifact')

    def test_outputs_are_deterministic_and_do_not_embed_host_paths(self):
        for data in self.artifacts.values():
            self.assertTrue(data.endswith(b'\n'))
            for name in (b'srv', b'mnt', b'tmp', b'home', b'root', b'opt'):
                self.assertNotIn(b'/' + name + b'/', data)
        self.assertEqual(self.artifacts['location.json'], m.encode_json(json.loads(self.artifacts['location.json'])))


if __name__ == '__main__':
    unittest.main()
