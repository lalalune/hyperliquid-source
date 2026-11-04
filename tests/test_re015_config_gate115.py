"""Static, target-grounded controls for the RE-015 configuration path."""
import collections
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import re015_config_gate115 as gate


class OverrideRead:
    """Change one returned byte without modifying the authenticated capture."""
    def __init__(self, image, va):
        self.image = image
        self.va = va

    def __getattr__(self, name):
        return getattr(self.image, name)

    def read(self, va, size, executable=False):
        result = bytearray(self.image.read(va, size, executable))
        if va <= self.va < va + size:
            result[self.va - va] ^= 1
        return bytes(result)


class GateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = gate.CAPTURE.read_bytes()
        cls.image = gate.Image(cls.data)
        cls.frames, cls.decoded = gate.selected_frames(cls.image)
        cls.rows = gate.instruction_map(cls.decoded)
        cls.patterns = gate.field_patterns(cls.image, cls.rows)
        cls.chain_patterns = gate.chain_key_patterns(cls.image, cls.rows)
        cls.constants = gate.name_constants(cls.rows)

    def test_authenticated_binary_is_required(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), gate.DIGEST)
        with self.assertRaisesRegex(gate.EvidenceError, 'digest'):
            gate.Image(self.data, '0' * 64)
        damaged = bytearray(self.data)
        damaged[0] ^= 1
        with self.assertRaisesRegex(gate.EvidenceError, 'digest'):
            gate.Image(bytes(damaged))

    def test_reject_missing_and_ambiguous_mappings(self):
        im = self.image
        for addr, size in ((0, 1), (-1, 1), (1 << 63, 1), (0x154aa00, 0)):
            with self.subTest(addr=addr, size=size), self.assertRaises(gate.EvidenceError):
                im.offset(addr, size)
        bss = im.byname['.bss']
        with self.assertRaises(gate.EvidenceError):
            im.offset(bss['address'], min(16, bss['size']))
        copied = copy.copy(im)
        text = im.byname['.text']
        copied.secs = im.secs + [dict(text)]
        with self.assertRaisesRegex(gate.EvidenceError, 'ambiguous'):
            copied.offset(0x154aa00, 1, True)
        with self.assertRaises(gate.EvidenceError):
            im.offset(text['address'] + text['size'] - 1, 2, True)

    def test_selected_fde_hash_rejects_body_corruption(self):
        altered = OverrideRead(self.image, 0x154aa22)
        with self.assertRaisesRegex(gate.EvidenceError, 'body mismatch'):
            gate.selected_frames(altered)

    def test_selected_fde_requires_unique_actual_record(self):
        cie, fdes = gate.eh_frame_records(self.data, self.image.secs)
        row = next(v for v in fdes if v['start'] == 0x154aa00)
        with mock.patch.object(gate, 'eh_frame_records', return_value=(cie, fdes + [dict(row)])):
            with self.assertRaisesRegex(gate.EvidenceError, 'FDE mismatch'):
                gate.selected_frames(self.image)
        modified = [dict(x) for x in fdes]
        next(v for v in modified if v['start'] == 0x154aa00)['end'] += 1
        with mock.patch.object(gate, 'eh_frame_records', return_value=(cie, modified)):
            with self.assertRaisesRegex(gate.EvidenceError, 'FDE mismatch'):
                gate.selected_frames(self.image)

    def test_relocation_identity_and_dynamic_symbol(self):
        self.assertEqual(self.image.rel(0x64e1058)[3], 0x154aa00)
        self.assertEqual(self.image.dyn_symbol(0x64df508), 'memcpy')
        with self.assertRaises(gate.EvidenceError):
            self.image.rel(0x64e1058, 0x154aa01)
        with self.assertRaises(gate.EvidenceError):
            self.image.dyn_symbol(0x64e1058)
        with self.assertRaises(gate.EvidenceError):
            self.image.rel(1)

    def test_duplicate_or_truncated_relocation_section_is_rejected(self):
        fake = object.__new__(gate.Image)
        item = struct.pack('<QQq', 0x1234, 8, 42)
        fake.data = item * 2
        fake.byname = {'.rela.dyn': {'type': 4, 'offset': 0, 'size': len(fake.data)}}
        fake.relocations = None
        with self.assertRaisesRegex(gate.EvidenceError, 'duplicate'):
            fake.rela()
        fake.byname['.rela.dyn']['size'] -= 1
        with self.assertRaisesRegex(gate.EvidenceError, 'invalid'):
            fake.rela()

    def test_bad_dynamic_symbol_index_rejected(self):
        fake = copy.copy(self.image)
        fake.relocations = dict(self.image.rela())
        at, kind, _, addend = fake.relocations[0x64df508]
        fake.relocations[0x64df508] = (at, kind, 1 << 30, addend)
        with self.assertRaisesRegex(gate.EvidenceError, 'outside table'):
            fake.dyn_symbol(0x64df508)

    def test_exact_templates_and_nul_terminator(self):
        self.assertEqual(gate.template(self.image, 'cham', 0x44ab69, b'/cham')[3],
                         'c0052f6368616d00')
        self.assertEqual(gate.template(self.image, 'static', 0x4401ef, b'/static_config')[3],
                         'c00e2f7374617469635f636f6e66696700')
        with self.assertRaises(gate.EvidenceError):
            gate.template(OverrideRead(self.image, 0x44ab70), 'cham', 0x44ab69, b'/cham')
        with self.assertRaises(gate.EvidenceError):
            gate.template(self.image, 'cham', 0x44ab6b, b'/cham')

    def test_descriptor_is_relocation_and_length_bound(self):
        row = gate.descriptor(self.image, 'name-18', 0x63f88a8, b'Ee')
        self.assertEqual(row[6:8], (2, 'Ee'))
        with self.assertRaises(gate.EvidenceError):
            gate.descriptor(self.image, 'wrong', 0x63f88a8, b'Ed')
        with self.assertRaises(gate.EvidenceError):
            gate.descriptor(OverrideRead(self.image, 0x63f88b0), 'name', 0x63f88a8, b'Ee')

    def test_pins_reject_changed_instruction_and_branch(self):
        changed = dict(self.rows)
        changed[0x154aa22] = dict(changed[0x154aa22], bytes='83f811')
        with self.assertRaisesRegex(gate.EvidenceError, 'pin'):
            gate.verify_pins(changed)
        changed = dict(self.rows)
        changed[0x51d0a8b] = dict(changed[0x51d0a8b], bytes='7518')
        with self.assertRaisesRegex(gate.EvidenceError, 'pin'):
            gate.verify_pins(changed)

    def test_decoder_rejects_truncated_and_branch_into_operand(self):
        with self.assertRaises(gate.EvidenceError):
            gate.decode(bytes.fromhex('488b05'), 0x1000)
        with self.assertRaisesRegex(gate.EvidenceError, 'branch targets instruction interior'):
            gate.decode(bytes.fromhex('eb01b800000000c3'), 0x1000)
        with self.assertRaises(gate.EvidenceError):
            gate.decode(bytes.fromhex('0fff'), 0x1000)

    def test_rbp_writer_detection_covers_operand_directions(self):
        # Register-destination arithmetic and SIMD extraction would invalidate
        # the sentinel even though the modified register is not the r/m operand.
        for raw in ('4833eb', '4823eb', '0fd7e8', '660f7ec5'):
            with self.subTest(raw=raw):
                self.assertTrue(gate.possible_rbp_writes(
                    gate.decode(bytes.fromhex(raw), 0x1000)[0]))
        # A compare and a move from rbp read it without changing it.
        for raw in ('4839eb', '4889ef'):
            with self.subTest(raw=raw):
                self.assertFalse(gate.possible_rbp_writes(
                    gate.decode(bytes.fromhex(raw), 0x1000)[0]))

    def test_jump_table_requires_instruction_starts(self):
        starts = {r['va'] for r in self.decoded['field_classifier']}
        rows = gate.table(self.image, 0x467458, 28, starts)
        self.assertEqual(rows[20][3], 0x155e58b)
        class BadTarget:
            def read(inner, va, size):
                if va == 0x467458 + 20 * 4:
                    return struct.pack('<i', 0x155e58c - 0x467458)
                return self.image.read(va, size)
        self.assertNotIn(0x155e58c, starts)
        with self.assertRaisesRegex(gate.EvidenceError, 'instruction start'):
            gate.table(BadTarget(), 0x467458, 28, starts)
        with self.assertRaises(gate.EvidenceError):
            gate.table(self.image, 0x467458, 0, starts)

    def test_two_field_names_and_all_one_bit_controls(self):
        expected = [(b'chain_to_etherscan_ws_urls', 28),
                    (b'chain_to_replica_s3_bucket', 34)]
        self.assertEqual(self.patterns, expected)
        for name, tag in expected:
            self.assertEqual(gate.field_match(name, self.patterns), tag)
            for bit in range(len(name) * 8):
                sample = bytearray(name)
                sample[bit // 8] ^= 1 << (bit % 8)
                self.assertEqual(gate.field_match(sample, self.patterns), 13)
        self.assertIsNone(gate.field_match(expected[1][0] + b'x', self.patterns))
        self.assertIsNone(gate.field_match(expected[1][0][:-1], self.patterns))

    def test_field_constant_corruption_is_rejected(self):
        with self.assertRaises(gate.EvidenceError):
            gate.field_patterns(OverrideRead(self.image, 0x4529c0), self.rows)
        with self.assertRaises(gate.EvidenceError):
            gate.field_patterns(OverrideRead(self.image, 0x4536a0), self.rows)

    def test_all_chain_keys_and_one_bit_controls(self):
        expected = [(b'Local', 0), (b'Sandbox', 1), (b'Testnet', 2), (b'Mainnet', 3)]
        self.assertEqual(self.chain_patterns, expected)
        for name, tag in expected:
            self.assertEqual(gate.chain_key_match(name, self.chain_patterns), tag)
            for bit in range(len(name) * 8):
                sample = bytearray(name)
                sample[bit // 8] ^= 1 << (bit % 8)
                self.assertIsNone(gate.chain_key_match(sample, self.chain_patterns))
            self.assertIsNone(gate.chain_key_match(name + b'\0', self.chain_patterns))

    def test_chain_key_opcode_corruption_rejected(self):
        changed = dict(self.rows)
        changed[0x14be0ed] = dict(changed[0x14be0ed], bytes='b954657375')
        with self.assertRaisesRegex(gate.EvidenceError, 'chain-key instruction'):
            gate.chain_key_patterns(self.image, changed)

    def test_all_256_name_bytes_and_invalid_bounds(self):
        self.assertEqual(self.constants, (5, 18, 2, 3))
        for value in range(256):
            self.assertEqual(gate.name_key(value, self.constants), {5: 2, 18: 3}.get(value))
        for bad in (-1, 256):
            with self.assertRaises(ValueError):
                gate.name_key(bad, self.constants)

    def test_lookup_empty_present_differs_from_absence(self):
        empty = gate.route_model(5, 1, {2: 0}, constants=self.constants)
        missing = gate.route_model(5, 1, {}, constants=self.constants)
        self.assertEqual((empty['outcome'], empty['first_word'], empty['pointer'],
                          empty['flag'], empty['release']), ('present', 0, 1, 1, False))
        self.assertEqual((missing['outcome'], missing['first_word'], missing['flag']),
                         ('missing', 1 << 63, 0))
        self.assertEqual(gate.route_model(18, 1, {3: 4}, constants=self.constants)['flag'], 1)
        self.assertEqual(gate.route_model(17, 1, {3: 4}, constants=self.constants)['flag'], 0)
        self.assertEqual(gate.route_model(33, 1, {2: 4}, constants=self.constants)['flag'], 0)

    def test_lookup_failure_and_full_name_cross_product(self):
        self.assertEqual(gate.route_model(5, 1, {2: 4}, allocation_ok=False)['outcome'],
                         'allocation_boundary')
        for tag in range(256):
            for option in (0, 1, 2):
                for root in (None, {}, {2: 0, 3: 7}):
                    r = gate.route_model(tag, option, root, constants=self.constants)
                    key = {5: 2, 18: 3}.get(tag)
                    present = option == 1 and root is not None and key is not None and key in root
                    self.assertEqual(r['flag'], int(present))
                    if present:
                        self.assertEqual(r['first_word'], root[key])
        with self.assertRaises(ValueError):
            gate.route_model(5, 1, {2: -1})
        with self.assertRaises(ValueError):
            gate.route_model(5, 1, {2: 1 << 63})

    def test_valid_and_corrupted_tree_shapes(self):
        node = {'pairs': [(2, 7)], 'children': [{'pairs': [(0, 1), (1, 2)]},
                                                {'pairs': [(3, 0)]}]}
        for key, expected in enumerate((1, 2, 7, 0)):
            self.assertEqual(gate.tree_lookup(key, node, 1), expected)
        self.assertIsNone(gate.tree_lookup(4, node, 1))
        self.assertIsNone(gate.tree_lookup(2, None, 0))
        with self.assertRaises(ValueError):
            gate.tree_lookup(2, {'pairs': [(3, 1), (1, 2)]}, 0)
        with self.assertRaises(ValueError):
            gate.tree_lookup(3, {'pairs': [(2, 0)], 'children': []}, 1)

    def test_map_replacement_and_new_key_counts(self):
        for pairs in ([], [(2, 5)], [(1, 0), (3, 9)]):
            for key in range(4):
                for length in (0, 7):
                    previous = dict(pairs).get(key)
                    expected = dict(pairs)
                    expected[key] = length
                    result, old, operation = gate.map_update_model(pairs, key, length)
                    self.assertEqual(result, sorted(expected.items()))
                    self.assertEqual(old, previous)
                    self.assertEqual(operation, 'replace' if key in dict(pairs) else 'insert')
        with self.assertRaises(ValueError):
            gate.map_update_model([(2, 3), (2, 4)], 2, 1)

    def test_replaced_value_release_modular_boundary(self):
        for word in range(65536):
            self.assertEqual(gate.replacement_release(word), (word & ((1 << 63) - 1)) != 0)
        for word in ((1 << 63) - 1, 1 << 63, (1 << 63) + 1, (1 << 64) - 1):
            self.assertEqual(gate.replacement_release(word), (word & ((1 << 63) - 1)) != 0)
        for bad in (-1, 1 << 64):
            with self.assertRaises(ValueError):
                gate.replacement_release(bad)

    def test_loader_failure_precedence(self):
        for second in (False, True):
            for read_ok in (False, True):
                for tag in (0, 1, 2):
                    self.assertEqual(gate.loader_model(False, second, read_ok, tag),
                                     'default-map-absent')
        self.assertEqual(gate.loader_model(True, False, True, 1), 'unwrap-boundary')
        self.assertEqual(gate.loader_model(True, True, False, 1), 'unwrap-boundary')
        self.assertEqual(gate.loader_model(True, True, True, 2), 'unwrap-boundary')
        self.assertEqual(gate.loader_model(True, True, True, 0), 'map-absent')
        self.assertEqual(gate.loader_model(True, True, True, 1), 'map-present')
        with self.assertRaises(ValueError):
            gate.loader_model(True, True, True, 3)

    def test_flag_consumer_modes_and_width_boundaries(self):
        for flag in range(256):
            for fail_a in (False, True):
                for fail_b in (False, True):
                    for zero in (False, True):
                        actual = gate.consumer_model(2, flag, fail_a, fail_b, zero)
                        if flag == 0:
                            expected = 'direct-handoff-then-drop'
                        elif fail_a or fail_b or zero:
                            expected = 'fallback-handoff-then-drop'
                        else:
                            expected = 'converted-handoff-then-drop'
                        self.assertEqual(actual, expected)
        self.assertEqual(gate.consumer_model(3, 1), 'drop-only')
        self.assertEqual(gate.consumer_model(0x100000003, 1), 'drop-only')
        self.assertEqual(gate.consumer_model(0x100000002, 1), 'alternate-handoff')
        for tag, flag in ((-1, 0), (1 << 64, 0), (2, -1), (2, 256)):
            with self.assertRaises(ValueError):
                gate.consumer_model(tag, flag)

    def test_downstream_handoff_sentinel_and_write_cases(self):
        missing = 1 << 63
        values = (0, 1, missing - 1, missing, missing + 1, (1 << 64) - 1)
        for current in values:
            for returned in values:
                model = gate.handoff_model(current, returned)
                self.assertEqual(model['write_forwarded'], current != missing)
                self.assertEqual(model['replace_current'], current != missing and returned != missing)
                self.assertEqual(model['release_returned'], current == missing and returned not in (0, missing))
                self.assertEqual(model['route'], 'inactive' if current == missing else
                                 'reuse' if returned == missing else 'replace')
        for current, returned in ((-1, 0), (0, -1), (1 << 64, 0), (0, 1 << 64)):
            with self.assertRaises(ValueError):
                gate.handoff_model(current, returned)
        changed = dict(self.rows)
        changed[0x4e39e91] = dict(changed[0x4e39e91], bytes='7024')
        with self.assertRaises(gate.EvidenceError):
            gate.verify_pins(changed)

    def test_scale_and_diagnostic_anchors_are_target_bytes(self):
        self.assertEqual(struct.unpack('<d', self.image.read(0x4593e0, 8))[0], 0.1)
        self.assertEqual(self.image.read(0x43351a, 22), b'\x11duplicate field `\xc0\x01`\x00')
        self.assertEqual(self.image.read(0x4681b8, 26), b'chain_to_replica_s3_bucket')
        self.assertEqual(self.rows[0x1568b56]['memory_va'], 0x43058f)

    def test_cfg_witness_edges_and_impossible_witness(self):
        rows = self.decoded['json_fields']
        path = gate.witness(rows, 0x157f3c4, 0x157fb66)
        index = {r['va']: r for r in rows}
        self.assertGreater(len(path), 2)
        for a, b in zip(path, path[1:]):
            self.assertIn(b, gate.successors(index[a]))
        changed = [dict(row) for row in rows]
        next(row for row in changed if row['va'] == 0x157f3c4)['kind'] = 'trap'
        with self.assertRaisesRegex(gate.EvidenceError, 'not found'):
            gate.witness(changed, 0x157f3c4, 0x157fb66)

    def test_constructor_sentinel_proof_and_negative_controls(self):
        rows = self.decoded['caller_constructor']
        count, outcomes, writers = gate.sentinel_flow(rows)
        self.assertEqual(count, 964)
        self.assertEqual(outcomes[0x51d0992], [True])
        self.assertEqual(outcomes[0x51d0a80], [True])
        self.assertEqual(len(writers), 8)
        changed = [dict(row) for row in rows]
        next(row for row in changed if row['va'] == 0x51cf728)['immediate'] ^= 1
        with self.assertRaisesRegex(gate.EvidenceError, 'sentinel'):
            gate.sentinel_flow(changed)
        changed = [dict(row) for row in rows]
        changed[4]['kind'] = 'jump_indirect'
        with self.assertRaisesRegex(gate.EvidenceError, 'indirect'):
            gate.sentinel_flow(changed)

    def test_exception_parser_rejects_bad_header_and_ranges(self):
        class Fake:
            def __init__(self, data):
                self.data = data
                self.byname = {'.gcc_except_table': {'type': 1, 'offset': 0, 'size': len(data)}}
            def offset(self, _va, _size):
                return 0
        frame = {'lsda': 0x2000, 'start': 0x1000, 'end': 0x1010}
        valid = bytes.fromhex('ffff010400010200')
        self.assertEqual(gate.exceptions(Fake(valid), frame, {0x1002})[0][1:5],
                         (0x1000, 0x1001, 0x1002, 0))
        with self.assertRaises(gate.EvidenceError):
            gate.exceptions(Fake(bytes.fromhex('00ff010400010200')), frame, {0x1002})
        with self.assertRaises(gate.EvidenceError):
            gate.exceptions(Fake(bytes.fromhex('ffff010400110200')), frame, {0x1002})
        with self.assertRaises(gate.EvidenceError):
            gate.exceptions(Fake(valid), frame, {0x1003})
        with self.assertRaises((ValueError, gate.EvidenceError)):
            gate.exceptions(Fake(valid[:-1]), frame, {0x1002})

    def test_wrong_historical_digest_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / 'wrong-image'
            sample.write_bytes(b'not a captured executable')
            with self.assertRaisesRegex(gate.EvidenceError, 'digest'):
                gate.compare_historical(sample)

    def test_repeated_outputs_are_byte_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            left, right = Path(directory) / 'one', Path(directory) / 'two'
            first = gate.generate(self.image, left)
            second = gate.generate(self.image, right)
            self.assertEqual(first, second)
            self.assertEqual(sorted(p.name for p in left.iterdir()),
                             sorted(p.name for p in right.iterdir()))
            for file in left.iterdir():
                self.assertEqual(file.read_bytes(), (right / file.name).read_bytes(), file.name)
            self.assertEqual(first['selected_fdes'], 19)
            self.assertEqual(first['field_probe_cases'], 418)
            self.assertEqual(first['chain_key_probe_cases'], 212)
            self.assertEqual(first['map_update_cases'], 24)
            self.assertEqual(first['consumer_cases'], 60)
            self.assertEqual(first['replacement_cases'], 7)
            self.assertEqual(first['handoff_cases'], 36)


if __name__ == '__main__':
    unittest.main()
