"""Static and synthetic controls for the node 94 creation/collision evidence."""

import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_create_collision94 as subject

MASK = (1 << 64) - 1
ROTATIONS = (
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
    41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
)
ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def rol64(value, count):
    return ((value << count) | (value >> ((64 - count) % 64))) & MASK


def reference_keccak256(message):
    """Independent synthetic oracle, checked against published fixed vectors."""
    rate = 136
    padding = rate - len(message) % rate
    tail = b'\x81' if padding == 1 else b'\x01' + bytes(padding - 2) + b'\x80'
    padded = message + tail
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], 'little')
        for constant in ROUND_CONSTANTS:
            col = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                   for x in range(5)]
            delta = [col[(x - 1) % 5] ^ rol64(col[(x + 1) % 5], 1) for x in range(5)]
            for y in range(5):
                for x in range(5):
                    state[x + 5 * y] ^= delta[x]
            moved = [0] * 25
            for y in range(5):
                for x in range(5):
                    i = x + 5 * y
                    moved[y + 5 * ((2 * x + 3 * y) % 5)] = rol64(state[i], ROTATIONS[i])
            for y in range(5):
                row = moved[5 * y:5 * y + 5]
                for x in range(5):
                    state[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
            state[0] ^= constant
    return b''.join(x.to_bytes(8, 'little') for x in state)[:32]


def synthetic_word_add(account, amount):
    """Project the selected add/set-carry sequence over four little-endian words."""
    a = [(account >> (64 * i)) & MASK for i in range(4)]
    b = [(amount >> (64 * i)) & MASK for i in range(4)]
    low = a[0] + b[0]
    middle = a[1] + b[1] + (low >> 64)
    third0 = a[2] + b[2]
    third1 = (third0 & MASK) + (middle >> 64)
    high0 = a[3] + b[3]
    high1 = (high0 & MASK) + ((third0 >> 64) | (third1 >> 64))
    words = [low & MASK, middle & MASK, third1 & MASK, high1 & MASK]
    return sum(word << (64 * i) for i, word in enumerate(words)), bool((high0 >> 64) | (high1 >> 64))


def synthetic_word_sub(account, amount):
    """Project the four selected subtraction words, retaining discarded borrow."""
    output, borrow = 0, 0
    for i in range(4):
        a, b = (account >> (64 * i)) & MASK, (amount >> (64 * i)) & MASK
        result = a - b - borrow
        borrow = int(result < 0)
        output |= (result & MASK) << (64 * i)
    return output, bool(borrow)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / subject.TARGET).read_bytes()
        cls.outputs = subject.collect(cls.data)
        cls.summary = json.loads(cls.outputs['summary.json'])
        cls.links = json.loads(cls.outputs['linkage.json'])
        cls.frames = json.loads(cls.outputs['function-bytes.json'])

    def test_pinned_binary_digest(self):
        self.assertEqual(subject.verify_digest(self.data), subject.DIGEST)

    def test_bad_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            subject.verify_digest(b'not the pinned node')

    def test_cli_rejects_bad_artifact_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / subject.TARGET
            fake.parent.mkdir(parents=True)
            fake.write_bytes(b'wrong binary')
            output = root / 'result'
            with mock.patch.object(subject, 'ROOT', root), mock.patch.object(sys, 'argv', ['tool', '--out', str(output)]):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    subject.main()
            self.assertFalse(output.exists())

    def test_all_ten_evidence_files_reproduce_exactly(self):
        published = ROOT / 'research/work-items/RE-021-eofcreate-key-collision-94'
        self.assertEqual(len(self.outputs), 10)
        for name, data in self.outputs.items():
            with self.subTest(name=name):
                self.assertEqual((published / name).read_bytes(), data)

    def test_selected_fdes_and_sizes(self):
        self.assertEqual(self.summary['selected_fdes'], 11)
        self.assertEqual(self.summary['selected_body_bytes'], 10801)
        self.assertEqual(len({f['start_va'] for f in self.frames}), 11)
        for frame in self.frames:
            self.assertGreater(len(bytes.fromhex(frame['bytes'])), 0)

    def test_selected_windows_and_transfer_counts(self):
        self.assertEqual(self.summary['reviewed_windows'], len(subject.ANCHORS))
        self.assertEqual(self.summary['selected_transfers'], len(subject.EDGES))
        self.assertEqual(self.summary['selected_immediates'], len(subject.IMMEDIATES))
        self.assertEqual(self.summary['selected_relative_relocations'], 23)

    def test_immediate_operands_and_sign_extension(self):
        rows = csv.DictReader(io.StringIO(self.outputs['immediates.tsv'].decode()), delimiter='\t')
        facts = {row['label']: int(row['value_hex'], 16) for row in rows}
        self.assertEqual(len(facts), 28)
        self.assertEqual(facts['opcode_base_gas_cost'], 32000)
        self.assertEqual(facts['opcode_maximum_rejected_gas'], 31999)
        self.assertEqual(facts['opcode_stack_minimum'], 4)
        self.assertEqual(facts['opcode_action_tag'], 0x6e)
        self.assertEqual(facts['create_depth_limit'], 0x400)
        self.assertEqual(facts['nonce_maximum'], (1 << 64) - 1)
        self.assertEqual(facts['create_registry_hit_status'], 0x5e)
        self.assertEqual(facts['checkpoint_collision_status'], 0x5e)
        self.assertEqual(facts['checkpoint_overflow_status'], 0x5f)
        self.assertEqual(facts['nonce_increment_journal_tag'], 4)
        self.assertEqual(facts['checkpoint_transfer_journal_tag'], 3)

    def test_immediate_rejects_corrupt_shape_and_sign(self):
        with self.assertRaises(ValueError):
            subject.decode_immediate(b'\x90\x01', b'\xc6', 'u8')
        with self.assertRaises(ValueError):
            subject.decode_immediate(b'\x48\x05\x01\x00\x00\x00', b'\x48\x05', 'negative_i32')
        with self.assertRaises(ValueError):
            subject.decode_immediate(b'\xc6', b'\xc6', 'u8')

    def test_windows_reject_single_bit_corruption(self):
        for label, va, encoded in subject.ANCHORS:
            raw = bytes.fromhex(encoded)
            offset = len(raw) // 2
            changed = raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]
            with self.subTest(label=label, va=hex(va)):
                with self.assertRaisesRegex(ValueError, 'window'):
                    subject.expect_window(changed, raw)

    def test_checked_transfers_reject_opcode_swap(self):
        raw = b'\xe8' + struct.pack('<i', 20)
        kind, target = subject.decode_transfer(100, raw)
        self.assertEqual((kind, target), ('call', 125))
        with self.assertRaises(ValueError):
            subject.checked_transfer(100, b'\xe9' + raw[1:], raw, kind, target)

    def test_checked_transfers_reject_displacement_change(self):
        raw = b'\x0f\x84' + struct.pack('<i', -4)
        with self.assertRaises(ValueError):
            subject.checked_transfer(100, raw[:-1] + bytes([raw[-1] ^ 1]), raw, 'conditional', 102)

    def test_entry_gas_and_stack_boundary_order(self):
        window = next(bytes.fromhex(raw) for name, _, raw in subject.ANCHORS
                      if name == 'opcode_gas_and_stack')
        self.assertEqual(window[7:9], b'\x48\x3d')
        largest_rejected = struct.unpack_from('<I', window, 9)[0]
        self.assertEqual(window[13:17], b'\x76\x23\x48\x05')
        fee = -struct.unpack_from('<i', window, 17)[0]
        self.assertEqual(largest_rejected + 1, fee)
        self.assertEqual(fee, 32000)
        # This projection is pinned to the selected compares/stores, not target execution.
        def project(gas, stack):
            if gas <= largest_rejected:
                return 0x50, gas
            remaining = gas - fee
            return (0x5b if stack < 4 else None), remaining
        self.assertEqual(project(31999, 4), (0x50, 31999))
        self.assertEqual(project(32000, 3), (0x5b, 0))
        self.assertEqual(project(32000, 4), (None, 0))
        self.assertEqual(project(32001, 4), (None, 1))

    def test_nonce_journal_precedes_increment(self):
        window = next(bytes.fromhex(raw) for name, _, raw in subject.ANCHORS
                      if name == 'nonce_append_and_increment')
        tag = window.index(bytes.fromhex('c6040804'))
        guard = window.index(bytes.fromhex('4883faff'))
        increment = window.index(bytes.fromhex('48ffc2'))
        store = window.index(bytes.fromhex('48895360'))
        self.assertLess(tag, guard)
        self.assertLess(guard, increment)
        self.assertLess(increment, store)
        entries = {name: target for name, _, _, _, target in subject.EDGES}
        self.assertEqual(entries['nonce_max'], 0x4dd6c47)
        self.assertEqual(entries['create_nonce_failed'], 0x4dd9327)

    def test_checked_addition_branches_precede_account_word_stores(self):
        window = next(bytes.fromhex(raw) for name, _, raw in subject.ANCHORS
                      if name == 'checkpoint_balance_addition')
        first_branch = window.index(bytes.fromhex('0f8211010000'))
        second_branch = window.index(bytes.fromhex('0f8508010000'))
        first_store = window.index(bytes.fromhex('49894f40'))
        self.assertLess(first_branch, second_branch)
        self.assertLess(second_branch, first_store)
        edges = {name: target for name, _, _, _, target in subject.EDGES}
        self.assertEqual(edges['checkpoint_add_overflow1'], 0x4dd68e2)
        self.assertEqual(edges['checkpoint_add_overflow2'], 0x4dd68e2)

    def test_transfer_shapes_and_signed_displacements(self):
        self.assertEqual(subject.decode_transfer(0x100, b'\x74\xfe'), ('conditional', 0x100))
        self.assertEqual(subject.decode_transfer(0x100, b'\xeb\x7f'), ('jump', 0x181))
        self.assertEqual(subject.decode_transfer(0x100, b'\xff\x15\x00\x00\x00\x00'),
                         ('indirect-call-slot', 0x106))
        with self.assertRaises(ValueError):
            subject.decode_transfer(0x100, b'\x90')

    def test_both_registry_arms_share_prior_lookup(self):
        edges = {name: (kind, target) for name, _, _, kind, target in subject.EDGES}
        self.assertEqual(edges['create_owned_lookup'], ('call', 0x488d0b0))
        self.assertEqual(edges['create_borrowed_lookup'], edges['create_owned_lookup'])
        self.assertEqual(edges['create_miss'], ('conditional', 0x4dd96bb))

    def test_revision9_and_revision18_callback_relocations(self):
        rows = subject.relocation_rows(self.data, subject.sections(self.data))
        slots = {row['slot_va']: row['addend_va'] for row in rows}
        self.assertEqual(slots['0x5745e28'], '0x4da6f00')
        self.assertEqual(slots['0x57245e8'], '0x4c98d40')
        self.assertEqual(slots['0x5745cd8'], '0x4da5f30')
        self.assertEqual(slots['0x5724de8'], '0x4c98d40')
        self.assertEqual(slots['0x574f0b0'], '0x4e9d2a0')
        self.assertEqual([b['revision_byte'] for b in self.links['callback_bindings']], [9, 18])

    def test_relocation_rejects_bad_slot(self):
        raw = struct.pack('<QQq', 0x1000, 8, 0x2000)
        with self.assertRaises(ValueError):
            subject.relative_record(raw, 0x1008)

    def test_relocation_rejects_nonrelative_and_symbol(self):
        for info in (1, 0, 0x100000008):
            with self.subTest(info=info):
                with self.assertRaises(ValueError):
                    subject.relative_record(struct.pack('<QQq', 0x1000, info, 0x2000), 0x1000)

    def test_relocation_rejects_truncation_and_negative_addend(self):
        with self.assertRaises(ValueError):
            subject.relative_record(bytes(23), 0x1000)
        with self.assertRaises(ValueError):
            subject.relative_record(struct.pack('<QQq', 0x1000, 8, -1), 0x1000)

    def test_prior_key_is_full_20_bytes(self):
        key = bytes.fromhex(self.links['address_09_key_hex'])
        self.assertEqual(key, bytes(19) + b'\x09')
        for bit in range(160):
            changed = bytearray(key)
            changed[bit // 8] ^= 1 << (bit % 8)
            self.assertNotEqual(key, changed)

    def test_account_hash_constant(self):
        self.assertEqual(self.links['account_hash_hex'], reference_keccak256(b'').hex())

    def test_selected_source_locations_are_sanitized(self):
        locations = self.links['location_records']
        self.assertEqual([(x['line'], x['column']) for x in locations[:3]], [(49, 50), (53, 9), (27, 10)])
        self.assertTrue(all(x['relative_suffix'] ==
                            'revm-interpreter-15.0.0/src/instructions/contract.rs'
                            for x in locations[:3]))
        self.assertTrue(all(x['relative_suffix'] == 'revm-19.2.0/src/journaled_state.rs'
                            for x in locations[3:]))
        self.assertEqual(len(locations), 13)
        self.assertEqual(len({x['path_sha256'] for x in locations}), 2)
        self.assertFalse(any(x['relative_suffix'].startswith('/') for x in locations))

    def test_location_lea_rejects_wrong_opcode(self):
        raw = b'\x48\x8d\x3d' + struct.pack('<i', -12)
        self.assertEqual(subject.decode_rip_lea(0x100, raw), 0xfb)
        with self.assertRaises(ValueError):
            subject.decode_rip_lea(0x100, b'\x48\x8b' + raw[2:])

    def test_source_location_rejects_corrupt_length_and_suffix(self):
        record = struct.pack('<QQII', 0, 0, 1, 1)
        with mock.patch.object(subject, 'read_at', return_value=record):
            with self.assertRaises(ValueError):
                subject.source_location(b'', [], 1, 2, 'expected')
        record = struct.pack('<QQII', 0, 3, 1, 1)
        with mock.patch.object(subject, 'read_at', side_effect=(record, b'bad')):
            with self.assertRaises(ValueError):
                subject.source_location(b'', [], 1, 2, 'expected')

    def test_journal_selected_tag_destinations(self):
        table = self.links['journal_table_selected_entries']
        self.assertEqual(len(table), 15)
        expected = {2: '0x4676010', 3: '0x46760d3', 4: '0x4676260', 5: '0x4676190'}
        self.assertEqual({i: table[i]['target_va'] for i in expected}, expected)
        self.assertEqual(self.links['journal_first_unselected_index'], 15)

    def test_relative_table_corruption_rejected(self):
        section = {'name': '.test', 'type': 1, 'address': 0x1000, 'offset': 0, 'size': 8}
        raw = struct.pack('<ii', 0x100, 0x104)
        rows = subject.bounded_relative_table(raw, [section], 0x1000, 2, 0x1100, 0x1110)
        self.assertEqual([x['target_va'] for x in rows], ['0x1100', '0x1104'])
        changed = struct.pack('<ii', 0x100, 0x500)
        with self.assertRaises(ValueError):
            subject.bounded_relative_table(changed, [section], 0x1000, 2, 0x1100, 0x1110)

    def test_action_table_entry_two(self):
        self.assertEqual(self.links['action_table_selected_entries'][2]['target_va'], '0x47f3880')

    def test_invalid_file_backing(self):
        sections = [dict(name='.data', type=1, address=0x1000, offset=0, size=16),
                    dict(name='.bss', type=8, address=0x2000, offset=0, size=32)]
        self.assertEqual(subject.file_offset(sections, 0x100c, 4, 16), 12)
        for addr, size in ((0x2000, 1), (0x100f, 2), (0xfff, 1), (0x1000, 0)):
            with self.subTest(addr=addr, size=size):
                with self.assertRaises(ValueError):
                    subject.file_offset(sections, addr, size, 16)

    def test_ambiguous_file_backing_rejected(self):
        sections = [dict(type=1, address=0x1000, offset=0, size=16),
                    dict(type=1, address=0x1008, offset=16, size=16)]
        with self.assertRaises(ValueError):
            subject.file_offset(sections, 0x1009, 2, 32)

    def test_file_backed_section_truncated(self):
        sections = [dict(type=1, address=0x1000, offset=3, size=16)]
        with self.assertRaises(ValueError):
            subject.file_offset(sections, 0x100e, 2, 16)

    def test_executable_extent_requires_full_file_backed_code_section(self):
        secs = [dict(type=1, flags=4, address=0x1000, size=16),
                dict(type=8, flags=4, address=0x2000, size=16),
                dict(type=1, flags=0, address=0x3000, size=16)]
        self.assertEqual(subject.executable_extent(secs, 0x1000, 0x1010), secs[0])
        for start, end in ((0x100f, 0x1011), (0x2000, 0x2001),
                           (0x3000, 0x3001), (0x1000, 0x1000)):
            with self.subTest(start=start, end=end):
                with self.assertRaises(ValueError):
                    subject.executable_extent(secs, start, end)

    def test_executable_extent_rejects_ambiguous_sections(self):
        secs = [dict(type=1, flags=4, address=0x1000, size=16),
                dict(type=1, flags=4, address=0x1008, size=16)]
        with self.assertRaises(ValueError):
            subject.executable_extent(secs, 0x1009, 0x100a)

    def test_lsda_headers_and_intervals(self):
        exceptions = json.loads(self.outputs['exceptions.json'])
        self.assertEqual(len(exceptions), 9)
        self.assertEqual(sum(len(x['entries']) for x in exceptions), 88)
        handler = next(x for x in exceptions if x['function_va'] == '0x4c98d40')
        covering = [e for e in handler['entries'] if int(e['start_va'], 16) <= 0x4c992d6
                    < int(e['start_va'], 16) + e['length']]
        self.assertEqual(len(covering), 1)
        self.assertEqual(covering[0]['landing_va'], '0x4c993a8')

    def test_synthetic_lsda_boundary_and_negative_controls(self):
        frame = {'start': 0x2000, 'end': 0x2004, 'lsda': 0x1000}
        section = {'name': '.gcc_except_table', 'type': 1, 'address': 0x1000,
                   'offset': 0, 'size': 8}
        raw = bytes([0xff, 0xff, 1, 4, 0, 1, 1, 0])
        result = subject.parse_lsda(raw, [section], frame)
        self.assertEqual(result['entries'][0]['landing_va'], '0x2001')
        for bad in (bytes([0, 0xff, 1, 4, 0, 1, 1, 0]),
                    bytes([0xff, 0xff, 2, 4, 0, 1, 1, 0]),
                    bytes([0xff, 0xff, 1, 4, 0, 5, 1, 0]),
                    bytes([0xff, 0xff, 1, 4, 0, 1, 5, 0]),
                    bytes([0xff, 0xff, 1, 9, 0, 1, 1, 0])):
            with self.subTest(data=bad.hex()):
                with self.assertRaises(ValueError):
                    subject.parse_lsda(bad, [section], frame)


class SyntheticProjectionTests(unittest.TestCase):
    def test_keccak_empty_and_sha3_negative(self):
        known = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
        self.assertEqual(reference_keccak256(b'').hex(), known)
        self.assertNotEqual(hashlib.sha3_256(b'').hexdigest(), known)

    def test_known_create2_example(self):
        payload_hash = reference_keccak256(b'\x00')
        preimage = subject.create2_preimage(bytes(20), bytes(32), payload_hash)
        self.assertEqual(len(preimage), 85)
        self.assertEqual(reference_keccak256(preimage)[12:].hex(),
                         '4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38')

    def test_preimage_field_positions(self):
        address, salt, digest = bytes(range(20)), bytes(range(32)), bytes(range(32, 64))
        preimage = subject.create2_preimage(address, salt, digest)
        self.assertEqual(preimage[0], 255)
        self.assertEqual(preimage[1:21], address)
        self.assertEqual(preimage[21:53], salt)
        self.assertEqual(preimage[53:85], digest)
        self.assertNotEqual(preimage, b'\xff' + address + salt[::-1] + digest)

    def test_preimage_rejects_wrong_types_and_lengths(self):
        args = (bytes(20), bytes(32), bytes(32))
        for changed in ((b'', args[1], args[2]), (args[0], bytes(31), args[2]),
                        (args[0], args[1], bytes(33)), (bytearray(20), args[1], args[2])):
            with self.subTest(changed=tuple(map(len, changed))):
                with self.assertRaises(ValueError):
                    subject.create2_preimage(*changed)

    def test_rlp_nonce_boundaries(self):
        address = bytes(range(20))
        expected = {
            0: 'd694' + address.hex() + '80',
            1: 'd694' + address.hex() + '01',
            127: 'd694' + address.hex() + '7f',
            128: 'd794' + address.hex() + '8180',
            255: 'd794' + address.hex() + '81ff',
            256: 'd894' + address.hex() + '820100',
            (1 << 64) - 1: 'de94' + address.hex() + '88' + 'ff' * 8,
        }
        for number, encoded in expected.items():
            with self.subTest(nonce=number):
                self.assertEqual(subject.rlp_address_nonce(address, number).hex(), encoded)

    def test_rlp_rejects_invalid_nonce_and_address(self):
        for nonce in (-1, 1 << 64, 1.0, True):
            with self.subTest(nonce=nonce):
                with self.assertRaises(ValueError):
                    subject.rlp_address_nonce(bytes(20), nonce)
        with self.assertRaises(ValueError):
            subject.rlp_address_nonce(bytes(19), 0)

    def test_rlp_independent_integer_lengths(self):
        address = bytes.fromhex('1234567890abcdef1234567890abcdef12345678')
        numbers = [0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000,
                   2**32 - 1, 2**32, 2**63, 2**64 - 1]
        for number in numbers:
            encoded = subject.rlp_address_nonce(address, number)
            self.assertEqual(encoded[0] - 0xc0, len(encoded) - 1)
            self.assertEqual(encoded[1:22], b'\x94' + address)
            last = encoded[22:]
            if number == 0:
                self.assertEqual(last, b'\x80')
            elif number < 128:
                self.assertEqual(last, bytes([number]))
            else:
                self.assertEqual(last[0] - 0x80, len(last) - 1)
                self.assertEqual(int.from_bytes(last[1:], 'big'), number)
                self.assertNotEqual(last[1], 0)

    def test_four_word_addition_against_integer_oracle(self):
        values = (0, 1, 2, 2**64 - 1, 2**64, 2**64 + 1,
                  2**128 - 1, 2**128, 2**192 - 1, 2**192,
                  2**255, 2**256 - 2, 2**256 - 1)
        modulus = 1 << 256
        for account in values:
            for amount in values:
                with self.subTest(account=account, amount=amount):
                    low, overflow = synthetic_word_add(account, amount)
                    self.assertEqual(low, (account + amount) % modulus)
                    self.assertEqual(overflow, account + amount >= modulus)

    def test_four_word_subtraction_against_integer_oracle(self):
        values = (0, 1, 2**64 - 1, 2**64, 2**128, 2**192, 2**256 - 1)
        modulus = 1 << 256
        for account in values:
            for amount in values:
                with self.subTest(account=account, amount=amount):
                    low, borrow = synthetic_word_sub(account, amount)
                    self.assertEqual(low, (account - amount) % modulus)
                    self.assertEqual(borrow, account < amount)


if __name__ == '__main__':
    unittest.main()
