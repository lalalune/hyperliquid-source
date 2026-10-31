import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_kv_schema as tool  # noqa: E402

FOLDER = ROOT / 'research' / 'work-items' / 'RE-009-evm-kv-schema-94'
STATE = {}


def loaded():
    if not STATE:
        data = tool.load_binary()
        STATE['data'] = data
        STATE['view'] = tool.View(data)
        STATE['report'], STATE['rows'] = tool.build(data)
    return STATE


class Patched(tool.View):
    """The real view with some virtual addresses replaced by other bytes."""

    def __init__(self, base, patches):
        self.__dict__.update(base.__dict__)
        self.base = base
        self.patches = patches

    def mem(self, va, size):
        raw = bytearray(self.base.mem(va, size))
        for where, value in self.patches.items():
            for index, byte in enumerate(value):
                if va <= where + index < va + size:
                    raw[where + index - va] = byte
        return bytes(raw)


ROUND = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
         0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
         0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
         0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
         0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
         0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROTATE = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
PILAR = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]


def keccak256_empty():
    """Keccak-256 of the empty string, with the original 0x01 padding."""
    mask = (1 << 64) - 1
    block = bytearray(136)
    block[0] = 0x01
    block[135] = 0x80
    lanes = list(struct.unpack('<17Q', bytes(block))) + [0] * 8
    for constant in ROUND:
        parity = [lanes[i] ^ lanes[i + 5] ^ lanes[i + 10] ^ lanes[i + 15] ^ lanes[i + 20] for i in range(5)]
        for i in range(5):
            right = parity[(i + 1) % 5]
            mixed = parity[(i + 4) % 5] ^ (((right << 1) | (right >> 63)) & mask)
            for j in range(0, 25, 5):
                lanes[j + i] ^= mixed
        last = lanes[1]
        for rotate, index in zip(ROTATE, PILAR):
            lanes[index], last = ((last << rotate) | (last >> (64 - rotate))) & mask, lanes[index]
        for j in range(0, 25, 5):
            row = lanes[j:j + 5]
            for i in range(5):
                lanes[j + i] = row[i] ^ (~row[(i + 1) % 5] & row[(i + 2) % 5] & mask)
        lanes[0] ^= constant
    return struct.pack('<4Q', *lanes[:4])


class EvidenceFiles(unittest.TestCase):
    def test_committed_files_match_a_fresh_build(self):
        state = loaded()
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            tool.write_outputs(state['report'], state['rows'], out)
            for name in (tool.JSON_NAME, tool.TSV_NAME):
                self.assertEqual((out / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_tool_runs_no_external_program(self):
        source = (ROOT / 'tools' / 'evm_kv_schema.py').read_text(encoding='utf-8')
        for word in ('subprocess', 'os.system', 'objdump', 'readelf'):
            self.assertNotIn(word + ' ', source.split('"""', 2)[2])

    def test_wrong_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'sha256 mismatch'):
            tool.load_binary(expected='00' * 32)


class View(unittest.TestCase):
    def test_nobits_and_unmapped_addresses_fail(self):
        view = loaded()['view']
        bss = next(s for s in view.sections if s['name'] == '.bss')
        for va in (bss['address'] + 8, 0x10, 1 << 40):
            with self.assertRaisesRegex(ValueError, 'outside file-backed'):
                view.mem(va, 8)

    def test_missing_relocation_fails(self):
        with self.assertRaisesRegex(ValueError, 'no RELATIVE'):
            loaded()['view'].relative(tool.LABEL_TABLE + 1)


class Pins(unittest.TestCase):
    def test_every_rip_pin_rejects_a_changed_opcode(self):
        view = loaded()['view']
        for pin in tool.RIP_PINS:
            patched = Patched(view, {pin[0]: b'\x90'})
            with self.assertRaises(ValueError):
                tool.check_rip_pin(patched, pin)

    def test_every_rip_pin_rejects_a_changed_target(self):
        view = loaded()['view']
        for pin in tool.RIP_PINS:
            offset = pin[0] + len(bytes.fromhex(pin[1]))
            low = view.mem(offset, 1)[0] ^ 0x40
            with self.assertRaisesRegex(ValueError, 'targets'):
                tool.check_rip_pin(Patched(view, {offset: bytes((low,))}), pin)

    def test_every_byte_pin_rejects_a_changed_last_byte(self):
        view = loaded()['view']
        for pin in tool.BYTE_PINS:
            last = pin[0] + len(bytes.fromhex(pin[1])) - 1
            value = view.mem(last, 1)[0] ^ 1
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                tool.check_byte_pin(Patched(view, {last: bytes((value,))}), pin)


class Reversal(unittest.TestCase):
    def test_slot_and_value_are_fully_reversed(self):
        view = loaded()['view']
        samples = [bytes(range(32)), bytes(range(0xe0, 0x100)), b'\x01' + bytes(31), bytes(31) + b'\x80']
        for sample in samples:
            self.assertEqual(tool.storage_slot_bytes(view, sample), sample[::-1])
            self.assertEqual(tool.u256_value_bytes(view, sample), sample[::-1])

    def test_each_selector_matters(self):
        view = loaded()['view']
        sample = bytes(range(32))
        for va in (0x37d0bef, 0x37d0bf4, 0x37d0bf9):
            patched = Patched(view, {va: b'\xe4'})
            self.assertNotEqual(tool.storage_slot_bytes(patched, sample), sample[::-1])

    def test_swapped_store_offsets_are_seen(self):
        view = loaded()['view']
        patched = Patched(view, {0x37d0c17: b'\x24', 0x37d0c52: b'\x14'})
        self.assertNotEqual(tool.storage_slot_bytes(patched, bytes(range(32))), bytes(range(32))[::-1])

    def test_unknown_encoding_fails_closed(self):
        view = loaded()['view']
        with self.assertRaisesRegex(ValueError, 'unsupported SSE'):
            tool.storage_slot_bytes(Patched(view, {0x37d0be3: b'\x90'}), bytes(32))


class Keys(unittest.TestCase):
    def test_labels(self):
        report = loaded()['report']
        self.assertEqual(len(report['labels']), 28)
        self.assertEqual([report['labels'][str(c)] for c in range(21, 27)], ['Et', 'En', 'Eb', 'Ea', 'Ec', 'Es'])

    def test_vectors_written_by_hand(self):
        view = loaded()['view']
        address = bytes(range(0xa0, 0xb4))
        slot = (1).to_bytes(32, 'little')
        key = tool.storage_key(view, 'Es', address, slot)
        self.assertEqual(key, b'Es' + address + bytes(31) + b'\x01')
        self.assertEqual(len(key), 54)
        self.assertEqual(tool.account_key('Ea', address), b'Ea' + address)
        self.assertEqual(tool.code_key('Ec', bytes(32)), b'Ec' + bytes(32))
        self.assertEqual(tool.height_key(b'Eb', 0x0102030405060708), b'Eb\x01\x02\x03\x04\x05\x06\x07\x08')

    def test_height_keys_sort_numerically(self):
        heights = [0, 1, 255, 256, 65535, 65536, 1 << 40, (1 << 64) - 1]
        keys = [tool.height_key(b'Eb', h) for h in heights]
        self.assertEqual(keys, sorted(keys))
        little = [b'Eb' + struct.pack('<Q', h) for h in heights]
        self.assertNotEqual(little, sorted(little))

    def test_bad_lengths_fail(self):
        view = loaded()['view']
        with self.assertRaises(ValueError):
            tool.account_key('Ea', bytes(19))
        with self.assertRaises(ValueError):
            tool.code_key('Ec', bytes(33))
        with self.assertRaises(ValueError):
            tool.storage_key(view, 'Es', bytes(20), bytes(31))
        with self.assertRaises(ValueError):
            tool.height_key(b'Eb', 1 << 64)


class Values(unittest.TestCase):
    def setUp(self):
        self.report = loaded()['report']
        self.view = loaded()['view']
        self.empty = self.report['account_value']['empty_code_hash']
        self.names = {'balance': 'b', 'nonce': 'n', 'code_hash': 'c'}

    def encode(self, balance, nonce, code_hash, named=True):
        return tool.encode_account(self.view, balance, nonce, code_hash, self.empty, self.names, named)

    def test_empty_hash_is_keccak_of_nothing(self):
        self.assertEqual(self.empty, keccak256_empty().hex())

    def test_hash_constants_must_agree(self):
        patched = Patched(self.view, {0x326d143: b'\x00'})
        with self.assertRaisesRegex(ValueError, 'constants differ'):
            tool.empty_code_hash(patched)

    def test_field_names_and_order(self):
        rows = self.report['account_value']['fields_in_write_order']
        self.assertEqual([(r['name'], r['offset']) for r in rows], [('b', '0x0'), ('n', '0x40'), ('c', '0x20')])

    def test_named_gate(self):
        self.assertEqual(self.report['named_mode_codes'], [23, 24, 25, 26])
        self.assertEqual([c for c in range(256) if tool.named_mode(c)], [23, 24, 25, 26])

    def test_encoder_rejects_changed_gate_and_flag(self):
        for start, callee, _ in tool.ENCODERS:
            tool.check_encoder(self.view, start, callee)
            for offset, value in ((0x1d, 0xea), (0x21, 0x05), (0x4d, 0x00), (0x93, 0x01)):
                with self.assertRaisesRegex(ValueError, 'bytes differ'):
                    tool.check_encoder(Patched(self.view, {start + offset: bytes((value,))}), start, callee)

    def test_default_fields_are_omitted(self):
        empty = bytes.fromhex(self.empty)
        self.assertEqual(self.encode(bytes(32), 0, empty), b'\x80')
        self.assertEqual(self.encode(bytes(32), 5, empty), b'\x81\xa1n\x05')
        self.assertEqual(self.encode(bytes(32), 0, bytes(32)), b'\x81\xa1c\xc4\x20' + bytes(32))

    def test_all_fields_in_order(self):
        balance = (0x0102).to_bytes(32, 'little')
        code = bytes(range(32))
        want = (b'\x83\xa1b\xc4\x20' + bytes(30) + b'\x01\x02' + b'\xa1n\xcc\xff' + b'\xa1c\xc4\x20' + code)
        self.assertEqual(self.encode(balance, 255, code), want)

    def test_array_mode_drops_names(self):
        self.assertEqual(self.encode(bytes(32), 5, bytes.fromhex(self.empty), named=False), b'\x91\x05')

    def test_bytecode_enum(self):
        self.assertEqual(self.report['bytecode_enum'],
                         {'name': 'Bytecode', 'variants': ['LegacyRaw', 'LegacyAnalyzed', 'Eof', 'Eip7702']})


class Census(unittest.TestCase):
    def test_counts(self):
        report = loaded()['report']
        self.assertEqual(report['concat_counts'], {hex(tool.CONCAT): 20, hex(tool.CONCAT_BLOCK): 7})
        self.assertEqual(len(report['named_store_sites']), 3)
        self.assertEqual(len(report['reader_init_sites']), 8)

    def test_three_parts_only_at_one_site(self):
        rows = loaded()['rows']
        self.assertEqual([hex(r['site']) for r in rows if r['parts'] == 3], ['0x3330a28'])
        self.assertTrue(all(r['parts'] in (2, 3) for r in rows))

    def test_unknown_concat_owner_fails(self):
        state = loaded()
        fewer = {k: v for k, v in tool.ROLES.items() if k != 0x33be120}
        ordered = [{'start': r['fde_start'], 'end': r['fde_end']}
                   for r in sorted(state['rows'], key=lambda r: r['fde_start'])]
        starts = [r['start'] for r in ordered]
        with mock.patch.object(tool, 'ROLES', fewer):
            with self.assertRaisesRegex(ValueError, 'unclassified'):
                tool.concat_rows(state['view'], starts, ordered)

    def test_binding_rejects_changed_code(self):
        view = loaded()['view']
        report = loaded()['report']
        names = [report['labels'][str(c)] for c in range(28)]
        for row in tool.BINDINGS:
            self.assertEqual(tool.binding_row(view, names, row)['label'], {0x18: 'Ea', 0x19: 'Ec', 0x1a: 'Es'}[row[0]])
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                tool.binding_row(Patched(view, {row[3] + 1: b'\x17'}), names, row)

    def test_report_is_plain_json(self):
        self.assertEqual(json.loads(json.dumps(loaded()['report'])), loaded()['report'])


if __name__ == '__main__':
    unittest.main()
