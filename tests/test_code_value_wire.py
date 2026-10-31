"""Tests for tools/code_value_wire.py, with negative controls on every pin."""
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'research' / 'work-items' / 'RE-009-code-value-wire-94'
SPEC = importlib.util.spec_from_file_location('code_value_wire', ROOT / 'tools' / 'code_value_wire.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['code_value_wire'] = tool
SPEC.loader.exec_module(tool)
CACHE = {}


def state():
    if not CACHE:
        CACHE['data'] = tool.load_binary()
        CACHE['view'] = tool.View(CACHE['data'])
        CACHE['report'] = tool.build(CACHE['data'])
    return CACHE


class Overlay(tool.View):
    """The same image with single bytes replaced."""

    def __init__(self, base, patches):
        self.data = base.data
        self.sections = base.sections
        self.loaded = base.loaded
        self.patches = patches

    def mem(self, va, size):
        raw = bytearray(super().mem(va, size))
        for where, value in self.patches.items():
            if va <= where < va + size:
                raw[where - va] = value
        return bytes(raw)


def flipped(view, va):
    return Overlay(view, {va: view.mem(va, 1)[0] ^ 0x01})


def patched_i32(view, va, value):
    return Overlay(view, dict(zip(range(va, va + 4), struct.pack('<i', value))))


class Reader:
    """A small MessagePack reader for the forms the model emits."""

    def __init__(self, raw):
        self.raw = raw
        self.pos = 0

    def take(self, size):
        chunk = self.raw[self.pos:self.pos + size]
        if len(chunk) != size:
            raise ValueError('truncated')
        self.pos += size
        return chunk

    def value(self):
        marker = self.take(1)[0]
        if marker < 0x80:
            return marker
        if marker & 0xf0 == 0x80:
            return {self.value(): self.value() for _ in range(marker & 0xf)}
        if marker & 0xf0 == 0x90:
            return [self.value() for _ in range(marker & 0xf)]
        if marker & 0xe0 == 0xa0:
            return self.take(marker & 0x1f).decode('ascii')
        if marker == 0xc4:
            return bytes(self.take(self.take(1)[0]))
        if marker == 0xcc:
            return self.take(1)[0]
        raise ValueError(f'marker {marker:#x}')


class Identity(unittest.TestCase):
    def test_wrong_digest_refused(self):
        with self.assertRaises(ValueError):
            tool.load_binary(expected='0' * 64)

    def test_evidence_regenerates_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            tool.write_outputs(state()['report'], out)
            for name in (tool.JSON_NAME, tool.TSV_NAME):
                self.assertEqual((out / name).read_bytes(), (FOLDER / name).read_bytes(), name)

    def test_digest_recorded(self):
        self.assertEqual(state()['report']['binary_sha256'], tool.SHA256)

    def test_evidence_has_no_absolute_paths(self):
        for name in (tool.JSON_NAME, tool.TSV_NAME):
            text = (FOLDER / name).read_text(encoding='utf-8')
            for mark in [chr(47) + word for word in ('tmp', 'srv', 'mnt', 'code_Mainnet')]:
                self.assertNotIn(mark, text)


class Pins(unittest.TestCase):
    def test_every_rip_pin_rejects_other_bytes(self):
        view = state()['view']
        for pin in tool.RIP_PINS:
            with self.assertRaises(ValueError):
                tool.check_rip_pin(flipped(view, pin[0]), pin)

    def test_every_rip_pin_rejects_other_targets(self):
        view = state()['view']
        for pin in tool.RIP_PINS:
            with self.assertRaises(ValueError):
                tool.check_rip_pin(view, (pin[0], pin[1], pin[2] + 1, pin[3]))

    def test_every_byte_pin_rejects_other_bytes(self):
        view = state()['view']
        for pin in tool.BYTE_PINS:
            last = pin[0] + len(bytes.fromhex(pin[1])) - 1
            with self.assertRaises(ValueError):
                tool.check_byte_pin(flipped(view, last), pin)

    def test_every_range_pin_rejects_other_bytes(self):
        view = state()['view']
        for pin in tool.RANGE_PINS:
            with self.assertRaises(ValueError):
                tool.check_range_pin(flipped(view, pin[1] - 1), pin)

    def test_pin_counts(self):
        report = state()['report']
        self.assertEqual(len(report['rip_pins']), len(tool.RIP_PINS))
        self.assertEqual(len(report['byte_pins']), len(tool.BYTE_PINS))
        self.assertEqual(len(tool.RANGE_PINS), 4)

    def test_bss_and_unmapped_addresses_refused(self):
        view = state()['view']
        bss = next(s for s in view.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], tool.SHT_NOBITS)
        for va in (bss['address'], 0, 0x7fffffffffff):
            with self.assertRaises(ValueError):
                view.mem(va, 1)

    def test_lea_target_refuses_other_instructions(self):
        view = state()['view']
        with self.assertRaises(ValueError):
            tool.lea_target(view, tool.WRITER)

    def test_fde_start_required(self):
        data = state()['data']
        _, ordered, _ = tool.fde_extents.fde_extents(data)
        starts = [row['start'] for row in ordered]
        self.assertEqual(tool.fde_row(starts, ordered, tool.WRITER)['end'], 0x3bf8d20)
        with self.assertRaises(ValueError):
            tool.fde_row(starts, ordered, tool.WRITER + 1)


class Variants(unittest.TestCase):
    def test_names_in_tag_order(self):
        names = [row['name'] for row in state()['report']['variants']]
        self.assertEqual(names, ['LegacyRaw', 'LegacyAnalyzed', 'Eof', 'Eip7702'])

    def test_name_match_indexes_agree_with_tags(self):
        pins = {pin[2]: pin[1] for pin in tool.BYTE_PINS}
        for tag, text in ((0, 'LegacyRaw'), (1, 'LegacyAnalyzed'), (2, 'Eof'), (3, 'Eip7702')):
            raw = pins[f'name match {text} = index {tag}']
            self.assertEqual(raw, '66c700' + bytes((9, tag)).hex())

    def test_writer_table_change_refused(self):
        view = state()['view']
        for row in tool.VARIANTS:
            slot = tool.WRITER_TABLE + 4 * row[0]
            bad = patched_i32(view, slot, view.i32(slot) + 1)
            with self.assertRaises(ValueError):
                tool.check_variant(bad, row)

    def test_decoder_table_swap_refused(self):
        view = state()['view']
        for table in (tool.MAP_TABLE, tool.BARE_TABLE):
            bad = patched_i32(view, table + 4, view.i32(table + 8))
            with self.assertRaises(ValueError):
                tool.check_variant(bad, tool.VARIANTS[1])

    def test_wrong_reader_refused(self):
        view = state()['view']
        row = list(tool.VARIANTS[0])
        row[6] += 1
        with self.assertRaises(ValueError):
            tool.check_variant(view, tuple(row))


class Fields(unittest.TestCase):
    def test_field_order_of_legacy_analyzed(self):
        names = [row['name'] for row in state()['report']['fields'] if row['owner'] == 'LegacyAnalyzed']
        self.assertEqual(names, ['bytecode', 'original_len', 'jump_table'])

    def test_field_counts_match_headers(self):
        counts = {}
        for row in state()['report']['fields']:
            counts[row['owner']] = counts.get(row['owner'], 0) + 1
        self.assertEqual(counts, {'LegacyAnalyzed': 3, 'Eip7702': 3, 'Eof': 3, 'Eof.header': 6, 'Eof.body': 5,
                                  'Eof.types_section row': 3, 'JumpTable': 4, 'JumpTable.head': 2})

    def test_wrong_name_refused(self):
        view = state()['view']
        row = list(tool.FIELDS[0])
        row[3] += 1
        with self.assertRaises(ValueError):
            tool.check_field(view, tuple(row))

    def test_wrong_length_refused(self):
        view = state()['view']
        row = list(tool.FIELDS[0])
        row[4] += 1
        with self.assertRaises(ValueError):
            tool.check_field(view, tuple(row))

    def test_wrong_callee_refused(self):
        view = state()['view']
        for row in tool.FIELDS:
            bad = list(row)
            bad[10] += 1
            with self.assertRaises(ValueError):
                tool.check_field(view, tuple(bad))

    def test_tsv_rows(self):
        lines = (FOLDER / tool.TSV_NAME).read_text(encoding='utf-8').splitlines()
        self.assertEqual(len(lines), len(tool.FIELDS) + 1)


class Domain(unittest.TestCase):
    def test_small_spans(self):
        self.assertEqual(tool.bit_domain(0, 0)[0], tool.EMPTY_BUILDER)
        for bits in (1, 7, 9, 15):
            self.assertEqual(tool.bit_domain(0, bits)[0], tool.TAIL_BUILDER)
        for bits in (8, 16, 800):
            self.assertEqual(tool.bit_domain(0, bits)[0], tool.WHOLE_BUILDER)

    def test_tail_length(self):
        for bits in range(1, 4096):
            tail = tool.bit_domain(0, bits)[2]
            self.assertEqual(tail, bits % 8 or 8)

    def test_nonzero_heads_leave_head_zero_builders(self):
        self.assertEqual(tool.bit_domain(4, 4)[0], tool.HEAD_FULL_BUILDER)
        self.assertEqual(tool.bit_domain(1, 2)[0], tool.HEAD_SINGLE_BUILDER)
        self.assertEqual(tool.bit_domain(1, 20)[0], tool.HEAD_SPAN_BUILDER)

    def test_sweep_counts(self):
        counts = state()['report']['bit_domain_sweep']['builder_counts']
        self.assertEqual(sum(counts.values()), tool.DOMAIN_SWEEP + 1)
        self.assertEqual(counts[hex(tool.EMPTY_BUILDER)], 1)
        self.assertEqual(counts[hex(tool.WHOLE_BUILDER)], tool.DOMAIN_SWEEP // 8)

    def test_tail_masks(self):
        self.assertEqual([tool.tail_mask(t) for t in range(1, 9)], [1, 3, 7, 15, 31, 63, 127, 255])
        with self.assertRaises(ValueError):
            tool.tail_mask(9)

    def test_elements(self):
        self.assertEqual(tool.data_elements(0, b''), [])
        self.assertEqual(tool.data_elements(12, b'\xff\xff'), [0xff, 0x0f])
        self.assertEqual(tool.data_elements(16, b'\xff\xff'), [0xff, 0xff])
        with self.assertRaises(ValueError):
            tool.data_elements(12, b'\xff')


class Capacity(unittest.TestCase):
    def test_boundary(self):
        self.assertTrue(tool.capacity_accepts(8, 0, 1))
        self.assertFalse(tool.capacity_accepts(9, 0, 1))

    def test_head_lowers_capacity(self):
        self.assertTrue(tool.capacity_accepts(5, 3, 1))
        self.assertFalse(tool.capacity_accepts(6, 3, 1))

    def test_saturates(self):
        self.assertTrue(tool.capacity_accepts(0, 7, 0))
        self.assertFalse(tool.capacity_accepts(1, 7, 0))

    def test_samples_match_model(self):
        for row in state()['report']['capacity_samples']:
            self.assertEqual(row['accepted'], tool.capacity_accepts(row['bits'], row['head'], row['capacity']))

    def test_panic_text(self):
        self.assertEqual(state()['report']['panic_text'], 'bit-vector capacity exceeded:')


class Wire(unittest.TestCase):
    def test_order_compare_covers_every_byte(self):
        report = state()['report']
        self.assertEqual(report['order_value'], 'bitvec::order::Lsb0')
        self.assertEqual(3 + 16, len(report['order_value']))

    def test_uint_forms(self):
        self.assertEqual(tool.uint_value(0x7f), b'\x7f')
        self.assertEqual(tool.uint_value(0x80), b'\xcc\x80')
        self.assertEqual(tool.uint_value(0x100), b'\xcd\x01\x00')
        self.assertEqual(tool.uint_value(0x10000), b'\xce\x00\x01\x00\x00')
        self.assertEqual(tool.uint_value(1 << 32), b'\xcf\x00\x00\x00\x01\x00\x00\x00\x00')

    def test_bin_and_array_forms(self):
        self.assertEqual(tool.bin_value(b'')[:2], b'\xc4\x00')
        self.assertEqual(tool.bin_value(bytes(0x100))[:3], b'\xc5\x01\x00')
        self.assertEqual(tool.bin_value(bytes(0x10000))[:5], b'\xc6\x00\x01\x00\x00')
        self.assertEqual(tool.array_header(15), b'\x9f')
        self.assertEqual(tool.array_header(16), b'\xdc\x00\x10')
        self.assertEqual(tool.array_header(0x10000), b'\xdd\x00\x01\x00\x00')

    def test_fixstr_limit(self):
        with self.assertRaises(ValueError):
            tool.fixstr('x' * 32)

    def test_address_length(self):
        with self.assertRaises(ValueError):
            tool.eip7702_value(bytes(19), 0, b'')

    def test_examples_parse(self):
        examples = state()['report']['examples']
        raw = Reader(bytes.fromhex(examples['legacy_raw'])).value()
        self.assertEqual(raw, {'LegacyRaw': bytes.fromhex('6001600155')})
        reader = Reader(bytes.fromhex(examples['legacy_analyzed_bits_12']))
        value = reader.value()
        self.assertEqual(reader.pos, len(reader.raw))
        body = value['LegacyAnalyzed']
        self.assertEqual(list(body), ['bytecode', 'original_len', 'jump_table'])
        self.assertEqual(body['jump_table']['head'], {'width': 8, 'index': 0})
        self.assertEqual(body['jump_table']['bits'], 12)
        self.assertEqual(body['jump_table']['data'], [0xff, 0x0f])
        self.assertEqual(Reader(bytes.fromhex(examples['eip7702'])).value()['Eip7702']['version'], 0)

    def test_empty_table_ends_with_empty_array(self):
        self.assertTrue(state()['report']['examples']['legacy_analyzed_bits_0'].endswith('a46461746190'))

    def test_json_sorted(self):
        text = (FOLDER / tool.JSON_NAME).read_text(encoding='utf-8')
        self.assertEqual(text, json.dumps(json.loads(text), indent=1, sort_keys=True) + '\n')


if __name__ == '__main__':
    unittest.main()
