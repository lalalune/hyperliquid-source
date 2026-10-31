import collections
import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import app_hash_builder as tool  # noqa: E402

FOLDER = ROOT / 'research' / 'work-items' / 'RE-009-app-hash-builder-94'
STATE = {}


def setUpModule():
    data = tool.BINARY.read_bytes()
    STATE['data'] = data
    STATE['view'] = tool.View(data)
    STATE['extents'] = tool.Extents(data)
    STATE['summary'], STATE['rows'] = tool.analyse(STATE['view'], STATE['extents'])


class Patched(tool.View):
    """Overlay byte patches on the real view; relocation addends stay shared."""

    def __init__(self, base, patches=None, addends=None):
        self.base = base
        self.patches = patches or {}
        self.addends = collections.ChainMap(addends or {}, base.addends)

    def mem(self, va, size):
        raw = bytearray(self.base.mem(va, size))
        for start, new in self.patches.items():
            for index, byte in enumerate(new):
                if va <= start + index < va + size:
                    raw[start + index - va] = byte
        return bytes(raw)


def rel(target, after):
    return struct.pack('<i', target - after)


class Base(unittest.TestCase):
    def analyse(self, patches=None, addends=None):
        return tool.analyse(Patched(STATE['view'], patches, addends), STATE['extents'])

    def rejects(self, patches=None, addends=None):
        with self.assertRaises(ValueError):
            self.analyse(patches, addends)


class GeneratedFiles(Base):
    def test_json_matches_folder(self):
        text = json.dumps(STATE['summary'], indent=2, sort_keys=True) + '\n'
        self.assertEqual((FOLDER / tool.JSON_NAME).read_text(), text)

    def test_rows_match_folder(self):
        self.assertEqual((FOLDER / tool.ROWS_NAME).read_text(), STATE['rows'])

    def test_manifest_hashes(self):
        lines = (FOLDER / 'MANIFEST.sha256').read_text().splitlines()
        names = sorted(line.split('  ')[1] for line in lines)
        self.assertEqual(names, sorted(p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256'))
        for line in lines:
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_evidence_text_is_ascii_without_at_sign(self):
        text = json.dumps(STATE['summary']) + STATE['rows']
        self.assertTrue(text.isascii())
        self.assertNotIn(tool.AT_SIGN, text)


class Digest(Base):
    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(STATE['data']).hexdigest(), tool.SHA256)

    def test_changed_byte_fails_digest(self):
        changed = bytearray(STATE['data'][:64])
        changed[0] ^= 1
        with self.assertRaises(ValueError):
            tool.build(bytes(changed))


class Summary(Base):
    def test_counts(self):
        summary = STATE['summary']
        self.assertEqual(summary['rows_per_table'], 41)
        self.assertEqual(summary['bodies_with_one_hash_core'], 82)
        self.assertEqual(summary['low_distinct_state_fields'], 71)
        self.assertEqual(summary['low_rows_by_capture'],
                         {'base pointer': 1, 'field': 32, 'field group': 3, 'vec': 5})
        self.assertEqual(sum(summary['low_rows_by_capture'].values()), 41)

    def test_box_sizes_total(self):
        sizes = STATE['summary']['box_sizes']
        self.assertEqual(sum(sizes.values()), 41)
        self.assertEqual((sizes['0x78'], sizes['0x80'], sizes['0x40']), (1, 1, 1))

    def test_every_site_cadence(self):
        for site in STATE['summary']['call_sites']:
            self.assertEqual((site['mode_threshold'], site['modulus_below_threshold'],
                              site['modulus_otherwise']), (2, 50, 2000))

    def test_every_output_uses_high_half_for_blocks(self):
        for output in STATE['summary']['outputs']:
            self.assertEqual(output['out_low_16'], 'digest_list_hash')
            self.assertEqual(output['out_high_16'], 'blocks_hash')

    def test_count_check_location(self):
        location = STATE['summary']['count_check_location']
        self.assertEqual(location['file'], 'l1/src/dex_registry/dex_registry.rs')
        self.assertGreater(location['line'], 0)

    def test_location_without_mark(self):
        view = Patched(STATE['view'], addends={tool.COUNT_CHECK_LOCATION: tool.LOG_TEMPLATE})
        with self.assertRaises(ValueError):
            tool.source_location(view, tool.COUNT_CHECK_LOCATION)

    def test_rows_file_shape(self):
        lines = STATE['rows'].splitlines()
        self.assertEqual(len(lines), 42)
        self.assertEqual({line.count('\t') for line in lines}, {13})

    def test_keccak_parameters(self):
        keccak = STATE['summary']['keccak']
        self.assertEqual((keccak['rate_bytes'], keccak['delimiter'], keccak['output_bytes']), (136, 1, 32))


class Tables(Base):
    def test_box_size_change(self):
        self.rejects({tool.LOW_TABLE + 8: struct.pack('<Q', 16)})

    def test_sibling_box_size_change(self):
        self.rejects({tool.SHARED_TABLE + 0x28: struct.pack('<Q', 8)})

    def test_missing_call_relocation(self):
        view = Patched(STATE['view'])
        view.addends = {slot: value for slot, value in STATE['view'].addends.items()
                        if slot != tool.LOW_TABLE + 0x18}
        with self.assertRaises(ValueError):
            tool.table_rows(view, STATE['extents'], tool.LOW_TABLE)

    def test_call_slot_inside_function(self):
        self.rejects(addends={tool.LOW_TABLE + 0x18: 0x2819490})

    def test_two_rows_same_call(self):
        self.rejects(addends={tool.LOW_TABLE + 0x38: STATE['view'].addends[tool.LOW_TABLE + 0x18]})

    def test_thunk_redirect(self):
        self.rejects({0x21e3245: rel(tool.PARALLEL_RUN, 0x21e3249)})


class HashCore(Base):
    def body(self):
        return 0x2819480

    def patch_at(self, needle, new):
        start, raw = STATE['extents'].body(STATE['view'], self.body())
        at = raw.index(needle)
        return {start + at: new}

    def test_rate_change(self):
        self.rejects(self.patch_at(bytes.fromhex('88000000'), bytes.fromhex('90000000')))

    def test_delimiter_change(self):
        start, raw = STATE['extents'].body(STATE['view'], self.body())
        at = tool.DELIM.search(raw).end() - 2
        self.rejects({start + at: b'\x06'})

    def test_output_length_change(self):
        self.rejects(self.patch_at(tool.FINAL_LEN, bytes.fromhex('ba10000000')))

    def test_update_slot_change(self):
        start, raw = STATE['extents'].body(STATE['view'], self.body())
        for match in tool.re.finditer(rb'\xff\x15(....)', raw, tool.re.S):
            if start + match.end() + struct.unpack('<i', match.group(1))[0] == tool.SLOT_UPDATE:
                self.rejects({start + match.start(1): rel(tool.SLOT_FINALIZE, start + match.end())})
                return
        self.fail('update call not found')

    def test_core_not_found_out_of_extent(self):
        with self.assertRaises(ValueError):
            tool.hash_core(STATE['view'], STATE['extents'], self.body() + 1)


class Keccak(Base):
    def test_round_word_change(self):
        self.rejects({tool.ROUND_TABLE + 0x40: struct.pack('<Q', 1)})

    def test_round_head_change(self):
        self.rejects({tool.ROUND_TABLE: struct.pack('<Q', 2)})

    def test_permutation_slot_change(self):
        self.rejects(addends={tool.SLOT_PERMUTE: tool.UPDATE_TARGET})

    def test_update_slot_target_change(self):
        self.rejects(addends={tool.SLOT_UPDATE: tool.FINALIZE_TARGET})

    def test_permutation_without_table(self):
        start, raw = STATE['extents'].body(STATE['view'], tool.PERMUTE_TARGET)
        for match in tool.re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](....)', raw, tool.re.S):
            if start + match.end() + struct.unpack('<i', match.group(1))[0] == tool.ROUND_TABLE:
                self.rejects({start + match.start(1): b'\0\0\0\0'})
                return
        self.fail('table reference not found')


class Captures(Base):
    def test_box_offset_duplicate(self):
        # Row 4 captures +0x80; give it the +0x5b8 of row 3.
        self.rejects({0x2756432 + 3: struct.pack('<i', 0x5b8)})

    def test_group_box_gap(self):
        self.rejects({0x27569a9 + 1: b'\x90'})

    def test_vtable_out_of_order(self):
        self.rejects({0x2756b7a: b'\x00\x00\x00\x00'})

    def test_data_store_moved(self):
        self.rejects({0x2756b87: b'\x18'})

    def test_unknown_source(self):
        self.rejects({0x2756b6e + 4: b'\x58'})


class Sites(Base):
    def test_low_modulus_change(self):
        self.rejects({0x220afc2 + 8: struct.pack('<I', 51)})

    def test_high_modulus_change(self):
        self.rejects({0x42e4f8a + 8 + 6: struct.pack('<I', 1000)})

    def test_mode_offset_change(self):
        self.rejects({0x220afc2 + 2: struct.pack('<I', 0x8f3)})

    def test_threshold_change(self):
        self.rejects({0x42e665a + 7: b'\x03'})

    def test_builder_call_redirect(self):
        self.rejects({0x220b007 + 1: rel(0x4d7c910, 0x220b00c)})

    def test_map_offset_change(self):
        self.rejects({0x42e4fea + 3: struct.pack('<I', 0x3b28)})

    def test_site_outside_caller(self):
        site = dict(tool.SITES[0], caller=0x42e4600)
        with self.assertRaises(ValueError):
            tool.check_site(STATE['view'], STATE['extents'], site)


class Output(Base):
    def test_swapped_high_half_source(self):
        # movupd xmm1, [rsp+0x2c8] becomes [rsp+0x2d8].
        self.rejects({0x27570be + 5: b'\xd8'})

    def test_low_half_read_moved(self):
        self.rejects({0x27570ac + 5: b'\x40'})

    def test_out_write_register_change(self):
        self.rejects({0x27570d8 + 3: b'\x50'})

    def test_sibling_chain_broken(self):
        self.rejects({0x4d7da31 + 5: b'\x40'})

    def test_out_slot_not_rdi(self):
        self.rejects({0x2755e01 + 3: b'\x8c'})

    def test_block_count_change(self):
        self.rejects({0x2757079: bytes.fromhex('ba20100000')})

    def test_log_template_repointed(self):
        self.rejects({0x2757420 + 3: b'\0\0\0\0'})


class Pins(Base):
    def test_every_byte_pin_is_checked(self):
        for va, raw, _meaning in tool.BYTE_PINS:
            first = bytes([bytes.fromhex(raw)[0] ^ 1])
            with self.assertRaises(ValueError, msg=hex(va)):
                tool.check_byte_pins(Patched(STATE['view'], {va: first}))

    def test_every_rip_pin_is_checked(self):
        for va, prefix, _target, _meaning in tool.RIP_PINS:
            at = va + len(bytes.fromhex(prefix))
            with self.assertRaises(ValueError, msg=hex(va)):
                tool.check_byte_pins(Patched(STATE['view'], {at: b'\0\0\0\0'}))


class Reads(Base):
    def test_nobits_section_is_not_readable(self):
        bss = next(s for s in STATE['view'].sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], tool.SHT_NOBITS)
        with self.assertRaises(ValueError):
            STATE['view'].mem(bss['address'], 8)

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            STATE['view'].mem(0x7fffffff0000, 8)

    def test_read_past_section_end(self):
        text = next(s for s in STATE['view'].sections if s['name'] == '.text')
        with self.assertRaises(ValueError):
            STATE['view'].mem(text['address'] + text['size'] - 4, 8)

    def test_address_without_extent(self):
        with self.assertRaises(ValueError):
            STATE['extents'].at(0x10)

    def test_template_bad_tag(self):
        with self.assertRaises(ValueError):
            tool.decode_template(Patched(STATE['view'], {tool.LOG_TEMPLATE: b'\x90'}), tool.LOG_TEMPLATE)

    def test_template_text_change(self):
        self.rejects({tool.LOG_TEMPLATE + 0x18: b'X'})


if __name__ == '__main__':
    unittest.main()
