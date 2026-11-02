"""Target-backed and negative-control tests for the BolePool codec extractor."""
import csv
import io
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bole_pool_codec_94 as codec


def rows(contents):
    return list(csv.DictReader(io.StringIO(contents.decode('utf-8')), delimiter='\t'))


class PatchView(codec.View):
    """Change a selected virtual-address byte without copying the ELF input."""
    def __init__(self, original, va, value):
        self.data = original.data
        self.sections = original.sections
        self.va = va
        self.value = value

    def get(self, va, size, executable=False):
        data = bytearray(super().get(va, size, executable))
        if va <= self.va < va + size:
            data[self.va - va] = self.value
        return bytes(data)


class BolePoolCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = codec.TARGET.read_bytes()
        cls.view = codec.View(cls.data)
        cls.output = codec.extract(cls.data)
        cls.fields = rows(cls.output['fields.tsv'])
        cls.keys = rows(cls.output['accepted-keys.tsv'])

    def test_type_identity_relocation(self):
        identity, = rows(self.output['type-record.tsv'])
        self.assertEqual(identity['literal'], 'struct BolePool with 21 elements')
        self.assertEqual(identity['relocation_type'], 'R_X86_64_RELATIVE')
        self.assertEqual(identity['literal_length'], '32')
        self.assertEqual(identity['slot_va'], '0x5685cc8')

    def test_writer_key_order_and_object_offsets(self):
        self.assertEqual([x['writer_key'] for x in self.fields],
            'dp du o pmmt pmmu e pmv pma r p n b bog pmdl pml uobc ubgl ubul bwo mbs u'.split())
        self.assertEqual([int(x['object_offset'], 16) for x in self.fields],
            [0x118, 0x119, 0x11a, 0xa8, 0xb0, 0x11b, 0xb8, 0xc0, 0xc8,
             0xe8, 0xf0, 0, 0x40, 0x50, 0x60, 0x90, 0x70, 0x80, 0x11c, 0xf8, 0x100])
        self.assertTrue(all(int(x['value_call_va'], 16) for x in self.fields))

    def test_aliases_and_unknown_near_misses(self):
        by_key = {x['accepted_key']: int(x['field_index']) for x in self.keys}
        self.assertEqual(len(by_key), 28)
        for long_name, short_name in [('opmb','o'), ('enabled','e'), ('reserves','r'),
                                      ('usdt_usdc_px','p'), ('enp','n'), ('bl','b'),
                                      ('user_to_state','u')]:
            self.assertEqual(by_key[long_name], by_key[short_name])
        for near_miss in ('DP', 'd', 'dx', 'pmm', 'pmmtx', 'enabledx',
                          'user_to_statex', '', 'reserves\0'):
            self.assertNotIn(near_miss, by_key)

    def test_dispatch_table_domains_and_unknown_slots(self):
        entries = rows(self.output['dispatch-tables.tsv'])
        self.assertEqual(len(entries), 55)
        counts = {name: sum(row['table'] == name for row in entries)
                  for name in ('key_length', 'single_byte_key', 'reader_field')}
        self.assertEqual(counts, {'key_length': 13, 'single_byte_key': 20, 'reader_field': 22})
        singles = [row for row in entries if row['table'] == 'single_byte_key']
        self.assertEqual(sum(row['classifier_index'] == '21' for row in singles), 13)
        self.assertEqual({row['selector'] for row in singles if row['classifier_index'] != '21'},
                         set('benopru'))

    def test_all_known_cases_have_matching_duplicate_diagnostics(self):
        self.assertEqual(len(self.fields), 21)
        self.assertEqual(len({r['reader_case_va'] for r in self.fields}), 21)
        self.assertEqual({r['duplicate_literal_va'] for r in self.fields}, {'0x1e0fd5'})
        for field in self.fields:
            with self.subTest(field=field['writer_key']):
                case = int(field['reader_case_va'], 16)
                comparison, location, sentinel, when, target = codec.guard(self.view, case)
                self.assertEqual(comparison.hex(), field['guard_bytes'])
                self.assertEqual(location, field['guard_location'])
                self.assertEqual(str(sentinel), field['sentinel'])
                self.assertEqual(when, field['duplicate_when'])
                self.assertEqual(hex(target), field['duplicate_target_va'])
                call = int(field['error_constructor_call_va'], 16)
                self.assertEqual(self.view.rel32(call, b'\xe8'), 0x1704040)

    def test_absent_scalar_and_pair_defaults(self):
        found = {r['field']: r for r in rows(self.output['default-branches.tsv'])}
        self.assertEqual({name: (int(row['first_word']), row['second_word'])
                          for name, row in found.items() if row['representation'] != 'helper-dependent'},
                         {'pmmt': (10, '-'), 'pmmu': (100000, '-'),
                          'pmv': (0, '-'), 'pma': (0, '-'),
                          'pmdl': (86400000, '50000'), 'pml': (60000, '10'),
                          'ubgl': (60000, '100'), 'ubul': (60000, '10'),
                          'dp': (0, '-'), 'du': (0, '-'), 'o': (0, '-'),
                          'e': (0, '-'), 'bwo': (0, '-')})
        self.assertEqual({name for name, row in found.items() if row['representation'] == 'helper-dependent'},
                         {'bog', 'uobc'})
        for name, row in found.items():
            with self.subTest(field=name):
                window = bytes.fromhex(row['window_bytes'])
                self.assertEqual(self.view.get(int(row['window_va'], 16), len(window)), window)

    def test_field_value_edges(self):
        edges = {r['role']: r for r in rows(self.output['edges.tsv'])}
        self.assertEqual(edges['reader_classifier']['target_va'], '0x22e3620')
        self.assertEqual(edges['pma_value']['target_va'], '0x25aaf40')
        self.assertEqual(edges['pmv_value']['target_va'], edges['mbs_value']['target_va'])
        for edge in edges.values():
            instruction = bytes.fromhex(edge['instruction_bytes'])
            self.assertEqual(self.view.get(int(edge['site_va'], 16), len(instruction)), instruction)

    def test_nested_u_collection_and_two_component_pipeline(self):
        edges = {r['role']: r for r in rows(self.output['edges.tsv'])}
        self.assertEqual(edges['u_nested_tail']['target_va'], '0x25e20f0')
        self.assertEqual(edges['u_collect_pairs']['target_va'], '0x2567ed0')
        self.assertEqual(edges['u_write_pairs']['target_va'], '0x1e490a0')
        self.assertEqual(edges['u_first_pair']['target_va'], '0x1de2330')
        self.assertEqual(edges['u_loop_pair']['target_va'], '0x1de2330')
        self.assertEqual(self.view.get(0x2567edf, 4), bytes.fromhex('49c1e704'))
        self.assertEqual(self.view.get(0x1e492a1, 4), bytes.fromhex('4883c510'))
        self.assertEqual(self.view.get(0x1de2397, 5), bytes.fromhex('ba02000000'))
        self.assertEqual(self.view.get(0x1de2437, 4), bytes.fromhex('c6040192'))
        with self.assertRaisesRegex(ValueError, 'unexpected instruction'):
            codec.View.rel32(PatchView(self.view, 0x1e4928e, 0x90), 0x1e4928e, b'\xe8')

    def test_nested_omission_predicate_and_corruption(self):
        omit = lambda a, b, c, d, ref: codec.nested_omits_o(self.view, a, b, c, d, ref)
        self.assertTrue(omit(0, 7, 0, 0, 7))
        for args in [(1, 7, 0, 0, 7), (0, 6, 0, 0, 7), (0, 7, 1, 0, 7),
                     (0, 7, 0, 1, 7), (0, 0xffffffff, 0, 0, 7)]:
            with self.subTest(args=args):
                self.assertFalse(omit(*args))
        with self.assertRaises(ValueError):
            omit(0, 0, 0, 0, 0)
        with self.assertRaises(ValueError):
            omit(0, 1 << 32, 0, 0, 7)
        patched = PatchView(self.view, 0x28d3d5c, 0x90)
        with self.assertRaisesRegex(ValueError, 'unexpected instruction'):
            codec.nested_omits_o(patched, 0, 7, 0, 0, 7)
        fields = rows(self.output['nested-fields.tsv'])
        self.assertEqual([(r['key'], r['presence'], r['object_offset']) for r in fields],
                         [('o', 'conditional', '0x0'), ('t', 'unconditional', '0x18')])

    def test_key_format_relocation_and_width(self):
        edges = {r['role']: r for r in rows(self.output['indirect-edges.tsv'])}
        self.assertEqual(edges['u_key_a_format']['target_va'], '0x29ed380')
        self.assertEqual(edges['u_key_a_format']['target_va'], edges['u_key_b_format']['target_va'])
        self.assertEqual(self.view.get(0x1e0d18b, 10), bytes.fromhex('be2a000000b914000000'))
        self.assertEqual(self.view.get(0x1e0d7ab, 10), bytes.fromhex('be2a000000b914000000'))

    def test_missing_field_paths_are_named_and_bounded(self):
        found = rows(self.output['missing-fields.tsv'])
        self.assertEqual([r['field'] for r in found], ['r', 'p', 'n', 'b', 'mbs', 'u'])
        self.assertEqual({r['missing_literal_va'] for r in found}, {'0x1df8f3'})
        self.assertEqual(self.view.get(0x17040c9, 3), bytes.fromhex('c60306'))
        for row in found:
            self.assertEqual(self.view.rel32(int(row['error_constructor_call_va'], 16), b'\xe8'), 0x1704040)
        default_names = {r['field'] for r in rows(self.output['default-branches.tsv'])}
        missing_names = {r['field'] for r in found}
        self.assertFalse(default_names & missing_names)
        self.assertEqual(default_names | missing_names, {r['writer_key'] for r in self.fields})
        self.assertTrue(all(0x198bad0 <= int(x['diagnostic_va'], 16) < 0x19905b7 for x in found))

    def test_bad_digest_rejected_before_parsing(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            codec.extract(b'not an ELF')
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            codec.check_digest(self.data, '0' * 64)

    def test_classifier_corruption_rejected(self):
        bad_opcode = PatchView(self.view, 0x22e367b, 0x90)
        with self.assertRaisesRegex(ValueError, 'unexpected instruction'):
            codec.classifier(bad_opcode)
        bad_table = PatchView(self.view, 0x3d9018, self.view.get(0x3d9018, 1)[0] ^ 1)
        with self.assertRaisesRegex(ValueError, 'length dispatch table mismatch'):
            codec.classifier(bad_table)
        bad_branch = PatchView(self.view, 0x22e3698, self.view.get(0x22e3698, 1)[0] ^ 1)
        with self.assertRaisesRegex(ValueError, 'two-byte mismatch branch'):
            codec.classifier(bad_branch)

    def test_out_of_range_and_nobits_rejected(self):
        with self.assertRaises(ValueError):
            self.view.get(-1, 1)
        with self.assertRaises(ValueError):
            self.view.get(1 << 63, 8)
        with self.assertRaises(ValueError):
            self.view.get(0x232ad20, 0)
        nobits = next(s for s in self.view.sections if s['name'] == '.bss' and s['type'] == 8 and s['size'])
        with self.assertRaises(ValueError):
            self.view.get(nobits['address'], 1)

    def test_guard_opcode_corruption_rejected(self):
        va = int(self.fields[0]['reader_case_va'], 16)
        with self.assertRaisesRegex(ValueError, 'unrecognized duplicate guard'):
            codec.guard(PatchView(self.view, va, 0x90), va)

    def test_field_key_length_corruption_rejected(self):
        va = codec.KEY_SITES[0][1]
        with self.assertRaisesRegex(ValueError, 'key length'):
            codec.key_instruction(PatchView(self.view, va + 1, 0), *codec.KEY_SITES[0][:2])

    def test_fde_extents_and_function_digests(self):
        got = rows(self.output['functions.tsv'])
        self.assertEqual(len(got), 22)
        self.assertEqual(got[0]['start_va'], '0x232ad20')
        self.assertEqual(got[0]['end_exclusive_va'], '0x232b3d9')
        self.assertEqual(got[1]['start_va'], '0x198bad0')
        self.assertEqual(got[2]['start_va'], '0x22e3620')
        for item in got:
            body = self.view.get(int(item['start_va'], 16), int(item['size']), True)
            codec.check_digest(body, item['body_sha256'])
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                codec.check_digest(body[:-1] + bytes([body[-1] ^ 1]), item['body_sha256'])


if __name__ == '__main__':
    unittest.main()
