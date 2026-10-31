import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_checkpoint_upload as tool  # noqa: E402

FOLDER = ROOT / 'research' / 'work-items' / 'RE-009-abci-checkpoint-upload-94'
CACHE = {}


def image():
    if 'image' not in CACHE:
        CACHE['image'] = tool.Image(tool.load_binary())
    return CACHE['image']


def result():
    if 'result' not in CACHE:
        CACHE['result'] = tool.analyse(image())
    return CACHE['result']


def patched(patches):
    return tool.Patched(image(), patches)


def flip(va):
    return {va: bytes([image().read(va, 1)[0] ^ 0xff])}


class Report(unittest.TestCase):
    def test_binary_digest_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / 'bad'
            bad.write_bytes(b'not the node')
            with self.assertRaises(SystemExit):
                tool.load_binary(bad)

    def test_function_extents(self):
        functions = result()[0]['functions']
        self.assertEqual(functions['closure']['bytes'], 0x235)
        self.assertEqual({k: v['start'] for k, v in functions.items()},
                         {k: f'{v:#x}' for k, v in tool.FUNCTIONS.items()})

    def test_pin_count_and_targets(self):
        report, rows = result()
        self.assertEqual(report['pin_count'], len(tool.PINS))
        self.assertEqual(sum(1 for row in rows if row[3] is not None), 42)

    def test_retry_budget(self):
        sleeps = result()[0]['default_sleeps']
        self.assertEqual(sleeps['seconds'], [0.001, 0.05, 1.0])
        self.assertEqual(sleeps['microseconds'], [1000, 50000, 1000000])
        self.assertEqual(sleeps['attempts_when_all_fail'], 4)

    def test_command_model(self):
        model = result()[0]['model']
        self.assertEqual(model['command'], 'lz4 -q -9 --rm <in> <in>.lz4')
        self.assertEqual(model['command_without_remove'], 'lz4 -q -9  <in> <in>.lz4')
        self.assertEqual(model['upload_words'], ['aws', 's3', 'mv', '<in>.lz4', '<destination>'])

    def test_exhaustion_template_has_no_newline(self):
        text = result()[0]['templates']['retry_exhausted']['text']
        self.assertEqual(text, 'sleep_retry retried {} for sleep times {} last err {}')
        self.assertNotIn(chr(10), text)

    def test_census_is_closed(self):
        census = result()[0]['census']
        self.assertEqual(census['direct_calls']['0x13c96c0'], ['0x432fc69'])
        self.assertEqual(census['direct_calls']['0x14503b0'], ['0x13c9716', '0x13c98ef'])
        self.assertEqual(census['indirect_slot_uses']['0x5776630'], ['0x433aa1a'])
        self.assertTrue(census['rip_lea_uses'])
        self.assertFalse(any(census['rip_lea_uses'].values()))

    def test_files_match_packet(self):
        report, rows = result()
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(Path(folder), report, rows)
            for name in (tool.JSON_NAME, tool.TSV_NAME):
                self.assertEqual((Path(folder) / name).read_bytes(), (FOLDER / name).read_bytes())

    def test_evidence_has_no_absolute_paths(self):
        report, rows = result()
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(Path(folder), report, rows)
            blob = b''.join(path.read_bytes() for path in sorted(Path(folder).iterdir()))
        for root in ('home', 'tmp', 'srv', 'mnt'):
            self.assertNotIn(('/' + root + '/').encode(), blob)


class NegativeControls(unittest.TestCase):
    def test_every_pin_rejects_a_flipped_first_byte(self):
        for _, va, _, _, _ in tool.PINS:
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                tool.check_pins(patched(flip(va)))

    def test_every_targeted_pin_rejects_a_flipped_last_byte(self):
        for _, va, raw, target, _ in tool.PINS:
            if target is None:
                continue
            last = va + len(bytes.fromhex(raw)) - 1
            with self.subTest(va=hex(va)), self.assertRaises(ValueError):
                tool.check_pins(patched(flip(last)))

    def test_pin_outside_its_function(self):
        row = ('closure', 0x432fe45, '90', None, 'out of range')
        with mock.patch.object(tool, 'PINS', [row]), self.assertRaisesRegex(ValueError, 'outside'):
            tool.check_pins(image())

    def test_unknown_function_start(self):
        with mock.patch.dict(tool.FUNCTIONS, {'closure': 0x432fc11}), self.assertRaisesRegex(ValueError, 'outside'):
            tool.check_pins(image())

    def test_target_rule_rejects_other_forms(self):
        with self.assertRaises(ValueError):
            tool.instruction_target(bytes.fromhex('4889e5'), 0x1000)

    def test_template_walker_rules(self):
        self.assertEqual(tool.decode_template(b'\x02ab\xc0\x00'), 'ab{}')
        with self.assertRaises(ValueError):
            tool.decode_template(b'\x81ab\x00')
        with self.assertRaises(ValueError):
            tool.decode_template(b'\x05ab')

    def test_template_bytes_are_bound(self):
        for name, (va, _) in tool.TEMPLATES.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                tool.check_templates(patched({va: b'\x81'}))
            with self.subTest(name=name), self.assertRaises(ValueError):
                tool.check_templates(patched({va + 1: b'\x41'}))

    def test_text_bytes_are_bound(self):
        for name, (va, _, _) in tool.TEXTS.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                tool.check_texts(patched({va: b'#'}))

    def test_static_suffix_length_is_bound(self):
        with self.assertRaisesRegex(ValueError, 'row differs'):
            tool.check_texts(patched({tool.SUFFIX_STR + 8: b'\x05'}))

    def test_sleep_table_is_bound(self):
        with self.assertRaises(ValueError):
            tool.check_sleeps(patched({tool.SLEEPS[0]: struct.pack('<d', 0.002)}))
        with self.assertRaises(ValueError):
            tool.check_sleeps(patched({tool.MICROS: struct.pack('<d', 1000.0)}))

    def test_location_line_is_bound(self):
        row = tool.LOCATIONS['mv_unwrap'][0]
        with self.assertRaisesRegex(ValueError, 'Location'):
            tool.check_locations(patched({row + 16: b'\x1c'}))

    def test_slot_binding_is_bound(self):
        view = patched({})
        view.relocs = dict(image().relocs)
        view.relocs[0x576efd8] = (tool.R_X86_64_RELATIVE, 0, 0x1000)
        with self.assertRaisesRegex(ValueError, 'does not bind'):
            tool.check_slots(view)

    def test_import_name_is_bound(self):
        with mock.patch.dict(tool.IMPORT_SLOTS, {0x576f690: 'rename'}, clear=True), \
                self.assertRaisesRegex(ValueError, 'does not import'):
            tool.check_slots(image())

    def test_vtable_size_is_bound(self):
        with self.assertRaisesRegex(ValueError, 'vtable'):
            tool.check_vtable(patched({tool.THREAD_VTABLE + 8: b'\x58'}))

    def test_census_rejects_a_missing_caller(self):
        view = patched({})
        view.text = lambda: (b'\x90' * 32, 0x1000)
        with self.assertRaisesRegex(ValueError, 'census'):
            tool.census(view)

    def test_read_refuses_nobits_and_section_ends(self):
        bss = image().section('.bss')
        with self.assertRaises(ValueError):
            image().read(bss['address'], 8)
        text = image().section('.text')
        with self.assertRaises(ValueError):
            image().read(0x10, 8)
        self.assertEqual(len(image().read(text['address'], 8)), 8)


class Scanners(unittest.TestCase):
    def test_direct_refs(self):
        text = b'\x90\xe8\x0b\x00\x00\x00\xe9\x05\x00\x00\x00\x90'
        found = tool.direct_refs(text, 0x1000, [0x1011, 0x1010, 0x2000])
        self.assertEqual(found, {0x1011: [0x1001], 0x1010: [0x1006], 0x2000: []})

    def test_slot_refs(self):
        text = b'\xff\x15\x10\x00\x00\x00\xff\x25\x0a\x00\x00\x00\xff\xd0'
        found = tool.slot_refs(text, 0x1000, [0x1016, 0x1017])
        self.assertEqual(found, {0x1016: [0x1000, 0x1006], 0x1017: []})

    def test_slot_refs_sees_a_mov_load(self):
        text = b'\x48\x8b\x05\x09\x00\x00\x00'
        self.assertEqual(tool.slot_refs(text, 0x1000, [0x1010]), {0x1010: [0x1000]})

    def test_lea_refs(self):
        text = b'\x90\x48\x8d\x3d\x08\x00\x00\x00\x90'
        self.assertEqual(tool.lea_refs(text, 0x1000, [0x1010, 0x1011]), {0x1010: [0x1001], 0x1011: []})

    def test_reloc_refs_keeps_relative_only(self):
        relocs = {0x20: (8, 0, 0x99), 0x10: (8, 0, 0x99), 0x30: (6, 1, 0x99)}
        self.assertEqual(tool.reloc_refs(relocs, [0x99]), {0x99: [0x10, 0x20]})


class Model(unittest.TestCase):
    TEMPLATE = 'lz4 -q -9 {} {} {}'

    def test_guard_boundaries(self):
        self.assertEqual(tool.lz4_command(self.TEMPLATE, 'lz4', True), 'lz4 -q -9 --rm lz4 lz4.lz4')
        self.assertEqual(tool.lz4_command(self.TEMPLATE, 'a.lz4x', True), 'lz4 -q -9 --rm a.lz4x a.lz4x.lz4')
        for path in ('.lz4', 'a.lz4'):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'zip_inner: '):
                tool.lz4_command(self.TEMPLATE, path, True)


if __name__ == '__main__':
    unittest.main()
