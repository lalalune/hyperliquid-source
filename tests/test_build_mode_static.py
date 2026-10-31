"""Real-target corruption controls for the node #94 build_mode static packet."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
from build_mode_static import (CONTROLS, LITERALS, LOCATIONS, RELOCATIONS, TEMPLATES, controls,
                               decode_template, generate, locations, objdump_targets, read_va,
                               relevant_relocations)

PACKET = ROOT / 'research/work-items/RE-001-build-mode-94/observed'


class BuildModeStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / 'artifacts/node/94/hl-node'
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == 'artifacts/node/94/hl-node')
        check(cls.path, identity)
        cls.data = cls.path.read_bytes()

    def flipped(self, va, delta=0):
        changed = bytearray(self.data)
        offset, _ = read_va(changed, va + delta, 1)
        changed[offset] ^= 1
        return changed

    def test_real_controls_relocations_and_locations(self):
        byte_controls, templates = controls(self.data)
        self.assertEqual(len(byte_controls), len(CONTROLS))
        self.assertEqual({k: v['tokens'] for k, v in templates.items()},
                         {hex(k): v for k, v in TEMPLATES.items()})
        self.assertEqual(len(relevant_relocations(self.data)), len(RELOCATIONS))
        rows = {r['record_va']: (r['line'], r['column']) for r in locations(self.data)}
        self.assertEqual(rows['0x566a0c0'], (199, 30))
        self.assertEqual(rows['0x566a0a8'], (29, 17))
        self.assertEqual(rows['0x566a090'], (32, 26))

    def test_real_instruction_corruptions_rejected(self):
        # Bypass the whole-file digest: each local proof obligation must fail on its own.
        for va, value in CONTROLS.items():
            for delta in sorted({0, len(bytes.fromhex(value)) - 1}):
                with self.subTest(va=hex(va), delta=delta):
                    with self.assertRaisesRegex(ValueError, 'control changed'):
                        controls(self.flipped(va, delta))

    def test_real_literal_and_template_corruptions_rejected(self):
        for va in [*LITERALS, *TEMPLATES]:
            with self.subTest(va=hex(va)):
                with self.assertRaises(ValueError):
                    controls(self.flipped(va, 1))

    def test_real_relocation_retargets_rejected(self):
        for slot, target in RELOCATIONS.items():
            with self.subTest(slot=hex(slot)):
                changed = bytearray(self.data)
                offset = changed.find(struct.pack('<QQq', slot, 8, target))
                self.assertGreaterEqual(offset, 0)
                changed[offset + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'relocation changed'):
                    relevant_relocations(changed)

    def test_reference_swapped_line_column_is_rejected(self):
        # The can1357 lead cites these anchors as 30:199, 17:29 and 26:32.
        for va, (path, line, column) in LOCATIONS.items():
            if b'build_mode.rs' not in path:
                continue
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va + 16, 8)
                struct.pack_into('<II', changed, offset, column, line)
                with self.assertRaisesRegex(ValueError, 'location changed'):
                    locations(changed)

    def test_template_decoder_fails_closed(self):
        va = 0x1F4EA1
        for patch, message in [(b'\x85', 'Unsupported template control'), (b'\xff', 'Unsupported')]:
            with self.subTest(patch=patch):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va, 1)
                changed[offset:offset + 1] = patch
                with self.assertRaisesRegex(ValueError, message):
                    decode_template(changed, va)
        self.assertEqual(decode_template(self.data, 0x1E4C77), (['{}', '/code/run-client'], 19))

    def test_objdump_target_parser(self):
        line = (' 13cd7ad:\tff 15 6d 12 3a 04    \tcall   *0x43a126d(%rip)        '
                '# 576ea20 <__register_atfork@plt+0x10d7e0>')
        self.assertEqual(objdump_targets(line), (0x13CD7AD, 'call', 0x576EA20))
        lea = (' 13cbae6:\t48 8d 05 93 f0 3a 04 \tlea    0x43af093(%rip),%rax        '
               '# 577ab80 <__register_atfork@plt+0x119940>')
        self.assertEqual(objdump_targets(lea), (0x13CBAE6, 'lea', 0x577AB80))
        self.assertIsNone(objdump_targets('0x576ea20 mentioned as data'))
        self.assertIsNone(objdump_targets(' 144a026:\tff d3                \tcall   *%rbx'))

    def test_packet_records_regenerate(self):
        with tempfile.TemporaryDirectory() as tmp:
            records = generate(self.path, Path(tmp))
            self.assertEqual((Path(tmp) / 'records.json').read_bytes(), (PACKET / 'records.json').read_bytes())
            self.assertEqual((Path(tmp) / 'references.tsv').read_bytes(), (PACKET / 'references.tsv').read_bytes())
        self.assertEqual(records['build_dir_caller_sites'], ['0x13cd7ad'])
        self.assertFalse(records['captured_binary_executed'])


if __name__ == '__main__':
    unittest.main()
