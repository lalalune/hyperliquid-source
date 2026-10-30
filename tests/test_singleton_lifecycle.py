"""Actual node #94 controls for the bounded registry lifecycle observations."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
from singleton_lifecycle import controls, decoded_reference, read_va, relocations


class SingletonLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'artifacts/node/94/hl-node'
        identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                        if i['path'] == 'artifacts/node/94/hl-node')
        check(path, identity)
        cls.data = path.read_bytes()

    def test_actual_instruction_data_and_relocation_controls(self):
        instructions, descriptors = controls(self.data)
        self.assertEqual(len(instructions), 29)
        self.assertEqual(len(descriptors), 6)
        self.assertEqual(len(relocations(self.data)), 10)

    def test_actual_lifecycle_control_corruptions(self):
        # Check the local obligations below the full-input hash gate. These do
        # not simply rediscover that a changed artifact has a different SHA.
        for va in [0x1439A64, 0x1439AB4, 0x1439ACB, 0x1439AD7,
                   0x1439B1A, 0x1439B92, 0x1439780, 0x1439790,
                   0x14397BB, 0x143981A, 0x1439831, 0x143983D,
                   0x1439853, 0x143987D, 0x1439941, 0x1445955,
                   0x144598C, 0x14459A7, 0x14459B1, 0x14459C0,
                   0x14459D6, 0x14CC522, 0x14CC8D7, 0x143F6D0]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'instruction control changed'):
                    controls(changed)

    def test_actual_descriptor_and_attribution_corruptions(self):
        for va in [0x1F05CD, 0x1E84E2, 0x1E6381, 0x2019CD, 0x1DE8E0, 0x1F8990]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = read_va(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'descriptor/path control changed'):
                    controls(changed)

    def test_actual_role_formatter_and_word_provider_retargets(self):
        for slot, target in [(0x576F008, 0x1445950), (0x576EFA0, 0x14396C0),
                             (0x576F4E0, 0x1439A40), (0x576E040, 0x1344760),
                             (0x576E9D8, 0x13CC380), (0x566A168, 0x1F8990)]:
            with self.subTest(slot=hex(slot)):
                changed = bytearray(self.data)
                offset = changed.find(struct.pack('<QQq', slot, 8, target))
                self.assertGreaterEqual(offset, 0)
                changed[offset + 16] ^= 1
                with self.assertRaisesRegex(ValueError, 'RELA target changed'):
                    relocations(changed)

    def test_actual_call_bytes_bind_lifecycle_operations(self):
        for site, size, kind, target in [(0x1439AD7, 5, 'direct', 0x14CC320),
                                        (0x14459C0, 5, 'direct', 0x14CC7C0),
                                        (0x1439790, 6, 'GOT', 0x576E9D8)]:
            body = read_va(self.data, site, size)[1]
            line = f' {site:x}: {body.hex(" ")}   call operand'
            self.assertEqual(decoded_reference(line), (site, kind, target))

    def test_address_mentions_and_opaque_register_calls_not_resolved(self):
        self.assertIsNone(decoded_reference('0x1445950 is a data reference'))
        self.assertIsNone(decoded_reference(' 1439790: ff d0 call *%rax # 576e9d8'))
