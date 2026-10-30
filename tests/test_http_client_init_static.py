"""Corruption controls for the captured HTTP factory, not a network simulation."""
import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import http_client_init_static as tool

PACKET = tool.ROOT / 'research/work-items/RE-001-http-client-factory-94'


class HttpFactoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (tool.ROOT / 'artifacts/node/94/hl-node').read_bytes()
        cls.secs = tool.sections(cls.data)
        cls.result = tool.build(cls.data)

    def changed(self, va, raw):
        ss = next(s for s in self.secs if s['type'] != 8 and
                  s['address'] <= va < s['address'] + s['size'])
        offset = ss['offset'] + va - ss['address']
        result = bytearray(self.data)
        result[offset:offset + len(raw)] = raw
        return result

    def test_real_target_record(self):
        self.assertEqual(json.loads((PACKET / 'records.json').read_bytes()), self.result)
        self.assertEqual(self.result['range']['bytes'], 1019)
        self.assertEqual(self.result['builder_result_guard']['compared_value'], '0x8000000000000006')
        self.assertEqual(self.result['raw_timeout_stores'],
                         {'f64':10.0,'f64_bits':'0x4024000000000000',
                          'value_offset':'0xb8','tag_offset':'0xc0','tag':1})
        self.assertEqual((self.result['unwrap']['line'],self.result['unwrap']['column']), (24,67))

    def test_builder_result_and_error_branch_controls(self):
        for va, raw, reason in [(0x1439147,b'\x07','discriminator'),
                                 (0x1439155,b'\x0f\x84','Instruction changed'),
                                 (0x1439157,struct.pack('<i',0),'Error branch target')]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, reason):
                    tool.observe(self.changed(va,raw))

    def test_raw_timeout_controls(self):
        for va, raw, reason in [(0x143927c,struct.pack('<d',60.0),'timeout value/offset'),
                                 (0x1439287,struct.pack('<I',0xb0),'timeout value/offset'),
                                 (0x1439291,b'\x00','timeout tag')]:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError, reason):
                    tool.observe(self.changed(va,raw))

    def test_message_and_fde_controls(self):
        with self.assertRaisesRegex(ValueError, 'Unwrap message'):
            tool.observe(self.changed(0x21969d,b'X'))
        fde = int(self.result['range']['fde_va'],16)
        with self.assertRaisesRegex(ValueError, 'HTTP factory FDE'):
            tool.observe(self.changed(fde+12,struct.pack('<I',1018)))

    def test_actual_source_and_panic_relocations(self):
        for slot, addend, reason in [(0x566a150,0x1eb91c,'source Location relocation'),
                                     (0x576e048,0x157aa10,'Unwrap call slot binding')]:
            with self.subTest(slot=hex(slot)):
                changed=bytearray(self.data)
                needle=struct.pack('<QQq',slot,8,addend)
                offset=changed.find(needle)
                self.assertGreaterEqual(offset,0)
                self.assertEqual(changed.find(needle,offset+1),-1)
                changed[offset+16]^=1
                with self.assertRaisesRegex(ValueError, reason):
                    tool.observe(changed)

    def test_factory_call_and_identity_controls(self):
        with self.assertRaisesRegex(ValueError, 'Factory helper call'):
            tool.observe(self.changed(0x143913b,struct.pack('<i',0)))
        with self.assertRaisesRegex(ValueError, 'Wrong node94 SHA-256'):
            tool.build(self.data[:-1]+bytes([self.data[-1]^1]))
