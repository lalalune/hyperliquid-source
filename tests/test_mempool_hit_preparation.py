import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
"""Independent raw-value expectations and actual captured operand mutations."""
import json
import unittest
import mempool_hit_preparation as tool

class HitPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (tool.ROOT/tool.BINARY).read_bytes()
        cls.image = tool.Image(cls.data)

    def changed(self, va, raw):
        data = bytearray(self.data)
        off = self.image.off(va, len(raw))
        data[off:off+len(raw)] = raw
        return data

    def test_marker_bypass_and_real_jcc_inversion(self):
        marker = (1 << 63)+1
        for word in (0, 1, marker-1, marker, marker+1, (1 << 64)-1):
            self.assertEqual(tool.first_match_action(self.image, word), 'second_lookup' if word == marker else 'prepare_first')
        changed = tool.Image(self.changed(0x44b9b4f, b'\x84'))
        self.assertEqual(tool.first_match_action(changed, marker), 'prepare_first')
        self.assertEqual(tool.first_match_action(changed, 0), 'second_lookup')

    def test_both_tags_and_all_byte_payloads(self):
        for kind, tag in (('first', (1 << 63)+35), ('second', (1 << 63)+36)):
            for payload in range(256):
                key = bytes((n+payload) % 256 for n in range(32))
                result = tool.prepare_hit(self.image, kind, payload, key)
                self.assertEqual(bytes.fromhex(result['prefix']), tag.to_bytes(8, 'little')+bytes([payload])+key)
                self.assertEqual(result['defined_offsets'], list(range(64, 105)))
                self.assertEqual(result['compared_tag'], (1 << 63)+42)
                self.assertEqual(result['route'], 'err_preparation')
                # No dependence on arbitrary contents outside defined stores.
                self.assertEqual(result, tool.prepare_hit(self.image, kind, payload, key, canary=0x3c))

    def test_tag_branch_and_store_operand_counterexamples(self):
        original = tool.prepare_hit(self.image, 'first', 3, bytes(range(32)))
        image = tool.Image(self.changed(0x44b9c13, b'\x29'))
        self.assertEqual(tool.prepare_hit(image, 'first', 3, bytes(range(32)))['route'], 'ok_preparation')
        image = tool.Image(self.changed(0x44b9c58, b'\x84'))
        self.assertEqual(tool.prepare_hit(image, 'first', 3, bytes(range(32)))['route'], 'ok_preparation')
        # Swap the two actual destination displacements; the key order changes.
        data = self.changed(0x44b9c2d, b'\x59')
        off = self.image.off(0x44b9c32, 1); data[off] = 0x49
        self.assertNotEqual(tool.prepare_hit(tool.Image(data), 'first', 3, bytes(range(32)))['prefix'], original['prefix'])
        for va, raw in ((0x44b9c13, b'\x29'), (0x44b9c58, b'\x84'), (0x44b9c2d, b'\x59')):
            with self.assertRaisesRegex(ValueError, 'owner changed'):
                tool.observe(self.changed(va, raw))

    def test_full_owner_data_call_and_identity_controls(self):
        self.assertEqual(tool.observe(self.data)['owners'][0]['sha256'], tool.OWNER_SHA)
        for va in (0x44b9a50, 0x44ba837, 0x6f4e29, 0x6f4e2c, 0x6f4f2e, 0x44b9cd5, 0x44b9d63):
            value = self.image.read(va, 1)[0] ^ 1
            with self.assertRaises(ValueError):
                tool.observe(self.changed(va, bytes([value])))
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            tool.build(self.data[:-1])

    def test_domain_and_undefined_read_rejection(self):
        for word in (-1, 1 << 64, True):
            with self.assertRaises(ValueError): tool.first_match_action(self.image, word)
        for payload in (-1, 256, True):
            with self.assertRaises(ValueError): tool.prepare_hit(self.image, 'first', payload, bytes(32))
        with self.assertRaises(ValueError): tool.prepare_hit(self.image, 'other', 0, bytes(32))
        with self.assertRaises(ValueError): tool.prepare_hit(self.image, 'first', 0, bytes(31))
        with self.assertRaisesRegex(ValueError, 'undefined'):
            tool.prepare_hit(tool.Image(self.changed(0x44b9c56, b'\x70')), 'first', 0, bytes(32))

class RetainedPacketTests(unittest.TestCase):
    def test_retained_packet(self):
        import json
        self.assertEqual(tool.build((tool.ROOT/tool.BINARY).read_bytes()),json.loads((tool.PACKET/'records.json').read_bytes()))

if __name__ == '__main__':
    unittest.main()
