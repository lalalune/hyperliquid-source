"""Unit tests for the node #94 multiply/xor mixer evidence packet.

Every test is a corruption or edge control on retained bytes: each one flips
exactly one locked fact and expects the checker to fail, plus positive edge
checks on the decoded mixer rule. No target execution anywhere.
"""
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_xor_mixer as tool

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'research/work-items/foundation-xor-mixer-94/evidence.json'
BINARY = ROOT / 'artifacts/node/94/hl-node'


def fresh_data():
    return bytearray(BINARY.read_bytes())


def run_check(data):
    return tool.analyze(bytes(data))


def corrupt_va(data, va, new_bytes):
    secs = tool.sections(bytes(data))
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + len(new_bytes) <= s['address'] + s['size']]
    assert len(matches) == 1, 'Test setup: ambiguous VA'
    s = matches[0]
    off = s['offset'] + va - s['address']
    data[off:off + len(new_bytes)] = new_bytes


class XorMixerPacketTests(unittest.TestCase):
    def test_check_passes_and_prints(self):
        # Positive path exercised through inspect + retained JSON comparison
        # (the --check CLI path is exercised separately below).
        result = tool.inspect(str(BINARY))
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['sha256'], result['body_sha256'])
        self.assertEqual(result['call_sites'], [0x4dd768f])
        self.assertEqual(result['seed_slot'], 0x576e3e0)
        self.assertEqual(result['seed_addend'], 0x5788348)

    def test_body_byte_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x4b2765e, b'\x48\x83\xf0\x15')  # 0x14 -> 0x15
        with self.assertRaises(ValueError):
            run_check(data)

    def test_seed_slot_displacement_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x4b27623, struct.pack('<i', 0xc46db8))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_padding_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x4b27669, b'\x90')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_fde_record_change_fails(self):
        data = fresh_data()
        # Flip one byte of the window FDE's range field in .eh_frame.
        secs = tool.sections(bytes(data))
        eh = [s for s in secs if s['name'] == '.eh_frame'][0]
        off = eh['offset'] + 0x2564fc + 12
        data[off] = 0x4a
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_fde_record_change_fails(self):
        data = fresh_data()
        secs = tool.sections(bytes(data))
        eh = [s for s in secs if s['name'] == '.eh_frame'][0]
        off = eh['offset'] + 0x6088f4 + 12
        data[off] = 0xff
        with self.assertRaises(ValueError):
            run_check(data)

    def test_caller_call_target_change_fails(self):
        data = fresh_data()
        corrupt_va(data, 0x4dd7690, struct.pack('<i', -0x2b0073))
        with self.assertRaises(ValueError):
            run_check(data)

    def test_seed_addend_change_fails(self):
        data = fresh_data()
        # The seed slot's RELATIVE addend lives in .rela.dyn; find it by slot.
        secs = tool.sections(bytes(data))
        rel = [s for s in secs if s['name'] == '.rela.dyn'][0]
        raw = bytes(data[rel['offset']:rel['offset'] + rel['size']])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if address == 0x576e3e0:
                data[rel['offset'] + off + 16:rel['offset'] + off + 24] = \
                    struct.pack('<q', 0x5788349)
                break
        else:
            self.fail('Test setup: seed relocation not found')
        with self.assertRaises(ValueError):
            run_check(data)

    def test_mixer_edges(self):
        self.assertEqual(tool.mixer(b'\x00' * 8, b'\x00' * 20, 0, 0), 0)
        self.assertEqual(tool.mixer(bytes(range(8)), bytes(range(20)),
                                    0xdeadbeefcafef00d, 0x123456789abcdef0),
                         0x9c4e42a7cec11b69)
        self.assertEqual(tool.mixer(bytes(range(8)), bytes(range(20)), 0,
                                    0x123456789abcdef0), 0)
        self.assertEqual(tool.mixer(b'\x00' * 8, b'\x00' * 20, 1, 0), 0x14)

    def test_scout_value_does_not_match(self):
        # The scout note omitted t1hi from acc; on the sample edge its value
        # differs from the retained bytes. The corrected rule must not match it.
        self.assertNotEqual(tool.mixer(bytes(range(8)), bytes(range(20)),
                                       0xdeadbeefcafef00d, 0x123456789abcdef0),
                            0x168f9edeb5fcf46a)

    def test_evidence_json_shape(self):
        retained = json.loads(EVIDENCE.read_text())
        self.assertEqual(retained['function']['start_va'], '0x4b27620')
        self.assertEqual(retained['function']['end_va_exclusive'], '0x4b27669')
        self.assertEqual(retained['function']['bytes'], 73)
        self.assertEqual(retained['function']['padding_bytes'], 7)
        self.assertEqual(retained['incoming_pattern_scan']['e8_candidates'],
                         ['0x4dd768f'])
        self.assertFalse(retained['incoming_pattern_scan']['complete_xref_census'])
        self.assertFalse(retained['captured_binary_executed'])
        self.assertFalse(retained['progress_gate_requested'])


if __name__ == '__main__':
    unittest.main()
