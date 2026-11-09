import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bridge_eth_event_wire_115 as wire  # noqa: E402

PACKET = ROOT / 'research/work-items/bridge-eth-event-wire-115'
IMAGE = wire.load_image()
USER = bytes(range(0x40, 0x54))
DIGEST = bytes(range(0xA0, 0xC0))


def flat_bytes(named, usd, block, t, i, event_name):
    """Independent hand-built msgpack of the flat action for the default fixture, no use of the rule list."""
    def uint(value):
        return bytes([value]) if value < 0x80 else bytes([0xCC, value]) if value < 0x100 else b'\xcd' + value.to_bytes(2, 'big')

    def text(value):
        raw = value.encode()
        return (bytes([0xA0 | len(raw)]) if len(raw) < 32 else bytes([0xD9, len(raw)])) + raw
    key = (lambda name: text(name)) if named else (lambda name: b'')
    ident = bytes([0x85 if named else 0x95]) + key('b') + uint(block) + key('t') + uint(t) + key('e') + text(event_name) + key('i') + uint(i) + key('h') + text('0x' + DIGEST.hex())
    head = bytes([0x84 if named else 0x94])
    return head + key('type') + text('VoteEthDepositAction') + key('user') + text('0x' + USER.hex()) + key('usd') + uint(usd) + key('ethId') + ident


class BridgeEthEventWire115(unittest.TestCase):
    def test_binary_identity(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), wire.SHA256)
        self.assertEqual(wire.SHA256, 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
        with self.assertRaises(wire.EvidenceError):
            wire.load_image(wire.BINARY, '0' * 64)

    def test_entries_are_unwind_starts(self):
        for target in wire.TARGETS:
            self.assertEqual(IMAGE.exact_fde(target)[0], target)
        for copy, base in wire.SERIALIZER_COPIES + wire.DECODER_COPIES:
            self.assertEqual(IMAGE.exact_fde(copy)[0], copy)
            self.assertIn(base, wire.NAMES)
        with self.assertRaises(wire.EvidenceError):
            IMAGE.exact_fde(wire.TARGETS[0] + 1)
        with self.assertRaises(wire.EvidenceError):
            IMAGE.offset(0x10)

    def test_import_slots_come_from_the_dynamic_symbols(self):
        roles = IMAGE.symbol_slots()
        self.assertEqual(sorted(set(roles.values())), ['alloc', 'compare', 'copy', 'free', 'realloc', 'stop'])
        self.assertEqual(roles[0x64DF508], 'copy')
        self.assertEqual(roles[0x64E1570], 'alloc')
        relative = IMAGE.relative()
        for slot, entry in ((0x64DF480, 0x6355830), (0x64DF4A0, 0x635DE30)):
            self.assertEqual(relative[slot], entry)
            self.assertIn(entry, wire.ALLOCATOR_ENTRIES)

    def test_flat_message_bytes_against_a_hand_built_form(self):
        harness = wire.Harness(IMAGE)
        for entry in (wire.FLAT_MP_A, wire.FLAT_MP_B):
            for named in (1, 0):
                for event, name in enumerate(wire.EVENTS):
                    case = wire.Ser('flat', entry, wire.Action(usd=100, block=0x1234, t=9, i=300, event=event), named)
                    self.assertEqual(harness.serialize(case), flat_bytes(named, 100, 0x1234, 9, 300, name))

    def test_every_entry_and_copy_matches_the_rule_list(self):
        harness = wire.Harness(IMAGE)
        for entry in sorted(wire.FORMS):
            for named in (1, 0) if wire.FORMS[entry][0] != 'j' else (1,):
                case = wire.Ser('all', entry, wire.Action(usd=0x10000, block=wire.MASK[8], event=5), named, 0)
                self.assertEqual(wire.run_case(harness, case), wire.spec_ser(case))
        copies = wire.copy_rows(IMAGE, harness, wire.named_cases())
        self.assertEqual(len(copies), 13)
        self.assertTrue(all(row[4] > 0 for row in copies))

    def test_reader_rules(self):
        harness = wire.Harness(IMAGE)
        rows = {name: value for name, value in wire.action_cases()}
        for entry in wire.DECODERS:
            for name in ('good', 'seq_good', 'extra_key', 'dup_usd', 'usd_minus', 'usd_newtype', 'user_upper', 'user_short', 'id_seq', 'not_struct_unit'):
                case = wire.De(name, entry, rows[name])
                self.assertEqual(wire.run_case(harness, case), wire.spec_run(case), name)
        good = wire.run_case(harness, wire.De('good', wire.DE_ACT_R, rows['good']))
        self.assertEqual(good[0], 'ok')
        self.assertEqual(good[1], 100000000)
        refused = wire.run_case(harness, wire.De('extra', wire.DE_ACT_R, rows['extra_key']))
        self.assertEqual(refused[0], 'error')
        self.assertIn('unknown field', refused[1])
        unit_json = wire.run_case(harness, wire.De('unit', wire.DE_ACT_J, rows['not_struct_unit']))
        unit_rmp = wire.run_case(harness, wire.De('unit', wire.DE_ACT_R, rows['not_struct_unit']))
        self.assertIn('null', unit_json[1])
        self.assertIn('unit value', unit_rmp[1])

    def test_event_names_and_texts_come_from_the_file(self):
        rows = wire.event_rows(IMAGE)
        self.assertEqual(len(rows), 18)
        self.assertEqual([row[1] for row in rows[:6]], list(wire.EVENTS))
        self.assertEqual(len(wire.text_rows(IMAGE)), 5)

    def test_negative_controls_are_all_caught(self):
        harness = wire.Harness(IMAGE)
        cases = wire.named_cases()
        named = wire.check_all(harness, cases)
        table = {}
        for target in wire.TARGETS:
            low, high = IMAGE.exact_fde(target)
            table[target] = [wire.row_at(IMAGE, va) for va in sorted(harness.machine.seen) if low <= va < high]
            for row in table[target]:
                row.data = bytes(IMAGE.blob[IMAGE.offset(row.va):IMAGE.offset(row.va) + row.size])
        rows = wire.negative_controls(IMAGE, harness, named, table)
        self.assertGreaterEqual(len(rows), 30)
        self.assertEqual([row for row in rows if not row[3]], [])

    def test_a_wrong_rule_list_is_rejected(self):
        harness = wire.Harness(IMAGE)
        case = wire.Ser('x', wire.FLAT_MP_A, wire.Action(usd=0x7F), 1)
        want = wire.spec_ser(case)
        self.assertEqual(wire.run_case(harness, case), want)
        right = wire.mp_uint
        restore = wire.patched('mp_uint', lambda value: b'\xcc' + bytes([value]) if value == 0x7F else right(value))
        try:
            self.assertNotEqual(wire.run_case(harness, case), wire.spec_ser(case))
        finally:
            restore()

    def test_a_flipped_head_byte_is_detected(self):
        probe = wire.Harness(IMAGE)
        case = wire.Ser('x', wire.NEST_MP_A, wire.Action(), 1)
        wire.run_case(probe, case)
        low, high = IMAGE.exact_fde(wire.NEST_MP_A)
        rows = [wire.row_at(IMAGE, va) for va in sorted(probe.machine.seen) if low <= va < high]
        for row in rows:
            row.data = bytes(IMAGE.blob[IMAGE.offset(row.va):IMAGE.offset(row.va) + row.size])
        head = wire.bound_imm_rows(wire.NEST_MP_A, rows)[0]
        self.assertEqual(head.data[head.imm_at], 0x82)
        broken = wire.Harness(IMAGE, {head.va + head.imm_at: 0x83})
        self.assertNotEqual(wire.run_case(broken, case), wire.spec_ser(case))

    def test_corrupted_inputs_are_refused(self):
        damaged = bytearray(IMAGE.blob)
        damaged[IMAGE.offset(IMAGE.relative()[wire.EVENT_POOLS[1]])] ^= 0x20
        with self.assertRaises(wire.EvidenceError):
            wire.event_rows(wire.Image(bytes(damaged)))
        cut = wire.Image(bytes(IMAGE.blob))
        cut.named = dict(cut.named)
        cut.named['.rela.dyn'] = dict(cut.named['.rela.dyn'], size=cut.named['.rela.dyn']['size'] + 1)
        with self.assertRaises(wire.EvidenceError):
            list(cut.relocations())

    def test_committed_packet_is_consistent(self):
        manifest = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        self.assertGreaterEqual(len(manifest), 12)
        for line in manifest:
            digest, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest, name)
        measure = json.loads((PACKET / 'measure.json').read_text())
        evidence = json.loads((PACKET / 'evidence.json').read_text())
        self.assertEqual(measure['cases'], evidence['cases'])
        self.assertGreaterEqual(measure['cases'], 10000)
        self.assertGreaterEqual(measure['negative_controls'], 30)
        self.assertEqual(measure['negative_detected'], measure['negative_controls'])
        self.assertEqual(evidence['sha256'], wire.SHA256)


if __name__ == '__main__':
    unittest.main()
