import hashlib
import json
import re
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import chain_entry_insert_static as pkt

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-005-node115-chain-entry-insert'
BINARY = ROOT / 'artifacts/node/115/hl-node'


def load_records():
    return json.loads((PACKET / 'records.json').read_text())


class ChainEntryInsertStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = BINARY.read_bytes()
        cls.records = load_records()

    def test_artifact_identity(self):
        self.assertEqual(len(self.data), pkt.TARGET_SIZE)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), pkt.TARGET_SHA256)

    def test_regeneration_byte_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'packet'
            pkt.generate(BINARY, out)
            for name in ('records.json', 'frames.txt',
                         'value_merge_builder_disassembly.txt',
                         'map_insert_disassembly.txt',
                         'get_or_insert_disassembly.txt',
                         'ctx_remove_op_disassembly.txt',
                         'value_copy_disassembly.txt',
                         'field_getter_disassembly.txt',
                         'entry_counter_a_disassembly.txt',
                         'entry_counter_b_disassembly.txt',
                         'worker_entry_window.txt',
                         'worker_remove_site_a_window.txt',
                         'worker_result_stores_a_window.txt',
                         'worker_result_store_b_window.txt',
                         'worker_result_store_c_window.txt',
                         'worker_map_ops_window.txt',
                         'worker_assembly_window.txt',
                         'worker_result_stores_b_window.txt'):
                fresh, retained = (out / name).read_bytes(), (PACKET / name).read_bytes()
                # GNU embeds the input filename in its header; paths differ
                # across worktrees. Preserve all remaining bytes verbatim.
                normalize = lambda raw: re.sub(
                    rb'^.*hl-node:\s+file format', b'hl-node:     file format',
                    raw, flags=re.M)
                self.assertEqual(normalize(fresh), normalize(retained), name)

    def test_owner_hashes(self):
        owners = {o['role']: o for o in self.records['owners']}
        self.assertEqual(
            owners['registry_worker']['sha256'],
            'b38566cd8062d559cbc2d01f63fa4a80854ffbb6c65560a23ae26b27c5fa1791')
        self.assertEqual(owners['registry_worker']['bytes'], 17970)
        self.assertEqual(
            owners['value_merge_builder']['sha256'],
            'a3cd3033412c3b151c94388b3299fbf561644dbbe1d150ea7177e12b6b9fc37e')
        self.assertEqual(owners['value_merge_builder']['bytes'], 2679)
        self.assertEqual(
            owners['map_insert']['sha256'],
            '19713809d5b33a780aa46af6e870e870fab5499f16da0ba435950bad2e718e50')
        self.assertEqual(
            owners['get_or_insert']['sha256'],
            '21dbfce6a49d692b60fb0f0b3d33da2e5f9fadd751698c224b735537106ac7af')
        self.assertEqual(
            owners['ctx_remove_op']['sha256'],
            'c1457eeb4364f3144c55511040a2146129f44b8a51f0b97b00bba48bcc538eeb')
        for role in ('entry_counter_a', 'entry_counter_b', 'value_copy'):
            start = int(owners[role]['start'], 16)
            end = int(owners[role]['end'], 16)
            body = pkt.read(self.data, start, end - start)
            self.assertEqual(hashlib.sha256(body).hexdigest(),
                             owners[role]['sha256'], role)

    def test_boundary_hashes(self):
        for name, entry in self.records['boundaries'].items():
            start = int(entry['start'], 16)
            body = pkt.read(self.data, start, entry['bytes'])
            self.assertEqual(hashlib.sha256(body).hexdigest(),
                             entry['sha256'], name)
        self.assertEqual(
            self.records['boundaries']['final_assembly']['sha256'],
            'a023ea6de0a9c1a7e5e4b81e1dffe82f3274dca6b93d1ecc2852a4cab74fd8df')

    def test_worker_callee_hashes(self):
        self.assertEqual(len(self.records['worker_callees']), 49)
        for start_hex, entry in self.records['worker_callees'].items():
            body = pkt.read(self.data, int(start_hex, 16), entry['bytes'])
            self.assertEqual(hashlib.sha256(body).hexdigest(),
                             entry['sha256'], start_hex)

    def test_chain_key_bytes(self):
        self.assertEqual(pkt.read(self.data, pkt.CHAIN_NAME_VA, 5), b'chain')

    def test_worker_insert_census(self):
        census = self.records['worker_census']
        self.assertEqual(census['direct_insert_calls'], [])
        self.assertEqual(census['direct_get_or_insert_calls'], [])
        self.assertEqual(census['direct_remove_op_calls'], [])
        self.assertEqual(census['get_or_insert_slot_sites'],
                         ['0x16327b9', '0x163281e'])
        self.assertEqual(census['remove_op_slot_sites'],
                         ['0x16317bf', '0x1632743', '0x1634350'])
        self.assertEqual(census['counter_a_slot_site'], '0x1631e47')
        self.assertEqual(census['counter_b_slot_site'], '0x1631c90')
        self.assertEqual(census['final_assembly_slot_site'], '0x16343d1')
        capability = census['callee_capability']
        self.assertEqual(capability['calls_insert'], ['0x1667540'])
        self.assertEqual(capability['calls_get_or_insert'], [])
        self.assertEqual(capability['calls_remove_op'], [])
        self.assertEqual(capability['psubq_bodies'], [])

    def test_whole_binary_helper_slot_census(self):
        census = self.records['worker_census']
        self.assertEqual(
            [(e['site'], e['owner'])
             for e in census['whole_binary_get_or_insert_sites']],
            [('0x162cf0b', 'entry_counter_a'),
             ('0x16327b9', 'registry_worker'),
             ('0x163281e', 'registry_worker'),
             ('0x163a239', 'entry_counter_b')])
        self.assertEqual(
            [(e['site'], e['owner'])
             for e in census['whole_binary_remove_op_sites']],
            [('0x16317bf', 'registry_worker'),
             ('0x1632743', 'registry_worker'),
             ('0x1634350', 'registry_worker')])
        self.assertEqual(self.records['helper_slot_bindings'],
                         {'map_insert': [], 'get_or_insert': ['0x64e1ba8'],
                          'ctx_remove_op': ['0x64e1c70']})

    def test_builder_insert_census(self):
        census = self.records['builder_census']
        self.assertEqual(census['insert_call_sites'], ['0x1667c0e', '0x1668034'])
        self.assertEqual(census['value_copy_call_sites'],
                         ['0x1667a47', '0x1667af9', '0x1667ba8', '0x1667fd9'])
        self.assertEqual(census['ctx_hash_call_sites'], ['0x1667cdd'])
        self.assertEqual(census['temp_hash_call_sites'], ['0x16678eb'])
        self.assertEqual(census['recursion_site'], '0x1667e3d')

    def test_helper_census(self):
        census = self.records['helper_census']
        self.assertEqual(census['map_insert']['hash_call_site'], '0x16693ca')
        self.assertEqual(census['map_insert']['reserve_slot_site'], '0x166961f')
        self.assertEqual(census['map_insert']['psubq_count'], 1)
        self.assertEqual(census['get_or_insert']['insert_call_site'], '0x16676bd')
        self.assertEqual(census['get_or_insert']['hash_call_site'], '0x166756f')
        self.assertEqual(census['ctx_remove_op']['insert_call_sites'], [])
        self.assertEqual(census['ctx_remove_op']['hash_call_site'], '0x1668536')

    def test_worker_asserted_sites_are_instruction_starts(self):
        body = pkt.read(self.data, pkt.WORKER[0],
                        pkt.WORKER[1] - pkt.WORKER[0])
        text = pkt.executable(
            'objdump',
            ['-d', '-M', 'intel', '--insn-width=16',
             f'--start-address={pkt.WORKER[0]:#x}',
             f'--stop-address={pkt.WORKER[1]:#x}', str(BINARY)])
        starts = set(pkt.decode_export(text, pkt.WORKER[0], pkt.WORKER[1], body))
        for va, _hex, _what in pkt.WORKER_PINS:
            self.assertIn(va, starts, hex(va))
        for site in (0x16327b9, 0x163281e, 0x16317bf, 0x1632743, 0x1634350,
                     0x16343d1, 0x163436b, 0x16327cd, 0x1631e47, 0x1631c90,
                     0x163180c):
            self.assertIn(site, starts, hex(site))

    def _mutated(self, va, delta=1):
        blob = bytearray(self.data)
        blob[va - 0x1000] ^= delta
        return bytes(blob)

    def test_counterfactual_pair_insert_call(self):
        with self.assertRaises(ValueError):
            pkt.analyze(self._mutated(0x1667c0e + 1))

    def test_counterfactual_drain_insert_call(self):
        with self.assertRaises(ValueError):
            pkt.analyze(self._mutated(0x1668034 + 1))

    def test_counterfactual_default_record_presence_word(self):
        with self.assertRaises(ValueError):
            pkt.analyze(self._mutated(0x166769a))

    def test_counterfactual_remove_op_items_decrement(self):
        with self.assertRaises(ValueError):
            pkt.analyze(self._mutated(0x16686dc))

    def test_counterfactual_ctx_miss_edge(self):
        with self.assertRaises(ValueError):
            pkt.analyze(self._mutated(0x16678b8))

    def test_counterfactual_get_or_insert_slot_binding(self):
        entry = next(e for e in pkt.relocations(self.data)
                     if e['slot'] == 0x64e1ba8)
        blob = bytearray(self.data)
        struct.pack_into('<q', blob, entry['addend_file_offset'],
                         pkt.INSERT_VA)
        with self.assertRaises(ValueError):
            pkt.analyze(bytes(blob))

    def test_counterfactual_descriptor_table_pointer(self):
        entry = next(e for e in pkt.relocations(self.data)
                     if e['type'] == 8 and 0x6405a48 <= e['slot'] < 0x6405b48
                     and e['slot'] not in pkt.SLOTS)
        blob = bytearray(self.data)
        struct.pack_into('<q', blob, entry['addend_file_offset'],
                         pkt.INSERT_VA)
        with self.assertRaises(ValueError):
            pkt.analyze(bytes(blob))

    def test_counterfactual_boundary_body(self):
        with self.assertRaises(ValueError):
            pkt.analyze(self._mutated(0x164df60))


if __name__ == '__main__':
    unittest.main()
