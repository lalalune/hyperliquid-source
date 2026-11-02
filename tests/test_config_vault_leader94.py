import copy
import hashlib
import json
import math
from pathlib import Path
import struct
import tempfile
import unittest

from tools import config_vault_leader94 as tool


class ConfigVaultLeaderEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Absence or corruption is a test failure, never a skipped test.
        cls.data = tool.TARGET.read_bytes()
        cls.image = tool.Image(cls.data)
        cls.result = tool.collect(cls.image)
        cls.at = {row['va']: row for row in cls.result['instructions']}

    def patched_read(self, address, replacement):
        clone = copy.copy(self.image)
        read = self.image.read
        def override(start, size):
            raw = bytearray(read(start, size))
            lo, hi = max(start,address), min(start + size,address + len(replacement))
            if lo < hi:
                raw[lo-start:hi-start] = replacement[lo-address:hi-address]
            return bytes(raw)
        clone.read = override
        return clone

    def test_capture_identity(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), tool.DIGEST)
        self.assertEqual(len(self.data), 91774280)

    def test_digest_control(self):
        damaged = bytearray(self.data)
        damaged[0x100] ^= 1
        with self.assertRaisesRegex(tool.EvidenceError, 'digest mismatch'):
            tool.Image(damaged)

    def test_fde_ranges_and_complete_partitions(self):
        self.assertEqual(len(self.result['functions']), 5)
        for function in self.result['functions']:
            rows = [r for r in self.result['instructions'] if r['function'] == function['entry']]
            self.assertEqual(rows[0]['va'], function['entry'])
            self.assertEqual(rows[-1]['va'] + rows[-1]['size'], function['end'])
            self.assertEqual(b''.join(bytes.fromhex(r['bytes']) for r in rows).hex(), function['bytes'])
            self.assertEqual(sum(r['size'] for r in rows), function['size'])
            self.assertEqual(hashlib.sha256(bytes.fromhex(function['bytes'])).hexdigest(), function['sha256'])

    def test_fde_extent_corruption_is_rejected(self):
        image = copy.copy(self.image)
        image.fdes = [dict(row) for row in self.image.fdes]
        next(x for x in image.fdes if x['start'] == 0x2586fd0)['end'] -= 1
        with self.assertRaisesRegex(tool.EvidenceError, 'extent changed'):
            tool.collect(image)

    def test_code_corruption_rejected_by_body_hash(self):
        image = self.patched_read(0x2587058, bytes.fromhex('b900603c81'))
        with self.assertRaisesRegex(tool.EvidenceError, 'FDE bytes changed'):
            tool.collect(image)

    def test_code_corruption_rejected_by_instruction_contract(self):
        image = self.patched_read(0x2587058, bytes.fromhex('b900603c81'))
        with self.assertRaisesRegex(tool.EvidenceError, 'instruction contract changed'):
            tool.collect(image, check_body_hashes=False)

    def test_valid_but_wrong_branch_target_is_rejected(self):
        # Still a valid short conditional jump, but it bypasses the slow path.
        image = self.patched_read(0x258704c, bytes.fromhex('751e'))
        with self.assertRaisesRegex(tool.EvidenceError, 'instruction contract changed'):
            tool.collect(image, check_body_hashes=False)

    def test_decoding_rejects_unknown_truncated_and_interior_branch(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'truncated'):
            tool.decode(b'\x0f', 0x1000)
        with self.assertRaisesRegex(tool.EvidenceError, 'unsupported'):
            tool.decode(b'\x62', 0x1000)
        with self.assertRaisesRegex(tool.EvidenceError, 'instruction interior'):
            tool.decode(b'\xeb\xff', 0x1000)

    def test_nobits_and_outside_range_have_no_file_bytes(self):
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(bss['address'], 1)
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(-1, 1)
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(1 << 64, 8)
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(0x2586fd0, 0)

    def test_relocation_links_are_recorded(self):
        by_slot = {r['slot']:r for r in self.result['relocations']}
        self.assertEqual(by_slot[0x576e928]['addend'], 0x577b288)
        self.assertEqual(by_slot[0x577b288]['addend'], 0x164ff00)
        self.assertEqual(by_slot[0x577ab80]['addend'], 0x143ef30)
        self.assertEqual(by_slot[0x576dfe0]['symbol'], 'memcpy')
        for row in by_slot.values():
            raw = bytes.fromhex(row['record_bytes'])
            slot, info, addend = struct.unpack('<QQq', raw)
            self.assertEqual((slot,info & 0xffffffff,info >> 32,addend),
                             (row['slot'],row['type'],row['symbol_index'],row['addend']))

    def test_wrong_relative_relocation_is_rejected(self):
        image = copy.copy(self.image)
        image.relocations = dict(self.image.relocations)
        image.relocations[0x576e928] ^= 8
        with self.assertRaisesRegex(tool.EvidenceError, 'config relocation changed'):
            tool.collect(image)

    def test_corrupt_rela_addend_is_rejected_when_reparsed(self):
        damaged = bytearray(self.data)
        position = self.image.relocation_offsets[0x576e928]
        damaged[position + 16] ^= 8
        image = tool.Image(damaged, verify=False)
        with self.assertRaisesRegex(tool.EvidenceError, 'config relocation changed'):
            tool.collect(image)

    def test_descriptor_corruption_is_rejected(self):
        image = self.patched_read(0x2180ff, b'X')
        with self.assertRaisesRegex(tool.EvidenceError, 'default descriptor changed'):
            tool.collect(image)

    def test_template_corruption_is_rejected(self):
        image = self.patched_read(0x1ef5f5, b'\xc1')
        with self.assertRaisesRegex(tool.EvidenceError, 'template anchor changed'):
            tool.collect(image)

    def test_descriptor_names_are_length_delimited(self):
        names = {r['index']:r for r in self.result['names']}
        self.assertEqual(names[32]['name'], 'NvTestnet')
        self.assertEqual(names[32]['pointer'], 0x2180ff)
        self.assertEqual(names[32]['length'], 9)
        self.assertFalse(names[32]['in_mask'])
        self.assertEqual([x['index'] for x in self.result['names'] if x['in_mask']],
                         [13,14,18,19,20,21,31])
        for row in names.values():
            self.assertEqual(self.image.read(row['pointer'],row['length']).decode('ascii'),row['name'])

    def test_complete_name_byte_domain(self):
        g = self.result['guard']
        accepted = {13,14,18,19,20,21,31}
        for tag in range(256):
            with self.subTest(tag=tag):
                self.assertEqual(tool.evaluate_gate(tag,4.0,g['threshold'],g['mask'],g['limit']), tag in accepted)
        for invalid in (-1,256,1.0,True):
            with self.assertRaises(tool.EvidenceError):
                tool.evaluate_gate(invalid,4.0,g['threshold'],g['mask'],g['limit'])

    def test_float_threshold_and_unordered(self):
        g = self.result['guard']
        for duration in (-math.inf,-0.0,0.0,3.0,math.nan):
            self.assertFalse(tool.evaluate_gate(13,duration,g['threshold'],g['mask'],g['limit']))
        for duration in (math.nextafter(3.0,math.inf),math.inf):
            self.assertTrue(tool.evaluate_gate(13,duration,g['threshold'],g['mask'],g['limit']))
        self.assertFalse(tool.evaluate_gate(32,math.inf,g['threshold'],g['mask'],g['limit']))

    def test_record_selection_all_byte_positions_and_closed_flag(self):
        key = bytes(range(20))
        self.assertTrue(tool.matches_record(key,key,0))
        for index in range(20):
            other = bytearray(key)
            other[index] ^= 0x80
            self.assertFalse(tool.matches_record(key,bytes(other),0))
        for flag in range(1,256):
            self.assertFalse(tool.matches_record(key,key,flag))
        with self.assertRaises(tool.EvidenceError):
            tool.matches_record(key[:-1],key,0)
        with self.assertRaises(tool.EvidenceError):
            tool.matches_record(key,key,256)

    def test_record_stride_allocation_and_growth_shapes(self):
        self.assertEqual(self.at[0x256a0aa]['immediate'], 176)
        self.assertEqual(self.at[0x256a1db]['immediate'], 48)
        self.assertEqual(self.at[0x2569e25]['immediate'], 192)
        self.assertEqual(self.at[0x2569e56]['immediate'], 4)
        self.assertEqual(self.at[0x2569e25]['immediate'],
                         self.at[0x2569e56]['immediate'] * self.at[0x256a1db]['immediate'])
        self.assertEqual(self.at[0x256a1e4]['target'],0x251b070)
        self.assertEqual(self.at[0x2569d1f]['target'],0x2569dd9)
        self.assertEqual(self.at[0x2569d76]['target'],0x2569d30)
        self.assertEqual(self.at[0x2569d7f]['target'],0x2569d30)
        self.assertEqual(self.at[0x2569dc4]['immediate'],1 << 63)
        self.assertEqual(self.at[0x256a156]['immediate'],1 << 63)
        self.assertEqual(self.at[0x2569dd1]['target'],0x2569d30)
        self.assertEqual(self.at[0x256a16b]['target'],0x2569ef0)

    def test_atomic_lock_boundaries(self):
        writer_mask = self.at[0x27d7ceb]['immediate']
        limit = (1 << 64) + self.at[0x27d7cf1]['immediate']
        wake_mask = self.at[0x27d7e3b]['immediate'] & ((1 << 64)-1)
        wake_value = self.at[0x27d7e3f]['immediate']
        requires_slow = lambda x: bool(x & writer_mask or x >= limit)
        self.assertFalse(requires_slow(0))
        self.assertFalse(requires_slow(16))
        self.assertTrue(requires_slow(8))
        self.assertTrue(requires_slow(limit))
        self.assertFalse(requires_slow(limit-16))
        self.assertTrue((0x12 & wake_mask) == wake_value)
        self.assertFalse((0x10 & wake_mask) == wake_value)
        self.assertEqual(self.at[0x27d7d0e]['mem']['disp'],16)
        self.assertEqual(self.at[0x27d7e2a]['immediate'],-16)

    def test_cleanup_copies_and_explicit_masks(self):
        c = self.result['cleanup_comparison']
        self.assertEqual((c['equal_bytes'],c['compared_bytes']),(118,124))
        self.assertEqual((c['outside_mask_equal_bytes'],c['outside_mask_bytes']),(116,116))
        self.assertEqual(c['masks'],[{'offset':32,'length':4},{'offset':110,'length':4}])
        self.assertEqual(self.at[0x277b80d]['memory_va'],self.at[0x278253d]['memory_va'])
        self.assertEqual(self.at[0x277b85c]['memory_va'],self.at[0x278258c]['memory_va'])

    def test_unwind_call_ranges_and_corrupt_lsda(self):
        def landing(call):
            return next(r['landing'] for r in self.result['lsda'] if r['start'] <= call < r['end'])
        self.assertEqual(landing(0x27d7e25),0x27d7f5e)
        self.assertEqual(landing(0x27d7f00),0x27d7f49)
        self.assertEqual(landing(0x25870f0),0x25870fb)
        funcs = [dict(row) for row in self.result['functions']]
        next(f for f in funcs if f['entry'] == 0x2586fd0)['lsda'] = 0x10
        with self.assertRaisesRegex(tool.EvidenceError, 'LSDA outside'):
            tool.exception_sites(self.image,funcs,self.result['instructions'])

    def test_control_flow_guards(self):
        checks = {r['label']:r for r in self.result['cfg']}
        self.assertFalse(checks['wrapper_gate_never_restarts_query']['reachable'])
        self.assertFalse(checks['no_normal_return_avoids_unlock']['reachable'])
        self.assertFalse(checks['empty_result_bypasses_allocation']['reachable'])
        self.assertTrue(checks['later_record_can_grow']['reachable'])
        self.assertTrue(checks['array_allocation_failure_reaches_trap']['reachable'])

    def test_generated_files_match_retained_bytes(self):
        retained = tool.ROOT / 'research/work-items/RE-015-vault-leader-gate-94'
        with tempfile.TemporaryDirectory() as dirname:
            output = Path(dirname)
            tool.write_outputs(self.result,output)
            generated = sorted(p.name for p in output.iterdir())
            expected = sorted(p.name for p in retained.iterdir() if p.suffix in ('.json','.tsv'))
            self.assertEqual(generated,expected)
            for name in generated:
                with self.subTest(file=name):
                    self.assertEqual((output/name).read_bytes(),(retained/name).read_bytes())
        summary = json.loads((retained/'summary.json').read_text(encoding='utf-8'))
        self.assertEqual(summary['target_sha256'],tool.DIGEST)


if __name__ == '__main__':
    unittest.main()
