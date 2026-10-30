"""Target expectations plus corruption controls; no target execution or network."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/spot-clearinghouse-inventory-94'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load('spot_inventory', ROOT / 'tools/spot_clearinghouse_inventory.py')
verifier = load('spot_packet_verify', PACKET / 'verify.py')


class SpotInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing evidence/tool is a failure, not a skipped positive test.
        cls.data = (ROOT / tool.TARGET).read_bytes()
        cls.results = tool.build(cls.data)
        cls.evidence = cls.results['inventory.json']
        cls.image = tool.Image(cls.data)
        cls.relocations = tool.relative_relocations(cls.image)
        cls.fdes = tool.Fdes(cls.image)
        cls.decoded = {}
        cls.raw = {}
        for run in cls.results['disassembly.json']['runs']:
            start = int(run['fde_start'], 16)
            text = '\n'.join(run['stdout_lines']) + '\n'
            cls.raw[start] = text
            cls.decoded[start] = tool.parse_disassembly(text, cls.image, cls.fdes.owner(start))

    def mutate(self, va, value):
        data = bytearray(self.data)
        _, offset = self.image.mapping(va, len(value))
        data[offset:offset + len(value)] = value
        return tool.Image(bytes(data))

    def test_target_counts_and_fixed_edges(self):
        verifier.verify_facts(self.evidence)
        self.assertEqual(self.evidence['metrics']['location_leas'], 27)
        self.assertEqual(self.evidence['metrics']['unique_path_line_column'], 16)

    def test_packet_byte_identical(self):
        for name in tool.OUTPUTS:
            self.assertEqual(tool.render(self.results[name]), (PACKET / name).read_bytes())

    def test_cli_hashseeds_and_optimized_regeneration(self):
        with tempfile.TemporaryDirectory() as temp:
            for seed in ('0', '97'):
                result = subprocess.run([sys.executable, '-O', '-B', str(ROOT / 'tools/spot_clearinghouse_inventory.py'),
                                         '--out', temp], env={**os.environ, 'PYTHONHASHSEED': seed},
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                for name in tool.OUTPUTS:
                    self.assertEqual((Path(temp) / name).read_bytes(), (PACKET / name).read_bytes())

    def test_wrong_digest_rejected_before_disassembly(self):
        for bad in (b'', self.data[:-1], self.data[:-1] + bytes([self.data[-1] ^ 1])):
            with self.subTest(size=len(bad)), patch.object(tool, 'disassemble') as dis:
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    tool.build(bad)
                dis.assert_not_called()

    def test_cli_bad_digest_writes_no_output(self):
        with tempfile.TemporaryDirectory() as temp:
            bad, out = Path(temp, 'bad'), Path(temp, 'out')
            bad.write_bytes(b'not node 94')
            process = subprocess.run([sys.executable, str(ROOT / 'tools/spot_clearinghouse_inventory.py'),
                                      '--binary', str(bad), '--out', str(out)], capture_output=True)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn(b'SHA-256 mismatch', process.stderr)
            self.assertFalse(out.exists())

    def test_bad_elf_architecture_and_section_table(self):
        for offset, data in ((4, b'\x01'), (18, b'\x03\x00'), (40, b'\xff' * 8)):
            b = bytearray(self.data)
            b[offset:offset + len(data)] = data
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                tool.Image(bytes(b))

    def test_reads_fail_on_unmapped_cross_section_or_zero(self):
        ro = self.image.by_name['.rodata']
        for va, size in ((-1, 1), (0xdeadbeef, 8), (ro['address'] + ro['size'] - 1, 2), (0, 0)):
            with self.subTest(va=va, size=size), self.assertRaises(ValueError):
                self.image.read(va, size)

    def test_location_line_column_and_relocation_bytes(self):
        loc = tool.decode_location(self.image, 0x56e8ac8, self.relocations[0x56e8ac8])
        self.assertEqual((loc['path'], loc['line'], loc['column']),
                         ('l1/src/spot_clearinghouse/spot_clearinghouse.rs', 846, 98))
        self.assertEqual(loc['path_length'], 76)
        self.assertEqual(loc['relocation']['addend'], '0x1fb334')
        self.assertEqual(bytes.fromhex(loc['bytes']), struct.pack('<QQII', 0, 76, 846, 98))

    def test_duplicate_coordinate_records_are_preserved(self):
        records = [x for x in self.evidence['locations'] if x['path'].endswith('/impl_outcome.rs')
                   and x['line'] == 155]
        self.assertEqual({x['va'] for x in records}, {'0x56bd7f8', '0x571fd48'})
        self.assertEqual({x['column'] for x in records}, {14})

    def test_location_corruption_pointer_length_line_column(self):
        slot = 0x56e8ac8
        for offset, raw in ((0, struct.pack('<Q', 1)), (8, struct.pack('<Q', 0)),
                            (8, struct.pack('<Q', 255)), (16, b'\0' * 4), (20, b'\0' * 4)):
            with self.subTest(offset=offset, raw=raw), self.assertRaises(ValueError):
                tool.decode_location(self.mutate(slot + offset, raw), slot, self.relocations[slot])

    def test_location_wrong_scope_or_unmapped_addend(self):
        for address in (0xdeadbeef, 0x5992e3):
            rel = {**self.relocations[0x56e8ac8], 'target': address}
            with self.subTest(address=address), self.assertRaises(ValueError):
                tool.decode_location(self.image, 0x56e8ac8, rel)
        with self.assertRaises(ValueError):
            tool.decode_location(self.image, 0x56e8ac9, self.relocations[0x56e8ac8])

    def test_relocation_duplicate_and_truncated_table(self):
        s = self.image.by_name['.rela.dyn']
        changed = self.mutate(s['address'] + 24, self.image.read(s['address'], 8))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            tool.relative_relocations(changed)
        changed = tool.Image(self.data)
        changed.by_name['.rela.dyn']['size'] -= 1
        with self.assertRaisesRegex(ValueError, 'truncated'):
            tool.relative_relocations(changed)

    def test_relocation_nonzero_symbol_rejected(self):
        rel = self.relocations[0x56e8ac8]
        changed = self.mutate(rel['entry_va'] + 8, struct.pack('<Q', (1 << 32) | 8))
        with self.assertRaisesRegex(ValueError, 'symbol'):
            tool.relative_relocations(changed)

    def test_fde_end_is_exclusive_and_instructions_must_fit(self):
        fde = self.fdes.owner(0x3723010)
        self.assertEqual(fde['end'], 0x3723056)
        self.assertEqual(self.fdes.owner(fde['start'])['start'], fde['start'])
        self.assertIsNotNone(self.fdes.owner(fde['end'] - 1))
        self.assertIsNone(self.fdes.owner(fde['end']))
        self.assertIsNone(self.fdes.owner(fde['end'] - 1, 2))

    def test_fde_start_mismatch_and_unsupported_cie(self):
        fde = self.fdes.owner(0x3723010)
        for address, raw in ((fde['fde'] + 8, struct.pack('<i', 1)), (fde['cie'] + 8, b'\x02')):
            with self.subTest(address=address), self.assertRaises(ValueError):
                tool.Fdes(self.mutate(address, raw))

    def test_lea_signed_displacement_and_extended_register(self):
        self.assertEqual(tool.decode_lea(bytes.fromhex('488d3557c9eefc'), 0x3308cd3), (0x1f5631, 6))
        self.assertEqual(tool.decode_lea(bytes.fromhex('4c8d05e431b101'), 0x3c01a9d), (0x5714c88, 8))
        for bad in ('488b3557c9eefc', '488d3457c9eefc', '488d3557c9ee', '488d3557c9eefc00'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                tool.decode_lea(bytes.fromhex(bad), 0x3308cd3)

    def test_disassembly_gaps_bytes_bad_and_truncation(self):
        raw = self.raw[0x3723010]
        fde = self.fdes.owner(0x3723010)
        for bad in (raw.replace('41 56 ', '41 57 ', 1), raw.replace('3723010:', '3723011:', 1),
                    raw.replace('push   r14', '(bad)', 1), '\n'.join(raw.splitlines()[:-1])):
            with self.subTest(bad=bad[:80]), self.assertRaises(ValueError):
                tool.parse_disassembly(bad, self.image, fde)

    def test_lea_and_call_bytes_inside_immediate_not_instructions(self):
        # LEA/E8 byte patterns inside a decoded movabs cannot gain boundaries.
        fake = [{'site': 0x1000, 'raw': bytes.fromhex('48b8488d3500000000c3'), 'text': 'movabs rax,imm64'}]
        with self.assertRaisesRegex(ValueError, 'inside another instruction'):
            tool.verified_lea(self.image, fake, 0x1002, 0x1009)
        fake[0]['raw'] = bytes.fromhex('48b8e805574d00000000')
        self.assertEqual(tool.scoped_edges(self.image, {0x1000: fake, 0x4d670c: []}), [])

    def test_rel32_positive_negative_and_invalid_opcodes(self):
        expected = [(0x3721beb, 'e830b5ffff', 0x371d120), (0x372c196, 'e805574d00', 0x3c018a0)]
        for site, code, target in expected:
            self.assertEqual(tool.decode_rel32(bytes.fromhex(code), site), target)
        for code in ('e930b5ffff', 'e830b5ff', 'e830b5ffff00'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                tool.decode_rel32(bytes.fromhex(code), 0x3721beb)

    def test_rel32_requires_scoped_callee_start(self):
        site = 0x3721beb
        fake = [{'site': site, 'raw': b'\xe8' + struct.pack('<i', 0x371d121 - site - 5), 'text': 'call'}]
        self.assertEqual(tool.scoped_edges(self.image, {0x3721780: fake, 0x371d120: []}), [])

    def test_ptr_length_pairs_and_same_call_locations(self):
        anchors = next(d for d in self.evidence['diagnostics'] if d['id'] == 'result_unwrap')['anchors']
        self.assertEqual(len(anchors), 8)
        self.assertEqual(sum(x['scoped_location_in_r8'] is not None for x in anchors), 7)
        self.assertEqual({x['length'] for x in anchors}, {43})
        self.assertEqual({x['relocated_callee'] for x in anchors}, {'0x157aa10'})

    def test_ptr_length_wrong_length_clobber_branch_and_call(self):
        insns = self.decoded[0x3c018a0]
        index = next(i for i, x in enumerate(insns) if x['site'] == 0x3c01a8f)
        setup = copy.deepcopy(insns[index:index + 6])
        text = b'called `Result::unwrap()` on an `Err` value'
        tool.ptr_length_pair(self.image, setup, 0, text)
        for which, raw in ((4, b'\xbe\x2a\0\0\0'), (1, bytes.fromhex('488d3db334b101')),
                           (5, bytes.fromhex('ff2594c5b601'))):
            bad = copy.deepcopy(setup)
            bad[which]['raw'] = raw
            with self.subTest(which=which), self.assertRaises(ValueError):
                tool.ptr_length_pair(self.image, bad, 0, text)
        bad = copy.deepcopy(setup)
        bad[1]['text'] = 'jmp 0x3c01aa9'
        with self.assertRaises(ValueError):
            tool.ptr_length_pair(self.image, bad, 0, text)
        with self.assertRaises(ValueError):
            tool.ptr_length_pair(self.image, setup[:-1], 0, text)

    def test_counted_prefix_exact_boundaries_and_corruption(self):
        literal = b'error while computing existing token balances total_wei='
        raw = tool.counted_prefix(self.image, 0x1f5631, literal)
        self.assertEqual(bytes.fromhex(raw['bytes']), bytes([56]) + literal + b'\xc0')
        for va, value in ((0x1f5631, b'\x37'), (0x1f5632, b'E'), (0x1f5631 + 57, b'\xc1')):
            with self.subTest(va=va), self.assertRaises(ValueError):
                tool.counted_prefix(self.mutate(va, value), 0x1f5631, literal)
        for anchor, text in ((0x1f5632, literal), (0x1f5631, literal[:-1])):
            with self.assertRaises(ValueError):
                tool.counted_prefix(self.image, anchor, text)

    def test_reference_absences_and_out_of_scope_literals_stay_unresolved(self):
        by = {d['id']: d for d in self.evidence['diagnostics']}
        self.assertEqual(by['spot_index']['rodata_occurrence_count'], 0)
        self.assertEqual(by['zero_total']['rodata_occurrence_count'], 1)
        self.assertEqual(by['insufficient_balance']['status'], 'unresolved')
        for name in ('remainder', 'allocation_total'):
            self.assertEqual(by[name]['status'], 'unresolved')
            self.assertEqual(len(by[name]['rejected_candidates']), 1)
            self.assertEqual(by[name]['rejected_candidates'][0]['owner'], '0x37227a0')

    def test_constants_uniqueness_and_decoded_operands(self):
        a, b = self.evidence['constants']
        self.assertEqual(a['occurrences'][0]['bytes'], '295c8fc2f528f03f')
        self.assertEqual((a['status'], len(a['scoped_operands'])), ('bound', 7))
        self.assertEqual((b['status'], len(b['occurrences']), len(b['scoped_operands'])), ('unresolved', 11, 6))
        for x in a['scoped_operands']:
            insn = x['instruction']
            self.assertEqual(tool.decode_scalar_rip(bytes.fromhex(insn['bytes']), int(insn['va'], 16)), 0x20a528)

    def test_constant_value_and_uniqueness_corruption(self):
        changed = self.mutate(0x20a528, struct.pack('<d', 1.02))
        self.assertEqual(tool.constant_inventory(changed, self.decoded)[0]['status'], 'unresolved')
        changed = self.mutate(self.image.by_name['.rodata']['address'], struct.pack('<d', 1.01))
        row = tool.constant_inventory(changed, self.decoded)[0]
        self.assertEqual((row['status'], len(row['occurrences'])), ('unresolved', 2))

    def test_scalar_wrong_opcode_addressing_and_truncation(self):
        for raw in ('f20f111d321af0fc', 'f20f101c321af0fc', 'f20f101d321af0'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                tool.decode_scalar_rip(bytes.fromhex(raw), 0x3308aee)

    def test_manifest_valid_and_result_required(self):
        verifier.verify_manifest(PACKET)
        self.assertIn('RESULT.md', verifier.MANIFEST)

    def test_manifest_corruption_controls(self):
        with tempfile.TemporaryDirectory() as temp:
            here = Path(temp)
            for mode in ('empty', 'duplicate', 'omitted_result', 'traversal', 'bad_hash',
                         'extra_file', 'symlink', 'changed_result'):
                with self.subTest(mode=mode):
                    for p in here.iterdir():
                        p.unlink()
                    for name in verifier.MANIFEST | {'MANIFEST.sha256'}:
                        shutil.copyfile(PACKET / name, here / name)
                    mf = here / 'MANIFEST.sha256'
                    lines = mf.read_text().splitlines()
                    if mode == 'empty': mf.write_text('')
                    elif mode == 'duplicate': mf.write_text('\n'.join(lines + [lines[0]]) + '\n')
                    elif mode == 'omitted_result': mf.write_text('\n'.join(x for x in lines if 'RESULT.md' not in x) + '\n')
                    elif mode == 'traversal': mf.write_text('\n'.join(lines).replace('README.md', '../README.md') + '\n')
                    elif mode == 'bad_hash': mf.write_text('f' * 64 + lines[0][64:] + '\n' + '\n'.join(lines[1:]) + '\n')
                    elif mode == 'extra_file': (here / 'extra.json').write_text('{}')
                    elif mode == 'symlink':
                        (here / 'RESULT.md').unlink()
                        (here / 'RESULT.md').symlink_to(PACKET / 'RESULT.md')
                    else: (here / 'RESULT.md').write_text('unearned strong claim')
                    with self.assertRaises(ValueError):
                        verifier.verify_manifest(here)

    def test_verifier_fact_corruption(self):
        for mode in ('census', 'edge', 'diagnostic', 'constant'):
            changed = copy.deepcopy(self.evidence)
            if mode == 'census': changed['metrics']['locations'] = 16
            elif mode == 'edge': changed['call_edges'][0]['callee'] = '0x371d121'
            elif mode == 'diagnostic': changed['diagnostics'][0]['status'] = 'bound'
            else: changed['constants'][1]['status'] = 'bound'
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                verifier.verify_facts(changed)


if __name__ == '__main__':
    unittest.main()
