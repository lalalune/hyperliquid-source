"""Actual source-byte controls for conditional record/batch proof bindings."""
import hashlib
import json
import mmap
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import node94_gap56319fd_variable_records as tool


class VariableRecords(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (ROOT/'artifacts/node/94/hl-node').open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if hashlib.sha256(data).hexdigest() != tool.DIGEST:
                raise AssertionError('Actual controls require authentic node #94')
            matches = [s for s in tool.sections(data) if s['type'] != 8 and s['flags'] & 4
                       and s['address'] <= tool.START < tool.END <= s['address']+s['size']]
            if len(matches) != 1:
                raise AssertionError('No unique executable mapping')
            offset = matches[0]['offset']+tool.START-matches[0]['address']
            cls.code = bytes(data[offset:offset+tool.END-tool.START])
        cls.rows, cls.raw, _ = tool.decode(cls.code)

    def changed(self, address, before, after):
        self.assertEqual(len(before), len(after))
        offset = address-tool.START
        self.assertEqual(self.code[offset:offset+len(before)], before)
        changed = bytearray(self.code)
        changed[offset:offset+len(after)] = after
        # A fresh actual GNU decode of private 1,269-byte counterfactual data.
        return tool.decode(bytes(changed))[0]

    def test_actual_complete_transfers_ordered_WORD_effects_and_unverified_domain(self):
        result = tool.contract(self.rows)
        self.assertEqual((result['cfg']['instructions'], result['cfg']['statically_reachable']), (324, 324))
        self.assertEqual((len(result['cfg']['blocks']), len(result['cfg']['branches'])), (9, 6))
        self.assertEqual(result['phase_rows'], dict(prologue=42, outer_guards=44,
                         stop_and_alignment=5, inner_body=196, outer_backedge=1, normal_return=36))
        self.assertEqual(result['table_record']['relative_read_envelope_bytes'], 8192)
        self.assertFalse(result['table_record']['actual_runtime_contents_recovered'])
        events, terms = result['ordered_WORD_write_events'], result['terms']
        self.assertEqual(len(events), 20)
        self.assertEqual([e['lane'] for e in events], list(range(4))*5)
        for event in events:
            self.assertEqual(event['width'], 16)
            self.assertEqual(terms[event['value']]['width'], 16)
            effects = event['little_endian_byte_effects']
            self.assertEqual(len(effects), 2)
            self.assertEqual([terms[e['value']]['low'] for e in effects], [0, 8])
            self.assertEqual([terms[e['value']]['width'] for e in effects], [8, 8])
            # The advance expression is a separate zero-extended byte3 load,
            # not the physical WORD width or the shift-byte2 expression.
            advance = event['record']['advance']
            self.assertNotEqual(advance, event['record']['shift'])
            self.assertEqual(terms[event['next_cursor']]['args'], [event['address'], advance])
        self.assertIn('within-lane overlap', result['memory_composition'])
        reads = [r for e in result['phases']['inner_body'] for r in e['memory_reads']]
        self.assertEqual(len(reads), 66)  # 60 fields, input0 restore,4refills,stop CMP
        self.assertFalse(result['mathematical_batch_contract']['all_premises_established_for_original_callers'])

    def test_actual_reciprocal_operands_cannot_be_changed(self):
        cases = [(0x5631a7a, '48ba9324499224499224', '48ba9224499224499224'),
                 (0x5631ad9, '48c1ea03', '48c1ea02')]
        for address, before, after in cases:
            with self.subTest(address=hex(address)):
                rows = self.changed(address, bytes.fromhex(before), bytes.fromhex(after))
                with self.assertRaisesRegex(ValueError, 'Reciprocal division source operands'):
                    tool.contract(rows)

    def test_each_output_minimum_is_used_in_the_actual_quotient(self):
        for address in (0x5631aaa, 0x5631ab9, 0x5631ac8):
            with self.subTest(address=hex(address)):
                rows = self.changed(address, bytes.fromhex('480f47d0'), b'\x90'*4)
                with self.assertRaisesRegex(ValueError, 'Actual quotient does not match'):
                    tool.contract(rows)

    def test_zero_and_input_order_guard_operands_are_bound(self):
        for address, before, after in [(0x5631af5, '4939c7', '4939d7'),
                                       (0x5631afe, '4d39c1', '4d39c0')]:
            with self.subTest(address=hex(address)):
                rows = self.changed(address, bytes.fromhex(before), bytes.fromhex(after))
                with self.assertRaisesRegex(ValueError, 'Zero-quotient/input-order guard'):
                    tool.contract(rows)

    def test_actual_record_fields_payload_and_physical_store_width(self):
        cases = [(0x5631b4b, '450fb70486', '450fb70446'), # payload scale4 ->2
                 (0x5631b50, '450fb67c8602', '450fb67c8603'), # shift from advance
                 (0x5631b56, '410fb6448603', '410fb6448602'), # advance from shift
                 (0x5631b5c, '66448906', '90448806'), # NOP+BYTE store instead of WORD
                 (0x5631b5c, '66448906', '66408906')] # AX instead of payload R8W
        for address, before, after in cases:
            with self.subTest(address=hex(address), after=after):
                rows = self.changed(address, bytes.fromhex(before), bytes.fromhex(after))
                with self.assertRaisesRegex(ValueError, 'WORD|Cursor advance|BSF'):
                    tool.contract(rows)

    def test_full_width_refill_and_post_shift_BSF_domain(self):
        for address, before, after in [(0x5631e27, '4929e8', '4901e8'),
                                       (0x5631e18, '480fbced', '480fbcea')]:
            with self.subTest(address=hex(address)):
                rows = self.changed(address, bytes.fromhex(before), bytes.fromhex(after))
                with self.assertRaisesRegex(ValueError, 'Input0 restore|BSF does not consume'):
                    tool.contract(rows)

    def test_valid_instruction_but_wrong_inner_backedge(self):
        before = bytes.fromhex('0f87a5fcffff')
        after = before[:2]+struct.pack('<i', struct.unpack('<i', before[2:])[0]+4)
        rows = self.changed(0x5631e95, before, after)  # skip next body's input0 save
        with self.assertRaisesRegex(ValueError, 'Contract control structure changed'):
            tool.contract(rows)

    def test_mutable_exit_stop_is_not_mislabeled_as_initial_or_current(self):
        result = tool.contract(self.rows)
        pop = next(e for e in result['phases']['normal_return'] if e['va'] == 0x5631ea9)
        read = pop['memory_reads'][0]
        seed = result['phases']['stop_and_alignment'][0]['memory_writes'][0]
        self.assertEqual(read['address'], seed['address'])
        self.assertEqual(seed['value'], result['stop_term'])
        self.assertNotEqual(read['value'], result['stop_term'])
        self.assertEqual(result['terms'][read['value']]['name'], 'exit.scratch48')
        self.assertEqual(result['exit_cutpoint']['mutable_frame_offsets'], [0, 48])

    def test_normal_state_and_saved_register_context_is_bound(self):
        cases = [(0x5631ed6, '4c896858', '4c896860'),
                 (0x5631eef, '5b58', '585b')]
        for address, before, after in cases:
            with self.subTest(address=hex(address)):
                rows = self.changed(address, bytes.fromhex(before), bytes.fromhex(after))
                with self.assertRaisesRegex(ValueError, 'state layout/value|Saved GPR restoration'):
                    tool.contract(rows)

    def test_stale_native_bytes_fail_even_after_private_view_is_restored(self):
        real_run = subprocess.run
        seen = []
        def native(argv, *args, **kwargs):
            if argv[-1] != 'slice.bin':
                return real_run(argv, *args, **kwargs)
            path = Path(kwargs['cwd'])/'slice.bin'
            original = path.read_bytes()
            self.assertEqual(original, self.code)
            altered = bytearray(original)
            altered[0x5631b56-tool.START+5] = 2
            path.write_bytes(altered)
            result = real_run(argv, *args, **kwargs)
            path.write_bytes(original)
            seen.append(path)
            return result
        with mock.patch.object(tool.subprocess, 'run', side_effect=native):
            with self.assertRaisesRegex(ValueError, 'Native bytes differ from input'):
                tool.decode(self.code)
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists())

    def test_wrong_identity_fails_before_native_tools_and_output_creation(self):
        with tempfile.TemporaryDirectory(prefix='vrecord-bad-') as temporary:
            bad = Path(temporary)/'wrong'
            bad.write_bytes(b'\x7fELF'+b'\x00'*60)
            with mock.patch.object(tool.subprocess, 'run', side_effect=AssertionError('native must not run')):
                with self.assertRaisesRegex(ValueError, 'Node #94 SHA-256 mismatch'):
                    tool.inspect_target(bad)

    def test_actual_CLI_repeat_and_output_preservation(self):
        with tempfile.TemporaryDirectory(prefix='vrecord spaces ') as temporary:
            directory = Path(temporary)
            argv = [sys.executable, '-B', str(ROOT/'tools/node94_gap56319fd_variable_records.py'), '--output-dir']
            outputs = [directory/'first report', directory/'second report']
            for output in outputs:
                subprocess.run(argv+[str(output)], check=True, capture_output=True, text=True,
                               env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            before = {p.name: p.read_bytes() for p in outputs[0].iterdir()}
            self.assertEqual(before, {p.name: p.read_bytes() for p in outputs[1].iterdir()})
            for name, digest in json.loads(before['OUTPUT-MANIFEST.json']).items():
                self.assertEqual(hashlib.sha256(before[name]).hexdigest(), digest)
            again = subprocess.run(argv+[str(outputs[0])], capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            self.assertIn('FileExistsError', again.stderr)
            self.assertEqual(before, {p.name: p.read_bytes() for p in outputs[0].iterdir()})
            bad = directory/'wrong'
            bad.write_bytes(b'\x7fELF'+b'\x00'*60)
            fresh = directory/'must remain absent'
            failed = subprocess.run(argv+[str(fresh), '--binary', str(bad)], capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse(fresh.exists())


if __name__ == '__main__':
    unittest.main()
