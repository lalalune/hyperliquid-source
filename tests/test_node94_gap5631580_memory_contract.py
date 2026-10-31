"""Target-grounded static transfers and mutations of real node #94 bytes."""
import hashlib
import json
import mmap
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node94_gap5631580_memory_contract as tool


class CandidateMemoryContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (ROOT / 'artifacts/node/94/hl-node').open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if hashlib.sha256(data).hexdigest() != tool.DIGEST:
                raise AssertionError('Focused controls need the authentic node #94 input')
            candidates = [s for s in tool.sections(data) if s['type'] != 8 and s['flags'] & 4
                          and s['address'] <= tool.START < tool.END <= s['address'] + s['size']]
            if len(candidates) != 1:
                raise AssertionError('No unique candidate mapping')
            offset = candidates[0]['offset'] + tool.START - candidates[0]['address']
            cls.code = bytes(data[offset:offset + tool.END - tool.START])
        cls.rows, cls.raw, _ = tool.decode(cls.code)

    def mutate(self, va, before, after):
        self.assertEqual(len(before), len(after))
        offset = va - tool.START
        self.assertEqual(self.code[offset:offset + len(before)], before)
        value = bytearray(self.code)
        value[offset:offset + len(after)] = after
        # Fresh native decoding of altered actual bytes, not edited JSON proof.
        return tool.decode(bytes(value))[0]

    def test_real_complete_cfg_and_memory_result(self):
        result = tool.contract(self.rows)
        self.assertEqual(result['cfg']['instructions'], 285)
        self.assertEqual(result['cfg']['statically_reachable'], 285)
        self.assertEqual(len(result['cfg']['blocks']), 9)
        self.assertEqual(len(result['cfg']['branches']), 6)
        self.assertEqual(sum(result['phase_instruction_count'].values()), 285)
        self.assertEqual([len(lane['emitted_stores']) for lane in result['lanes']], [5] * 4)
        self.assertEqual([r['entry_rdi_offset'] for r in result['normal_return_writebacks']], list(range(0, 0x60, 8)))
        self.assertEqual(result['restored_gprs'], ['rax', 'rbx', 'rcx', 'rdx', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'])
        self.assertEqual(result['table']['read_span_bytes'], 4096)
        # A physical little-endian word contributes bits 15:8, not its low byte.
        nodes = result['terms']
        for lane in result['lanes']:
            for store in lane['emitted_stores']:
                expr = nodes[store['value']]
                self.assertEqual((expr['op'], expr['width'], expr['low']), ('extract', 8, 8))
            self.assertEqual(nodes[lane['required_nonzero_bsf_word']]['width'], 64)

    def test_fifth_store_offset_corruption(self):
        rows = self.mutate(0x5631884, bytes.fromhex('886604'), bytes.fromhex('886605'))
        with self.assertRaisesRegex(ValueError, 'Five-byte lane footprint'):
            tool.contract(rows)

    def test_low_byte_instead_of_high_byte_corruption(self):
        rows = self.mutate(0x56316c8, bytes.fromhex('8826'), bytes.fromhex('8806'))
        with self.assertRaisesRegex(ValueError, 'table-word high byte'):
            tool.contract(rows)

    def test_actual_vex_shift_count_register_corruption(self):
        rows = self.mutate(0x56316c3, bytes.fromhex('c4e281f7ed'), bytes.fromhex('c4e289f7ed'))
        self.assertIn('r14', next(r['assembly'] for r in rows if r['va'] == 0x56316c3))
        with self.assertRaisesRegex(ValueError, 'table-word high byte|BSF/refill word transfer'):
            tool.contract(rows)

    def test_refill_bit_mask_corruption(self):
        rows = self.mutate(0x56318bd, bytes.fromhex('4883e007'), bytes.fromhex('4883e00f'))
        with self.assertRaisesRegex(ValueError, 'BSF/refill word transfer'):
            tool.contract(rows)

    def test_input_cursor_retreat_corruption(self):
        rows = self.mutate(0x56318c9, bytes.fromhex('4929e8'), bytes.fromhex('4901e8'))
        with self.assertRaisesRegex(ValueError, 'BSF/refill word transfer|cursor retreat'):
            tool.contract(rows)

    def test_state_writeback_offset_corruption(self):
        rows = self.mutate(0x56319e1, bytes.fromhex('4c896858'), bytes.fromhex('4c896860'))
        with self.assertRaisesRegex(ValueError, 'State writeback layout/value'):
            tool.contract(rows)

    def test_saved_register_pop_order_corruption(self):
        rows = self.mutate(0x56319fa, bytes.fromhex('5b58'), bytes.fromhex('585b'))
        with self.assertRaisesRegex(ValueError, 'Saved GPR restoration'):
            tool.contract(rows)

    def test_normal_return_reads_mutable_exit_scratch_not_entry_r15(self):
        result = tool.contract(self.rows)
        pop = next(e for e in result['phases']['normal_return'] if e['va'] == 0x56319b2)
        read = pop['memory_reads'][0]
        term = result['terms'][read['value']]
        # The authentic seed writes stop at the exact address of this dead POP.
        # After a cycle, it is not the dummy entry.r15 from the first prologue.
        seed = next(e for e in result['phases']['seed'] if e['va'] == 0x5631669)
        self.assertEqual(seed['memory_writes'][0]['address'], read['address'])
        self.assertEqual(seed['memory_writes'][0]['value'], result['loop_stop_term'])
        self.assertEqual(term.get('name'), 'exit.scratch24')
        self.assertNotEqual(read['value'], result['loop_stop_term'])
        self.assertEqual(result['normal_return_cutpoint']['mutable_frame_offsets'], [0, 8, 16, 24])
        self.assertEqual(len(result['normal_return_writebacks']), 12)
        self.assertEqual(len(result['restored_gprs']), 15)

    def test_aligned_but_wrong_loop_backedge(self):
        before = bytes.fromhex('0f8725fdffff')
        after = before[:2] + struct.pack('<i', struct.unpack('<i', before[2:])[0] + 3)
        rows = self.mutate(0x5631995, before, after)
        with self.assertRaisesRegex(ValueError, 'Contract control structure'):
            tool.contract(rows)

    def test_stale_native_listing_byte_binding(self):
        changed = bytearray(self.code)
        changed[0x5631884 - tool.START + 2] = 5
        with self.assertRaisesRegex(ValueError, 'Native bytes differ'):
            tool.parse_native(self.raw, bytes(changed))

    def test_actual_cli_reproducible_and_existing_output_preserved(self):
        with tempfile.TemporaryDirectory(prefix='hl-gap-contract-test-') as directory:
            directory = Path(directory)
            outputs = [directory / 'first', directory / 'second']
            argv = [sys.executable, '-B', str(ROOT / 'tools/node94_gap5631580_memory_contract.py'), '--output-dir']
            for output in outputs:
                subprocess.run(argv + [str(output)], check=True, capture_output=True, text=True)
            before = {p.name: p.read_bytes() for p in outputs[0].iterdir()}
            self.assertEqual(before, {p.name: p.read_bytes() for p in outputs[1].iterdir()})
            manifest = json.loads(before['OUTPUT-MANIFEST.json'])
            for name, expected in manifest.items():
                self.assertEqual(hashlib.sha256(before[name]).hexdigest(), expected)
            result = subprocess.run(argv + [str(outputs[0])], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('FileExistsError', result.stderr)
            self.assertEqual(before, {p.name: p.read_bytes() for p in outputs[0].iterdir()})


if __name__ == '__main__':
    unittest.main()
