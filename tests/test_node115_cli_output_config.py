"""Target-backed integrity and semantic-observation controls, not target execution."""
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import node115_cli_output_config as output


class OutputConstructor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT/output.ARTIFACT).read_bytes()
        cls.image = output.Image(cls.data)
        cls.observation = output.observe(cls.image)

    def changed(self, va, replacement):
        value = bytearray(self.data)
        pos = self.image.offset(va, len(replacement))
        value[pos:pos+len(replacement)] = replacement
        return output.Image(value, authenticate=False)

    def test_exact_target_and_complete_extents(self):
        self.assertEqual(output.sha(self.data), output.DIGEST)
        for start, end, _ in output.RANGES:
            extent = self.image.extent(start, end)
            rows = output.instructions(self.image, start, end)
            self.assertEqual(sum(i.size for i in rows), extent['length'])
            self.assertEqual(rows[-1].address+rows[-1].size, end)
        self.assertEqual(output.RANGES[0][1]-output.PRIMARY, 840)

    def test_old_release_or_modified_input_not_admitted(self):
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            output.Image(b'old release pointer')
        changed = bytearray(self.data)
        changed[self.image.offset(output.PRIMARY, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            output.Image(changed)

    def test_current_output_order_and_new_owned_value(self):
        observed = self.observation
        fields = observed['presence_destinations']
        self.assertEqual([f['offset'] for f in fields], list(range(24,36)))
        self.assertEqual([f['name'] for f in fields], [
            'write-trades', 'write-fills', 'write-raw-book-diffs',
            'write-order-statuses', 'write-misc-events',
            'write-hip3-oracle-updates', 'write-system-and-core-writer-actions',
            'disable-output-file-buffering', 'batch-by-block',
            'stream-with-block-info', 'serve-evm-rpc', 'serve-info'])
        self.assertEqual(observed['optional_value']['name'],
                         'write-user-clearinghouse-states')
        self.assertEqual(observed['output_byte_span'], 37)
        self.assertEqual(observed['style_offset'], 36)

    def test_style_chunks_cover_all_actual_bytes(self):
        self.assertEqual({x['text']: x['tag'] for x in self.observation['style']},
                         {'actions': 0, 'recent-actions': 2, 'actions-and-responses': 1})
        # Actual instruction operands/data constants, not mutations of prose:
        # every distinct byte supplying the immediate/SIMD comparisons is attacked.
        windows = [(0x564d56d,4), (0x564d574,4),
                   (0x564d589,8), (0x564d596,8), (0x450640,16), (0x454130,16)]
        controls = 0
        for start, length in windows:
            for address in range(start,start+length):
                original = self.image.read(address,1)
                changed = self.changed(address, bytes([original[0]^1]))
                try:
                    value = output.observe(changed)['style']
                except ValueError:
                    pass # inconsistent overlapping comparison bytes are rejected
                else:
                    self.assertNotEqual(value, self.observation['style'])
                controls += 1
        self.assertEqual(controls,56)

    def test_destination_operand_corruption_changes_observation(self):
        # MOVQ [rbx+0x18],xmm0: change only the actual displacement to 0x19.
        self.assertEqual(self.image.read(0x564d610,1), b'\x18')
        actual = output.observe(self.changed(0x564d610,b'\x19'))
        self.assertEqual(actual['presence_destinations'][0]['offset'],25)
        self.assertNotEqual(actual['presence_destinations'],
                            self.observation['presence_destinations'])
        # Also attack each directly stored scalar byte's destination.
        for va in [0x564d618,0x564d61c,0x564d620,0x564d624]:
            original = self.image.read(va,1)
            actual = output.observe(self.changed(va,bytes([original[0]+1])))
            self.assertNotEqual(actual['presence_destinations'],
                                self.observation['presence_destinations'])

    def test_lookup_name_and_callee_controls(self):
        actual = output.observe(self.changed(0x92abc3,b'r'))
        self.assertEqual(actual['optional_value']['name'],
                         'rrite-user-clearinghouse-states')
        self.assertNotEqual(actual['queries_in_execution_order'],
                            self.observation['queries_in_execution_order'])
        # The first direct call is displaced by one byte, no longer the lookup entry.
        original = self.image.read(0x564d3b4,1)
        with self.assertRaisesRegex(ValueError,'query inventory'):
            output.observe(self.changed(0x564d3b4,bytes([original[0]+1])))

    def test_fde_end_corruption_is_not_a_valid_window(self):
        fde = next(f for f in self.image.fdes if f['start']==output.PRIMARY)
        value = struct.unpack('<i',self.image.read(fde['fde']+12,4))[0]
        changed = self.changed(fde['fde']+12,struct.pack('<i',value+1))
        with self.assertRaisesRegex(ValueError,'Changed selected FDE'):
            changed.extent(output.PRIMARY,output.RANGES[0][1])

    def test_primary_lsda_cleanup_intervals_and_bad_encoding(self):
        fde = next(f for f in self.image.fdes if f['start']==output.PRIMARY)
        value = output.lsda(self.image,output.PRIMARY,fde['lsda'])
        self.assertEqual(value['header_and_call_sites'][:8],'ffff0111')
        self.assertIsNone(value['type_table_file_offset'])
        self.assertTrue(any(r['landing']=='0x564d6ad' for r in value['call_sites']))
        changed = self.changed(fde['lsda']+1,b'\xfe')
        with self.assertRaisesRegex(ValueError,'type encoding'):
            output.lsda(changed,output.PRIMARY,fde['lsda'])

    def test_actual_command_edges_and_relocation(self):
        calls = self.observation['selected_command_callers']
        self.assertEqual(len(calls),2)
        rels = [r for r in self.image.relocations() if r['slot']==0x64ebcb8]
        self.assertEqual(len(rels),1)
        self.assertEqual((rels[0]['type'],rels[0]['addend']),(8,output.PRIMARY))
        # A real relocation addend edit, with the whole-target guard explicitly
        # disabled only in this static negative-control Image.
        data = bytearray(self.data)
        pos = rels[0]['record_offset']+16
        struct.pack_into('<q',data,pos,output.PRIMARY+1)
        corrupt = output.Image(data,authenticate=False)
        changed_rel = next(r for r in corrupt.relocations() if r['slot']==0x64ebcb8)
        self.assertNotEqual(changed_rel['addend'],output.PRIMARY)

    def test_each_primary_control_transfer_is_retained(self):
        raw = output.instructions(self.image,output.PRIMARY,output.RANGES[0][1])
        expected = [i.address for i in raw if i.mnemonic.startswith('j') or i.mnemonic=='call']
        actual = [int(x['instruction']['va'],16)
                  for x in self.observation['primary_control_transfers']]
        self.assertEqual(actual,expected)
        starts = {i.address for i in raw}
        for edge in self.observation['primary_control_transfers']:
            if edge.get('inside_primary'):
                self.assertIn(int(edge['target'],16),starts)


if __name__=='__main__':
    unittest.main()
