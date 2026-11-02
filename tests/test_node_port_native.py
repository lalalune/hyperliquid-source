"""Native port corridors, prior width gaps and executable corruption controls."""
import json
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import node_port_native as subject
import node_port_rust as rust


class NodePortNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.output=Path(cls.temp.name)/'native'
        cls.result=subject.produce(cls.output)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_target_oracle_regenerates_all_site_cases_and_frozen_vectors(self):
        self.assertEqual(self.result,{'site_cases':8960,'distinct_cases':1536,'width_cases':1536})
        self.assertEqual((self.output/'target-vectors.tsv').read_bytes(),
                         (rust.COMPONENT/'target-vectors.tsv').read_bytes())
        self.assertEqual((self.output/'freeze.json').read_bytes(),
                         (rust.PACKET/'frozen-before-rust.json').read_bytes())

    def test_previously_inferred_widths_cover_both_tags_and_all_byte_indices(self):
        rows=json.loads((self.output/'width-rows.json').read_text())
        self.assertEqual(len(rows),1536)
        self.assertEqual(len({tuple(row[:3]) for row in rows}),1536)
        for start,tag,index,scalar,stop in rows:
            self.assertEqual(scalar,index if tag else 0)

    def test_actual_instruction_mutations_change_target_outcomes(self):
        rows=json.loads((self.output/'native-controls.json').read_text())
        self.assertEqual([row['mismatches'] for row in rows],[61,256,66])
        self.assertTrue(all(row['old_byte']!=row['new_byte'] and row['cases']==256 for row in rows))

    def test_narrow_mul_all_u16_values_preserve_upper_words_and_flag_knownness(self):
        cpu=subject.cpu
        site=subject.records['sites'][0]
        va=int(site['mul'],16)+4
        insn=cpu.decode(subject.data,subject.image.file_offset(va),va)
        machine=subject.Machine(subject.image)
        for value in range(65536):
            machine.set_reg(cpu.RAX,0xaabbccdd12340000|value)
            machine.set_reg(cpu.RDX,0x1122334455660000)
            machine.set_reg(cpu.RCX,1000)
            machine.unary(insn,0xf7,16,va)
            product=value*1000
            self.assertEqual(machine.get(cpu.RAX,64),0xaabbccdd12340000|(product&65535))
            self.assertEqual(machine.get(cpu.RDX,64),0x1122334455660000|(product>>16))
            overflow=bool(product>>16)
            self.assertEqual(machine.flags,[overflow,None,None,overflow])

    def test_changed_oracle_is_rejected_before_any_compiler(self):
        with tempfile.TemporaryDirectory() as folder:
            def corrupted(output):
                shutil.copytree(self.output,output)
                (Path(output)/'target-vectors.tsv').write_text('corrupted\\n')
                return {}
            with mock.patch.object(rust.native,'produce',side_effect=corrupted), \
                 mock.patch.object(rust.subprocess,'check_output',side_effect=AssertionError('compiler called')):
                with self.assertRaisesRegex(ValueError,'frozen vector identity differs'):
                    rust.build(Path(folder)/'compiler',Path(folder)/'new')
            with self.assertRaisesRegex(ValueError,'output must be new'):
                rust.build(Path(folder)/'compiler',Path(folder))
