"""Real pinned-input controls, not synthetic target behavior."""
from pathlib import Path
import importlib.util,unittest
SPEC=importlib.util.spec_from_file_location('vault_coordinate',Path('research/work-items/RE-001-node115-vault-diagnostic/verify.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)
class Coordinates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=m.TARGET.read_bytes();cls.coordinates=m.structural(cls.data)
    def test_digest_and_native_alignment(self):self.assertEqual(m.verify()['observed_bindings'],1)
    def corrupt(self,field,delta=0):
        b=bytearray(self.data);b[self.coordinates[field]+delta]^=1
        with self.assertRaises(ValueError):m.structural(b)
    def test_source_corruption(self):self.corrupt('source_file_offset')
    def test_location_line_corruption(self):self.corrupt('location_file_offset',16)
    def test_relocation_type_corruption(self):self.corrupt('relocation_file_offset',8)
    def test_lea_opcode_corruption(self):self.corrupt('instruction_file_offset')
    def test_lea_destination_corruption(self):self.corrupt('instruction_file_offset',3)
    def test_fde_start_corruption(self):self.corrupt('fde_file_offset',8)
    def test_fde_range_corruption(self):self.corrupt('fde_file_offset',12)
    def test_cie_version_corruption(self):self.corrupt('cie_file_offset',8)
if __name__=='__main__':unittest.main()
