"""Target-grounded static replay; never executes the captured node."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-fini-callback-boundary'
spec = importlib.util.spec_from_file_location('fini_byte_proof', PACKET / 'byte_proof.py')
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class FiniCallbackBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ROOT / proof.TARGET
        cls.data = cls.target.read_bytes()
        proof.authenticate(cls.data)
        cls.observed = proof.derive(cls.data)
        cls.record = json.loads((PACKET / 'byte-proof.json').read_text())

    def test_authenticated_target_and_record(self):
        self.assertEqual(self.record['sha256'], hashlib.sha256(self.data).hexdigest())
        self.assertTrue(proof.compare(self.observed, self.record['observation']))
        self.assertFalse(self.record['target_executed'])
        with self.assertRaises(AssertionError):
            proof.authenticate(self.data[:-1])

    def test_relocation_backed_plt_identity(self):
        self.assertEqual(self.observed['plt_got_slot'], '0x64ee170')
        self.assertEqual(self.observed['selected_symbol_relocations'], [
            {'va': '0x64df468', 'type': 6, 'symbol': '_ITM_deregisterTMCloneTable', 'addend': 0},
            {'va': '0x64df478', 'type': 6, 'symbol': '__cxa_finalize', 'addend': 0},
            {'va': '0x64ee170', 'type': 7, 'symbol': '__cxa_finalize', 'addend': 0}])

    def test_control_flow_envelope(self):
        self.assertEqual(self.observed['guard'], '0x64ffe40')
        self.assertEqual(self.observed['return_sites'], ['0x14193d4', '0x14193d8'])
        self.assertEqual(self.observed['reachable_envelope_end_exclusive'], '0x14193d9')
        self.assertEqual(self.observed['direct_calls'], [
            {'site': '0x14193c2', 'target': '0x63f0a40'},
            {'site': '0x14193c7', 'target': '0x1419330'}])

    def test_native_instruction_alignment(self):
        output = subprocess.check_output(['objdump', '-d', '--start-address=0x14193a0',
            '--stop-address=0x14193d9', str(self.target)], text=True, timeout=30)
        rows = re.findall(r'^[ \t]*([0-9a-f]+):[ \t]+(?:[0-9a-f]{2}[ \t]+)+([a-z][a-z0-9]*)[ \t]*(.*)$', output, re.M)
        observed = {int(a,16): (op, tail) for a,op,tail in rows}
        self.assertEqual(list(observed), [0x14193a0,0x14193a4,0x14193ab,0x14193ad,
            0x14193ae,0x14193b6,0x14193b9,0x14193bb,0x14193c2,0x14193c7,
            0x14193cc,0x14193d3,0x14193d4,0x14193d5,0x14193d8])
        self.assertEqual(observed[0x14193a0][0], 'endbr64')
        for site,target in [(0x14193ab,'14193d8'),(0x14193b9,'14193c7'),
                            (0x14193c2,'63f0a40'),(0x14193c7,'1419330')]:
            self.assertEqual(observed[site][1].split()[0], target)
        self.assertEqual(observed[0x14193d4][0], 'ret')
        self.assertEqual(observed[0x14193d8][0], 'ret')

    def test_complete_native_unwind_census(self):
        output = subprocess.check_output(['readelf','--debug-dump=frames',str(self.target)],
                                         text=True, timeout=60)
        extents = [(int(a,16),int(b,16)) for a,b in re.findall(
            r'FDE.*?pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)',output)]
        self.assertEqual(len(extents), 135313)
        self.assertFalse(any(a<=0x14193a0<b for a,b in extents))
        self.assertIn((0x1419300,0x1419326), extents)
        self.assertIn((0x14193f0,0x1419618), extents)

    def test_actual_instruction_corruption_controls(self):
        # Hash checks deliberately bypassed to exercise field/edge proof itself.
        for delta in [0,6,12,17,21,26,30,35,40,46,50,52,56]:
            with self.subTest(callback_byte=delta):
                data=bytearray(self.data)
                data[0x14183a0+delta]^=1
                with self.assertRaises(AssertionError):proof.derive(data)

    def test_actual_relocation_and_plt_corruption_controls(self):
        shoff=struct.unpack_from('<Q',self.data,40)[0]
        size,count=struct.unpack_from('<HH',self.data,58)
        headers=[struct.unpack_from('<IIQQQQIIQQ',self.data,shoff+i*size) for i in range(count)]
        selected=[]
        for s in headers:
            if s[1]!=4:continue
            for at in range(s[4],s[4]+s[5],s[9]):
                va=struct.unpack_from('<Q',self.data,at)[0]
                if va in {0x63f36c0,0x64df478,0x64df468,0x64ee170}:selected.append(at)
        self.assertEqual(len(selected),4)
        # Relocation type, symbol index and addend corruption must each fail.
        for at in selected:
            for field in [8,12,16]:
                with self.subTest(relocation=hex(at),field=field):
                    data=bytearray(self.data);data[at+field]^=1
                    with self.assertRaises(AssertionError):proof.derive(data)
        mappings=[s[4]+0x63f0a40-s[3] for s in headers if s[1]!=8 and s[2]&2 and s[3]<=0x63f0a40<s[3]+s[5]]
        self.assertEqual(len(mappings),1)
        plt_file=mappings[0]
        for at in [plt_file,plt_file+2,0x63f16c0]:
            with self.subTest(file_offset=hex(at)):
                data=bytearray(self.data);data[at]^=1
                with self.assertRaises(AssertionError):proof.derive(data)

    def test_record_comparator_rejects_corruption(self):
        for key in self.observed:
            with self.subTest(field=key):
                changed=copy.deepcopy(self.observed)
                changed[key]=None
                self.assertFalse(proof.compare(self.observed,changed))
        changed=copy.deepcopy(self.observed)
        changed['direct_calls'][0]['target']='0x1419330'
        self.assertFalse(proof.compare(self.observed,changed))

    def test_identical_input_replay(self):
        self.assertTrue(proof.compare(proof.derive(self.data),self.observed))


if __name__=='__main__':unittest.main()
