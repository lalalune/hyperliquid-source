"""Target-grounded corruption controls for the bounded poll TLS-gate packet."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-012-poll-tls-gate-115'
spec=importlib.util.spec_from_file_location('poll_tls_gate_115',PACKET/'collect.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

class PollTlsGate115(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=gate.load(ROOT)

    def altered_read(self, address, replacement):
        original=self.image.read
        def read(va,length):
            result=bytearray(original(va,length))
            for i,byte in enumerate(replacement):
                if va<=address+i<va+length:
                    result[address+i-va]=byte
            return bytes(result)
        return patch.object(self.image,'read',side_effect=read)

    def test_reproduce_packet(self):
        self.assertEqual(len(gate.collect(ROOT,PACKET)['bodies']),4)

    def test_changed_semantic_operands_rejected(self):
        # Four different evidence premises, all changed in actual mapped bytes.
        for address,replacement in [(0x5ce9536,b'\x02'), # stack restore pair
                                    (0x5ce9574,b'\x02'), # normal restore pair
                                    (0x5cf31df,b'\x44'), # cleanup second TLS offset
                                    (0x2b7b07d,b'\x03'), # sender boolean mask
                                    (0x5cdf414,b'\x01')]: # callback terminal state
            with self.subTest(address=hex(address)),self.altered_read(address,replacement):
                with self.assertRaisesRegex(ValueError,'instruction anchor'):
                    gate.bind(self.image)

    def test_duplicate_and_redirected_relocation_rejected(self):
        original=self.image.relocations()
        for values in [[(8,0x5cf3190),(8,0x5cf3190)],[(8,0x5cf3191)]]:
            changed=dict(original);changed[0x64e13b0]=values
            with self.subTest(values=values),patch.object(self.image,'relocations',return_value=changed):
                with self.assertRaisesRegex(ValueError,'relocation'):
                    gate.bind(self.image)

    def test_import_name_rejected(self):
        with patch.object(self.image,'symbol',return_value='wrong_symbol'):
            with self.assertRaisesRegex(ValueError,'import name'):
                gate.bind(self.image)

    def test_wrong_fde_lsda_pointer_rejected(self):
        changed=copy.deepcopy(self.image.fdes)
        next(f for f in changed if f['start']==0x5ce94c0)['lsda']+=1
        with patch.object(self.image,'fdes',changed):
            with self.assertRaisesRegex(ValueError,'LSDA pointer'):
                gate.unwind(self.image)

    def test_wrong_cie_personality_rejected(self):
        changed=copy.deepcopy(self.image.cies)
        fde=next(f for f in self.image.fdes if f['start']==0x5ce94c0)
        changed[fde['cie']]['personality_slot']+=8
        with patch.object(self.image,'cies',changed):
            with self.assertRaisesRegex(ValueError,'CIE'):
                gate.unwind(self.image)

    def test_changed_lsda_landing_and_action_rejected(self):
        for offset,replacement in [(11,b'\xdc'),(13,b'\x01')]:
            with self.subTest(offset=offset),self.altered_read(0x40360c+offset,replacement):
                with self.assertRaisesRegex(ValueError,'call-site mapping'):
                    gate.unwind(self.image)

    def test_malformed_lsda_bounds_and_encoding_rejected(self):
        raw=self.image.read(0x40360c,52)
        cases=[raw[:10],raw[:3]+b'\x02'+raw[4:],raw[:4]+b'\xff'*12,raw[:2]+b'\x00'+raw[3:]]
        for data in cases:
            with self.subTest(data=data.hex()),self.assertRaises(ValueError):
                gate.lsda_table(data,0x5ce94c0,0x5ce95b7)

    def test_native_gap_and_byte_corruption_rejected(self):
        raw=(PACKET/'native/wrapper.gnu.objdump').read_bytes()
        lines=raw.splitlines(keepends=True)
        index=next(i for i,line in enumerate(lines) if line.lstrip().startswith(b'5ce9531:'))
        corruptions=[b''.join(lines[:index]+lines[index+1:]),
                     raw.replace(b'66 c7 44 24 0e 01 00',b'66 c7 44 24 0e 02 00',1)]
        for data in corruptions:
            with self.subTest(length=len(data)),self.assertRaisesRegex(ValueError,'Native byte'):
                gate.native_rows(data,self.image,0x5ce94c0,0x5ce95b7)

    def test_lock_prefix_join_is_explicit(self):
        raw=(PACKET/'native/callback.llvm.objdump').read_bytes()
        rows=gate.native_rows(raw,self.image,0x5cdf410,0x5cdf457)
        joined,joins=gate.join_lock(rows)
        self.assertEqual(joins,['0x5cdf42b','0x5cdf43c'])
        self.assertEqual(len(joined),22)
        with self.assertRaisesRegex(ValueError,'LOCK continuation'):
            gate.join_lock([(0x5cdf42b,b'\xf0'),(0x5cdf42c,b'\x90')])

if __name__=='__main__':
    unittest.main()
