"""Captured bindings, raw date boundaries, and a real pinned Rust comparison."""
import hashlib
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import daycount115_rust as tool

RUSTC=os.environ.get('HYPERLIQUID_NODE115_DAYCOUNT_RUSTC')
DECODER=importlib.util.find_spec('capstone') is not None

class DaycountRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=tool.target.TARGET.read_bytes();cls.oracle=tool.NativeDateOracle(cls.data)

    def new_directory(self):
        root=Path(__file__).resolve().parents[1]
        work=(root/'work/daycount-rust-tests').resolve();work.mkdir(parents=True,exist_ok=True)
        output=Path(tempfile.mkdtemp(prefix='case-',dir=work)).resolve()
        self.assertTrue(output.is_relative_to(work))
        return output

    def test_original_identity_is_checked_before_binding(self):
        with self.assertRaisesRegex(ValueError,'captured target'):
            tool.NativeDateOracle(self.data[:-1])
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),tool.target.SHA256)
        self.assertEqual(hashlib.sha256(self.oracle.reader.read(tool.target.START,tool.target.END-tool.target.START)).hexdigest(),tool.target.BODY_SHA256)
        self.assertEqual((self.oracle.records['owner']['bytes'],self.oracle.records['owner']['instructions']),(378,92))
        self.assertEqual([r['path'].split('/z_vendor/')[1] for r in self.oracle.records['locations']],['chrono/src/naive/date/mod.rs','chrono/src/naive/internals.rs','chrono/src/naive/date/mod.rs','chrono/src/naive/date/mod.rs'])
        for va in (0x1628f59,0x1628fb5,0x1628fc7,0x46bcaa,0x46be3b,0x64053c0,0x64df848):
            changed=bytearray(self.data);changed[self.oracle.reader.off(va,1)]^=1
            with self.assertRaises(ValueError):tool.NativeDateOracle(bytes(changed))

    def test_raw_epoch_signed_and_range_boundaries(self):
        for raw,expected in ((-365,0x14),(-1,0x16d4),(0,0x16e4),(1,0x201e),(719163,0xf6401a),(719164,0xf6402a)):
            self.assertEqual(self.oracle.date(raw),expected)
        for raw in (-(1<<31),(1<<31)-366,(1<<31)-365,(1<<31)-1):
            self.assertEqual(self.oracle.date(raw),0)
        for year in (-262143,262142):
            packed=self.oracle.date(tool.beginning(year))
            self.assertNotEqual(packed,0)
            self.assertEqual(tool.engine.signed(packed,32)>>13,year)
        for year in (-262144,262143):
            self.assertEqual(self.oracle.date(tool.beginning(year)),0)
        # Calendar-to-day arithmetic must agree with the captured integer constructor.
        for year in (-262143,-401,-400,-399,-4,-1,0,1,1970,262142):
            with self.subTest(calendar_year=year):
                raw=tool.target.days_from_civil(year,1,1)+719163
                packed=self.oracle.date(raw)
                self.assertNotEqual(packed,0)
                self.assertEqual((tool.engine.signed(packed,32)>>13,(packed>>4)&511),(year,1))
        for raw in (True,-(1<<31)-1,1<<31):
            with self.assertRaises(ValueError):self.oracle.date(raw)

    def test_only_needed_scoped_instruction_extensions(self):
        engine=tool.engine;machine=tool.DateMachine([],tool.NoExternalMemory(),{})
        for value in (0,1,0x7fffffff,0x80000000,0xffffffff):
            machine.reset();machine.setreg(engine.RDI,value)
            machine.i_movsxd((('r',engine.RAX,8),('r',engine.RDI,4)))
            expected=struct.unpack('<i',value.to_bytes(4,'little'))[0]&((1<<64)-1)
            self.assertEqual(machine.regs[engine.RAX],expected)
            machine.setreg(engine.RAX,value);machine.sf=True;machine.zf=False
            machine.i_ror((('r',engine.RAX,4),('i',2)))
            text=f'{value:032b}';rotated=int(text[-2:]+text[:-2],2)
            self.assertEqual(machine.regs[engine.RAX],rotated)
            self.assertEqual(machine.cf,bool(rotated>>31));self.assertIsNone(machine.of)
            self.assertTrue(machine.sf);self.assertFalse(machine.zf)
        with self.assertRaises(tool.engine.Unmodelled):machine.i_ror((('r',engine.RAX,4),('i',3)))

    def test_captured_binary_cannot_enter_own_object_evaluator(self):
        with self.assertRaises(ValueError):tool.own_machine(tool.target.TARGET)
        from unittest.mock import patch
        with patch('subprocess.run',side_effect=AssertionError('Captured dispatch forbidden')):
            with self.assertRaisesRegex(ValueError,'Captured artifact'):tool.verify(tool.target.TARGET,self.new_directory()/'forbidden')
        folder=self.new_directory()
        for index,data in enumerate((b'',b'not-an-object',b'\x7fELF\x01\x01'+bytes(80))):
            path=folder/f'bad-{index}.o';path.write_bytes(data)
            with self.assertRaises(ValueError):tool.own_machine(path)
        with self.assertRaises(tool.engine.Unmodelled):tool.NoExternalMemory().read(0x1234,8)

    def test_retained_source_and_native_provenance(self):
        record=json.loads((tool.PACKET/'rust-validation.json').read_bytes())
        self.assertEqual(record['target_sha256'],tool.target.SHA256)
        self.assertEqual(record['mismatches'],0)
        self.assertEqual(record['complete_cycle_cases'],292194)
        self.assertTrue(record['signed_division_bound']['holds'])
        self.assertEqual([r['profile'] for r in record['evaluator_blockers']],['shared','movsxd_only'])
        self.assertEqual(len(record['native_operand_controls']),4)
        self.assertEqual(record['native_bindings'],self.oracle.records)
        self.assertFalse(record['captured_binary_executed'])
        self.assertFalse(record['target_code_identity_measured'])
        self.assertEqual(record['source_sha256'],{name:hashlib.sha256((tool.CRATE/name).read_bytes()).hexdigest()
                                                 for name in ('Cargo.toml','Cargo.lock','src/lib.rs')})
        self.assertEqual(record['checker_source_sha256'],hashlib.sha256(Path(tool.__file__).read_bytes()).hexdigest())
        self.assertEqual(record['native_binder_sha256'],hashlib.sha256(Path(tool.target.__file__).read_bytes()).hexdigest())
        self.assertEqual(record['evaluator_source_sha256'],hashlib.sha256(Path(tool.engine.__file__).read_bytes()).hexdigest())

    @unittest.skipUnless(RUSTC and DECODER,'explicit direct HYPERLIQUID_NODE115_DAYCOUNT_RUSTC and Capstone5.0.6 required; not a Rust pass')
    def test_real_rust_build_and_complete_calendar_comparison(self):
        import capstone
        self.assertEqual(capstone.__version__,'5.0.6')
        directory=self.new_directory()
        with (directory/'comparison-progress.txt').open('w',encoding='utf8') as progress,contextlib.redirect_stdout(progress):
            actual=tool.verify(Path(RUSTC),directory/'comparison')
        retained=json.loads((tool.PACKET/'rust-validation.json').read_bytes())
        for field in ('target_sha256','source_sha256','checker_source_sha256','native_binder_sha256',
                      'evaluator_source_sha256','native_owner','cases','complete_cycle_cases','mismatches'):
            self.assertEqual(actual[field],retained[field])
        self.assertEqual(actual['mismatches'],0)
        self.assertEqual(actual['own_object_reproducible'],retained['own_object_reproducible'])
        self.assertEqual([c['control'] for c in actual['source_controls']],['offset','leap','flag'])
        self.assertTrue(all(c['rejected'] for c in actual['source_controls']))
        self.assertEqual(actual['native_operand_controls'],retained['native_operand_controls'])
        self.assertEqual(actual['evaluator_blockers'],retained['evaluator_blockers'])
        self.assertTrue(all(c['expected']!=c['changed'] and c['rejected'] for c in actual['native_operand_controls']))

if __name__=='__main__':unittest.main()
