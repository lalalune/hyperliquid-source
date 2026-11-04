"""Original bindings, raw null behavior and actual own-code Rust comparisons."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import checksum_selector2_rust as tool

RUSTC=os.environ.get('HYPERLIQUID_CHECKSUM_RUSTC')
DECODER=importlib.util.find_spec('capstone') is not None

class ChecksumRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(tool.ROOT/tool.BINARY).read_bytes()
        cls.oracle,cls.original=tool.native_record(cls.data)

    def directory(self):
        root=Path(__file__).resolve().parents[1]/'work/checksum-rust-tests'
        root.mkdir(parents=True,exist_ok=True)
        return Path(tempfile.mkdtemp(prefix='case-',dir=root))

    def test_original_identity_fde_and_selected_tail_route(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),tool.SHA256)
        self.assertEqual([(r['start'],r['end'],r['bytes']) for r in self.original['owners']],
                         [('0x61da8b0','0x61daa52',418),('0x616bca0','0x616bd51',177)])
        self.assertEqual(self.original['selected_raw_tag'],2)
        self.assertEqual(self.original['selected_tail_target'],'0x61da8b0')
        self.assertEqual(self.original['selected_seed'],0)
        with self.assertRaises(ValueError):tool.NativeFormula(self.data[:-1])

    def test_empty_seed_null_length_and_synthetic_domains(self):
        self.assertEqual(self.oracle.hash(b'',0),0x02cc5d05)
        self.assertEqual(self.oracle.hash(b'',0x9e3779b1),0x36b78ae7)
        for seed in (0,1,0xffffffff):
            for length in (0,1,16,1<<32,(1<<64)-1):
                self.assertEqual(self.oracle.hash(None,seed,length),self.oracle.hash(b'',seed))
        for payload,seed,length in ((b'',True,0),(b'',-1,0),(b'',1<<32,0),('a',0,0),(None,0,-1),(None,0,1<<64)):
            with self.assertRaises(ValueError):self.oracle.hash(payload,seed,length)
        with self.assertRaises(ValueError):tool.evaluate(None,b'',0,offset=8)

    def test_scoped_rotate_uses_architectural_flags(self):
        e=tool.engine;machine=tool.HashMachine([],tool.NoExternalMemory(),{})
        for count in (1,7,11,12,13,17,18):
            for value in (0,1,0x7fffffff,0x80000000,0xffffffff,0x12345678):
                machine.reset();machine.setreg(e.RAX,value);machine.cf=True;machine.of=True
                machine.sf=True;machine.zf=None
                machine.i_rol((('r',e.RAX,4),('i',count)))
                bits=f'{value:032b}';rotated=bits[count:]+bits[:count]
                self.assertEqual(machine.regs[e.RAX],int(rotated,2))
                self.assertEqual(machine.known[e.RAX],e.MASK)
                self.assertEqual(machine.cf,rotated[-1]=='1')
                self.assertEqual(machine.of,(rotated[0]!=rotated[-1]) if count==1 else None)
                self.assertTrue(machine.sf);self.assertIsNone(machine.zf)
        with self.assertRaises(e.Unmodelled):machine.i_rol((('r',e.RAX,8),('i',13)))
        with self.assertRaises(e.Unmodelled):machine.i_rol((('r',e.RAX,4),('i',0)))

    def test_capture_never_enters_object_or_compiler_dispatch(self):
        target=tool.ROOT/tool.BINARY
        with self.assertRaises(ValueError):tool.own_machine(target)
        with patch.object(tool.subprocess,'run',side_effect=AssertionError('No captured executable dispatch')):
            with self.assertRaisesRegex(ValueError,'Captured artifact'):
                tool.verify(target,self.directory()/'forbidden-compiler')
        root=self.directory()
        for index,data in enumerate((b'',b'not ELF',b'\x7fELF\x01\x01'+bytes(80))):
            path=root/f'bad-{index}.o';path.write_bytes(data)
            with self.assertRaises(ValueError):tool.own_machine(path)
        with self.assertRaises(tool.engine.Unmodelled):tool.NoExternalMemory().read(0x1234,8)

    def test_retained_actual_source_provenance_and_limits(self):
        r=json.loads((tool.PACKET/'rust-validation.json').read_bytes())
        self.assertEqual(r['target_sha256'],tool.SHA256)
        self.assertEqual(r['mismatches'],0)
        self.assertEqual(r['evaluation_counts'],{'boundaries':1620,'one_byte':1024,'null':40})
        self.assertFalse(r['captured_binary_executed'])
        self.assertFalse(r['target_code_identity_measured'])
        self.assertEqual(r['source_sha256'],{n:hashlib.sha256((tool.CRATE/n).read_bytes()).hexdigest()
                                             for n in ('Cargo.toml','Cargo.lock','src/lib.rs')})
        self.assertEqual(r['checker_source_sha256'],hashlib.sha256(Path(tool.__file__).read_bytes()).hexdigest())
        import fde_extents,elf_index
        self.assertEqual(r['dependencies_sha256'],{Path(m.__file__).name:hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
                                                  for m in (tool.engine,fde_extents,elf_index)})
        # Decoder row counts are retained separately from stdlib FDE/body binding.
        for actual,retained in zip(self.original['owners'],r['native']['owners']):
            self.assertEqual(actual,{k:v for k,v in retained.items() if k!='instructions'})

    @unittest.skipUnless(RUSTC and DECODER,'explicit HYPERLIQUID_CHECKSUM_RUSTC and Capstone5.0.6 required; not a Rust pass')
    def test_real_compilation_full_corpus_and_operative_controls(self):
        import capstone
        self.assertEqual(capstone.__version__,'5.0.6')
        actual=tool.verify(Path(RUSTC),self.directory()/'comparison')
        retained=json.loads((tool.PACKET/'rust-validation.json').read_bytes())
        for field in ('source_sha256','checker_source_sha256','dependencies_sha256',
                      'native','evaluation_counts','mismatches','own_code_sha256'):
            self.assertEqual(actual[field],retained[field])
        self.assertTrue(actual['own_object_reproducible'])
        self.assertEqual(len(actual['compiled_source_controls']),6)
        self.assertEqual(len(actual['native_operand_controls']),8)
        for row in actual['compiled_source_controls']+actual['native_operand_controls']:
            self.assertTrue(row['rejected']);self.assertNotEqual(row['expected'],row['changed'])

if __name__=='__main__':unittest.main()
