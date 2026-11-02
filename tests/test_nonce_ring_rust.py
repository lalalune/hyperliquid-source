"""Target identity, valid-ring assumptions and an actual compiled Rust comparison."""
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
import nonce_ring_rust as tool

RUSTC=os.environ.get('HYPERLIQUID_NONCE_RING_RUSTC')
DECODER=importlib.util.find_spec('capstone') is not None

class NonceRingRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=tool.native.TARGET.read_bytes()
        cls.original,cls.parameters=tool.bind_native(cls.data)

    def directory(self):
        root=Path(__file__).resolve().parents[1]/'work/nonce-ring-rust-tests'
        root.mkdir(parents=True,exist_ok=True)
        return Path(tempfile.mkdtemp(prefix='case-',dir=root))

    def test_pinned_target_and_all_five_native_predicates(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),tool.native.SHA)
        self.assertEqual(len(self.original['owners']),5)
        for entry in tool.native.BRANCHES:
            self.assertEqual(tool.native.parameters(self.data,entry),[0x72,0x72])
        with self.assertRaisesRegex(ValueError,'identity'):tool.bind_native(self.data[:-1])

    def test_native_wrap_boundary_and_unsigned_equality(self):
        p=self.parameters;ordered=tool.native.ordered
        self.assertTrue(ordered(p,[],0,0))
        self.assertTrue(ordered(p,[9],0,1))
        self.assertTrue(ordered(p,[3,4,1,2],2,4))
        self.assertFalse(ordered(p,[0,1],1,2))
        self.assertFalse(ordered(p,[7,7],0,2))
        self.assertTrue(ordered(p,[0x7fffffffffffffff,0x8000000000000000],0,2))
        self.assertFalse(ordered(p,[0xffffffffffffffff,0],0,2))
        self.assertIn((1,1,0),tool.native.obligations(2,1,2))

    def test_invalid_metadata_and_non_u64_values_never_reach_unsafe_code(self):
        # Validation is the harness's synthetic-input boundary, not a claim
        # that the original native providers reject malformed metadata.
        for values,head,count in (([],1,0),([1],0,2),([1],-1,1),([1],0,-1),
                                  ([True],0,1),([-1],0,1),([1<<64],0,1),([1],True,1)):
            with self.assertRaises(ValueError):tool.evaluate(None,values,head,count)

        with self.assertRaises(ValueError):tool.evaluate(None,[1,2],0,2,8)

    def test_own_object_entry_rejects_capture_and_malformed_inputs(self):
        with self.assertRaises(ValueError):tool.own_machine(tool.native.TARGET)
        # A dispatch spy proves rejection without ever executing the capture.
        with patch.object(tool.subprocess,'run',side_effect=AssertionError('No captured program dispatch')):
            with self.assertRaisesRegex(ValueError,'Captured artifact'):
                tool.verify(tool.native.TARGET,self.directory()/'forbidden-compiler')
        root=self.directory()
        for index,data in enumerate((b'',b'not ELF',b'\x7fELF\x01\x01'+bytes(80))):
            path=root/f'bad-{index}.o';path.write_bytes(data)
            with self.assertRaises(ValueError):tool.own_machine(path)
        with self.assertRaises(tool.engine.Unmodelled):tool.NoExternalMemory().read(0x1234,8)

    def test_retained_actual_provenance_and_measured_limits(self):
        r=json.loads((tool.PACKET/'rust-validation.json').read_bytes())
        self.assertEqual(r['target_sha256'],tool.native.SHA)
        self.assertEqual(r['native_spec_sha256'],tool.native.SPEC_SHA)
        self.assertEqual(r['mismatches'],0)
        self.assertEqual(r['evaluation_counts'],{'exhaustive':14161,'layouts':47872,'unaligned':5784})
        self.assertFalse(r['captured_binary_executed'])
        self.assertFalse(r['target_code_identity_measured'])
        self.assertTrue(r['unset_storage_rejected'])
        self.assertEqual(r['source_sha256'],{n:hashlib.sha256((tool.CRATE/n).read_bytes()).hexdigest()
                                             for n in ('Cargo.toml','Cargo.lock','src/lib.rs')})
        for field,path in (('checker_source_sha256',tool.__file__),
                           ('native_binder_sha256',tool.native.__file__),
                           ('evaluator_source_sha256',tool.engine.__file__)):
            self.assertEqual(r[field],hashlib.sha256(Path(path).read_bytes()).hexdigest())

    @unittest.skipUnless(RUSTC and DECODER,'explicit HYPERLIQUID_NONCE_RING_RUSTC and Capstone5.0.6 required; not a Rust pass')
    def test_actual_compilation_layouts_and_source_corruptions(self):
        import capstone
        self.assertEqual(capstone.__version__,'5.0.6')
        actual=tool.verify(Path(RUSTC),self.directory()/'comparison')
        retained=json.loads((tool.PACKET/'rust-validation.json').read_bytes())
        for field in ('source_sha256','checker_source_sha256','native_binder_sha256',
                      'evaluator_source_sha256','native_record','evaluation_counts','mismatches','own_code_sha256'):
            self.assertEqual(actual[field],retained[field])
        self.assertTrue(actual['own_object_reproducible'])
        self.assertEqual([c['control'] for c in actual['compiled_source_controls']],['equal','wrap','first_pair'])
        self.assertTrue(all(c['rejected'] for c in actual['compiled_source_controls']))

if __name__=='__main__':unittest.main()
