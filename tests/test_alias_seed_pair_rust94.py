"""Native factory projection, actual authored Rust and honest checkpoint history."""
import base64
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-001-seed-pair-rust-94'
SPEC=importlib.util.spec_from_file_location('alias_seed_pair94',PACKET/'verify.py')
v=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


class AliasSeedPairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
        cls.secs,cls.frozen=v.authenticate(cls.data)
        cls.original=v.span(cls.data,cls.secs,0x1452070,101)

    def test_complete_callback_initializer_once_and_relocation_chain(self):
        native=json.loads((PACKET/'native.json').read_text())
        self.assertEqual(native['new_selected_bytes'],197)
        self.assertEqual(native['new_rows_each'],51)
        self.assertEqual([r['bytes'] for r in native['functions']],[96,101,540])
        self.assertEqual({r['slot']:r['addend'] for r in native['relocations']},{'0x576e8b8':'0x4ee3b20','0x566a7d8':'0x1447590','0x577ae30':'0x1452070','0x566a9d8':'0x202e90'})

    def test_frozen_old_pair_and_low_word_wrap_full_envelopes(self):
        normal=v.fields(self.original,self.original)
        self.assertEqual(normal,(0x74,3,0x48,3))
        for frame in self.frozen['frames']:
            result=v.relation(frame,normal)
            self.assertEqual(result['returned_pair'],frame['returned_seed_pair_u64'])
            self.assertEqual(result['next_pair'],frame['expected_next_pair_u64'])
            self.assertEqual(result['output56_hex'],frame['initializer_output56_hex'])
            self.assertEqual(result['tls_after_hex'],frame['tls_after_hex'])
            self.assertEqual(bytes.fromhex(result['tls_after_hex'])[8:],bytes.fromhex(frame['tls_before_hex'])[8:])
        rows={r['id']:r for r in self.frozen['frames']}
        self.assertEqual(rows['wrap']['expected_next_pair_u64'][0],'0000000000000000')
        self.assertEqual(rows['carry32']['expected_next_pair_u64'][0],'1122334500000000')

    def test_four_frozen_native_controls_are_operative_equations(self):
        controls=v.controls(self.data,self.secs,self.frozen)
        self.assertEqual(v.js(controls),(PACKET/'native-controls.json').read_bytes())
        self.assertEqual(len(controls),4)
        self.assertTrue(all(c['original']!=c['changed'] for c in controls))
        self.assertEqual(controls[0]['changed'],{'route':'opaque0x13c8970'})
        self.assertEqual(controls[1]['changed']['returned_pair'],['0000000000202e90','0000000000000000'])
        self.assertEqual(controls[2]['changed']['next_pair'][0],'1122334400000000')
        self.assertEqual(controls[3]['changed']['next_pair'][0],'ffffffffffffffff')

    def test_identity_undeclared_change_and_unknown_operands_fail_closed(self):
        with self.assertRaises(ValueError):v.authenticate(self.data[:-1])
        changed=bytearray(self.original);changed[0]^=1
        with self.assertRaises(ValueError):v.fields(changed,self.original)
        changed=bytearray(self.original);changed[0x145209c-0x1452070]=0x49
        with self.assertRaises(ValueError):v.fields(changed,self.original)
        zero={**self.frozen['frames'][0],'tls_before_hex':'00'*24}
        self.assertEqual(v.relation(zero,v.fields(self.original,self.original)),{'route':'opaque0x13c8970'})

    def test_input_only_stream_and_exact_result_comparator(self):
        inputs,expected=v.streams();self.assertEqual((len(inputs),len(expected)),(280,357))
        self.assertEqual(v.compare(expected,expected),[])
        changed=bytearray(expected);changed[9]^=1
        self.assertEqual(len(v.compare(changed,expected)),1)
        for raw in [expected[:-1],expected+b'x',b'x'+expected[1:]]:
            with self.assertRaises(ValueError):v.compare(raw,expected)
        changed[7]^=1
        with self.assertRaises(ValueError):v.compare(changed,expected)
        offset=7
        for frame in self.frozen['frames']:
            _,low,high,length=struct.unpack_from('<HQQI',inputs,offset);offset+=22
            self.assertEqual([f'{low:016x}',f'{high:016x}'],frame['original_pair_u64'])
            self.assertEqual(inputs[offset:offset+length],b'A'*17);offset+=length
        self.assertEqual(offset,len(inputs))
        driver=(PACKET/'input-only.rs').read_text()
        self.assertNotIn('include_',driver);self.assertNotIn('std::fs',driver)
        self.assertEqual(driver.count('next_seed_pair(&mut source)'),1)

    def test_actual_current_source_builds_streams_and_all_seven_mutants(self):
        receipt=v.retained()
        self.assertEqual(len(receipt['builds']),16)
        self.assertFalse(receipt['captured_execution'])
        expected={'baseline':0,'return-new':7,'omit-increment':7,'increment-high':7,'memory32':3,'decrement':7,'swap-return':6,'wrong-native-source':7}
        self.assertEqual({(r['variant'],r['opt']) for r in receipt['builds']},{(name,opt) for name in expected for opt in [0,3]})
        for r in receipt['builds']:self.assertEqual(r['different_cases'],expected[r['variant']])
        original=json.loads((PACKET/'PLAN.json').read_text())
        self.assertFalse(original['new_rust_written'])
        self.assertEqual(receipt['source_input_pins']['src/node94-alias/src/lib.rs']['sha256'],v.sha((ROOT/'src/node94-alias/src/lib.rs').read_bytes()))

    def test_actual_durable_checkpoints_and_stopped_attempt_are_separate(self):
        v.checkpoint_evidence()
        _,raw=v.bundle('checkpoints.json')
        self.assertEqual(len(raw),8)
        self.assertFalse(any(name.endswith(('.rs','.so','.rlib','.o','.bin')) for name in raw))
        stopped=json.loads(raw['inline-carrier-seed-factory-current-orchestration.json'])
        self.assertNotIn('receipt_sha256',stopped)
        for stem,count in [('inline-carrier-seed-factory-fresh',15),('key-hash-seed-factory-fresh',16)]:
            doc=json.loads(raw[stem+'-checkpoint.json']);self.assertEqual(doc['completed_builds'],count)
            self.assertEqual(doc['status'],'PARTIAL: not final qualifier success')

    def test_packet_manifest(self):v.manifest_check()
