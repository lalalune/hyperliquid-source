"""Static controls for the node94 post-call packet; no captured code execution."""
import copy
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import postcall_settlement94 as m


class PatchedImage(m.Image):
    """A sparse read corruption, after the real target has been authenticated."""
    def __init__(self, original, va, data):
        self.__dict__ = original.__dict__.copy()
        self.patch_va, self.patch_data = va, data

    def read(self, va, size):
        raw = bytearray(super().read(va, size))
        lo, hi = max(va, self.patch_va), min(va+size, self.patch_va+len(self.patch_data))
        if lo < hi:
            raw[lo-va:hi-va] = self.patch_data[lo-self.patch_va:hi-self.patch_va]
        return bytes(raw)


def limb_credit(balance, price, gas):
    """Independent schoolbook base-2**32 multiply, truncate, then saturating add."""
    mask = (1 << 32) - 1
    a = [(price >> (32*i)) & mask for i in range(8)]
    b = [(gas >> (32*i)) & mask for i in range(2)]
    product = [0] * 10
    for i, x in enumerate(a):
        for j, y in enumerate(b): product[i+j] += x*y
    for i in range(9):
        product[i+1] += product[i] >> 32
        product[i] &= mask
    total = []; carry = 0
    for i in range(8):
        v = product[i] + ((balance >> (32*i)) & mask) + carry
        total.append(v & mask); carry = v >> 32
    return m.U256 if carry else sum(v << (32*i) for i,v in enumerate(total))


class PostcallSettlementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im = m.Image((ROOT/'artifacts'/'node'/'94'/'hl-node').read_bytes())
        cls.decoded = {a:m.decode(cls.im.read(a,cls.im.fde(a)['end']-a),a) for a in m.FUNCTIONS}
        cls.output = m.collect(cls.im)

    def test_authenticated_target_and_selected_bodies(self):
        self.assertEqual(hashlib.sha256(self.im.data).hexdigest(),m.SHA)
        self.assertEqual(set(m.FUNCTIONS),set(m.BODY_HASHES))
        for a in m.FUNCTIONS:
            self.assertEqual(self.decoded[a][-1]['va']+self.decoded[a][-1]['size'],self.im.fde(a)['end'])

    def test_wrong_digest_rejected_before_elf_parse(self):
        with self.assertRaisesRegex(ValueError,'digest'): m.Image(b'not the target')

    def test_changed_body_fails(self):
        with self.assertRaisesRegex(ValueError,'body changed'):
            m.collect(PatchedImage(self.im,0x276d870,b'\x90'))

    def test_all_semantic_windows_reject_byte_corruption(self):
        for va,raw,_ in m.WINDOWS:
            with self.subTest(va=hex(va)):
                with self.assertRaisesRegex(ValueError,'byte predicate'):
                    m.validate_windows(PatchedImage(self.im,va,bytes([int(raw[:2],16)^1])),self.decoded)

    def test_invalid_and_non_file_backed_ranges(self):
        for va,size in [(-1,1),(0,0),(1<<64,1),(True,1),(0x276d870,-1)]:
            with self.subTest(va=va,size=size),self.assertRaises(ValueError): self.im.read(va,size)
        bss=next(s for s in self.im.secs if s['name']=='.bss')
        with self.assertRaises(ValueError): self.im.read(bss['address'],1)
        text=self.im.section('.text')
        with self.assertRaises(ValueError): self.im.read(text['address']+text['size']-1,2)

    def test_ambiguous_mapping_rejected(self):
        other=copy.copy(self.im);other.secs=self.im.secs+[dict(self.im.section('.text'))]
        with self.assertRaises(ValueError): other.read(0x276d870,1)

    def test_missing_duplicate_and_extended_fde(self):
        for replacement in ([],self.im.fdes[0x276d870]*2):
            other=copy.copy(self.im);other.fdes=dict(self.im.fdes);other.fdes[0x276d870]=replacement
            with self.assertRaises(ValueError): other.fde(0x276d870)
        other=copy.copy(self.im);other.fdes=dict(self.im.fdes)
        other.fdes[0x276d870]=[dict(self.im.fde(0x276d870),end=self.im.fde(0x276d870)['end']+1)]
        with self.assertRaisesRegex(ValueError,'body changed'): m.collect(other)

    def test_decoder_fails_on_unsupported_truncated_and_middle_branch(self):
        for raw in ('c5','e8','48b8','ebff'):
            with self.subTest(raw=raw),self.assertRaises(ValueError): m.decode(bytes.fromhex(raw),0x100)

    def test_table_corruption_rejected(self):
        other=PatchedImage(self.im,0x3e1ce0,b'\0\0\0\0')
        with self.assertRaisesRegex(ValueError,'table bytes changed'):
            m.branch_table(other,0x3e1ce0,108,0x242be40,self.decoded)

    def test_table_target_must_be_an_instruction_boundary(self):
        raw=bytearray(self.im.read(0x3e1ce0,432))
        struct.pack_into('<i',raw,0,0x242be41-0x3e1ce0)
        other=PatchedImage(self.im,0x3e1ce0,raw)
        with patch.dict(m.TABLE_HASHES,{(0x3e1ce0,108):m.digest(raw)}):
            with self.assertRaisesRegex(ValueError,'boundaries'):
                m.branch_table(other,0x3e1ce0,108,0x242be40,self.decoded)

    def test_changed_classifier_terminal_rejected(self):
        with self.assertRaisesRegex(ValueError,'terminal shape'):
            m.classifier_terminal(PatchedImage(self.im,0x242bec9,b'\x90'),0x242bec9,2)

    def test_table_requires_actual_dispatch_binding(self):
        rows=copy.deepcopy(self.decoded)
        row=next(r for r in rows[0x242be40] if r['va']==0x242be46)
        row['rip']+=4
        with self.assertRaisesRegex(ValueError,'not bound'):
            m.branch_table(self.im,0x3e1ce0,108,0x242be40,rows)

    def test_failure_store_order_is_explicit(self):
        ledger={row['va']:row for row in m.failure_ledger(self.decoded)}
        self.assertEqual(ledger['0x244f405']['condition'],'overflow')
        self.assertEqual(ledger['0x244f415']['same_path_prior_writes'][0]['va'],'0x244f40a')
        for va in ('0x2468e92','0x2468e9c'):
            self.assertEqual(ledger[va]['condition'],'below')
            self.assertEqual(ledger[va]['same_path_prior_writes'][0]['va'],'0x2468e83')
        self.assertEqual(ledger['0x2469277']['taken'],'0x24692ec')
        self.assertEqual(ledger['0x2469277']['same_path_prior_writes'][0]['va'],'0x246926e')

    def test_classifier_domain_is_explicit(self):
        for status in (-1,108,255,256,True):
            with self.subTest(status=status),self.assertRaises(ValueError): m.classify(self.im,status,self.decoded)

    def test_precompile_outcomes_bind_to_distinct_final_results(self):
        for status,category,reason in ((2,0,1),(83,2,3),(96,2,13)):
            row=m.classify(self.im,status,self.decoded)
            self.assertEqual((row['category'],row['reason'],row['terminal']),(category,reason,'return'))
        table=json.loads(self.output['output-table.json'])
        self.assertEqual([r['target_va'] for r in table],['0x246945c','0x2469503','0x24694f8','0x24696a5','0x24696a5'])
        self.assertEqual(m.classify(self.im,5,self.decoded)['terminal'],'ud2')
        self.assertEqual(m.classify(self.im,101,self.decoded)['category'],3)

    def test_callback_relocation_type_and_target_controls(self):
        for replacement in ((1,0x276d870,0),(8,0x244f400,0)):
            other=copy.copy(self.im);other.relas=dict(self.im.relas);other.relas[0x56bfa68]=replacement
            with self.assertRaises(ValueError): m.collect(other)

    def test_exception_ranges_have_valid_endpoints(self):
        for a,rows in self.decoded.items():
            sites,_=m.exception_sites(self.im,a,rows)
            boundaries={r['va'] for r in rows}|{self.im.fde(a)['end']}
            for site in sites:
                self.assertIn(int(site['range_start'],16),boundaries)
                self.assertIn(int(site['range_end'],16),boundaries)
                if site['landing_pad']: self.assertIn(int(site['landing_pad'],16),boundaries)

    def test_malformed_exception_header(self):
        a=0x2469250;off=self.im.offset(self.im.fde(a)['lsda'],1)
        other=copy.copy(self.im);data=bytearray(self.im.data);data[off]=0;other.data=data
        with self.assertRaisesRegex(ValueError,'landing-pad base'): m.exception_sites(other,a,self.decoded[a])

    def test_all_status_gas_normalization(self):
        keep_both=[];keep_remaining=[];clear=[]
        for status in range(256):
            g=m.normalize_gas(status,500,123,7)
            self.assertEqual(g['limit'],500)
            { (123,7):keep_both,(123,0):keep_remaining,(0,0):clear }[(g['remaining'],g['refund'])].append(status)
        self.assertEqual(keep_both,list(range(5)))
        self.assertEqual(keep_remaining,list(range(16,22)))
        self.assertEqual(len(clear),245)

    def test_refund_overflow_and_store_order(self):
        self.assertEqual(m.cap_refund(10,0,(1<<63)-1,1),{'failure':'signed-refund-overflow','refund':(1<<63)-1})
        self.assertEqual(m.cap_refund(10,0,1<<63,-1)['failure'],'signed-refund-overflow')
        self.assertEqual(m.cap_refund(10,11,7,2),{'failure':'spent-underflow','refund':9})
        self.assertEqual(m.cap_refund(10,0,0,-1),{'failure':None,'refund':2})
        self.assertEqual(m.cap_refund(10,0,m.U64,1),{'failure':None,'refund':0})

    def test_refund_division_matches_target_magic(self):
        magic=int.from_bytes(self.im.read(0x244f419,8),'little')
        shift=self.im.read(0x244f427,1)[0]
        rng=random.Random(94)
        values=[0,1,4,5,6,24,25,26,m.U64]+[rng.getrandbits(64) for _ in range(4096)]
        for spent in values:
            quotient=((spent*magic)>>64)>>shift
            self.assertEqual(quotient,spent//5)
            self.assertEqual(m.cap_refund(spent,0,m.U64,0)['refund'],quotient)

    def test_effective_price_presence_and_wrapping(self):
        self.assertEqual(m.effective_price(100,30,5,1),35)
        self.assertEqual(m.effective_price(32,30,5,1),32)
        for tag in (0,2,(1<<32)-1): self.assertEqual(m.effective_price(100,30,5,tag),100)
        self.assertEqual(m.effective_price(m.U256,m.U256,1,1),0)

    def test_credit_limb_oracle_and_overflow_boundaries(self):
        rng=random.Random(94)
        cases=[(0,0,0),(0,m.U256,2),(m.U256,1,1),(1,1<<255,2),(0,1<<255,3)]
        cases += [(rng.getrandbits(256),rng.getrandbits(256),rng.getrandbits(64)) for _ in range(4096)]
        for balance,price,gas in cases:
            self.assertEqual(m.credit_balance(balance,price,gas),limb_credit(balance,price,gas))
        self.assertEqual(m.credit_balance(1,1<<255,2),1)
        self.assertEqual(m.credit_balance(m.U256,1,1),m.U256)

    def test_callback_pipeline_success_and_exceptional_status(self):
        args=dict(limit=100000,remaining=98000,refund=7,extra=0,cap=100,base=30,priority=5,
                  priority_tag=1,sender_balance=1000,beneficiary_balance=2000)
        success=m.settlement(status=2,**args)
        self.assertEqual((success['gas_used'],success['gas_refund']),(1993,7))
        self.assertEqual(success['caller_balance'],1000+98007*35)
        self.assertEqual(success['beneficiary_balance'],2000+1993*5)
        for status in (83,96):
            fail=m.settlement(status=status,**args)
            self.assertEqual((fail['gas_used'],fail['gas_refund']),(100000,0))
            self.assertEqual(fail['caller_balance'],1000)
            self.assertEqual(fail['beneficiary_balance'],502000)

    def test_external_refund_can_follow_exceptional_status(self):
        result=m.settlement(83,100000,98000,7,100,100,30,5,1,0,0)
        self.assertEqual((result['normalized']['refund'],result['gas_refund'],result['gas_used']),(0,100,99900))

    def test_model_input_boundaries(self):
        for args in ((256,0,0,0),(0,-1,0,0),(0,0,0,1<<64)):
            with self.assertRaises(ValueError): m.normalize_gas(*args)
        with self.assertRaises(ValueError): m.cap_refund(1,0,0,1<<63)
        with self.assertRaises(ValueError): m.effective_price(-1,0,0,1)
        with self.assertRaises(ValueError): m.credit_balance(0,0,1<<64)

    def test_source_locations_are_retained_as_bytes_and_relative_suffixes(self):
        rows=json.loads(self.output['source-locations.json'])
        names={r['source_suffix'] for r in rows}
        self.assertIn('revm-19.2.0/src/handler/mainnet/post_execution.rs',names)
        self.assertIn('revm-interpreter-15.0.0/src/gas.rs',names)
        for row in rows:
            self.assertFalse(row['source_suffix'].startswith('/'))
            self.assertTrue(bytes.fromhex(row['path_bytes']).endswith(row['source_suffix'].encode()))

    def test_retained_generated_files_match(self):
        folder=ROOT/'research'/'work-items'/'RE-021-postcall-settlement-94'
        retained={p.name for p in folder.iterdir() if p.suffix in ('.json','.tsv')}
        self.assertEqual(retained,set(self.output))
        for name,value in self.output.items():
            self.assertEqual((folder/name).read_bytes(),value.encode('ascii'),name)


if __name__=='__main__': unittest.main()
