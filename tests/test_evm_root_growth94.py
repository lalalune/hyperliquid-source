"""Native-root CFG/operand bindings and independent final-layout controls."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-009-evm-root-growth-94"
SPEC = importlib.util.spec_from_file_location("root_growth94",PACKET/"verify.py")
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


class RootGrowthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = v.NODE.read_bytes();cls.secs=v.sections(cls.data)
        cls.c = v.validate(cls.data,cls.secs)
        cls.plan = json.loads((PACKET/"PLAN.json").read_text())

    def mutate(self,address,byte):
        sec = next(s for s in self.secs if s["type"] != 8 and s["address"] <= address < s["address"]+s["size"])
        at=sec["offset"]+address-sec["address"];changed=bytearray(self.data)
        self.assertNotEqual(changed[at],byte);changed[at]=byte
        return changed

    def fixture(self):
        a={"old":0x1000,"child":0x2000,"root":0x3000,"map":0x4000,"result":0x5000}
        b={"old":bytearray([0x91])*720,"child":bytearray([0x82])*720,
           "root":bytearray([0xA5])*816,"map":bytearray(24),"result":bytearray([0x76])*24}
        struct.pack_into("<Q",b["old"],0x2C0,0)
        struct.pack_into("<H",b["old"],0x2CA,5)
        struct.pack_into("<H",b["child"],0x2CA,6)
        struct.pack_into("<QQQ",b["map"],0,a["old"],0,0x12345678)
        return {name:bytes(x) for name,x in b.items()},a

    def independent_expected(self,initial,a,key,value,selected,index):
        e={name:bytearray(b) for name,b in initial.items()}
        for name,offset,fmt,val in (
            ("root",0x2C0,"<Q",0),("root",0x2CA,"<H",1),
            ("root",0x2D0,"<Q",a["old"]),("root",0x2D8,"<Q",a["child"]),
            ("old",0x2C0,"<Q",a["root"]),("old",0x2C8,"<H",0),
            ("child",0x2C0,"<Q",a["root"]),("child",0x2C8,"<H",1),
            ("map",0,"<Q",a["root"]),("map",8,"<Q",1)):
            struct.pack_into(fmt,e[name],offset,val)
        e["root"][0:32]=key;e["root"][0x160:0x180]=value
        e["result"][:]=struct.pack("<QQQ",selected,0,index)
        return {name:bytes(b) for name,b in e.items()}

    def test_authenticated_record_and_selected_cfg(self):
        actual=v.analyze(self.data)
        self.assertEqual(actual,json.loads((PACKET/"evidence.json").read_text()))
        self.assertEqual(actual["counts"]["selected_bytes"],310)
        self.assertEqual(actual["allocator_relocation"]["addend"],"0x54c06b0")
        self.assertEqual(actual["credited_memcpy_import"]["version"],"GLIBC_2.14")
        self.assertEqual(actual["fields"]["null_parent"]["target"],"0x1ab45df")
        self.assertEqual(actual["fields"]["level_guard"]["opcode"],"0f85")
        self.assertEqual(actual["fixed_store_widths_bits"],{"parent_pointer":64,"child_edge":64,
            "map_word":64,"node_index":16,"node_count":16,"prepared_half":128,"result_word":64})
        self.assertEqual(actual["selected_normal_cfg"][3],
            {"site":"0x1ab4638","taken":False,"next":"0x1ab463e"})

    def test_full_layout_and_preservation_for_both_selected_children(self):
        initial,a=self.fixture();key=bytes(range(32));value=bytes(range(128,160))
        for selected in (a["old"],a["child"]):
            for index in (0,5,2**64-1):
                actual=v.apply_contract(self.c,initial,a,key,value,selected,index)
                expected=self.independent_expected(initial,a,key,value,selected,index)
                self.assertEqual(actual,expected)
                self.assertEqual(actual["old"][0x2CA:0x2CC],b"\x05\0")
                self.assertEqual(actual["child"][0x2CA:0x2CC],b"\x06\0")
                self.assertEqual(actual["root"][0x2C8:0x2CA],b"\xa5\xa5")
                self.assertEqual(actual["map"][16:],initial["map"][16:])

    def test_every_prepared_buffer_position(self):
        initial,a=self.fixture()
        for lane in range(32):
            key=bytes(0x80 if i==lane else 0 for i in range(32))
            value=bytes(0x7F if i==31-lane else 0 for i in range(32))
            actual=v.apply_contract(self.c,initial,a,key,value,a["old"],lane)
            self.assertEqual(actual,self.independent_expected(initial,a,key,value,a["old"],lane))

    def test_all_frozen_native_field_mutations(self):
        self.assertTrue(self.plan["frozen_before_model"])
        self.assertEqual(len(self.plan["native_mutations"]),9)
        for row in self.plan["native_mutations"]:
            changed=self.mutate(int(row["va"],16),int(row["byte"],16))
            with self.subTest(field=row["field"]):
                self.assertNotEqual(v.fields(changed,self.secs),self.c)
                with self.assertRaisesRegex(ValueError,"contract changed"):
                    v.validate(changed,self.secs)

    def test_mutated_edge_count_and_copy_offsets_have_layout_counterexamples(self):
        initial,a=self.fixture();key=bytes(range(32));value=bytes(range(128,160))
        expected=self.independent_expected(initial,a,key,value,a["old"],2)
        for address,replacement in ((0x1AB462E,0xD8),(0x1AB467A,0xC8),(0x1AB46AA,0x70)):
            altered=v.fields(self.mutate(address,replacement),self.secs)
            self.assertNotEqual(v.apply_contract(altered,initial,a,key,value,a["old"],2),expected)

    def test_alias_entry_and_pointer_premises_are_explicit(self):
        initial,a=self.fixture()
        for name,value in (("root",a["old"]),("root",a["old"]+8),("root",-8),("root",2**64-8)):
            with self.assertRaises(ValueError):
                v.apply_contract(self.c,initial,{**a,name:value},bytes(32),bytes(32),a["old"],0)
        invalid=dict(initial);m=bytearray(initial["map"]);struct.pack_into("<Q",m,8,1);invalid["map"]=bytes(m)
        with self.assertRaisesRegex(ValueError,"entry premise"):
            v.apply_contract(self.c,invalid,a,bytes(32),bytes(32),a["old"],0)
        for key,value in ((bytes(31),bytes(32)),(bytes(32),bytes(33))):
            with self.assertRaisesRegex(ValueError,"prepared-buffer"):
                v.apply_contract(self.c,initial,a,key,value,a["old"],0)

    def test_height_inc_boundary_without_fault_path_execution(self):
        self.assertEqual(v.increment_height(0),(1,False))
        self.assertEqual(v.increment_height(2**64-2),(2**64-1,False))
        self.assertEqual(v.increment_height(2**64-1),(0,True))
        for height in (-1,2**64,True):
            with self.assertRaises(ValueError):v.increment_height(height)

    def test_relocation_type_and_symbol_are_extracted_below_identity(self):
        rel=v.relocation(self.data,self.secs,0x576DFE0);row=int(rel["row_va"],16)
        changed=self.mutate(row+8,8)
        self.assertNotEqual(v.relocation(changed,self.secs,0x576DFE0)["type"],6)
        changed=self.mutate(row+12,9)
        self.assertEqual(v.relocation(changed,self.secs,0x576DFE0)["symbol"],"memmove")
        alloc=v.relocation(self.data,self.secs,0x576DFD8)
        changed=self.mutate(int(alloc["row_va"],16)+16,0xB1)
        self.assertEqual(v.relocation(changed,self.secs,0x576DFD8)["addend"],"0x54c06b1")

    def test_identity_opcode_and_listing_corruptions(self):
        with self.assertRaisesRegex(ValueError,"identity mismatch"):
            v.analyze(self.mutate(0x1AB4601,0x20))
        with self.assertRaisesRegex(ValueError,"native form"):
            v.fields(self.mutate(0x1AB4646,0x67),self.secs)
        listing=(PACKET/"selected.asm").read_text();v.check_listing(listing,self.data)
        with self.assertRaisesRegex(ValueError,"incomplete"):v.check_listing("",self.data)
        with self.assertRaisesRegex(ValueError,"differ"):
            v.check_listing(listing.replace("\t45 31 ed","\t45 31 ec",1),self.data)

    def test_invalid_unmapped_ambiguous_and_nobits_ranges(self):
        for address,size in ((-1,1),(0x1AB45DF,0),(True,1),(2**64,1)):
            with self.assertRaises(ValueError):v.span(self.data,self.secs,address,size)
        sec=next(s for s in self.secs if s["address"] <= 0x1AB45DF < s["address"]+s["size"])
        for mapping in ([sec,sec],[{**sec,"type":8}]):
            with self.assertRaisesRegex(ValueError,"uniquely file backed"):
                v.span(self.data,mapping,0x1AB45DF,1)
        with self.assertRaisesRegex(ValueError,"exceeds input"):
            v.span(self.data[:10],[sec],0x1AB45DF,1)


if __name__ == "__main__":
    unittest.main()
