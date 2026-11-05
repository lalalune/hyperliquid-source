"""Comparator corruption controls. No captured-code execution or emulation."""
from pathlib import Path
import copy, importlib.util, json, unittest
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("metadata_extract",HERE/"extract.py")
extract=importlib.util.module_from_spec(spec);spec.loader.exec_module(extract)

class MetadataEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet=json.loads((HERE/"native.json").read_text(encoding="utf-8"))
    def changed(self):
        return copy.deepcopy(self.packet)
    def ins(self,p,address):
        return next(i for r in p["records"] for i in r["instructions"] if i["address"]==address)
    def test_positive_anchors(self):
        self.assertEqual(extract.qualify(self.packet)["fieldCalls"],10)
    def test_wrong_input_offset_rejected(self):
        p=self.changed();self.ins(p,"0x2f18798")["operands"]="rcx, [rbx + 0x2c]"
        with self.assertRaises(AssertionError):extract.qualify(p)
    def test_wrong_growth_default_rejected(self):
        p=self.changed();self.ins(p,"0x2f1883d")["operands"]="r12b, 0"
        with self.assertRaises(AssertionError):extract.qualify(p)
    def test_wrong_omission_target_rejected(self):
        p=self.changed();self.ins(p,"0x2f18841")["operands"]="0x2f18870"
        with self.assertRaises(AssertionError):extract.qualify(p)
    def test_field_call_order_rejected(self):
        p=self.changed();self.ins(p,"0x2f18751")["operands"]="0x2ec0710"
        with self.assertRaises(AssertionError):extract.qualify(p)
    def test_wrong_key_rejected(self):
        p=self.changed();p["keys"][5]["text"]="isDeleted"
        with self.assertRaises(AssertionError):extract.qualify(p)
    def test_wrong_precision_rejected(self):
        p=self.changed();p["data"]["feeDescriptor"]="c520000070090000"
        with self.assertRaises(AssertionError):extract.qualify(p)
    def test_wrong_escape_class_rejected(self):
        p=self.changed();b=bytearray.fromhex(p["data"]["escapeClasses"]);b[10]=0
        p["data"]["escapeClasses"]=b.hex()
        with self.assertRaises(AssertionError):extract.qualify(p)
    def test_wrong_callback_rejected(self):
        p=self.changed();self.ins(p,"0x168876f")["operands"]="0x167c040"
        with self.assertRaises(AssertionError):extract.qualify(p)
    def test_frozen_adapter_is_exact(self):
        packet=json.loads((HERE/"frozen-cases.json").read_text(encoding="utf-8"))
        rows=[line.split("\t") for line in (HERE/"frozen-cases.tsv").read_text(encoding="utf-8").splitlines()
              if not line.startswith("#")]
        self.assertEqual(len(rows),223)
        for row,case in zip(rows,packet["cases"],strict=True):
            m=case["input"];t=m["last_fee_time"]
            time=[str(t[k]) for k in ["packed_date","seconds","nanos"]] if t is not None else ["-"]*3
            want=[case["id"],str(m["sz_decimals"]),m["name"].encode().hex(),str(m["max_leverage"]),str(m["margin_table_id"]),str(int(m["only_isolated"])),str(int(m["is_delisted"])),str(m["margin_mode"]),str(m["growth_mode"]),*time,m["fee_bits"] if m["fee_bits"] is not None else "-",case["expectedUtf8Hex"]]
            self.assertEqual(row,want)
        self.assertEqual(len(packet["cases"]),223)

if __name__=="__main__": unittest.main()
