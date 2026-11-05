"""Offline checks of evidence integrity and independent pre-Rust expectations.
Controls alter evidence in memory; they never execute/emulate the target.
The separate four Rust counterfactual builds exercise real compiled Rust.
"""
from pathlib import Path
import copy,hashlib,json,struct,unittest
from qualify_native import qualify
E=Path(__file__).resolve().parent
PACKET=json.loads((E/"native.json").read_text(encoding="utf-8"))
FROZEN=json.loads((E/"frozen-cases.json").read_text(encoding="utf-8"))

def snapshot(m):
    if m["snapshot"]=="referrerStates":return {"type":"referrerStates"}
    assert m["snapshot"]=="l4Snapshots"
    v={"type":"l4Snapshots","includeUsers":m["include_users"],"includeTriggerOrders":m["include_trigger_orders"]}
    if m["coin"]:v["coin"]=m["text"]
    if m["include_l4_details"]:v["includeL4Details"]=True
    return v

def expected(case):
    m=case["input"];s=FROZEN["spec"][case["selectorIndex"]];v={"type":s["type"]}
    for f in s["fields"]:
        key,k=f["name"],f["kind"]
        if k=="text":item=m["out_path"] if key=="outPath" else m["text"]
        elif k=="address":item="0x"+m["second_address" if key=="builder" else "address"]
        elif k=="optional_address":item="0x"+m["address"] if m["optional_address"] else None
        elif k=="bool":item=m["flag"]
        elif k in {"u32","u64"}:item=m[k];assert 0<=item<2**int(k[1:])
        elif k=="snapshot":item=snapshot(m)
        else:raise AssertionError(k)
        v[key]=item
    return v

def tsv(case):
    m=case["input"];i=case["selectorIndex"]
    nested=",".join(snapshot(m)) if i==0 else "-"
    return [case["id"],str(i),m["text"].encode().hex(),m["out_path"].encode().hex(),
      m["address"],m["second_address"],str(m["u64"]),str(m["u32"]),str(int(m["flag"])),
      str(int(m["optional_address"])),str(int(m["snapshot"]=="l4Snapshots")),
      str(int(m["coin"])),str(int(m["include_users"])),str(int(m["include_trigger_orders"])),
      str(int(m["include_l4_details"])),case["expectedUtf8Hex"],
      ",".join(expected(case)),nested]

class Evidence(unittest.TestCase):
    def test_complete_native_profile(self):
        result=qualify(PACKET,FROZEN["spec"])
        self.assertEqual(result,json.loads((E/"qualified-profile.json").read_text()))
        self.assertEqual(len(result["arms"]),55)
    def test_pre_rust_190_whole_values_and_all_18_tsv_columns(self):
        self.assertEqual(hashlib.sha256((E/"frozen-cases.json").read_bytes()).hexdigest(),
          "dbeb3498fd3d66c7948832f5a32416162c708284e553c2d4db3da3c72eb7fa9d")
        cases=FROZEN["cases"];self.assertEqual(len(cases),190)
        lines=[l.split("\t") for l in (E/"frozen-cases.tsv").read_text().splitlines() if not l.startswith("#")]
        self.assertEqual(lines,[tsv(c) for c in cases])
        self.assertEqual(len({c["id"] for c in cases}),190)
        for c in cases:
            rendered=json.dumps(expected(c),ensure_ascii=False,sort_keys=True,separators=(",",":"))
            self.assertEqual(rendered,c["expectedCanonicalJson"],c["id"])
            self.assertEqual(rendered.encode().hex(),c["expectedUtf8Hex"],c["id"])
        for i in range(55):
            self.assertIn("default_"+str(i),[c["id"] for c in cases])
            self.assertIn("changed_"+str(i),[c["id"] for c in cases])

    def reject(self,p):
        with self.assertRaises((AssertionError,KeyError,StopIteration,ValueError,UnicodeError)):
            qualify(p,FROZEN["spec"])
    def record(self,p,start):
        return next(r for r in p["records"] if r["start"]==start)
    def ins(self,p,start,site):
        return next(i for i in self.record(p,start)["instructions"] if i["address"]==site)
    def test_dispatch_counterfactual(self):
        p=copy.deepcopy(PACKET)
        x,y=p["dispatch"][1],p["dispatch"][38]
        x["destination"],y["destination"]=y["destination"],x["destination"]
        x["bytes"],y["bytes"]=y["bytes"],x["bytes"]
        self.reject(p)
    def test_native_byte_width_counterfactual(self):
        # Same-size REX.W change: original mov eax,dword[r15] -> mov rax,qword[r15].
        import capstone
        p=copy.deepcopy(PACKET);r=self.record(p,"0x26ebcc0")
        i=self.ins(p,"0x26ebcc0","0x26ebd7f");raw=bytearray.fromhex(i["bytes"])
        self.assertEqual(raw[0],0x41);raw[0]=0x49
        d=list(capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(bytes(raw),int(i["address"],16)))
        self.assertEqual(len(d),1);i.update(bytes=bytes(raw).hex(),mnemonic=d[0].mnemonic,operands=d[0].op_str)
        r["sha256"]=hashlib.sha256(b"".join(bytes.fromhex(x["bytes"]) for x in r["instructions"])).hexdigest()
        self.reject(p)
    def test_metadata_semantic_counterfactuals(self):
        # Altered metadata is identified as such, not represented as native execution.
        changes=[
          ("u64 width","0x26eb010","0x26eb0cf","eax, dword ptr [r15]"),
          ("optional null","0x26ebe80","0x26ebf8b","rax, r15"),
          ("compact address","0x26eba60","0x26ebb44","r8d, 1"),
          ("coin omission","0x273f3b0","0x273f5ed","0x273f477"),
          ("details omission","0x273f3b0","0x273f60e","0x273f60b"),
        ]
        for name,start,site,operands in changes:
            with self.subTest(name=name):
                p=copy.deepcopy(PACKET);self.ins(p,start,site)["operands"]=operands;self.reject(p)
    def test_data_literal_counterfactual(self):
        p=copy.deepcopy(PACKET);r=self.record(p,"0x273bf30")
        ref=next(r for r in r["ripReferences"] if r["site"]=="0x273e433")
        ref["raw64"]=b"perpDexWrong".hex()+ref["raw64"][24:];self.reject(p)
    def test_hex_alphabet_counterfactual(self):
        p=copy.deepcopy(PACKET);p["data"]["hexAlphabet"]=b"0123456789ABCDEF".hex();self.reject(p)
    def test_address_relocation_counterfactual(self):
        p=copy.deepcopy(PACKET);next(r for r in p["relocations"] if r["slot"]=="0x64e4d08")["addend"]="0x2eabb51";self.reject(p)
    def test_target_identity_counterfactual(self):
        p=copy.deepcopy(PACKET);p["targetSha256"]="0"*64;self.reject(p)

if __name__=="__main__":unittest.main(verbosity=2)
