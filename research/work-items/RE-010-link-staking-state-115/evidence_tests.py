"""Offline integrity, native-data and frozen mathematical expectation controls."""
from pathlib import Path
import copy,hashlib,json,unittest
from qualify_profile import qualify
from frozen_reference import reference
E=Path(__file__).resolve().parent
P=json.loads((E/"native.json").read_text(encoding="utf-8"))
F=json.loads((E/"frozen-cases.json").read_text(encoding="utf-8"))

def records(rows):
 return ",".join(r["key"]+":"+str(r["tag"])+":"+r["peer"] for r in rows) or "-"
def tsv(c):
 e=c["expected"]
 return [c["id"],"0" if c["mode"]=="request" else "1",c["callerKey"],c["payloadKey"],
  ",".join(c["stakeKeys"]) or "-",records(c["relations"]),str(e["outcome"]),records(e["writes"]),
  records(e["relations"]),str(e["outerTag"]),str(e["innerTag"])]

class Evidence(unittest.TestCase):
 def row(self,p,start):return next(r for r in p["records"] if r["start"]==start)
 def ins(self,p,start,site):return next(i for i in self.row(p,start)["instructions"] if i["address"]==site)
 def reject(self,p):
  with self.assertRaises((AssertionError,KeyError,StopIteration,ValueError)):
   qualify(p,F)
 def patch(self,p,start,site,change):
  import capstone
  r=self.row(p,start);i=self.ins(p,start,site);raw=bytearray.fromhex(i["bytes"]);change(raw)
  decoded=list(capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(bytes(raw),int(site,16)))
  self.assertEqual(len(decoded),1);d=decoded[0]
  self.assertEqual(d.size,len(raw))
  i.update(bytes=bytes(raw).hex(),mnemonic=d.mnemonic,operands=d.op_str)
  r["sha256"]=hashlib.sha256(b"".join(bytes.fromhex(x["bytes"]) for x in r["instructions"])).hexdigest()
 def test_complete_static_profile(self):
  self.assertEqual(qualify(P,F),json.loads((E/"qualified-profile.json").read_text()))
 def test_frozen_274_whole_states_and_all_11_tsv_columns(self):
  self.assertEqual(hashlib.sha256((E/"frozen-cases.json").read_bytes()).hexdigest(),
   "ab67314e108401b5f2632b851435d67bc9337b30b3cb8af4bf4c5f930466a923")
  self.assertEqual(hashlib.sha256((E/"frozen-cases.tsv").read_bytes()).hexdigest(),
   "4509967eaf7f98fc7b109a3fed63f3c13a7ccb3ec26e096de9d5c9a53c5efb65")
  cases=F["cases"];self.assertEqual(len(cases),274)
  self.assertEqual(len({c["id"] for c in cases}),274)
  self.assertEqual([l.split("\t") for l in (E/"frozen-cases.tsv").read_text().splitlines() if not l.startswith("#")],[tsv(c) for c in cases])
  for c in cases:
   initial={r["key"]:(r["tag"],r["peer"]) for r in c["relations"]}
   self.assertEqual(reference(c["mode"],c["callerKey"],c["payloadKey"],c["stakeKeys"],initial),c["expected"],c["id"])
  self.assertEqual((E/"messages.tsv").read_text().splitlines(),[x["text"] for x in F["errorLiterals"]])
  self.assertEqual({c["expected"]["outcome"] for c in cases},set(range(6)))
 def test_aliased_finalize_preserves_two_writes_and_last_write(self):
  cases=[c for c in F["cases"] if c["mode"]=="finalize" and c["callerKey"]==c["payloadKey"] and c["expected"]["outcome"]==0]
  self.assertTrue(cases)
  for c in cases:
   w=c["expected"]["writes"];self.assertEqual([r["tag"] for r in w],[1,2]);self.assertEqual(w[0]["key"],w[1]["key"])
   final=next(r for r in c["expected"]["relations"] if r["key"]==w[0]["key"])
   self.assertEqual(final,w[1])
 def test_native_branch_byte_counterfactual(self):
  p=copy.deepcopy(P)
  def change(b):
   if b[0]==0x0f:self.assertEqual(b[1],0x85);b[1]=0x84
   else:self.assertEqual(b[0],0x75);b[0]=0x74
  self.patch(p,"0x469fe90","0x469ffff",change);self.reject(p)
 def test_native_write_tag_byte_counterfactual(self):
  p=copy.deepcopy(P)
  def change(b):self.assertEqual(b[-1],1);b[-1]=2
  self.patch(p,"0x469fe90","0x46a0259",change);self.reject(p)
 def test_native_error_data_counterfactual(self):
  p=copy.deepcopy(P);r=self.row(p,"0x469fa60")
  ref=next(x for x in r["ripReferences"] if x["site"]=="0x469fc71")
  ref["raw64"]=b"Staking user alr".hex()+ref["raw64"][32:];self.reject(p)
 def test_indirect_finalize_relocation_counterfactual(self):
  p=copy.deepcopy(P);next(x for x in p["relocations"] if x["slot"]=="0x64e7a80")["addend"]="0x469fe91";self.reject(p)
 def test_complete_extent_counterfactual(self):
  p=copy.deepcopy(P);self.row(p,"0x58c07d0")["end"]="0x58c08b9";self.reject(p)
 def test_wrong_target_identity(self):
  p=copy.deepcopy(P);p["targetSha256"]="0"*64;self.reject(p)

if __name__=="__main__":unittest.main(verbosity=2)
