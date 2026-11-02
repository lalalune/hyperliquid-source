"""Packaging of the already reviewed pre-Rust logical cases, not new answers.

Qualified and outside-domain streams stay separate: semantic mutants are only
evaluated on the 341 qualified cases. Own error class has no native tag claim.
"""
from pathlib import Path
import base64, hashlib, json, struct
HERE=Path(__file__).resolve().parent; PRE=HERE.parent
def sha(b):return hashlib.sha256(b).hexdigest()
def inputs(rows):
    out=bytearray(b'ILD1'+struct.pack('<I',len(rows)))
    for r in rows:
        out+=struct.pack('<IIIIBIIqqQB',r['id'],r['custom_id'],r['position_table'],r['mode_word'],int(r['cross']),r['old'],r['requested'],r['size'],r['margin'],r['price'],len(r['tiers']))
        for key,cap in r['tiers']:out+=struct.pack('<QB',key,cap)
    return bytes(out)
def decision(ident,value):
    kind,tag,cap=value
    return struct.pack('<IBHBI',ident,0 if kind=='EnterCommit' else 1,tag or 0,int(cap is not None),cap or 0)
def freeze():
    pre=json.loads((PRE/'PRE-RUST-FREEZE.json').read_text())
    for n,h in pre['files'].items():assert sha((PRE/n).read_bytes())==h,n
    rows=json.loads((PRE/'inputs.json').read_text());expected=json.loads((PRE/'expected.json').read_text())
    policies=[dict(v['input'],id=341+i) for i,v in enumerate(json.loads((PRE/'excluded-domain.json').read_text()))]
    payloads={'qualified-input.bin.b64':inputs(rows),'qualified-expected.bin.b64':b''.join(decision(r['id'],r['value']) for r in expected),'policy-input.bin.b64':inputs(policies),'policy-expected.bin.b64':b''.join(struct.pack('<IBHBI',r['id'],2,0,0,0) for r in policies)}
    records={}
    for n,raw in payloads.items():
        encoded=base64.b64encode(raw)+b'\n';(HERE/n).write_bytes(encoded)
        records[n]={'decoded_sha256':sha(raw),'decoded_bytes':len(raw),'text_sha256':sha(encoded)}
    doc={'semantic_freeze_sha256':sha((PRE/'PRE-RUST-FREEZE.json').read_bytes()),'qualified':341,'policy':9,'qualified_only_mutants':True,'wire_only_packaging_after_Rust_draft':True,'logical_expected_values_unchanged':True,'files':records}
    (HERE/'WIRE-FREEZE.json').write_text(json.dumps(doc,sort_keys=True,indent=2)+'\n')
    print(json.dumps(doc,sort_keys=True))
if __name__=='__main__':freeze()
