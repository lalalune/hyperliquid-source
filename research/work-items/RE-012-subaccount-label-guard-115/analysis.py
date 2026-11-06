#!/usr/bin/env python3
"""Authenticate selected label guard bytes; length examples are static arithmetic."""
from pathlib import Path
import hashlib,json
import collect as c
P=Path(__file__).resolve().parent
SITES=[0x366b361,0x366b365,0x366b369,0x366b36b,0x366b388,0x366b394,
       0x366b39d,0x366b3ad,0x366b3bb,0x366b407,0x366b40d,0x366b414,
       0x366b423,0x366b426,0x366b42b,0x366b446,0x366b456,0x366b45d,
       0x366b478,0x366b481,0x366b48d,0x366b491,0x366b49e,0x366b4a7,
       0x366b4bc,0x366b4c4]
def generate():
 data=(c.ROOT/'artifacts/node/115/hl-node').read_bytes();c.require(hashlib.sha256(data).hexdigest()==c.SHA,'identity mismatch');facts=c.anchors(data);controls=[]
 for at in SITES:
  off,b=c.read(data,at,1);changed=bytearray(data);changed[off]^=1
  try:c.anchors(changed)
  except ValueError:pass
  else:raise ValueError('ineffective structural control '+hex(at))
  controls.append({'va':hex(at),'old':b[0],'new':changed[off],'result':'rejected below whole-image digest; not native output comparison'})
 m=(1<<64)-1;values=sorted(set(range(34))|{1<<32,1<<63,m-18,m-17,m-16,m-1,m})
 examples=[{'raw_length':n,'admitted':((n-17)&m)>m-16} for n in values]
 assert all(x['admitted']==(1<=x['raw_length']<=16) for x in examples)
 plan={'native_or_rust_execution':False,'whole_label_model':False,'helper_results_supplied':False,'facts':facts,
       'all_u64_partition_reason':'For n>=17, n-17 is at most MAX-17 and fails strict > MAX-16. n=0 gives MAX-16 equality and fails. For n in1..16 subtraction wraps into MAX-15..MAX and passes.',
       'length_math_illustrations':examples,'normalized_duplicate_rule':'length equality before bcmp; result zero, retained across temporary cleanup, selects tag0xe6',
       'unclosed':['Unicode/transformation semantics','lookup/record production','helper side effects','ownership/lifetimes/types','full subaccount creation']}
 (P/'controls.json').write_text(json.dumps(controls,indent=2)+'\n');(P/'label-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
 print('STATIC PASS',len(controls),'structural controls;',len(examples),'length-math illustrations, not native/helper results')
if __name__=='__main__':generate()
