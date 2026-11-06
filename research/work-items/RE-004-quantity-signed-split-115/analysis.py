#!/usr/bin/env python3
"""Static instruction obligations and illustrative local arithmetic, not execution."""
from pathlib import Path
import hashlib,json
import collect as c
P=Path(__file__).resolve().parent
SITES=[0x3f10c25,0x3f10c2e,0x3f10c45,0x3f10c52,0x3f10cb1,
       0x3f10cc6,0x3f10d06,0x3f10d10,0x3f10d33,0x3f10d43,
       0x3f10d51,0x3f10d5f,0x3f10d70,0x3f10d92,0x3f10db3,
       0x3f10dc3,0x3f10dc8,0x3f10dd1,0x3f10dd4,0x3f10de3,
       0x3f10deb,0x3f10df3,0x3f10dfc,0x3f10e19,0x3f10e23,0x3f10e80]
def scalar_view(value,old):
 """Illustrates only arithmetic between opaque helper boundaries."""
 if value==0:return {'path':'zero-no-entry-helper'}
 if value<0:return {'path':'negative-insertion-request','magnitude':min(-value,(1<<63)-1)}
 scaled=value*100
 if scaled>=(1<<64):return {'path':'positive-scale-overflow-no-entry-helper'}
 return {'path':'positive-entry-request','product':scaled,'old_supplied_for_illustration':old,
         'carry':old+scaled>=(1<<64),'conditional_saved_operands_store':min(old+scaled,(1<<64)-1)}
def generate():
 data=(c.ROOT/'artifacts/node/115/hl-node').read_bytes()
 c.require(hashlib.sha256(data).hexdigest()==c.SHA,'identity mismatch')
 facts=c.anchors(data);controls=[]
 for at in SITES:
  off,b=c.read(data,at,1);mutant=bytearray(data);mutant[off]^=1
  try:c.anchors(mutant)
  except ValueError:pass
  else:raise ValueError('ineffective structural control '+hex(at))
  controls.append({'va':hex(at),'old':b[0],'new':mutant[off],
                   'result':'rejected below whole-image digest check; not a native output comparison'})
 threshold=((1<<64)-1)//100
 values=[-(1<<63),-(1<<63)+1,-100,-1,0,1,100,threshold,threshold+1,(1<<63)-1]
 olds=[0,1,(1<<64)-101,(1<<64)-100,(1<<64)-1]
 plan={'native_or_rust_execution':False,'whole_transform_model':False,'helper_results_supplied':False,
       'facts':facts,'positive_scale_unsigned_threshold':threshold,
       'negative_helper':'0x3cde300','positive_entry_helpers':['0x3cd0da0','0x3f14f20'],
       'opaque_iterator':'0x37c3750','diagnostic_slot':'0x64e4ea8','diagnostic_location':'0x6487460',
       'carry_store_basis':'saved R12 old value and R14 product, not a reload after diagnostic',
       'unclosed':['entry creation/default','duplicate-key policy','tree iterator','drop/unwind','source ownership/units'],
       'local_math_illustrations':[{'value':v,'old':o,'view':scalar_view(v,o)} for v in values for o in olds]}
 (P/'controls.json').write_text(json.dumps(controls,indent=2)+'\n')
 (P/'split-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
 print('STATIC PASS',len(controls),'real-byte structural controls;50local arithmetic illustrations, not native vectors')
if __name__=='__main__':generate()
