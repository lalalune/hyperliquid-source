"""Static operand controls and explicitly local mathematical illustrations.

No helper result is supplied to an emulator or used as a complete-call oracle.
"""
from pathlib import Path
import importlib.util,json,mmap
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
spec=importlib.util.spec_from_file_location('limiter_static_collect',P/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
def generate():
 with (ROOT/'artifacts/node/115/hl-node').open('rb') as f:
  data=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);facts=c.anchors(data);controls=[]
  for address,raw in c.CONFIG['anchors'].items():
   at=int(address,16);off,_=c.read(data,at,len(bytes.fromhex(raw)));changed=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed[off];changed[off]=old^1
    try:c.anchors(changed)
    except ValueError as e:controls.append({'va':address,'old':old,'changed':old^1,'rejected':str(e),'kind':'exact decoded-group structural rejection, not output change'})
    else:raise ValueError('unrejected local byte corruption '+address)
   finally:changed.close()
  for at,raw in c.DATA.items():
   off,_=c.read(data,at,16);changed=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed[off];changed[off]=old^1
    try:c.anchors(changed)
    except ValueError as e:controls.append({'va':hex(at),'old':old,'changed':old^1,'rejected':str(e),'kind':'selected readonly data structural rejection, not output change'})
    else:raise ValueError('unrejected selected data corruption')
   finally:changed.close()
  data.close()
 maximum=(1<<64)-1;minimum=facts['raw_charge_minimum'];factor=facts['budget_wrapping_factor']
 values=[0,1,2,10000,1000000,maximum//factor,maximum//factor+1,1<<63,maximum]
 budgets=[{'budget':b,'wrapped10':(b*factor)&maximum,'unbounded_product':b*factor} for b in values]
 charges=[{'raw':a,'charge':max(minimum,a)} for a in [0,1,2,maximum-1,maximum]]
 additions=[{'old':old,'raw':a,'result':min(maximum,old+max(minimum,a))} for old in [0,1,maximum-1,maximum] for a in [0,1,2,maximum]]
 increments=[{'old':old,'result':min(maximum,old+1)} for old in [0,1,maximum-1,maximum]]
 final_compare=[];secondary=[]
 for threshold in sorted({x['wrapped10'] for x in budgets}):
  for charge in sorted({0,threshold,max(0,threshold-1),min(maximum,threshold+1),maximum}):
   final_compare.append({'budget10':threshold,'charge':charge,'strictly_over':charge>threshold})
   for multiplier in [0,1,2,maximum]:
    product=threshold*multiplier;overflow=product>maximum
    secondary.append({'budget10':threshold,'factor':multiplier,'charge':charge,'overflow':overflow,'secondary_call_local':not overflow and charge>(product&maximum)})
 relations={'native_or_rust_execution':False,'whole_function_model':False,'premise':'Only isolated decoded scalar arithmetic; no clock/hash/callback/lock/container/alias effects or complete caller outcomes supplied. Later charge is a fresh reload, not assumed equal to an earlier value.','charges':charges,'budgets':budgets,'saturating_additions':additions,'saturating_increments':increments,'final_compare':final_compare,'secondary_compare':secondary}
 (P/'controls.json').write_text(json.dumps(controls,indent=2)+'\n');(P/'relations.json').write_text(json.dumps(relations,indent=2)+'\n');print('STATIC CONTROLS',len(controls),'local scalar rows',sum(len(v) for v in relations.values() if isinstance(v,list)))
if __name__=='__main__':generate()
