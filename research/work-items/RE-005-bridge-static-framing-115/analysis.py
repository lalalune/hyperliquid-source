"""Static framing obligations and explicit conditional examples, no target oracle."""
from pathlib import Path
import importlib.util,json,mmap,re
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
spec=importlib.util.spec_from_file_location('bridge_static_collect',P/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
def generate():
 controls=[]
 with (ROOT/'artifacts/node/115/hl-node').open('rb') as f:
  data=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);facts=c.anchors(data)
  for label,at,raw in [('instruction',int(a,16),v) for a,v in c.CONFIG['anchors'].items()]+[('table',a,v) for a,v in c.DATA.items()]:
   off,_=c.read(data,at,len(bytes.fromhex(raw)));changed=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed[off];changed[off]=old^1
    try:c.anchors(changed)
    except ValueError as e:controls.append({'kind':label+' structural rejection, not output change','va':hex(at),'old':old,'new':old^1,'rejected':str(e)})
    else:raise ValueError('unrejected selected mutation')
   finally:changed.close()
  data.close()
 owners={0x47b72c:0x169dcc0,0x47b784:0x169e6d0,0x47b770:0x169e1d0,0x47b754:0x169df80};tables=[]
 for table,owner in owners.items():
  text=(P/f'{owner:x}.objdump.txt').read_text();starts={int(m[1],16) for line in text.splitlines() if (m:=re.match(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s)+',line))};targets=facts['dispatch_targets'][hex(table)];assert all(int(x,16) in starts for x in targets);tables.append({'table':hex(table),'owner':hex(owner),'targets':targets,'all_instruction_starts':True})
 examples=[]
 for seed in [0,1,127,255]:
  raw=bytes((seed+17*i)&255 for i in range(52));examples.append({'input52':raw.hex(),'conditional_word_views':[(bytes(12)+raw[:20]).hex(),raw[20:52].hex()]})
 plan={'native_or_rust_execution':False,'whole_encoding_model':False,'helper_results_supplied':False,'premises':'Stable52byte input and successful ordinary allocator/copy/append/flatten behavior; no native complete trace or outputs supplied. Padding/source types/cleanup stayunknown.','actual':{'raw_tags':[0,1],'length32_normalized_classes':[0,0],'counts':[1,1],'head_each':[32,32],'tail_each':[0,0],'total_accounting':64,'word_buffer_capacity_like':64,'allocation_call_RDI':2048},'tag_byte_counterfactual':{'private_site':'0x4302d4e','old':1,'changed':2,'normalized_second_class':2,'normalized_second_count':2,'second_head':32,'second_tail':64,'pair_total_accounting':128,'executed':False},'dispatch_tables':tables,'conditional_examples':examples}
 (P/'controls.json').write_text(json.dumps(controls,indent=2)+'\n');(P/'framing-plan.json').write_text(json.dumps(plan,indent=2)+'\n');print('STATIC',len(controls),'structural controls;4validated tables;4conditional word-view examples;not a native/Rust oracle')
if __name__=='__main__':generate()
