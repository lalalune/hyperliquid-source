"""Static corruption controls and symbolic call/branch obligations, no oracle."""
from pathlib import Path
import importlib.util,json,mmap
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
spec=importlib.util.spec_from_file_location('floor_policy_collect',P/'collect.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
def generate():
 controls=[]
 with (ROOT/'artifacts/node/115/hl-node').open('rb') as f:
  data=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);c.anchors(data)
  for label,at,raw in [('instructions',int(a,16),v) for a,v in c.CONFIG['anchors'].items()]+[('readonly',a,v) for a,v in c.DATA.items()]:
   off,_=c.read(data,at,len(bytes.fromhex(raw)));changed=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY)
   try:
    old=changed[off];changed[off]=old^1
    try:c.anchors(changed)
    except ValueError as e:controls.append({'kind':label+' structural rejection, not output change','va':hex(at),'old':old,'new':old^1,'rejected':str(e)})
    else:raise ValueError('unrejected selected mutation '+hex(at))
   finally:changed.close()
  data.close()
 calls=[(0x36a5a08,'w','0.2',0x36a5a22),(0x36a5a42,'w','6',0x36a5a5c),(0x36a5a78,'w','0.1',0x36a5a92),(0x36a5ab2,'w','2',0x36a5acc),(0x36a5b28,'w','40',0x36a5c18),(0x36a5b45,'x','0.2',0x36a5bf8),(0x36a5b62,'x','6',0x36a5bec),(0x36a5b7f,'x','0.1',0x36a5be0),(0x36a5b9c,'x','2',0x36a5bd4),(0x36a5bb9,'x','40',0x36a5bca)]
 plan={'native_or_rust_execution':False,'helper_results_supplied':False,'whole_function_model':False,'calls':[{'site':hex(a),'inputs':[value,coefficient,'previously rounded B*'+coefficient],'result':'opaqueM'+str(i),'comparison_site':hex(compare)} for i,(a,value,coefficient,compare) in enumerate(calls)],'sum_checks':[{'site':'0x36a59d8','input':'B+w'},{'site':'0x36a5c0e','input':'B+x'}],'late_gate':{'call':'0x36a5cb2','head_qword_equal':2,'result_if_equal':'local AL1 assuming normal returns','other':'local AL0 after conditional cleanup'},'limits':'Symbolic local dataflow only; no concrete math, validator, CPU feature or callback return is supplied.'}
 flags=[('value<epsilon',0,0,0),('value==epsilon',0,1,0),('value>epsilon',1,0,0),('unordered',1,1,1)]
 plan['ucomisd_epsilon_value']=[{'relation':label,'CF':cf,'ZF':zf,'PF':pf,'JA':not cf and not zf,'JBE':bool(cf or zf)} for label,cf,zf,pf in flags]
 (P/'controls.json').write_text(json.dumps(controls,indent=2)+'\n');(P/'symbolic-plan.json').write_text(json.dumps(plan,indent=2)+'\n');print('STATIC',len(controls),'structuralcontrols;10opaque symbolic calls/2sumchecks/4flagrows;no execution/answers')
if __name__=='__main__':generate()
