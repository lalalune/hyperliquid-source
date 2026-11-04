#!/usr/bin/env python3
"""Operand-derived local relations; no target execution or instruction emulation."""
import argparse
import itertools
import struct
import verify

def u(im,a,n=1):
    return int.from_bytes(im.get(a,n),'little')

def changed_relation(data,va,new,fn):
    image=verify.Image(data)
    altered=bytearray(data);altered[image.off(va)]=new
    before,after=fn(data),fn(altered)
    verify.require(before!=after,'surviving relation counterfactual')
    return {'va':hex(va),'new_byte':new,'original':verify.json.loads(verify.encoded(before)),'mutated':verify.json.loads(verify.encoded(after))}

def operands(data):
 im=verify.Image(data)
 return [{'clear_budget':u(im,a),'suspended':u(im,b),'exit_required':u(im,c),'skip_restore':u(im,d)} for a,b,c,d in [(0x4e46442,0x4e46464,0x4e464c3,0x4e46504),(0x4e471fd,0x4e4721c,0x4e4727b,0x4e472bc)]]
def project(mode,preflight_error,enter,tls,old_executor,after_executor,after_tls,o):
 if mode==0:return ['core']
 if preflight_error:return ['preflight-fatal']
 if not enter:return ['core']
 if tls==2:return ['tls-unavailable-fatal']
 trace=['budget-enabled='+str(o['clear_budget'])]
 if old_executor==2:return trace+['already-suspended-fatal']
 trace+=['executor='+str(o['suspended']),'core']
 if after_executor!=o['exit_required']:return trace+['executor-changed-fatal']
 trace+=['restore-executor='+str(old_executor)]
 if after_tls!=2 and old_executor!=o['skip_restore']:trace+=['call-budget-restore-with-saved-word']
 return trace
def evaluate(data):
 ops=operands(data);verify.require(ops==[{'clear_budget':0,'suspended':2,'exit_required':2,'skip_restore':2}]*2,'paired adapter operands');count=0;examples=[]
 for mode,error,enter,tls,old,after,after_tls in itertools.product([0,1],[0,1],[0,1],[0,1,2],[0,1,2],[0,1,2],[0,1,2]):
  a,b=[project(mode,error,enter,tls,old,after,after_tls,o) for o in ops];verify.require(a==b,'paired suspension policy');count+=1
  if mode==0 or not error and not enter:verify.require(a==['core'],'bypass')
  if mode and not error and enter and tls!=2 and old!=2 and after==2:
   verify.require(a[:3]==['budget-enabled=0','executor=2','core'],'suspend before core')
   verify.require(('call-budget-restore-with-saved-word' in a)==(after_tls!=2),'restore gate')
 for old,after,tls in itertools.product(range(3),range(3),[1,2]):examples.append({'old_executor':old,'after_executor':after,'after_tls':tls,'trace':project(1,0,1,1,old,after,tls,ops[0])})
 controls=[changed_relation(data,0x4e46464,1,lambda d:project(1,0,1,1,1,2,1,operands(d)[0])),changed_relation(data,0x4e464c3,1,lambda d:project(1,0,1,1,1,2,1,operands(d)[0])),changed_relation(data,0x4e472bc,1,lambda d:project(1,0,1,1,1,2,1,operands(d)[1]))]
 return {'native_operands':ops,'paired_cases':count,'examples':examples,'counterfactuals':controls,'limits':'Preflight output and TLS/helper availability supplied; normal returning core. Models visible executor bytes and restore-helper invocation, not scheduler, lock correctness or actual restored budget. Full unwind context retained but not emulated.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
