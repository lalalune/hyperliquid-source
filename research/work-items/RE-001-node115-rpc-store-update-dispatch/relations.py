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
    return {'pending':u(im,0x4fafac2),'terminal':u(im,0x4fafb02),'first_store_tag':u(im,0x4fafcab),
            'stats_skip':u(im,0x4fafbbd),'limits':[u(im,0x4faf5b6,4),u(im,0x4faf693,4)],
            'flags':[u(im,0x4faf5c1),u(im,0x4faf682)],'channel_argument':u(im,0x4faf732,4),
            'worker_delay_bits':u(im,0x4faf7b6,8),'descriptor_bytes':u(im,0x649fa70,8),'descriptor_alignment':u(im,0x649fa78,8)}

def project(tag,stats,op):
    if tag==op['pending']:return {'return':1,'state':3,'events':[]}
    if tag==op['terminal']:return {'return':0,'state':1,'events':['cleanup']}
    report=bool(stats) if op['stats_skip']==0x84 else not bool(stats)
    events=['stats reads','stats report'] if report else []
    events+=['store A' if tag==op['first_store_tag'] else 'store B','next poll']
    return {'return':None,'state':None,'events':events}

def evaluate(data):
    op=operands(data)
    verify.require(op=={'pending':3,'terminal':2,'first_store_tag':1,'stats_skip':0x84,'limits':[100000,100000],'flags':[1,0],'channel_argument':5000,'worker_delay_bits':0x404e000000000000,'descriptor_bytes':136,'descriptor_alignment':8},'RPC operands')
    cases=[]
    for tag,stats in itertools.product(range(4),range(256)):
        actual=project(tag,stats,op)
        if tag==3:expected={'return':1,'state':3,'events':[]}
        elif tag==2:expected={'return':0,'state':1,'events':['cleanup']}
        else:expected={'return':None,'state':None,'events':(['stats reads','stats report'] if stats else [])+['store A' if tag==1 else 'store B','next poll']}
        verify.require(actual==expected,'RPC dispatch')
        if stats in (0,1,255):cases.append({'tag':tag,'stats_result':stats,**actual})
    controls=[changed_relation(data,0x4fafac2,2,lambda d:project(3,1,operands(d))),
              changed_relation(data,0x4fafcab,0,lambda d:project(1,1,operands(d))),
              changed_relation(data,0x4fafbbd,0x85,lambda d:project(0,0,operands(d)))]
    return {'native_operands':op,'projection_cases':1024,'examples':cases,'counterfactuals':controls,'limits':'Valid worker state and supplied poll/timing results; helper calls normally return. Constructor fields are raw initialized inputs, not a proved cache capacity or eviction policy. No queue execution, timing guarantee or target emulation.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
