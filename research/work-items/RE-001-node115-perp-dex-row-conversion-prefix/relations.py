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
 return {'source_stride':u(im,0x294b973,4),'output_stride':u(im,0x294b956,4),'index_branch':u(im,0x294b9a1),'registry_shift':u(im,0x294b9c8),'registry_inner':u(im,0x294b9d0)}
def project(old,completed,index,limit,sentinel,o):
 rejected=(index>=limit if o['index_branch']==0x73 else index>limit) and not sentinel
 return {'length':old+completed,'next_source':completed*o['source_stride'],'next_output':(old+completed)*o['output_stride'],'path':'sentinel' if sentinel else 'fatal' if rejected else 'convert','registry_offset':None if sentinel or rejected else (index<<o['registry_shift'])+o['registry_inner']}
def evaluate(data):
 o=operands(data);verify.require(o=={'source_stride':0x510,'output_stride':0x110,'index_branch':0x73,'registry_shift':9,'registry_inner':0x18},'collector operands');n=0
 for old,count,index,limit,sentinel in itertools.product([0,1,4],[0,1,3],[0,1,2,(1<<64)-1],[0,1,2],[0,1]):
  r=project(old,count,index,limit,sentinel,o);want='sentinel' if sentinel else 'fatal' if index>=limit else 'convert'
  verify.require(r['path']==want and r['length']==old+count and r['next_source']==count*1296 and r['next_output']==(old+count)*272,'prefix indexing');n+=1
 controls=[changed_relation(data,0x294b973,0x11,lambda d:project(0,1,0,1,0,operands(d))),changed_relation(data,0x294b956,0x18,lambda d:project(1,1,0,1,0,operands(d))),changed_relation(data,0x294b9a1,0x77,lambda d:project(0,0,1,1,0,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'Safe complete input rows and adequate output allocation supplied. Completed count advances after the native copy. No meaning is assigned to sentinel-row trailing bytes or the opaque converter output. Normal/unwind publication is preserved in native obligations; no exception engine is simulated.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
