#!/usr/bin/env python3
"""Operand-derived local relations; no target execution or instruction emulation."""
import argparse
import struct
import verify

def u(im,a,n=1):
    return int.from_bytes(im.get(a,n),'little')

def s(im,a,n):
    return im.get(a,n).decode('ascii')

def changed_relation(data,va,new,fn):
    image=verify.Image(data)
    altered=bytearray(data);altered[image.off(va)]=new
    before,after=fn(data),fn(altered)
    verify.require(before!=after,'surviving relation counterfactual')
    return {'va':hex(va),'new_byte':new,'original':verify.json.loads(verify.encoded(before)),'mutated':verify.json.loads(verify.encoded(after))}



def operands(data):
 im=verify.Image(data)
 return {'peers_compare_immediate':u(im,0x5a80385),'open_brace':u(im,0x5a803d9),'quote':u(im,0x5a803f1),'colon':u(im,0x5a80440),'inner_open_brace':u(im,0x5a80458),'close_brace':u(im,0x5a804ea),'field_tag':u(im,0x5a80465,2),'client_blocks':s(im,0x93b87d,12),'start_round':s(im,0x93b889,11),'end_round':s(im,0x93b894,9),'peers':s(im,0x93b89d,5),'gossip_status':s(im,0x93b8a2,12)}
def project(discriminant,o):
 if discriminant==0:
  return [chr(o['open_brace']),chr(o['quote']),o['client_blocks'],chr(o['quote']),chr(o['colon']),chr(o['inner_open_brace']),'field:'+o['start_round'],'field:'+o['end_round'],chr(o['close_brace']),chr(o['close_brace'])]
 if (discriminant&0xffffffff)==o['peers_compare_immediate']:
  return [chr(o['quote']),o['peers'],chr(o['quote'])]
 return [chr(o['quote']),o['gossip_status'],chr(o['quote'])]
def evaluate(data):
 o=operands(data);verify.require(o=={'peers_compare_immediate':1,'open_brace':0x7b,'quote':0x22,'colon':0x3a,'inner_open_brace':0x7b,'close_brace':0x7d,'field_tag':0x100,'client_blocks':'ClientBlocks','start_round':'start_round','end_round':'end_round','peers':'Peers','gossip_status':'GossipStatus'},'writer operands');n=0
 for d in [0,1,2,3,255,0xffffffff,0x80000000,0x100000000,0xffffffffffffffff]:
  if d==0:
   want=['{','"','ClientBlocks','"',':','{','field:start_round','field:end_round','}','}']
  elif (d&0xffffffff)==1:
   want=['"','Peers','"']
  else:
   want=['"','GossipStatus','"']
  verify.require(project(d,o)==want,'variant projection');n+=1
 controls=[changed_relation(data,0x5a80385,0x02,lambda d:project(1,operands(d))),changed_relation(data,0x5a803d9,0x7c,lambda d:project(0,operands(d))),changed_relation(data,0x5a80440,0x3b,lambda d:project(0,operands(d))),changed_relation(data,0x93b89d,0x51,lambda d:project(1,operands(d)))]
 return {'native_operands':o,'projection_cases':n,'counterfactuals':controls,'limits':'The discriminant is the eight-byte value at input+0x0: the zero test is 64-bit while the Peers comparison reads the low 32 bits. Only the emitted token skeleton is projected; field values, helper bodies 0x50783d0/0x50a3510/0x5963a10, buffer growth and any source-level type name remain unresolved. No network or target execution.'}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target')
    result=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(result)
    else:verify.require((verify.PACKET/'relations.json').read_text()==result,'relations drift')
    print('PASS: native operand relations and counterfactuals')
