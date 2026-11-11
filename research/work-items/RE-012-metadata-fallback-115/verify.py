#!/usr/bin/env python3
"""Reproduce metadata capability/projection evidence and attack actual obligations."""
import argparse,json,struct
from pathlib import Path
import collect as c

def binding_check(im):
 sec=next(s for s in im.ss if s['name']=='.rela.dyn')
 c.require(sec['size']%24==0,'bad rela size')
 seen={}
 for o in range(sec['offset'],sec['offset']+sec['size'],24):
  a,i,t=struct.unpack_from('<QQq',im.b,o)
  if a in c.BINDINGS:
   c.require(a not in seen,'duplicate binding');seen[a]=(i,t)
 for a,t in c.BINDINGS.items():c.require(seen.get(a)==(8,t),'changed binding: '+hex(a))

def verify():
 raw=c.TARGET.read_bytes();im=c.Image(raw);record,_=c.collect(raw)
 c.require(record==json.loads((c.PACKET/'records.json').read_text()),'retained record differs')
 scope=c.obligations(im);rejected=[]
 for pin in scope['pins']+scope['data_pins']:
  a=int(pin['va'],16);n=len(bytes.fromhex(pin['bytes']));b=bytearray(raw);b[im.offset(a,n)+n-1]^=1
  try:c.obligations(c.Image(b),only=pin['name'])
  except ValueError as e:c.require(str(e)=='changed obligation: '+pin['name'],'wrong narrow rejection');rejected.append(pin['name'])
  else:raise ValueError('missed instruction/data corruption')
 binding_check(im);binding_rejected=[]
 for r in record['relocation_writers']:
  a=int(r['slot'],16)
  if a not in c.BINDINGS:continue
  b=bytearray(raw);b[int(r['rela_file_offset'],16)+16]^=1
  try:binding_check(c.Image(b))
  except ValueError as e:c.require(str(e)=='changed binding: '+hex(a),'wrong binding rejection');binding_rejected.append(hex(a))
  else:raise ValueError('missed relocation corruption')
 import_rejected=[]
 for r in record['imports']:
  b=bytearray(raw);b[int(r['rela_file_offset'],16)+8]^=1
  try:c.imports(c.Image(b))
  except ValueError:import_rejected.append(r['name'])
  else:raise ValueError('missed imported writer mutation')
 for b in [raw[:-1],bytes([raw[0]^1])+raw[1:]]:
  try:c.collect(b)
  except ValueError as e:c.require(str(e)=='wrong capture','wrong identity rejection')
  else:raise ValueError('missed identity control')
 # Bit-placement proof for observed 32+32-bit device packing, not target execution.
 low_major_mask=int.from_bytes(im.read(0x5c9f860,4),'little')
 high_major_mask=int.from_bytes(im.read(0x5c9f866,4),'little')
 high_minor_mask=int.from_bytes(im.read(0x5c9f87d,4),'little',signed=True)&(2**64-1)
 c.require((low_major_mask,high_major_mask,high_minor_mask)==(0xfff00,0xfffff000,0xfffffffffff00000),'device masks')
 values=[0,2**32-1]+[1<<i for i in range(32)];device_checks=0
 for major in values:
  for minor in values:
   relation=((major<<8)&low_major_mask)|((major&high_major_mask)<<32)|(minor&255)|((minor<<12)&high_minor_mask)
   independent=sum(((major>>i)&1)<<(i+8 if i<12 else i+32) for i in range(32))
   independent|=sum(((minor>>i)&1)<<(i if i<8 else i+12) for i in range(32))
   c.require(relation==independent,'device bit placement');device_checks+=1
 return {'target_sha256':c.SHA,'device_bit_placement_checks':device_checks,'retained_records_equal':True,'instruction_data_corruptions_rejected':rejected,'relocation_addend_corruptions_rejected':binding_rejected,'import_writer_mutations_rejected':import_rejected,'identity_controls_rejected':2,'full_fdes':len(record['owners']),'exported_bytes':sum(o['length'] for o in record['owners']),'exported_instructions':sum(o['instructions'] for o in record['owners']),'captured_code_executed_or_emulated':False,'rust_implementation_or_native_runtime_equivalence_claimed':False}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--out',type=Path,required=True);o=a.parse_args().out;c.require(not o.exists(),'output must be fresh');r=verify();o.write_text(c.dump(r));print(c.dump(r))
