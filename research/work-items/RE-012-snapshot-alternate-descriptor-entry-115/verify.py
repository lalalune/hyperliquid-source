#!/usr/bin/env python3
"""RE-001: RE-012: map node #115 snapshot alternate descriptor intake"""
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
 raw=c.TARGET.read_bytes();im=c.Image(raw);record,exports=c.collect(raw,True)
 for name,text in exports.items():c.require(text==(c.PACKET/name).read_text(),'native export differs '+name)
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
 return {'target_sha256':c.SHA,'retained_records_equal':True,'instruction_corruptions_rejected':rejected,'relocation_addend_corruptions_rejected':binding_rejected,'import_writer_mutations_rejected':import_rejected,'identity_controls_rejected':2,'full_fdes':len(record['owners']),'exported_bytes':sum(o['length'] for o in record['owners']),'exported_instructions':sum(o['instructions'] for o in record['owners']),'captured_code_executed_or_emulated':False}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--out',type=Path,required=True);o=a.parse_args().out;c.require(not o.exists(),'output must be fresh');r=verify();o.write_text(c.dump(r));print(c.dump(r))
