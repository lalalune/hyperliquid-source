#!/usr/bin/env python3
"""Reproduce boxed I/O-error construction/vtable/lifecycle evidence and attack actual obligations."""
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
 # Redirect an actual first-slot relocation into the supposedly fixed size word.
 writer=next(item for item in record['relocation_writers'] if item['slot']=='0x64c4178')
 altered=bytearray(raw);struct.pack_into('<Q',altered,int(writer['rela_file_offset'],16),0x64c4180)
 try:c.vtable_layout(c.Image(altered))
 except ValueError as error:c.require(str(error)=='unexpected fixed-field relocation','wrong vtable control rejection')
 else:raise ValueError('missed relocation into fixed vtable field')
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
 lsda_truncations=[]
 gcc=next(sec for sec in im.ss if sec['name']=='.gcc_except_table');blob=raw[gcc['offset']:gcc['offset']+gcc['size']]
 for item in record['exception_sites']:
  va=int(item['lsda_va'],16);h=item['parsed_call_site_table']['header'];end=va-gcc['address']+h['call_site_table_offset']+h['call_site_table_length']
  try:c.decode_lsda(blob[:end-1],va,gcc['address'])
  except ValueError:lsda_truncations.append(item['owner'])
  else:raise ValueError('missed call-site table truncation')
 return {'target_sha256':c.SHA,'lsda_truncations_rejected':lsda_truncations,'unexpected_vtable_size_relocation_rejected':True,'retained_records_equal':True,'instruction_data_corruptions_rejected':rejected,'relocation_addend_corruptions_rejected':binding_rejected,'import_writer_mutations_rejected':import_rejected,'identity_controls_rejected':2,'full_fdes':len(record['owners']),'exported_bytes':sum(o['length'] for o in record['owners']),'exported_instructions':sum(o['instructions'] for o in record['owners']),'captured_code_executed_or_emulated':False,'rust_implementation_or_native_runtime_equivalence_claimed':False}
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--out',type=Path,required=True);o=a.parse_args().out;c.require(not o.exists(),'output must be fresh');r=verify();o.write_text(c.dump(r));print(c.dump(r))
