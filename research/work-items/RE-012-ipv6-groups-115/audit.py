"""Recheck real helper/caller arguments and explicitly unexecuted imports."""
import hashlib,json,struct,capstone
import native

def audit():
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;record=json.loads((native.PACKET/'FREEZE.json').read_text());owners=[];by={}
  _,off,n=im.view.sections['.rela.dyn'];relocations={}
  for at in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',im.data,at)
   if slot in relocations:raise ValueError('duplicate relocation slot')
   relocations[slot]=(kind&0xffffffff,kind>>32,add)
  _,symoff,_=im.view.sections['.dynsym'];_,strings,_=im.view.sections['.dynstr']
  for item in record['owners']:
   lo,hi=int(item['start'],16),int(item['end'],16);raw=im.view.read(lo,hi-lo);rows=list(cs.disasm(raw,lo));by.update({x.address:x for x in rows})
   if hashlib.sha256(raw).hexdigest()!=item['sha256'] or im.view.fde(lo)!=(lo,hi):raise ValueError('owner changed')
   calls=[]
   for row in rows:
    if row.mnemonic!='call':continue
    entry=dict(site=hex(row.address),raw_hex=row.bytes.hex(),operand=row.op_str)
    if row.op_str.startswith('0x'):
     dest=int(row.op_str,16);entry.update(target=hex(dest),interpreted=(row.address,dest) in {(0x16860b9,0x167ccb0),(0x16861a6,0x167ccb0),(0x1686112,0x167c8b0),(0x168620e,0x167c8b0)})
    elif row.bytes[:2]==b'\xff\x15':
     slot=row.address+row.size+struct.unpack_from('<i',row.bytes,2)[0];kind,symbol,add=relocations[slot];entry.update(slot=hex(slot),relocation_type=kind,interpreted=False)
     if kind==8:entry['relative_addend']=hex(add)
     else:
      start=struct.unpack_from('<I',im.data,symoff+24*symbol)[0]+strings;end=im.data.find(b'\x00',start);entry['symbol']=im.data[start:end].decode()
    calls.append(entry)
   owners.append(dict(start=hex(lo),end=hex(hi),calls=calls,unvisited_addresses=[hex(x.address) for x in rows if x.address not in set(record['visited_addresses'])]))
  if by[0x167d0b9].bytes.hex()!='ba08000000' or by[0x167d13d].bytes.hex()!='ba07000000' or by[0x167d142].bytes.hex()!='4829c2' or by[0x167d145].bytes.hex()!='4883fa08' or by[0x167d149].mnemonic!='jae':raise ValueError('caller capacity contract changed')
  for site in (0x167d0c1,0x167d152):
   if by[site].mnemonic!='call' or int(by[site].op_str,16)!=native.START:raise ValueError('caller changed')
  for site,raw in [(0x16860f0,'48c745c001000000'),(0x16860f8,'48c745c804000000'),(0x1686100,'c745d010000000'),(0x1686107,'c645d401'),(0x16861ec,'48c745c001000000'),(0x16861f4,'48c745c804000000'),(0x16861fc,'c745d010000000'),(0x1686203,'c645d401')]:
   if by[site].bytes.hex()!=raw:raise ValueError('actual numeric configuration changed')
  memcpy=[c for owner in owners for c in owner['calls'] if c.get('symbol')=='memcpy']
  if len(memcpy)!=1 or memcpy[0]['site']!='0x167d17c':raise ValueError('wrapper copy import changed')
  locations=[]
  for site in (0x167d19e,0x167d1b5,0x167d1ce):
   row=by[site];va=row.address+row.size+row.operands[1].mem.disp;kind,_,add=relocations[va];size,line,column=struct.unpack('<QII',im.view.read(va+8,16))
   if kind!=8 or not 0<size<256:raise ValueError('invalid source context')
   locations.append(dict(site=hex(site),location=hex(va),path=im.view.read(add,size).decode(),line=line,column=column,scope='unexecuted wrapper bounds context, not source identity proof'))
  result=dict(target_sha256=native.SHA,owners=owners,caller_capacities='first8,second7-count guarded unsignedbelow8',numeric_configuration='bounded tag1,max4,radix16,zero-prefixflag1; other configurations unclosed',source_context=locations,no_import_stub=True,captured_process_executed=False,whole_compression_wrapper_closed=False)
  (native.PACKET/'audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
 finally:im.close()
if __name__=='__main__':audit()
