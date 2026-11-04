"""Static context: actual callers, unclosed helpers and owner attribution data."""
import hashlib,json,struct
from pathlib import Path
import native,capstone

def audit():
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  record=json.loads((native.PACKET/'FREEZE.json').read_text());cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
  _,off,n=im.view.sections['.rela.dyn'];rels={}
  for pos in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',im.data,pos)
   if kind&0xffffffff==8:
    if slot in rels:raise ValueError('duplicate RELATIVE slot')
    rels[slot]=add
  owners=[]
  for index,((lo,hi,start,end,_,_),frozen) in enumerate(zip(native.SPECS,record['owners'])):
   raw=im.view.read(lo,hi-lo);rows=list(cs.disasm(raw,lo));selected=[x for x in rows if start<=x.address<end];calls=[]
   if hashlib.sha256(raw).hexdigest()!=frozen['sha256']:raise ValueError('owner changed')
   if any(x.mnemonic=='call' for x in selected):raise ValueError('selected helper call')
   for x in rows:
    if x.mnemonic=='call':
     item=dict(site=hex(x.address),raw_hex=x.bytes.hex(),operand=x.op_str,closed=False)
     if x.op_str.startswith('0x'):item['target']=x.op_str
     elif x.bytes[:2]==b'\xff\x15':
      slot=x.address+x.size+struct.unpack_from('<i',x.bytes,2)[0];item['slot']=hex(slot);item['relative_addend']=hex(rels[slot]) if slot in rels else None
     calls.append(item)
   owners.append(dict(owner=index,start=hex(lo),end=hex(hi),selected_no_calls_or_writes=True,unclosed_context_calls=calls))
  label=next(x for x in cs.disasm(im.view.read(0x4230841,7),0x4230841));target=label.address+label.size+label.operands[1].mem.disp
  if target!=0x7bac52 or im.view.read(target,19)!=b'gas_auction_restart' or im.view.read(0x423084d,9).hex()!='48c744241013000000':raise ValueError('restart label/length changed')
  location=0x64768d8;path=rels[location];size,line,column=struct.unpack('<QII',im.view.read(location+8,16));source=im.view.read(path,size).decode()
  if (source,line,column)!=('l1/src/spot_meta.rs',119,33):raise ValueError('source Location changed')
  callers=[]
  for site,dest in [(0x2be6219,0x3673a10),(0x54b0b6f,0x3673a10),(0x54bd189,0x3673a10),(0x3d72e30,0x42306f0)]:
   row=next(cs.disasm(im.view.read(site,5),site));lo,hi=im.view.fde(site)
   if row.mnemonic!='call' or row.size!=5 or int(row.op_str,16)!=dest:raise ValueError('caller edge changed')
   callers.append(dict(site=hex(site),raw_hex=row.bytes.hex(),target=hex(dest),context_fde=[hex(lo),hex(hi)],whole_caller_closed=False))
  report=dict(target_sha256=native.SHA,owners=owners,callers=callers,label=dict(site='0x4230841',va=hex(target),data_hex=im.view.read(target,19).hex(),length=19),source_location_context=dict(va=hex(location),path=source,line=line,column=column,scope='bounds-failure context, not original conversion source identity'),source_identity_and_ABI_unclosed=True,captured_process_executed=False)
  (native.PACKET/'audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
 finally:im.close()
if __name__=='__main__':audit()
