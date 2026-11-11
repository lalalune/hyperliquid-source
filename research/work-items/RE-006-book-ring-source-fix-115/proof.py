"""Retain target-backed before/after attribution, snapshots and actual COW controls."""
import argparse,hashlib,json,mmap
from collections import Counter
from pathlib import Path
import native
import book_ring_append_static as book
def collect(out):
 if out.exists():raise ValueError('new output required')
 im=native.Image()
 try:
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('wrong115target')
  inputs,expected,seen=native.corpus(im);owners=[]
  for base in native.BASES:
   if im.view.fde(base)!=(base,base+663):raise ValueError('wrong containing FDE')
   raw=im.view.read(base,663)
   owners.append(dict(start=hex(base),bytes=663,sha256=hashlib.sha256(raw).hexdigest(),origin=book.element0_origin(raw,base)))
  controls=[]
  specs=[('grow-gate',0x1fb,0x74),('record-word',0x234,0x34),('length-step',0x215,2),('element-stride',0x231,4),('payload-offset',0x243,0x10),('dword-offset',0x239,9)]
  for alias,base in enumerate(native.BASES):
   for name,offset,byte in specs:
    changed=native.Image();changed.data=mmap.mmap(changed.view.file.fileno(),0,access=mmap.ACCESS_COPY)
    try:
     address=base+offset;changed.data[changed.view.offset(address)]=byte;row=(alias,2,1,0,17,900)
     before=native.evaluate(im,row)[0];after=native.evaluate(changed,row)[0]
     if before==after:raise ValueError('ineffective ring control '+name)
     controls.append(dict(name=name,alias=alias,va=hex(address),original_byte=im.view.read(address,1).hex(),changed_byte=hex(byte),input=row,original=before,changed=after))
    finally:changed.close()
  # Reuse the preserved pre-change declaration, not an invented old implementation.
  current=json.loads((native.ROOT/'research/work-items/RE-006-node115-book-ring-append/records.json').read_text())
  observed=native.check_declared_source(current)
  old=json.loads(json.dumps(current));old['trace']['append']['element_fields'][0]['source']='the qword cached at level +0x28'
  try:native.check_declared_source(old)
  except ValueError as error:old_rejected=str(error)
  else:raise ValueError('old attribution was not distinguished')
  if hashlib.sha256(im.data).hexdigest()!=native.SHA:raise ValueError('capture modified')
  report=dict(target_sha256=native.SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',rows=len(expected.splitlines()),outcomes=dict(Counter(x.split(b':')[0].decode() for x in expected.splitlines())),input_sha256=hashlib.sha256(inputs).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),owners=owners,visited_addresses=sorted(seen),counterexamples=observed,old_declaration_rejected=old_rejected,captured_process_executed=False,qualification='fresh post-callback ring-tail points, actual RET/RSP; no callback or grow execution, return assumption or whole insert trace')
  out.mkdir(parents=True);(out/'inputs.tsv').write_bytes(inputs);(out/'expected.tsv').write_bytes(expected)
  (native.PACKET/'proof.json').write_text(json.dumps(report,indent=2)+'\n');(native.PACKET/'native-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
  print('PROOF PASS',report['rows'],report['outcomes'],'actual COW controls',len(controls),'selected starts',len(seen))
 finally:im.close()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();collect(a.output.resolve())
