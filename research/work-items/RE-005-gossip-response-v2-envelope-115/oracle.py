#!/usr/bin/env python3
"""Frozen scalar relation for selected response-v2 envelope; never target execution."""
from pathlib import Path
import hashlib,itertools,json,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(R/'tools'));sys.path.insert(0,str(P))
import gossip_response_record as record
import verify as native
U64=(1<<64)-1

def relation(source,limited,charged,limit,parameters):
 pos=0
 def finish(value):return f'{value}|{pos}|{charged}'
 if limited:
  if charged>U64-4:return finish('e2')
  charged+=4
  if charged>limit:return finish('e2')
 if not source:return finish('e0:1')
 slow=len(source)<=4;marker=source[0]
 if slow:pos=1
 if marker<251:kind=marker;pos=1
 elif marker in (251,252):
  size=3 if marker==251 else 5
  if len(source)<size:return finish('e0:'+str(size-len(source)))
  kind=int.from_bytes(source[1:size],'little');pos=size
 else:return finish('e3:2:'+str({253:3,254:4,255:12}[marker]))
 if kind<2:return finish('other:'+str(kind))
 if kind>2:return finish('variant:'+str(kind))
 if limited:
  if charged==U64:return finish('e2')
  charged+=1
  if charged>limit:return finish('e2')
 if pos==len(source):return finish('e0:1')
 outer=source[pos];pos+=1
 if outer==0:return finish('ok:none')
 if outer!=1:return finish('outer:'+str(outer))
 child=record.relation(source[pos:],limited,charged,limit,parameters);result,used,after=child.split('|');pos+=int(used);charged=int(after)
 if result.startswith('ok:'):result='ok:some:'+result[3:]
 elif result.startswith('e5:'):result='inner:'+result[3:]
 return finish(result)

def cases():
 # All existing scalar fixtures become selected Some payloads with canonical
 # tag2; no existing scalar decoder/reader implementation is executed.
 out=set()
 for mode,used,limit,body in record.cases():
  out.add((mode,used,limit,b'\x02\x01'+body))
 # Tag widths, outer markers, suffixes and limited-count boundaries are new.
 tags=[b'\x02',b'\xfb\x02\x00',b'\xfc\x02\x00\x00\x00',b'\x00',b'\x01',b'\x03',b'\xfb\xff\xff',b'\xfc\xff\xff\xff\xff',b'\xfd',b'\xfe',b'\xff',b'\xfc\x02',b'']
 for tag in tags:
  for marker in range(256):
   for suffix in [b'',bytes(5),bytes(range(10))]:out.add((0,0,0,tag+bytes([marker])+suffix))
 for source in [b'',b'\x02',b'\x02\x00',b'\x02\x01',b'\x02\x01'+bytes(5),b'\x02\x01'+bytes(4)+b'\x01\x00',b'\x02\x02',b'\xff',b'\xff'+bytes(5),b'\xfc\x02',b'\xfb\x02\x00\x00']:
  for used in [0,1,U64-46,U64-38,U64-5,U64-4,U64-1,U64]:
   out.add((0,used,0,source))
   for limit in [0,3,4,5,6,12,13,20,21,28,29,37,38,45,46,47,U64-1,U64]:out.add((1,used,limit,source))
 return sorted(out)

def freeze():
 data=native.TARGET.read_bytes();native.collect(data,True);record.validate(native.TARGET);parameters=record.parameters(data);rows=cases();raw=''.join(f'{mode}\t{used}\t{limit}\t{source.hex() or "-"}\t{relation(source,mode==1,used,limit,parameters)}\n' for mode,used,limit,source in rows).encode()
 return raw,{'target_sha256':native.SPEC['target_sha256'],'cases':len(rows),'fixture_sha256':hashlib.sha256(raw).hexdigest(),'new_rust_exists':(R/'src/node115-gossip-response-v2-envelope').exists(),'method':'Independent static scalar equations; existing immutable record relation reused/credited; no Reader/Rust/captured execution','record_oracle_sha256':hashlib.sha256((R/'tools/gossip_response_record.py').read_bytes()).hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope_sha256':hashlib.sha256((P/'scope.json').read_bytes()).hexdigest()}
if __name__=='__main__':
 out=Path(sys.argv[1]);native.need(not out.exists(),'fresh freeze directory');out.mkdir(parents=True);raw,meta=freeze();(out/'cases.tsv').write_bytes(raw);(out/'freeze.json').write_text(native.dump(meta));print(native.dump(meta))
