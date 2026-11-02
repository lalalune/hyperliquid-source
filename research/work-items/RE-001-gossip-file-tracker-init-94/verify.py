"""Digest-bound static evidence verifier; no target execution or emulation (MIT)."""
from __future__ import annotations
import argparse,gzip,hashlib,json,pathlib,re,struct,sys
P=pathlib.Path(__file__).resolve().parent
ROOT=P.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES=[(74718656,74722481,19428304,"4b3d97adfb4083f72ad464059eb34202c74784529294f8fa8f7931d92a4929c3"),(74572256,74572728,19406200,"cd54b3d6db1b48e1812b1edcd087cbfe1b3ade37c9e6712a8488a7f4852bf17c"),(74585152,74587048,19406728,"5804d3a1f901d4b2b5ba49923bc7bf60feed5b0b4228d22d22a03bea5900d5af")]
ANCHORS=[(74718885,"e836c3fdff","caller-to-specialized-initializer"),(74718898,"4883f802","caller-rejects-result-tag2"),(74718902,"0f85d1070000","non2-to-loaded-config"),(74718794,"0f84eb030000","missing-file-to-compiled-root-selection"),(74719614,"48b80000000000000080","outer-error-niche-base"),(74719624,"4883c03c","outer-error-niche-addend"),(74719628,"498906","outer-error-tag-store"),(74572298,"ff15e0070501","initializer-metadata-call"),(74572304,"837c240801","metadata-error-tag1"),(74572309,"7507","metadata-nonerror-branch"),(74572338,"e809320000","initializer-to-load-helper"),(74572353,"4883f902","load-error-tag2"),(74572357,"7533","load-nonerror-branch"),(74572359,"49894708","initializer-error-payload-store"),(74572363,"49c70702000000","initializer-error-tag-store"),(74572554,"48b80000000000001440","initializer-interval-bits"),(74585858,"48f7d8","read-result-negation"),(74585861,"0f8104010000","read-non-sentinel-branch"),(74586014,"48894308","read-error-payload-store"),(74586018,"48c70302000000","read-error-tag-store"),(74586178,"e85922c8ff","text-parser-boundary"),(74586183,"83bc248000000002","parser-error-tag2"),(74586191,"0f85f6010000","parser-nonerror-branch"),(74586332,"48894308","parse-error-payload-store"),(74586336,"48c70302000000","parse-error-tag-store")]
EXPORTS={"disassembly.json.gz":{"sha256":"a786b22d4c4a0e068ec09c26c360cf81f35db97346aeca976f50bca8ad7d92bf","bytes":16947},"gnu.objdump.txt.gz":{"sha256":"2e70ceadfb4da3e23faac5d8d48bb438278327609030891dbc82f406586d7018","bytes":14499}}
BINDINGS={91679216:21285168,91679208:21276432,91682344:21276160,91682376:82678144,91682368:82679776}
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(b):return hashlib.sha256(b).hexdigest()
def layout(data):
 ss=sections(data);by={s['name']:s for s in ss}
 def offset(va,n):
  found={s['offset']+va-s['address'] for s in ss if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']}
  need(len(found)==1,'VA not uniquely file backed')
  pos=found.pop();need(0<=pos and pos+n<=len(data),'File bounds')
  return pos
 return ss,by,offset
def export_check(data,offset,exports,gnu):
 need(len(exports)==len(RANGES),'Export range count')
 actual_gnu={}
 for line in gnu.decode('utf8').splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
  if m:
   addr=int(m[1],16)
   need(addr not in actual_gnu,'Duplicate GNU instruction')
   actual_gnu[addr]=bytes.fromhex(m[2])
 expected_gnu={}
 for row,expected in zip(exports,RANGES):
  start,end,fde,digest=expected
  need(row['start']==hex(start) and row['end']==hex(end) and row['fde']==hex(fde),'Export extent identity')
  cursor=start
  for ins in row['instructions']:
   addr=int(ins['va'],16);raw=bytes.fromhex(ins['bytes'])
   need(addr==cursor and 1<=len(raw)<=15 and addr+len(raw)<=end,'Contiguous complete export')
   need(raw==data[offset(addr,len(raw)):offset(addr,len(raw))+len(raw)],'Export byte mismatch')
   expected_gnu[addr]=raw;cursor+=len(raw)
  need(cursor==end,'Incomplete export')
 need(actual_gnu==expected_gnu,'Independent GNU address/byte disagreement')
def observe(data, *, authenticate=True, check_bodies=True, check_exports=True):
 if authenticate:need(len(data)==91774280 and sha(data)==TARGET,'Target digest/size')
 ss,by,offset=layout(data)
 _,fdes=eh_frame_records(data,ss)
 for start,end,fde,digest in RANGES:
  found=[f for f in fdes if f['start']==start]
  need(len(found)==1 and found[0]['end']==end and found[0]['fde']==fde,'FDE extent identity')
  if check_bodies:need(sha(data[offset(start,end-start):offset(start,end-start)+end-start])==digest,'Body identity')
 for addr,raw,label in ANCHORS:
  expected=bytes.fromhex(raw);pos=offset(addr,len(expected))
  need(data[pos:pos+len(expected)]==expected,'Anchor '+label)
 rela=by['.rela.dyn'];bindings={}
 for pos in range(rela['offset'],rela['offset']+rela['size'],24):
  slot,info,addend=struct.unpack_from('<QQq',data,pos)
  if slot in BINDINGS:
   need((info&0xffffffff)==8 and slot not in bindings,'RELA type/duplicate')
   bindings[slot]=addend
 need(bindings==BINDINGS,'Relative binding identity')
 for va,target in [(0x4741ea5,0x471e1e0),(0x471e232,0x4721440),(0x4721842,0x43a3aa0)]:
  pos=offset(va,5);need(data[pos]==0xe8 and va+5+struct.unpack_from('<i',data,pos+1)[0]==target,'Direct call identity')
 instruction_count=None
 if check_exports:
  metadata=json.loads((P/'records.json').read_text())
  need(metadata['targetSha256']==TARGET and metadata['targetBytes']==91774280,'Record target identity')
  need(metadata['exports']==EXPORTS,'Pinned archive metadata')
  need([(int(x['start'],16),int(x['end'],16),int(x['fde'],16),x['bodySha256']) for x in metadata['ranges']]==RANGES,'Record range identity')
  need([(int(x['va'],16),x['bytes'],x['obligation']) for x in metadata['anchors']]==ANCHORS,'Record anchor identity')
  need({int(k,16):int(v,16) for k,v in metadata['relativeBindings'].items()}==BINDINGS,'Record binding identity')
  for name,entry in metadata['exports'].items():
   raw=(P/name).read_bytes();need(sha(raw)==entry['sha256'] and len(raw)==entry['bytes'],'Export archive identity')
  exports=json.loads(gzip.decompress((P/'disassembly.json.gz').read_bytes()))
  gnu=gzip.decompress((P/'gnu.objdump.txt.gz').read_bytes())
  export_check(data,offset,exports,gnu)
  instruction_count=sum(len(row['instructions']) for row in exports)
 return {'targetSha256':TARGET,'targetExecuted':False,'ranges':len(RANGES),'bytes':sum(e-s for s,e,_,_ in RANGES),'instructions':instruction_count,'selectedInitializerMetadataErrorTag':1,'selectedInitializerLoadErrorTag':2,'selectedCallerFailureTag':'0x800000000000003c','condition':'Only recorded branches/stores under ordinary opaque-helper returns. No concrete file input, parser grammar, complete CFG/ABI or dynamic differential claim.'}
def controls(data):
 ss,by,offset=layout(data);out=[]
 def refused(label,alter,fn):
  damaged=bytearray(data);alter(damaged)
  try:fn(damaged)
  except (ValueError,KeyError,IndexError,struct.error):out.append({'name':label,'refused':True})
  else:raise ValueError('Control unexpectedly accepted: '+label)
 inner=lambda d:observe(d,authenticate=False,check_bodies=False,check_exports=False)
 for addr,raw,label in ANCHORS:
  pos=offset(addr,len(bytes.fromhex(raw)))+len(bytes.fromhex(raw))-1
  refused('actual-byte-'+label,lambda d,p=pos:d.__setitem__(p,d[p]^1),inner)
 rela=by['.rela.dyn']
 for pos in range(rela['offset'],rela['offset']+rela['size'],24):
  slot,info,_=struct.unpack_from('<QQq',data,pos)
  if slot in BINDINGS:refused('actual-RELA-'+hex(slot),lambda d,p=pos+16:d.__setitem__(p,d[p]^1),inner)
 exports=json.loads(gzip.decompress((P/'disassembly.json.gz').read_bytes()))
 gnu=gzip.decompress((P/'gnu.objdump.txt.gz').read_bytes())
 bad=json.loads(json.dumps(exports));bad[0]['instructions'][0]['bytes']='90'
 try:export_check(data,offset,bad,gnu)
 except ValueError:out.append({'name':'export-instruction-byte-disagreement','refused':True})
 else:raise ValueError('Export corruption accepted')
 refused('full-target-digest',lambda d:d.__setitem__(0,d[0]^1),lambda d:observe(d))
 return {'controls':out,'count':len(out),'allRefused':True,'scope':'Actual capture anchor/RELA changes bypass image/body/export checks to exercise local obligations. Export and full-image checks have separate controls. These controls do not emulate the target or prove full helper semantics.'}
def main():
 a=argparse.ArgumentParser();a.add_argument('--binary',type=pathlib.Path,required=True);a.add_argument('--controls',action='store_true');a.add_argument('--out',type=pathlib.Path)
 args=a.parse_args();data=args.binary.read_bytes();result={'observation':observe(data)}
 if args.controls:result['negativeControls']=controls(data)
 raw=json.dumps(result,indent=2)+'\n'
 if args.out:args.out.write_text(raw,encoding='utf8')
 print(raw,flush=True)
if __name__=='__main__':main()
