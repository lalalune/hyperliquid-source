#!/usr/bin/env python3
"""Node115 response scalar record: static branch relation, never capture execution."""
import argparse,hashlib,itertools,json,struct
from pathlib import Path
from elf_index import sections
from fde_extents import eh_frame_records
ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-005-node115-gossip-response-record'
COMPONENT=ROOT/'src/node115-gossip-response-record'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
U64=(1<<64)-1
EXTENTS={0x5aabd20:0x5aabf7a,0x5821250:0x5821335,0x58225c0:0x58226fc,0x5822700:0x582270e}
CONTEXT={0x5aac7c0:0x5aacc22}
SLOTS={0x64e6c38:0x58225c0,0x64e7f78:0x5822700}
TABLES={0x935bdc:[0x58212b6,0x58212ce,0x58212c2,0x5821305],0x935c24:[0x5822627,0x5822641,0x5822634,0x58226cc]}
ANCHORS={0x5aabd39:'e81255d7ff',0x5aabd58:'e8f354d7ff',0x5aabd78:'e8d354d7ff',0x5aabd98:'e8b354d7ff',0x5aabe33:'e81854d7ff',
0x5aabdb0:'41833e01',0x5aabdcd:'4883feff',0x5aabdd1:'0f8410010000',0x5aabddb:'4c8d4e01',0x5aabddf:'4d894e20',0x5aabde3:'4c39c6',0x5aabde6:'0f83fb000000',
0x5aabe12:'49897e10',0x5aabe16:'49895618',0x5aabe1a:'85f6',0x5aabe22:'83fe01',0x5aabf14:'b205',0x5aabf61:'48c70302000000',
0x5aabefb:'488903',0x5aabefe:'48894b08',0x5aabf02:'4c897b10',0x5aabf06:'4c896318',0x5aabf0a:'4c896b20',0x5aabf0e:'48896b28',
0x5821251:'833e01',0x582125a:'4883f8f7',0x582125e:'7711',0x5821264:'4883c008',0x582127d:'4883f808',0x582128a:'4881fafb000000',0x58212f8:'31d2',0x58225d9:'4c890e',
0x5822700:'4889f8c6070340887701885702c3',0x5aac7fb:'83f802',0x5aac877:'83ff01',0x5aac886:'e895f4ffff'}
def need(ok,msg):
 if not ok:raise ValueError(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(data,secs,va,n):
 hits=[s for s in secs if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
 need(len(hits)==1,'ambiguous/unmapped image VA');s=hits[0];off=s['offset']+va-s['address'];return off,data[off:off+n]
def analyze(data):
 need(len(data)==105896032 and sha(data)==SHA,'target identity differs')
 secs=sections(data);frames=eh_frame_records(data,secs)[1];bodies=[]
 for start,end in {**EXTENTS,**CONTEXT}.items():
  f=next((f for f in frames if f['start']==start),None);need(f is not None and f['end']==end,'actual FDE bounds differ')
  off,raw=read(data,secs,start,end-start);unwind={}
  for name in ('fde','cie'):
   va=f[name];length=int.from_bytes(read(data,secs,va,4)[1],'little');need(0<length<4096,'unwind record length');unwind[name]={'imageVA':hex(va),'bytesHex':read(data,secs,va,length+4)[1].hex()}
  bodies.append({'start':hex(start),'end':hex(end),'bodySHA256':sha(raw),'fileOffset':hex(off),'bytes':len(raw),'frame':f,'unwindRecords':unwind,'implementedScope':start in EXTENTS,'contextOnly':start in CONTEXT})
 anchors=[]
 for va,want in ANCHORS.items():
  off,actual=read(data,secs,va,len(bytes.fromhex(want)));need(actual.hex()==want,'native operand differs '+hex(va));anchors.append({'imageVA':hex(va),'fileOffset':hex(off),'bytesHex':want})
 bindings=[]
 for s in secs:
  if s['type']!=4:continue
  need(s['size']%24==0,'RELA size')
  for off in range(s['offset'],s['offset']+s['size'],24):
   where,info,target=struct.unpack_from('<QQq',data,off)
   if where not in SLOTS:continue
   need(info==8 and target==SLOTS[where],'selected relative helper differs');need(not any(x['slot']==hex(where) for x in bindings),'duplicate binding')
   bindings.append({'slot':hex(where),'target':hex(target),'type':8,'recordFileOffset':hex(off)})
 need(len(bindings)==2,'missing actual helper bindings')
 tables=[]
 for va,want in TABLES.items():
  off,raw=read(data,secs,va,16);got=[va+x for x in struct.unpack('<iiii',raw)];need(got==want,'reader table differs');tables.append({'imageVA':hex(va),'fileOffset':hex(off),'bytesHex':raw.hex(),'targets':list(map(hex,got))})
 need(read(data,secs,0x93c571,17)[1]==b'GossipRpcResponse','actual response type differs')
 raw_context=read(data,secs,0x9173df,50)[1]
 return {'targetSHA256':SHA,'coordinateSystem':'ELF image virtual address','bodies':bodies,'anchors':anchors,'bindings':sorted(bindings,key=lambda x:x['slot']),'dispatchTables':tables,'optionalMarkerDiagnostic':{'imageVA':'0x9173df','bytesHex':raw_context.hex(),'nativeLengthArgument':50,'formattingNotModeled':True},'sourceContext':{'imageVA':'0x451270','bytesHex':read(data,secs,0x451270,32)[1].hex()},'actualCaller':{'callVA':'0x5aac886','targetVA':'0x5aabd20','parentFDE':'0x5aac7c0','parentType':'GossipRpcResponse','scope':'variant2 outer present branch context only; other response variants/container helpers remain unclosed'},'reusedReaderCommit':'45e91f8499f1a78460407d235f580c1625f44d1a','scope':'Whole selected scalar record logical value/error/cursor/charge relation under canonical limit modes and disjoint valid slices. Not original ABI/padding, field units or whole response decoder.'}
def parameters(data):
 secs=sections(data);byte=lambda va:read(data,secs,va,1)[1][0]
 comparison=byte(0x5aabde7);need(comparison in (0x83,0x87),'unsupported flag limit condition')
 return {'readCharge':byte(0x5821267),'readThreshold':byte(0x5821280),'markerFloor':int.from_bytes(read(data,secs,0x582128d,4)[1],'little'),'someMarker':byte(0x5aabe24),'flagCharge':byte(0x5aabdde),'flagLimitCondition':'jae' if comparison==0x83 else 'ja'}
def relation(source,limited,charged,limit,p):
 position=0
 def integer():
  nonlocal position,charged
  if limited:
   if charged>U64-p['readCharge']:return 'e2',None
   charged+=p['readCharge']
   if charged>limit:return 'e2',None
  n=len(source)-position;slow=n<=p['readThreshold']
  if not n:return 'e0:1',None
  begin=position;marker=source[begin]
  if slow:position+=1
  if marker<p['markerFloor']:position=begin+1;return None,marker
  width={251:3,252:5,253:9}.get(marker)
  if width is None:return f'e3:{3 if slow else 2}:{4 if marker==254 else 12}',None
  if n<width:return 'e0:'+str(width-n),None
  position=begin+width;return None,int.from_bytes(source[begin+1:begin+width],'little')
 def run():
  nonlocal position,charged
  values=[]
  for _ in range(4):
   error,value=integer()
   if error:return error
   values.append(value)
  if limited:
   if charged==U64:return 'e2'
   previous=charged;charged+=p['flagCharge']
   if (previous>=limit if p['flagLimitCondition']=='jae' else previous>limit):return 'e2'
  if position==len(source):return 'e0:1'
  marker=source[position];position+=1
  if marker==0:tail='-'
  elif marker==p['someMarker']:
   error,value=integer()
   if error:return error
   tail=str(value)
  else:return 'e5:'+str(marker)
  return 'ok:'+':'.join(map(str,values))+':'+tail
 result=run();return result+f'|{position}|{charged}'
def forms(value):
 result=[bytes([value])] if value<251 else []
 for marker,n in ((251,2),(252,4),(253,8)):
  if value<1<<(8*n):result.append(bytes([marker])+value.to_bytes(n,'little'))
 return result
def cases():
 streams={b'',b'\0',bytes(4),bytes(5),bytes(4)+b'\1',bytes(4)+b'\1\0'}
 values=(0,1,250,251,65535,65536,(1<<32)-1,1<<32,U64)
 for row in itertools.product((0,250,251,U64),repeat=4):
  for wide in (False,True):
   prefix=b''.join(forms(v)[-1 if wide else 0] for v in row);streams.add(prefix+b'\0')
   for last in values:
    for encoded in {forms(last)[0],forms(last)[-1]}:streams.add(prefix+b'\1'+encoded)
 for index in range(4):
  for value in values:
   for encoded in forms(value):streams.add(bytes(index)+encoded+bytes(4-index))
 for index in range(5):
  prefix=bytes(index) if index<4 else bytes(4)+b'\1'
  for marker in range(256):
   for count in (0,1,2,3,4,5,7,8,9,12):
    part=bytes([marker])+bytes(range(count));streams.add(prefix+part)
    if index<4:streams.add(prefix+part+bytes(4-index))
 for marker in range(256):
  for count in (0,1,4,8,9):streams.add(bytes(4)+bytes([marker])+bytes(range(count)))
 for row in ((0,1,250,251),(U64,1<<32,65536,65535)):
  wire=b''.join(forms(v)[-1] for v in row)+b'\1'+forms(U64)[-1];streams.update(wire[:n] for n in range(len(wire)+1))
 result={(0,0,0,s) for s in streams}
 reps=[b'',b'\0',bytes(2),bytes(3),bytes(4),bytes(5),bytes(4)+b'\1',bytes(4)+b'\1\0',bytes(4)+b'\2',bytes(4)+b'\xff',b'\xff',b'\xff'+bytes(9),b'\xfb',b'\xfd'+bytes(3),bytes(4)+b'\1\xff',bytes(4)+b'\1\xff'+bytes(9)]
 for source in reps:
  for used in (0,1,U64-41,U64-33,U64-32,U64-31,U64-8,U64-1,U64):
   result.add((0,used,0,source))
   for limit in (0,7,8,15,16,23,24,31,32,33,40,41,42,U64-1,U64):result.add((1,used,limit,source))
 state=0x5aabd20
 for i in range(512):
  state=(state*6364136223846793005+1442695040888963407)&((1<<128)-1);source=state.to_bytes(16,'little')[:i%17];result.add((i&1,(state>>64)&U64,(state>>32)&U64,source))
 return sorted(result)
def corpus(data):
 p=parameters(data);return ''.join(f'{m}\t{used}\t{limit}\t{s.hex() or "-"}\t{relation(s,m==1,used,limit,p)}\n' for m,used,limit,s in cases()).encode()
def validate(binary):
 data=Path(binary).read_bytes();need(analyze(data)==json.loads((PACKET/'records.json').read_text()),'frozen records differ');raw=corpus(data);need(raw==(COMPONENT/'cases.tsv').read_bytes(),'frozen cases differ');return {'status':'PASS','targetSHA256':SHA,'cases':len(raw.splitlines()),'fixtureSHA256':sha(raw),'captureExecutionOrEmulation':False}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/115/hl-node');a=p.parse_args();print(json.dumps(validate(a.binary),indent=2))
