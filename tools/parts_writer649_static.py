#!/usr/bin/env python3
"""Bind the actual649-byte writer's native/math/data closure; never execute it."""
import argparse,hashlib,json,re,struct,subprocess,tempfile
from pathlib import Path
import libcore_fmt_correspondence as elf
ROOT=Path(__file__).resolve().parents[1]
START,END=0x1572B20,0x1572DA9
BODY_SHA='8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3'
LITERAL=0x252CB8
NAME='_ZN4core3fmt9Formatter21write_formatted_parts17h07d1759b5e21a5fcE'
def need(ok,message):
 if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def decode(body):
 with tempfile.TemporaryDirectory(prefix='writer649-native-')as directory:
  p=Path(directory)/'span.raw';p.write_bytes(body)
  argv=['objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16','--adjust-vma='+hex(START),str(p)]
  result=subprocess.run(argv,check=True,capture_output=True);need(p.read_bytes()==body,'Owned span changed')
 rows=[];cursor=START
 for line in result.stdout.decode().splitlines():
  fields=line.split('\t')
  if len(fields)<3 or not re.fullmatch(r'\s*[0-9a-f]+:',fields[0]):continue
  address=int(fields[0].strip()[:-1],16);raw=bytes.fromhex(fields[1]);need(address==cursor and raw and '(bad)'not in fields[2],'Incomplete native tiling')
  need(body[address-START:address-START+len(raw)]==raw,'Native bytes differ');rows.append({'va':address,'raw':raw.hex(),'assembly':fields[2]});cursor+=len(raw)
 need(cursor==END and len(rows)==169,'Wrong complete instruction domain')
 return rows,result.stdout.decode().replace(str(p),'<owned-writer649-span>'),{'argv':argv[:-1]+['<owned-writer649-span>'],'stderr_hex':result.stderr.hex(),'version':subprocess.run(['objdump','--version'],capture_output=True,check=True).stdout.decode().splitlines()[0]}
def loader_writes(image):
 need(not any(s['type']in(9,19)and s['size']for s in image.sections),'Unhandled REL/RELR table')
 counts={};tables=[];protected=[(START,END,'writer-code'),(LITERAL,LITERAL+64,'ASCII-zero-literal')]
 for s in image.sections:
  if s['type']!=4:continue
  need(s['entsize']==24 and s['size']%24==0,'Malformed RELA table')
  for at in range(s['offset'],s['offset']+s['size'],24):
   address,info,addend=struct.unpack_from('<QQq',image.data,at);kind=info&0xffffffff
   need(kind in(1,6,7,8,18)and address<=(1<<64)-8,'Unhandled/wrapping actual8B relocation')
   need(not any(address<b and a<address+8 for a,b,_ in protected),'Loader write overlaps protected writer code/data')
   counts[kind]=counts.get(kind,0)+1
  tables.append({'name':s['name'],'records':s['size']//24,'index':s['index']})
 need(counts=={8:78833,6:263,1:924,18:2,7:278},'Actual RELA census changed')
 return {'records':sum(counts.values()),'kind_counts':counts,'all_observed_write_widths':8,'protected':protected,'overlaps':0,'tables':tables}
def arithmetic(body):
 def operand(va,width,expected):
  actual=int.from_bytes(body[va-START:va-START+width],'little');need(actual==expected,'Decimal/chunk operand changed at '+hex(va));return actual
 values={name:operand(va,width,value)for name,va,width,value in[
 ('a',0x1572BCC,4,0x5FFF6),('b',0x1572BD2,4,0x7FF9C),('c',0x1572BDA,4,0xDFC18),('d',0x1572BE0,4,0x7D8F0),('len_shift',0x1572BEA,1,17),
 ('q10_mul',0x1572CA7,4,0xCCCD),('q10_shift',0x1572CAD,1,19),('rem_mul',0x1572CD0,4,0x199A),('rem_shift',0x1572CD6,1,15),
 ('q100_pre',0x1572CF4,1,2),('q100_mul',0x1572CF7,4,0x147B),('q100_shift',0x1572CFD,1,17),
 ('q1000_pre',0x1572D24,1,3),('q1000_mul',0x1572D27,4,0x20C5),('q1000_shift',0x1572D2D,1,20),
 ('q10000_pre',0x1572D52,1,4),('q10000_mul',0x1572D55,4,0x347),('q10000_shift',0x1572D5B,1,19)]}
 for n in range(65536):
  width = 1 if n == 0 else (((n + values['a']) & (n + values['b'])) ^ ((n + values['c']) & (n + values['d']))) // (1 << values['len_shift']) + 1
  q10=n*values['q10_mul']//(1<<values['q10_shift'])
  q100=(n//(1<<values['q100_pre']))*values['q100_mul']//(1<<values['q100_shift'])
  q1000=(n//(1<<values['q1000_pre']))*values['q1000_mul']//(1<<values['q1000_shift'])
  q10000=(n//(1<<values['q10000_pre']))*values['q10000_mul']//(1<<values['q10000_shift'])
  need((q10,q100,q1000,q10000)==(n//10,n//100,n//1000,n//10000),'Reciprocal quotient mismatch')
  digits=[n-10*q10]
  for q in(q10,q100,q1000):
   need(q*values['rem_mul']<1<<32,'Product exceeds u32')
   even=(q*values['rem_mul']//(1<<values['rem_shift']))&~1;digit=q-5*even;need(digit==q%10,'Remainder mismatch');digits.append(digit)
  digits.append(q10000);need(1<=width<=5 and all(0<=d<=9 for d in digits),'Invalid digit/width')
  encoded=bytes(48|digits[i]for i in range(width-1,-1,-1));need(encoded==str(n).encode('ascii'),'Complete numeral mismatch')
 return {'domain':65536,'complete_numeral_mismatches':0,'maximum_width':5,'actual_operands':values,'no_PC_register_memory_or_opcode_evaluator':True}
def derive(target_bytes,archive_bytes):
 target=elf.Elf(target_bytes,3);writes=loader_writes(target);cies,fdes=elf.eh_frame_records(target_bytes,target.sections)
 f=[f for f in fdes if f['start']==START];need(len(f)==1 and f[0]['end']==END,'Wrong/ambiguous complete649B FDE');fde=f[0]
 body,mapping=target.va_bytes(START,END-START,executable=True)
 patterns={0x1572B3A:'488b5208',0x1572B58:'498b4718',0x1572B65:'4d8b6710',0x1572B9F:'410fb70424',0x1572BB1:'410fb7442402',0x1572C00:'4d8b6c2408',0x1572C05:'4983fd41',0x1572C39:'4983c5c0',0x1572C3D:'4983fd40',0x1572D94:'b001',0x1572D98:'31c0'}
 for va,encoded in patterns.items():need(body[va-START:va-START+len(bytes.fromhex(encoded))]==bytes.fromhex(encoded),'Native role/loop operand changed at '+hex(va))
 math=arithmetic(body)
 rows,listing,tool=decode(body)
 for va in(0x1572C28,0x1572C80):
  offset=va-START;need(body[offset:offset+3]==bytes.fromhex('488d35'),'Literal addressing opcode changed')
  need(va+7+int.from_bytes(body[offset+3:offset+7],'little',signed=True)==LITERAL,'Literal call argument binding changed')
 literal,literal_mapping=target.va_bytes(LITERAL,64);need(literal==b'0'*64,'Actual64 ASCII-zero bytes changed');need(literal_mapping['PT_LOAD']['flags']==4 and not literal_mapping['section']['flags']&1,'Literal is not read-only')
 need(sha(body)==BODY_SHA,'Root-reviewed complete body identity differs')
 calls=[r for r in rows if r['assembly'].startswith('call')];need([r['va']for r in calls]==[0x1572B49,0x1572B87,0x1572C2F,0x1572C5D,0x1572C8A],'Dynamic call closure changed')
 frame={}
 for label,va in [('FDE',fde['fde']),('CIE',fde['cie'])]:
  head,_=target.va_bytes(va,4);size=int.from_bytes(head,'little')+4;frame[label]=target.va_bytes(va,size)[0].hex()
 members=elf.ar_members(archive_bytes);need(sha(members[elf.MEMBER])==elf.MEMBER_SHA256,'Official member identity differs');official=elf.Elf(members[elf.MEMBER],1)
 section=official.by_name('.text.'+NAME);symbol=official.function(section['index'],NAME)
 need(section['size']==581,'Preserved official negative candidate extent differs')
 provenance={'source_symbol':symbol,'source_section':section,'source_bytes':581,'target_bytes':649,'result':'EXTENT_MISMATCH_NO_COMPARISON','cropping_or_stitching':False,'byte_window_credit':False}
 return {'schema':'node94-parts-writer649-static/1','target_sha256':sha(target_bytes),'target_bytes':len(target_bytes),'archive_sha256':sha(archive_bytes),'member_sha256':elf.MEMBER_SHA256,'range':[hex(START),hex(END)],'body_sha256':sha(body),'bytes':649,'rows':169,'FDE':fde,'CIE':cies[fde['cie']],'frame_raw':frame,'mapping':mapping,'native_rows':rows,'native_tool':tool,'dynamic_calls':calls,'fixed_called_helpers':[],'literal':{'VA':hex(LITERAL),'raw':literal.hex(),'mapping':literal_mapping},'loader_write_audit':writes,'decimal_arithmetic':math,'published_candidate':provenance,'captured_execution_or_instruction_evaluator':False,'component_gates_requested':False},{'captured-main.bin':body,'main.objdump.txt':listing.encode(),'ASCII-zero64.bin':literal}
def analyze(target_bytes,archive_bytes):
 need(type(target_bytes)is bytes and len(target_bytes)==91774280 and sha(target_bytes)==elf.TARGET_SHA256,'Target immutable snapshot differs')
 need(type(archive_bytes)is bytes and sha(archive_bytes)==elf.CORE_SHA256,'Archive immutable snapshot differs')
 return derive(target_bytes,archive_bytes)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--target',type=Path,default=ROOT/'artifacts/node/94/hl-node');p.add_argument('--core-archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();need(not a.output.exists(),'Preserve original results');report,exports=analyze(a.target.read_bytes(),a.core_archive.read_bytes());a.output.mkdir(parents=True)
 for name,raw in exports.items():(a.output/name).write_bytes(raw)
 (a.output/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps({'bytes':649,'rows':169,'official_candidate':'581vs649 extent mismatch; no byte credit'}))
