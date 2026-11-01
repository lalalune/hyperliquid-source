"""Independent read-only flag-OR review: manual ELF program mapping and formula."""
from pathlib import Path
import gzip,hashlib,json,re,struct
root=Path(__file__).resolve().parents[3]
p=root/'research/work-items/RE-004-flag-or-family-rust-94'
sha=lambda b:hashlib.sha256(b).hexdigest()
data=(root/'artifacts/node/94/hl-node').read_bytes()
def require(condition,message):
 if not condition:raise ValueError(message)
require(sha(data)=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','full target')
require(data[:6]==b'\x7fELF\x02\x01','ELF64 little endian')
phoff=struct.unpack_from('<Q',data,32)[0];entsize,num=struct.unpack_from('<HH',data,54)
require(entsize==56,'program header size')
segments=[struct.unpack_from('<IIQQQQQQ',data,phoff+i*entsize) for i in range(num)]
def read(va,size):
 hits=[s for s in segments if s[0]==1 and s[3]<=va and va+size<=s[3]+s[5]]
 require(len(hits)==1,'unique file-backed PT_LOAD')
 s=hits[0];offset=s[2]+va-s[3]
 return data[offset:offset+size]
source=(root/'src/node94-flag-or-family/lib.rs').read_bytes()
array=source.decode().split('const READ_WORDS: [u32; 362] = [',1)[1].split('];',1)[0]
words=[int(x,16) for x in re.findall(r'0x[0-9a-f]+',array)]
require(len(words)==362,'source word count')
union=read(0x2516ec,1448)
require(b''.join(w.to_bytes(4,'little') for w in words)==union,'all source words match raw target')
static=json.loads((p/'static.json').read_text());descriptors=[]
for i,entry in enumerate((0x15625e0,0x1566100,0x1568bb0)):
 body=read(entry,21)
 require(body[:7]==bytes.fromhex('400fb6c6488d0d') and body[11:16]==bytes.fromhex('8b04810987') and body[-1]==0xc3,'complete manual opcode layout')
 table=entry+11+int.from_bytes(body[7:11],'little',signed=True)
 field=int.from_bytes(body[16:20],'little')
 raw=read(table,1024);offset=(table-0x2516ec)//4
 require(b''.join(w.to_bytes(4,'little') for w in words[offset:offset+256])==raw,'all 256 source window words')
 require(bytes.fromhex(static['members'][i]['table_hex'])==raw,'all 256 frozen static window words')
 descriptors.append((table,field))
require(descriptors==[(0x2516ec,416),(0x25178c,168),(0x251894,416)],'member descriptors')
inputs=gzip.decompress((p/'inputs.bin.gz').read_bytes());expected=gzip.decompress((p/'expected.bin.gz').read_bytes())
require(len(inputs)%40==0 and len(expected)==len(inputs)//40*32,'fixture sizes')
actual=bytearray();counts=[0]*3;indices=[set() for _ in range(3)];high=0
for start in range(0,len(inputs),40):
 row=inputs[start:start+40];kind,index,bias,obj,old=struct.unpack('<5Q',row)
 require(kind<3 and old<2**32,'input domain');table,field=descriptors[kind]
 selected=int.from_bytes(read(table+4*row[8],4),'little')
 # Union cardinality per bit: x OR y = x+y-(x AND y). No oracle import,
 # precomputed static table lookup, native execution or instruction stepping.
 updated=old+selected-(old&selected)
 actual.extend(selected.to_bytes(8,'little'))
 actual.extend((bias+table).to_bytes(9,'little')[:8])
 actual.extend((obj+field).to_bytes(9,'little')[:8])
 actual.extend(updated.to_bytes(8,'little'))
 counts[kind]+=1;indices[kind].add(row[8]);high+=index>255
require(actual==expected,'every frozen output tuple')
# Independent raw RELA scan through ELF section headers, with no packet parser.
shoff=struct.unpack_from('<Q',data,40)[0];shsize,shnum=struct.unpack_from('<HH',data,58)
require(shsize==64,'section header size')
headers=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*shsize) for i in range(shnum)]
entries={0x15625e0,0x1566100,0x1568bb0};named=[];relocations=[]
for s in headers:
 if s[1]!=4:continue
 require(s[9]==24 and s[5]%24==0,'RELA shape')
 for off in range(s[4],s[4]+s[5],24):
  dst,info,add=struct.unpack_from('<QQq',data,off);relocations.append((dst,info,add))
  if add in entries:
   require(info==8 and read(dst,8)==bytes(8),'relative zero symbol and raw slot')
   named.append((dst,info,add))
require(len(named)==12 and len({n[0] for n in named})==12,'12 unique naming slots')
for dst,info,add in named:
 require([r for r in relocations if r[0]<dst+8 and dst<r[0]+8]==[(dst,info,add)],'unique slot writer')
for dst,info,add in relocations:
 require(not (dst<0x251c94 and 0x2516ec<dst+8),'no relocation over full read union')
result={'result':'PASS','source_sha256':sha(source),'oracle_sha256':sha((p/'oracle.py').read_bytes()),'static_sha256':sha((p/'static.json').read_bytes()),'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'independently_rederived_sha256':sha(actual),'cases':len(inputs)//40,'cases_per_member':counts,'indices_per_member':[len(s) for s in indices],'high_index_cases':high,'source_words_verified':362,'window_words_verified':768,'union_bytes':1448,'target_sha256':sha(data),'manual_segment_mapping':True,'raw_relocation_count':len(relocations),'unique_relative_entry_slots':12,'proof_review':'pending proof availability','native_execution':False,'captured_execution':False,'instruction_emulation':False}
print(json.dumps(result,indent=2))
