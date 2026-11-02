"""Independent integer/slice specification, frozen before new Rust code.

Cases are value observations, not execution of captured instructions. Input bytes
are synthetic and contain no user/network data. The oracle uses predicate
regions and Python unbounded integer byte conversion; Rust will use checked
branching and byte accumulation. Both are grounded in the selected native CFG.
"""
import random,pathlib,hashlib,json,gzip,datetime
U=(1<<64)-1;I=-(1<<63)

def expect(row):
 op=row[0]
 if op=='B':
  _,width,adj,cap=row;maximum=(1<<(8*width))-1 if width<8 else U
  return f"B {min(cap,max(0,min(U,maximum+adj)))}"
 if op=='H':
  m=row[1];valid=16384<=m<=16777215
  q=(1<<24)//m if valid else 0
  return f"H {int(valid)} {max(5,q+q//4) if valid else 0}"
 _,cap,width,offset,adj,st,skip,big,state,pending,hexdata=row
 data=bytes.fromhex(hexdata);available=len(data);consumed=rd=rh=frame=0
 nextstate=state;nextlen=pending if state else 0
 def result(status):return 'D '+' '.join(map(str,[status,consumed,nextstate,nextlen,rd,rh,frame]))
 head=offset+width
 effective_skip=skip if st else head
 needhead=max(head,effective_skip)
 if state==0:
  if head>U:return result(4)
  if available<needhead:return result(0)
  if width>8:return result(5)
  value=int.from_bytes(data[offset:offset+width],'big'if big else'little')
  if value>cap:return result(2)
  if adj==I:return result(6)
  length=value+adj
  if not 0<=length<=U:return result(3)
  consumed=effective_skip;available-=consumed
  rd=max(0,length-available);nextstate=1;nextlen=length
 else:length=pending
 if available<length:return result(0)
 # Conditional successful split_to: valid stable storage and ordinary helper return.
 consumed+=length;available-=length;frame=length;nextstate=0;nextlen=0
 if head>U:return result(4)
 rh=max(0,needhead-available)
 return result(1)

r=random.Random(1155013);cases=[]
for w in range(9):
 for adj in [I,I+1,-65536,-257,-256,-9,-1,0,1,9,255,65536,(1<<63)-1]:
  for cap in [0,1,255,256,65535,1<<24,1<<53,U]:cases.append(['B',w,adj,cap])
for m in [0,1,16383,16384,16385,32767,32768,1<<23,16777214,16777215,16777216,U]+[r.randrange(0,1<<25)for _ in range(1000)]:cases.append(['H',m])
# Every field width and byte order; exact threshold and adjustment boundaries.
for w in range(9):
 values=sorted({0,1,2,8,9,15,16,255,256,65535,(1<<(8*w))-1 if w else 0})
 for big in [0,1]:
  for value in values:
   if value>=1<<(8*w) and w:continue
   if not w and value:continue
   prefix=b'\xa5\x5a';encoded=value.to_bytes(w,'big'if big else'little')
   data=prefix+encoded+bytes(range(32))
   for cap in sorted({0,max(0,value-1),value,min(U,value+1),U}):
    for adj in [I,-9,-1,0,1,9,(1<<63)-1]:
     for st,skip in [(0,0),(1,0),(1,1),(1,len(prefix)+w+2)]:
      cases.append(['D',cap,w,2,adj,st,skip,big,0,0,data.hex()])
# Streaming and header incompleteness around real h2 payload sizes; no allocation of announced size.
for n in [0,1,2,3,8,9,15,16,31,32,16383,16384,16385,16777215]:
 full=n.to_bytes(3,'big')+bytes(range(6))+bytes(range(32))
 for size in range(42):
  cases.append(['D',16384,3,0,9,1,0,1,0,0,full[:size].hex()])
  cases.append(['D',16384,3,0,9,1,0,1,1,n+9,full[:size].hex()])
# Arithmetic and lazy-admission counterexamples: overflow is only inspected when reached.
for state in [0,1]:
 for pending in [0,1,3,8,32,33,U]:
  for off,w,st,skip in [(U,1,0,0),(U-7,8,1,0),(0,9,0,0),(0,0,0,0),(0,8,1,U),(2,3,1,0)]:
   for size in [0,2,3,8,16,40]:cases.append(['D',U,w,off,I,st,skip,1,state,pending,bytes(range(size)).hex()])
for _ in range(2500):
 w=r.randrange(9);offset=r.randrange(5);size=r.randrange(65);data=bytes(r.randrange(256)for _ in range(size));cases.append(['D',r.choice([0,1,8,255,65535,U]),w,offset,r.choice([-9,-1,0,1,9]),r.randrange(2),r.randrange(20),r.randrange(2),r.randrange(2),r.randrange(80),data.hex()])
packet=pathlib.Path('research/work-items/RE-012-h2-framing-115');directory=packet/'oracle';directory.mkdir(parents=True,exist_ok=True)
raw=''.join(json.dumps(dict(input=c,expected=expect(c)),separators=(',',':'))+'\n'for c in cases).encode();(directory/'cases.jsonl.gz').write_bytes(gzip.compress(raw,mtime=0))
freeze=dict(cases=len(cases),raw_sha256=hashlib.sha256(raw).hexdigest(),archive_sha256=hashlib.sha256((directory/'cases.jsonl.gz').read_bytes()).hexdigest(),created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),new_rust_present=pathlib.Path('src/node115-h2-framing').exists(),oracle_source_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),ancestry='Fresh native CFG and pinned public licensed comparator read; no earlier own framing Rust used. This is local independent-formula qualification, not target execution or a blind discovery.')
if freeze['new_rust_present']:raise RuntimeError('freeze after Rust creation')
(directory/'FREEZE.json').write_text(json.dumps(freeze,indent=2)+'\n');print(json.dumps(freeze,indent=2))
