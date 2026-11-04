#!/usr/bin/env python3
"""Static ELF extraction; never execute captured code or evaluate instructions."""
import argparse,hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START,END=0x50de300,0x50de518
PINS={0x50de324:'4883fa09',0x50de32a:'48b82f6465762f6e756c',0x50de337:'410fb64f08',0x50de33c:'4883f16c',0x50de345:'31db',0x50de351:'41803f2f',0x50de366:'c644242006',0x50de386:'807c246009',0x50de39c:'4883f802',0x50de3a2:'6681392e2e',0x50de3cc:'8079fe2e',0x50de3da:'48f7d6',0x50de3dd:'4801c6',0x50de3e0:'488d15fe7538fb',0x50de3ec:'e8af184cfc',0x50de3f5:'41bc80000000',0x50de412:'c7006e756c6c',0x50de4a7:'41c64500c0',0x50de4c9:'48b80300000026000000'}
BINDINGS={0x64e0938:0x5cab560,0x64df480:0x6355830,0x64e0028:0x15020f0,0x64e09e8:0x15024a0,0x64df4a0:0x635de30,0x64df498:0x141e264}
def need(ok,msg):
 if not ok:raise ValueError(msg)
def analyze(data):
 ss=sections(data)
 def read(va,n):
  matches=[s for s in ss if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
  need(len(matches)==1,'mapping');s=matches[0];off=s['offset']+va-s['address'];return off,data[off:off+n]
 for va,h in PINS.items():need(read(va,len(bytes.fromhex(h)))[1]==bytes.fromhex(h),'instruction pin '+hex(va))
 need(read(0x4659e5,3)[1]==b'rmp','suffix bytes')
 _,fs=eh_frame_records(data);matches=[f for f in fs if f['start']==START]
 need(len(matches)==1 and matches[0]['end']==END,'FDE extent');f=matches[0]
 def frame(va):
  off,raw=read(va,4);n=struct.unpack('<I',raw)[0]+4;return {'va':hex(va),'offset':off,'hex':read(va,n)[1].hex()}
 rel={}
 for s in ss:
  if s['type']==4:
   for off in range(s['offset'],s['offset']+s['size'],24):
    slot,kind,target=struct.unpack_from('<QQq',data,off)
    if slot in BINDINGS:
     need(kind==8 and target==BINDINGS[slot],'relocation '+hex(slot));rel[hex(slot)]={'offset':off,'hex':data[off:off+24].hex(),'target':hex(target)}
 need(len(rel)==len(BINDINGS),'missing relocation')
 off,body=read(START,END-START)
 return {'target_sha256':SHA,'start':hex(START),'end':hex(END),'bytes':len(body),'offset':off,'body_sha256':hashlib.sha256(body).hexdigest(),'body_hex':body.hex(),'fde':f,'fde_raw':frame(f['fde']),'cie_raw':frame(f['cie']),'pins':{hex(k):v for k,v in PINS.items()},'relocations':rel,'suffix':{'va':'0x4659e5','hex':read(0x4659e5,3)[1].hex()},'normalization_masks':[]}
def main():
 a=argparse.ArgumentParser();a.add_argument('--target',type=Path,default=ROOT/'artifacts/node/115/hl-node');a.add_argument('--output',type=Path,required=True);a.add_argument('--objdump',required=True);a.add_argument('--readelf',required=True);args=a.parse_args()
 data=args.target.read_bytes();need(hashlib.sha256(data).hexdigest()==SHA,'input identity');result=analyze(data)
 # Mutations run below the public digest gate to exercise actual obligations.
 controls=[]
 for va in PINS:
  off=result['offset']+va-START;changed=bytearray(data);changed[off]^=1
  try:analyze(changed)
  except ValueError as e:controls.append({'mutation':hex(va),'rejected':str(e)})
  else:raise ValueError('pin corruption escaped')
 for label,off in [('suffix',next(s['offset']+0x4659e5-s['address'] for s in sections(data) if s['type']!=8 and s['address']<=0x4659e5<s['address']+s['size'])),('FDE range',result['fde_raw']['offset']+12),('relocation',next(iter(result['relocations'].values()))['offset']+16)]:
  changed=bytearray(data);changed[off]^=1
  try:analyze(changed)
  except ValueError as e:controls.append({'mutation':label,'rejected':str(e)})
  else:raise ValueError('metadata corruption escaped')
 target=str(args.target.resolve())
 cmd=[args.objdump,'--disassemble','--x86-asm-syntax=intel','--start-address='+hex(START),'--stop-address='+hex(END),target]
 raw=subprocess.check_output(cmd,text=True);raw=raw.replace(target,'artifacts/node/115/hl-node').rstrip('\n')+'\n'
 rows=[]
 for line in raw.splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+(.+)',line)
  if m:rows.append((int(m[1],16),bytes.fromhex(m[2]),m[3]))
 need(rows and rows[0][0]==START,'decode start');cursor=START
 for va,b,ins in rows:need(va==cursor,'decode continuity');need(data[result['offset']+va-START:result['offset']+va-START+len(b)]==b,'decode bytes');cursor+=len(b)
 need(cursor==END,'decode end');result['instruction_count']=len(rows)
 frames=subprocess.check_output([args.readelf,'--debug-dump=frames',target],text=True)
 blocks=frames.split('\n\n');selected=[x for x in blocks if re.search(r'pc=0*50de300\.\.0*50de518',x)]
 need(len(selected)==1,'native FDE confirmation')
 versions={'python':sys.version.split()[0],'objdump':subprocess.check_output([args.objdump,'--version'],text=True).splitlines()[0],'readelf':subprocess.check_output([args.readelf,'--version'],text=True).splitlines()[0]}
 args.output.mkdir(parents=True,exist_ok=False)
 for name,value in [('evidence.json',json.dumps(result,indent=2)+'\n'),('validation.json',json.dumps({'negative_controls':controls,'count':len(controls),'versions':versions,'captured_execution':False,'instruction_evaluation':False},indent=2)+'\n'),('owner.objdump.txt',raw),('owner.frames.txt',selected[0].rstrip('\n')+'\n')]: (args.output/name).write_text(value)
 print(json.dumps({'instructions':len(rows),'bytes':END-START,'negative_controls':len(controls)}))
if __name__=='__main__':main()
