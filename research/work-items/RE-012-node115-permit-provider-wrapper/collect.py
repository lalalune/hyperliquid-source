#!/usr/bin/env python3
"""Digest-bound static native export; no captured execution or instruction evaluator."""
import argparse,hashlib,json,re,struct,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
BASE='05bc2de303c05525b71e7e257426e741bc66a390'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CONFIG={'ranges': [(74927184, 74927787)], 'pins': {'74927212': '807e2000', '74927216': '0f84ac010000', '74927289': '4084ed', '74927298': '48c7c078fbffff', '74927305': '6448833800', '74927385': '4883f801', '74927568': '486bf038', '74927587': '488d7270', '74927619': '41b901000000', '74927630': '0f10442448', '74927635': '0f1103', '74927650': '498b16', '74927661': '498b4610', '74927689': '41b901000000', '74927700': '0f10442448', '74927705': '0f1103', '74927708': '4889d8'}, 'data': [(8263105, 59), (4400752, 40), (105473528, 24)]}
RANGES=[tuple(x) for x in CONFIG['ranges']]
PINS={int(k):bytes.fromhex(v) for k,v in CONFIG['pins'].items()}
def need(ok,why):
 if not ok:raise ValueError(why)
def analyze(data,expected=None):
 ss=sections(data)
 def read(va,size):
  ms=[s for s in ss if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']]
  need(len(ms)==1,'unique file mapping');s=ms[0];off=s['offset']+va-s['address'];return off,data[off:off+size]
 for va,b in PINS.items():need(read(va,len(b))[1]==b,'semantic instruction pin '+hex(va))
 _,fs=eh_frame_records(data);owners=[]
 def rawframe(va):
  off,b=read(va,4);size=struct.unpack('<I',b)[0]+4;return {'va':hex(va),'offset':off,'raw':read(va,size)[1].hex()}
 for start,end in RANGES:
  ms=[f for f in fs if f['start']==start];need(len(ms)==1 and ms[0]['end']==end,'exact FDE bounds');f=ms[0]
  off,b=read(start,end-start);owners.append({'start':hex(start),'end':hex(end),'bytes':len(b),'offset':off,'sha256':hashlib.sha256(b).hexdigest(),'raw':b.hex(),'fde':f,'fde_raw':rawframe(f['fde']),'cie_raw':rawframe(f['cie'])})
 selected=[{'va':hex(va),'offset':read(va,size)[0],'raw':read(va,size)[1].hex()} for va,size in CONFIG['data']]
 if expected is not None:
  need(selected==expected['selected_data'],'selected data bytes')
  need([o['fde_raw'] for o in owners]==[o['fde_raw'] for o in expected['owners']],'raw FDE record')
 return {'base':BASE,'target_sha256':SHA,'owners':owners,'selected_data':selected,'pins':{hex(k):v.hex() for k,v in PINS.items()},'normalization_masks':[]}
def validate_writers(data,expected):
 ss=sections(data)
 for r in expected:
  hits=[]
  for sec in ss:
   if sec['type']==4:
    for pos in range(sec['offset'],sec['offset']+sec['size'],24):
     slot,kind,add=struct.unpack_from('<QQq',data,pos)
     if slot==int(r['slot'],16):hits.append((kind & 0xffffffff,kind>>32,add))
  need(hits==[(r['type'],r['symbol_index'],r['addend'])],'selected relocation binding '+r['slot'])
def main():
 p=argparse.ArgumentParser();p.add_argument('--target',type=Path,default=ROOT/'artifacts/node/115/hl-node');p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',required=True);p.add_argument('--readelf',required=True);a=p.parse_args()
 data=a.target.read_bytes();need(len(data)==105896032 and hashlib.sha256(data).hexdigest()==SHA,'target identity');need(not a.output.exists(),'new output required');record=analyze(data)
 ss=sections(data)
 def off(va):
  s=next(s for s in ss if s['type']!=8 and s['address']<=va<s['address']+s['size']);return s['offset']+va-s['address']
 controls=[]
 for label,offset in [('pin '+hex(va),off(va)) for va in PINS]+[('data '+row['va'],row['offset']) for row in record['selected_data']]+[('FDE '+o['start'],o['fde_raw']['offset']+12) for o in record['owners']]:
  changed=bytearray(data);changed[offset]^=1
  try:analyze(changed,record)
  except (ValueError,struct.error) as e:controls.append({'mutation':label,'rejected':str(e)})
  else:raise ValueError('corruption escaped: '+label)
 exports={};allrows=[];rip=[];edges=[]
 with tempfile.TemporaryDirectory(prefix='node115-static-',dir=ROOT/'work') as temp:
  snapshot=Path(temp)/'input.elf';snapshot.write_bytes(data)
  frameall=subprocess.check_output([a.readelf,'--debug-dump=frames',str(snapshot)],text=True)
  for start,end in RANGES:
   text=subprocess.check_output([a.objdump,'-d','--x86-asm-syntax=intel','--start-address='+hex(start),'--stop-address='+hex(end),str(snapshot)],text=True).replace(str(snapshot),'artifacts/node/115/hl-node').rstrip('\n')+'\n'
   rows=[];cursor=start
   for line in text.splitlines():
    m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+(.+)',line)
    if not m:continue
    va=int(m[1],16);raw=bytes.fromhex(m[2]);ins=m[3];need(va==cursor,'contiguous decode');need(data[off(va):off(va)+len(raw)]==raw,'native instruction bytes');cursor+=len(raw);rows.append({'va':hex(va),'raw':raw.hex(),'instruction':ins})
    if 'rip' in ins:
     t=re.search(r'#\s*(0x[0-9a-f]+)',ins);need(t is not None,'RIP target printed');target=int(t[1],16);indices=[i for i in range(len(raw)-3) if va+len(raw)+int.from_bytes(raw[i:i+4],'little',signed=True)==target];need(len(indices)==1,'unique RIP displacement');rip.append({'site':hex(va),'raw':raw.hex(),'target':hex(target),'displacement_offset':indices[0]})
    if len(raw)==5 and raw[0] in (0xe8,0xe9):edges.append({'site':hex(va),'kind':'call' if raw[0]==0xe8 else 'jump','target':hex(va+5+int.from_bytes(raw[1:],'little',signed=True)),'raw':raw.hex()})
   need(cursor==end,'full owner decode endpoint');allrows+=rows;exports[hex(start)+'.objdump.txt']=text
   blocks=[b for b in frameall.split('\n\n') if re.search('pc=0*'+format(start,'x')+r'\.\.0*'+format(end,'x'),b)];need(len(blocks)==1,'independent native FDE');exports[hex(start)+'.frames.txt']=blocks[0].rstrip('\n')+'\n'
 slots={int(r['target'],16) for r in rip};rel=[]
 for s in ss:
  if s['type']==4:
   for pos in range(s['offset'],s['offset']+s['size'],24):
    slot,kind,add=struct.unpack_from('<QQq',data,pos)
    if slot in slots:rel.append({'slot':hex(slot),'type':kind & 0xffffffff,'symbol_index':kind>>32,'addend':add,'offset':pos,'raw':data[pos:pos+24].hex()})
 need(len({r['slot'] for r in rel})==len(rel),'unique selected relocations')
 # Normal and mutated inputs use the same parsed binding checker below identity.
 validate_writers(data,rel)
 for r in rel:
  changed=bytearray(data);changed[r['offset']+16]^=1
  try:validate_writers(changed,rel)
  except ValueError as e:controls.append({'mutation':'relocation '+r['slot'],'rejected':str(e),'control_kind':'parsed relocation binding lock'})
  else:raise ValueError('relocation mutation escaped')
 record.update({'native_rows':allrows,'native_instruction_count':len(allrows),'rip_references':rip,'direct_edges':edges,'relocations':rel})
 versions={'python':sys.version.split()[0],'objdump':subprocess.check_output([a.objdump,'--version'],text=True).splitlines()[0],'readelf':subprocess.check_output([a.readelf,'--version'],text=True).splitlines()[0]}
 exports['evidence.json']=json.dumps(record,indent=2)+'\n';exports['validation.json']=json.dumps({'controls':controls,'count':len(controls),'versions':versions,'captured_execution':False,'instruction_evaluation':False,'native_input':'private byte-identical authenticated snapshot; only path and terminal newlines normalized'},indent=2)+'\n'
 a.output.mkdir(parents=True)
 for name,value in exports.items():(a.output/name).write_text(value)
 print(json.dumps({'bytes':sum(e-s for s,e in RANGES),'FDEs':len(RANGES),'instructions':len(allrows),'negative_controls':len(controls)}))
if __name__=='__main__':main()
