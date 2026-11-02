"""Re-export three authenticated node94 FDEs with Capstone and GNU (MIT)."""
import argparse,gzip,hashlib,json,pathlib,re,struct,subprocess,sys
ap=argparse.ArgumentParser()
ap.add_argument('--binary',type=pathlib.Path,required=True)
ap.add_argument('--objdump',type=pathlib.Path,required=True)
ap.add_argument('--capstone-dir',type=pathlib.Path,required=True)
ap.add_argument('--out',type=pathlib.Path,required=True)
a=ap.parse_args()
if a.out.exists():raise ValueError('Use a new output directory; retained evidence is never overwritten')
sys.path.insert(0,str(a.capstone_dir))
import capstone
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[3]/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
data=a.binary.read_bytes();sha=hashlib.sha256(data).hexdigest()
if len(data)!=91774280 or sha!='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f':raise ValueError('Wrong target')
secs=sections(data);by={s['name']:s for s in secs};_,fdes=eh_frame_records(data,secs)
def fileoff(va,size=1):
 offsets={s['offset']+va-s['address'] for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']}
 if len(offsets)!=1:raise ValueError('VA is not uniquely file backed')
 return offsets.pop()
rels={};s=by['.rela.dyn']
for pos in range(s['offset'],s['offset']+s['size'],24):
 where,info,add=struct.unpack_from('<QQq',data,pos)
 if info&0xffffffff==8:rels[where]=add
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
results=[];rawexports=[]
for start in (0x4741dc0,0x471e1e0,0x4721440):
 owners=[f for f in fdes if f['start']==start]
 if len(owners)!=1:raise ValueError('Missing unique FDE')
 f=owners[0];end=f['end'];off=fileoff(start,end-start);raw=data[off:off+end-start]
 ins=list(md.disasm(raw,start))
 if not ins or sum(i.size for i in ins)!=len(raw):raise ValueError('Incomplete decode')
 print('$ export '+hex(start),flush=True)
 p=subprocess.run([str(a.objdump),'-d','--wide','--insn-width=16','-M','intel','--start-address='+str(start),'--stop-address='+str(end),str(a.binary)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=20)
 if p.stderr:raise ValueError('Unexpected GNU diagnostics: inspect locally')
 pairs=[]
 for line in p.stdout.decode('utf8').splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
  if m and start<=int(m[1],16)<end:pairs.append((int(m[1],16),bytes.fromhex(m[2])))
 if pairs!=[(i.address,bytes(i.bytes)) for i in ins]:raise ValueError('Decoder disagreement')
 records=[];calls=[]
 for i in ins:
  row={'va':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}
  if i.mnemonic in ('call','jmp') and len(i.bytes)==6 and i.bytes[:2] in (b'\xff\x15',b'\xff\x25'):
   slot=i.address+i.size+struct.unpack('<i',i.bytes[2:])[0]
   row['slot']=hex(slot);row['relativeTarget']=hex(rels[slot]) if slot in rels else None
   if slot in rels:
    t=rels[slot];fo=[x for x in fdes if x['start']<=t<x['end']]
    row['targetFDEs']=[{k:hex(x[k]) for k in ('start','end','fde')} for x in fo]
   calls.append(row.copy())
  records.append(row)
 results.append({'targetSha256':sha,'targetExecuted':False,'sourceHead':'e5c9b6436876b2a4a39daef813171f9879317699','start':hex(start),'end':hex(end),'fde':hex(f['fde']),'bodySha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'instructionCount':len(ins),'allDecoderPairsAgree':True,'instructions':records,'indirectTransfers':calls,'question':'What observable byte/dataflow constraints are added by the file tracker branch beyond previously mapped optional roots and chain-byte check?','status':'static transcript and resolved relative slots only; no helper semantics or completed reconstruction claim'})
 rawexports.append(p.stdout.replace(str(a.binary).encode(),b'<node94>'))
a.out.mkdir(parents=True)
for name,raw in [('disassembly.json.gz',json.dumps(results,indent=2).encode()),('gnu.objdump.txt.gz',b'\n'.join(rawexports))]:
 (a.out/name).write_bytes(gzip.compress(raw,mtime=0))
version=subprocess.check_output([str(a.objdump),'--version'],timeout=10).decode().splitlines()[0]
report={'python':sys.version.split()[0],'capstoneWrapper':capstone.__version__,'capstoneAPI':list(capstone.cs_version()),'objdump':version,'targetSha256':sha,'targetExecuted':False,'ranges':3,'bytes':sum(r['bytes'] for r in results),'instructions':sum(r['instructionCount'] for r in results),'normalization':'Only local input pathname in GNU header; no instruction masks. gzip mtime0. Archive bytes require compatible Python/compressor/disassembler rendering.','exports':{n:{'sha256':hashlib.sha256((a.out/n).read_bytes()).hexdigest(),'bytes':(a.out/n).stat().st_size} for n in ('disassembly.json.gz','gnu.objdump.txt.gz')}}
(a.out/'export-report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps(report),flush=True)
