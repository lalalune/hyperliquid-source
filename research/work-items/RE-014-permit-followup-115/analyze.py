"""Static empty-list follow-up relation; never executes capture or substitutes calls."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];PACKET=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
from ip_permit_state_static import read,parameters as acquisition_parameters
from fde_extents import fde_extents
import capstone
TARGET=ROOT/'artifacts/node/115/hl-node';SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS=[(0x5ce5310,0x5ce56ec,'f2dfba566a05745e7377ac7fce3da0abe1a5028523fa4305d112b812940a465a'),(0x4770f40,0x47710d9,'085721faf2d6da872af52d3a7d41f276d7e77f54dd112d73fe2ce593453d7c1a')]
ANCHORS=[(0x4771053,'4d8d7710'),(0x4771063,'be010000004c89f74c89f2'),(0x5ce5321,'4889d34889742408'),(0x5ce53c6,'488b5310'),(0x5ce54ad,'48ba0000000000000020'),(0x5ce54c0,'488d0c00f0490fc14e20'),(0x5ce54ca,'48d1e94801c14839d1'),(0x5ce54e5,'b00131c9f00fb00b')]

def parameters(data):
 for va,raw in ANCHORS:
  if read(data,va,len(bytes.fromhex(raw)))[1]!=bytes.fromhex(raw):raise ValueError('follow-up operand changed')
 p=acquisition_parameters(data)
 if p['capacity_shift']!=61 or p['cas_offset']!=48 or p['state_init_offset']!=48:raise ValueError('acquisition encoding changed')
 return dict(count=struct.unpack('<I',read(data,0x4771064,4)[1])[0],owner_to_lock=read(data,0x4771056,1)[1][0],queue_from_lock=read(data,0x5ce53c9,1)[1][0],state_from_lock=read(data,0x5ce54c9,1)[1][0],limit=struct.unpack('<Q',read(data,0x5ce54af,8)[1])[0],state_scale=2,acquire_delta=p['delta'])

def empty_relation(p,word):
 """Algebra for already-held lock, null list field and one successful XADD.
 Not a captured interpreter; all caller/atomic/no-alias preconditions are external.
 """
 if not 0<=word<1<<64:raise ValueError('raw u64 required')
 after=(word+p['state_scale']*p['count'])&((1<<64)-1)
 return dict(after=after,post_guard=(word>>1)+p['count']<p['limit'],low_bit_preserved=(after&1)==(word&1))

def analyze(data,authenticate=True):
 if authenticate and hashlib.sha256(data).hexdigest()!=SHA:raise ValueError('wrong pinned node115')
 p=parameters(data);raw=read(data,0x477106e,5)[1]
 if raw[0]!=0xe8 or 0x4771073+struct.unpack_from('<i',raw,1)[0]!=0x5ce5310:raise ValueError('follow-up call changed')
 for a,b,sha in OWNERS:
  if hashlib.sha256(read(data,a,b-a)[1]).hexdigest()!=sha:raise ValueError('owner instruction bytes changed')
 _,fdes,_=fde_extents(data);owners=[];cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
 for a,b,sha in OWNERS:
  fs=[f for f in fdes if (f['start'],f['end'])==(a,b)]
  if len(fs)!=1:raise ValueError('FDE extent changed')
  off,raw=read(data,a,b-a);rows=list(cs.disasm(raw,a))
  if sum(x.size for x in rows)!=b-a:raise ValueError('incomplete disassembly')
  unwind={}
  for name in ('fde','cie'):
   va=fs[0][name];n=struct.unpack('<I',read(data,va,4)[1])[0]+4;unwind[name]=dict(va=hex(va),raw_hex=read(data,va,n)[1].hex())
  owners.append(dict(start=hex(a),end=hex(b),file_offset=hex(off),bytes=b-a,sha256=sha,instructions=[dict(va=hex(x.address),raw=x.bytes.hex(),mnemonic=x.mnemonic,operands=x.op_str) for x in rows],unwind=unwind,scope='follow-up helper; empty-list route selected' if a==0x5ce5310 else 'existing acquisition caller context'))
 return dict(target_sha256=SHA,base='8fd8db680ec4bfef40996e5616bce3d5156d0b86',owners=owners,parameters=p,relation=dict(selected_count=1,lock_address='owner+0x10',null_field='owner+0x20',xadd_address='owner+0x30',xadd_addend=2,release='winning byte CMPXCHG1->0 at owner+0x10',normal_even_input_max=(1<<62)-4,constructor_capacity_domain=[1,(1<<61)-1],conditional_restore='if state remains2*n-2 after winning acquire and provider returns0, empty-list follow-up adds2 to restore2*n'),native_behavioral_comparisons=0,captured_process_executed=False,all_component_gates=False,limits='Conditional static path only; nonempty list, failed lock operations, provider effects, concurrent interference, callback dispatch, high-word post-write guard failures, cleanup and unwind remain open. No unconditional refund, whole-helper or whole-caller equivalence.')

def generate(out):
 if out.exists():raise ValueError('output must be new')
 report=analyze(TARGET.read_bytes());out.mkdir(parents=True);(out/'records.json').write_text(json.dumps(report,indent=2)+'\n');(out/'instructions.tsv').write_text(''.join(f"{r['va']}\t{r['raw']}\t{r['mnemonic']}\t{r['operands']}\n" for o in report['owners'] for r in o['instructions']));return report
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();r=generate(a.out);print(json.dumps(dict(bytes=sum(x['bytes'] for x in r['owners']),instructions=sum(len(x['instructions']) for x in r['owners']),parameters=r['parameters'],native_behavioral_comparisons=0)))
