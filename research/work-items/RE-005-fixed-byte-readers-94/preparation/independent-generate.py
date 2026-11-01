"""Pre-Rust immutable-byte/budget oracle; no machine instructions or target execution."""
from pathlib import Path
from collections import Counter
import hashlib,json,subprocess,datetime
BASE=Path(__file__).parent
U=(1<<64)-1;M=(1<<32)-1
sha=lambda b:hashlib.sha256(b).hexdigest()
compact=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True)
hexbytes=lambda xs:''.join(format(x,'02x')for x in xs)
def le64(n):
 out=[]
 for _ in range(8):n,r=divmod(n,256);out.append(r)
 assert n==0
 return out
plans=[];seen=set();families={};selected={}
def add(family,w,mode,limit,charged,wire,initial=None,calls=1,name=None):
 assert w in(20,32) and 0<=mode<=M and 0<=limit<=U and 0<=charged<=U and 1<=calls<=4
 wire=tuple(wire);initial=tuple(initial if initial is not None else ((19+37*i)%256 for i in range(w+1)))
 assert len(initial)==w+1 and all(0<=v<256 for v in wire+initial)
 key=(w,mode,limit,charged,wire,initial,calls);stats=families.setdefault(family,{'attempts':0,'distinct_added':0});stats['attempts']+=1
 if key in seen:return
 seen.add(key);stats['distinct_added']+=1;ident='f'+str(w)+'_'+format(len(plans),'06d')
 plan={'id':ident,'width':w,'mode':mode,'limit':limit,'charged':charged,'wire':wire,'initial_output':initial,'calls':calls}
 plans.append(plan)
 if name:selected[name]=ident

def oracle(plan):
 # A mathematical transaction on an immutable sequence and byte-assignment map.
 # The unbounded candidate sum is not a simulated native wrapping ADD.
 n=plan['width'];wire=plan['wire'];count=plan['charged'];cursor=0;output=list(plan['initial_output'])
 for call in range(1,plan['calls']+1):
  candidate=count+n
  permitted=plan['mode']!=1 or (candidate<=U and candidate<=plan['limit'])
  if plan['mode']==1 and candidate<=U:count=candidate
  before=cursor;additional=None
  if not permitted:kind='charge'
  elif len(wire)-cursor<n:kind='end';additional=n-(len(wire)-cursor)
  else:kind='value';cursor+=n
  assignments={}
  if kind=='value':
   assignments[0]=18 if n==20 else 0
   assignments.update({1+i:wire[before+i]for i in range(n)})
  elif n==20:
   assignments[0]=2 if kind=='charge'else 0
   if kind=='end':assignments.update({8+i:v for i,v in enumerate(le64(additional))})
  else:
   assignments[0]=1;assignments[8]=2 if kind=='charge'else 0
   if kind=='end':assignments.update({16+i:v for i,v in enumerate(le64(additional))})
  output=[assignments.get(i,v)for i,v in enumerate(output)]
  yield {'additional':additional,'call':call,'charged':count,'consumed':cursor-before,'cursor':cursor,'id':plan['id'],'kind':kind,'limit':plan['limit'],'mode':plan['mode'],'output':hexbytes(output),'remaining':len(wire)-cursor,'tail':hexbytes(wire[cursor:])}

def serialize(plan):
 # The actual client receives only this raw eight-field stimulus, not a plan or oracle.
 return '|'.join([plan['id'],str(plan['width']),str(plan['mode']),format(plan['limit'],'016x'),format(plan['charged'],'016x'),hexbytes(plan['wire']),hexbytes(plan['initial_output']),str(plan['calls'])])+'\n'

for n in(20,32):
 pat=lambda length:[(11+29*i)%256 for i in range(length)]
 add('named',n,2,0,U,pat(n),calls=1,name=f'{n}_disabled_exact')
 add('named',n,1,U,U-n+1,pat(n),name=f'{n}_overflow_unchanged')
 add('named',n,1,U,U-n,pat(n),calls=2,name=f'{n}_exact_max_then_overflow')
 add('named',n,1,n+6,7,pat(n),name=f'{n}_limit_exceeded_retains_charge')
 add('named',n,1,U,7,pat(n-1),calls=4,name=f'{n}_shortage_charges_repeated')
 add('named',n,0,0,U,pat(n-1),calls=4,name=f'{n}_disabled_shortage')
 add('named',n,1,4*n,0,pat(3*n+1),calls=4,name=f'{n}_success_then_shortage')
 add('named',n,1,2*n,0,pat(3*n+1),calls=4,name=f'{n}_success_then_charge')
 # Raw equality discriminator: all byte values at every mode byte position.
 modes={0,1,2,M,0x10000001,0x80000001,0xffffff01}
 modes.update(v<<(8*i)for i in range(4)for v in range(256))
 modes.update((1<<i)^1 for i in range(32))
 for mode in sorted(modes):
  for length in(0,n-1,n,n+1):add('raw_mode_byte_basis',n,mode,0,U,pat(length),calls=2)
 # Every 64-bit power boundary and the exact N-byte overflow frontier.
 counts={0,1,n-1,n,n+1,U-n-1,U-n,U-n+1,U-1,U}
 counts.update(v for bit in range(64)for v in((1<<bit)-1,1<<bit,(1<<bit)+1)if 0<=v<=U)
 for count in sorted(counts):
  candidate=count+n;limits={0,U}
  limits.update(v for v in(candidate-1,candidate,candidate+1)if 0<=v<=U)
  for limit in sorted(limits):
   for length in(0,n-1,n,n+1,2*n+1):add('u64_budget_frontiers',n,1,limit,count,pat(length),calls=4)
 # All possible source octets at each copied position, then a second shortage.
 for pos in range(n):
  for value in range(256):
   wire=pat(n+3);wire[pos]=value
   add('copied_payload_octet_basis',n,0,0,U,wire,calls=2)
 # Every shortage length and every octet value, with immutable tails retained.
 for length in range(n):
  for value in range(256):add('short_input_octets',n,0,0,U,[value]*length,calls=2)
 # Every possible old byte simultaneously at every output position, on all routes.
 for value in range(256):
  initial=[value]*(n+1)
  for route in('value','end','overflow','limit'):
   mode,limit,count,length={'value':(0,0,U,n),'end':(0,0,U,n-1),'overflow':(1,U,U-n+1,n),'limit':(1,n-1,0,n)}[route]
   add('output_all_octets',n,mode,limit,count,pat(length),initial)
 # Independent output-position mutations detect erroneous neighboring stores.
 for pos in range(n+1):
  for value in(0,1,2,18,127,255):
   initial=[(19+37*i)%256 for i in range(n+1)];initial[pos]=value
   for route in('value','end','overflow','limit'):
    mode,limit,count,length={'value':(0,0,U,n),'end':(0,0,U,n-1),'overflow':(1,U,U-n+1,n),'limit':(1,n-1,0,n)}[route]
    add('output_position_basis',n,mode,limit,count,pat(length),initial)
 # Whole streams around every four-call consumption and charge boundary.
 for length in range(4*n+3):
  for limit in sorted({0,1,n-1,n,n+1,2*n-1,2*n,2*n+1,3*n,4*n,U}):
   add('four_call_prefix_retention',n,1,limit,0,pat(length),calls=4)
  for mode in(0,2,M):add('four_call_disabled_modes',n,mode,0,U,pat(length),calls=4)

# Authority is an immutable input declaration. It is never passed to the Rust client.
authority={'schema':'fixed217-pre-rust-authority-v1','domain_proof_sha256':sha((BASE/'PROOF.md').read_bytes()),'native_review_sha256':sha((BASE/'NATIVE-REVIEW.json').read_bytes()),'cases':plans}
(BASE/'authority.json').write_text(compact(authority)+'\n')
counts=Counter();width_counts=Counter();observations=0
with (BASE/'inputs.txt').open('w')as inputs,(BASE/'expected.jsonl').open('w')as expected:
 for plan in plans:
  inputs.write(serialize(plan));width_counts[plan['width']]+=1
  for row in oracle(plan):expected.write(compact(row)+'\n');counts[row['kind']]+=1;observations+=1
need=lambda v,m:None if v else (_ for _ in()).throw(ValueError(m))
ROOT=Path('/tmp/hl-resume-20261101/arithmetic-56c');need(not(ROOT/'src/node94-fixed-byte-readers').exists(),'Rust appeared before freeze')
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip();status=subprocess.check_output(['git','status','--porcelain=v1'],cwd=ROOT).decode();need(head=='56c0ec672bd8fdcfaa80f2db700a61e6240b3663'and not status,'pre-source author view changed')
files={name:{'bytes':(BASE/name).stat().st_size,'sha256':sha((BASE/name).read_bytes())}for name in['PROOF.md','NATIVE-REVIEW.json','generate.py','authority.json','inputs.txt','expected.jsonl']}
freeze={'schema':'fixed217-pre-rust-freeze-v1','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'basis':'Independent complete native/domain proof and pure immutable-byte/unbounded-integer oracle; no target execution, CPU/PC evaluator or new Rust source read.','author_head':head,'author_clean':not status,'new_source_path_absent':True,'stimuli':len(plans),'distinct_complete_inputs_excluding_id':len(seen),'observations':observations,'width_stimuli':dict(width_counts),'outcome_observations':dict(counts),'construction_families':families,'named_cases':selected,'input_protocol':'id|width20or32|rawmode_decimal_u32|limit16hex|counter16hex|wirehex|initialized_output42or66hex|calls1..4','output_protocol':{'serialization':'sorted keys, compact separators, ensure_ascii=True, one LF per JSON row','keys':['additional','call','charged','consumed','cursor','id','kind','limit','mode','output','remaining','tail'],'integer_domains':'charged/limit full exactu64 JSON integers; mode exactu32; call/consumed/cursor/remaining nonnegative integers','kind':'own logical value/end/charge names, not nominal native enum','additional':'integer only for end, otherwise null','output_and_tail':'complete lowercase hex, result reused across calls'},'files':files,'limits':['All-domain theorem has initialized separated memory premises; finite corpus is not native execution or a census of every u32/u64/input string.','Only the actual raw eight-field inputs reach the future client; plans/expectations and roles remain outside it.','No original nominal ABI, padding initialization, arbitrary aliases, faults/unwind, caller/whole-node equivalence, byte identity or component gate claim.']}
(BASE/'FREEZE.json').write_text(json.dumps(freeze,sort_keys=True,indent=2)+'\n')
print(json.dumps({'stimuli':len(plans),'observations':observations,'outcomes':dict(counts),'freeze_sha256':sha((BASE/'FREEZE.json').read_bytes()),'input_sha256':files['inputs.txt']['sha256'],'expected_sha256':files['expected.jsonl']['sha256']}))
