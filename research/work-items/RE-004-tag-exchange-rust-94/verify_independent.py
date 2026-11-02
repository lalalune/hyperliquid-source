import gzip,hashlib,json,struct
from pathlib import Path
root=Path(__file__).resolve().parents[3];p=root/'research/work-items/RE-004-tag-exchange-rust-94'
sha=lambda b:hashlib.sha256(b).hexdigest()
def need(c,m):
 if not c:raise ValueError(m)
a=gzip.decompress((p/'inputs.bin.gz').read_bytes());e=gzip.decompress((p/'expected.bin.gz').read_bytes());f=json.loads((p/'frozen.json').read_text());rows=list(struct.iter_unpack('<QQQ',a));got=list(struct.iter_unpack('<QQQQ',e));table=bytes([0,1,2]+[1]*253);mask=2**64-1
need(len(rows)==len(got)==76240,'framing/count');pairs=set();counts={'high_tag_bits':0,'high_old_bit':0,'wrapped_field_address':0,'stored_zero':0,'stored_one':0,'stored_two':0}
for i,((tag,obj,old),actual) in enumerate(zip(rows,got)):
 need(old<=255,'oldbyte');v=table[tag&255];want=(old,0,(obj+16)&mask,v)
 need(actual==want,f'value mismatch {i}');pairs.add((tag&255,old));counts['high_tag_bits']+=tag>255;counts['high_old_bit']+=old>=128;counts['wrapped_field_address']+=obj>mask-16;counts[['stored_zero','stored_one','stored_two'][v]]+=1
need(len(pairs)==65536,'pairs');need(sha(a)==f['inputs_sha256'] and sha(e)==f['expected_sha256'],'frozen hashes')
need(all(f[k]==v for k,v in counts.items()),'coverage counters')
b=(root/'artifacts/node/94/hl-node').read_bytes();need(sha(b)=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','target hash')
shoff=struct.unpack_from('<Q',b,40)[0];ents,num,stridx=struct.unpack_from('<HHH',b,58);need(ents==64,'ELF64 section shape');sections=[struct.unpack_from('<IIQQQQIIQQ',b,shoff+i*ents) for i in range(num)];ns=sections[stridx];names=b[ns[4]:ns[4]+ns[5]]
name=lambda s:names[s[0]:].split(b'\0',1)[0].decode()
def at(v,n):
 ss=[s for s in sections if s[1]!=8 and s[3]<=v and v+n<=s[3]+s[5]];need(len(ss)==1,'mapped extent');s=ss[0];return b[s[4]+v-s[3]:s[4]+v-s[3]+n],s
body,section=at(0x4f7fb20,24);need(body.hex()=='4080fe020f94c0fec031c94084f60fb6c00f44c1864710c3','complete raw body');need(at(0x4f7fb38,8)[0]==b'\xcc'*8,'padding')
rels=[]
for s in sections:
 if s[1]==4:
  need(s[9]==24 and s[5]%24==0,'RELA shape')
  for offset in range(s[4],s[4]+s[5],24):rels.append((offset,*struct.unpack_from('<QQq',b,offset)))
need(len(rels)==80300,'full RELA count');naming=[r for r in rels if r[3]==0x4f7fb20];need(len(naming)==36,'36 naming records');need(len(set(r[1] for r in naming))==36,'unique slots')
for offset,dest,info,addend in naming:
 need(info==8,'symbolzero relative');raw,s=at(dest,8);need(raw==bytes(8) and name(s)=='.data.rel.ro','slot file contents')
 writers=[r for r in rels if r[1]<dest+8 and dest<r[1]+8];need(writers==[(offset,dest,info,addend)],'unique full qword writer')
need(not any(r[1]<0x4f7fb40 and 0x4f7fb20<r[1]+8 for r in rels),'no body/padding relocation')
reviewed={str(x.relative_to(root)):sha(x.read_bytes()) for x in [root/'src/node94-tag-exchange/lib.rs',root/'src/node94-tag-exchange/input_only_driver.rs',root/'src/node94-tag-exchange/README.md',p/'PROOF.md',p/'oracle.py',p/'verify_static.py',p/'verify_rust.py',p/'frozen.json',p/'static.json']}
r={'reviewed_hashes':reviewed,'independent_fixture_relation':'Literal 256-byte normalization table, oldbyte identity, RCX literal zero, unbounded object+16 modulo64; no oracle import or Rust execution','cases':len(rows),'complete_low_tag_old_byte_pairs':len(pairs),'fixture_mismatches':0,'recalculated_counts':counts,'raw_body_hex':body.hex(),'raw_body_sha256':sha(body),'independent_ELF_parser':'struct-only ELF64 section and RELA parsing, no packet parser import','rela_records':len(rels),'unique_entry_slots':len(naming),'all_slots_single_writer':True,'primary_sources':[{'url':'https://cdrdv2-public.intel.com/671143/334569-sdm-vol-2d.pdf','pages':'6-28 through 6-29','finding':'Memory XCHG invokes locking regardless of LOCK prefix; opcode86 is byte exchange.'},{'url':'https://raw.githubusercontent.com/rust-lang/rust/1.94.1/library/core/src/sync/atomic.rs','finding':'Reviewed atomic access discipline and byte swap/SeqCst contract.'}],'captured_execution':False,'native_replay':False,'conclusion':'No blocking defect in library, full-register proof, isolated value oracle, relocation closure, or explicit finite concurrency/IR qualification scope.'}
print(json.dumps(r,indent=2,sort_keys=True))
