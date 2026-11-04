#!/usr/bin/env python3
"""Read-only independent selected CPU115 static/value review; no packet imports."""
import argparse,hashlib,json,math,re,struct,subprocess,os
from pathlib import Path
A=argparse.ArgumentParser();A.add_argument('--root',type=Path,required=True);A.add_argument('--out',type=Path,required=True);a=A.parse_args();a.out.mkdir(parents=True,exist_ok=True)
root=a.root.resolve();packet=root/'research/work-items/RE-002-cpu-quota-115';target=root/'artifacts/node/115/hl-node';data=target.read_bytes()
def check(ok,msg):
 if not ok:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def saved(p):return sha(p.read_bytes())
check(sha(data)=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','target digest')
check(data[:6]==b'\x7fELF\x02\x01','ELF')
sho=struct.unpack_from('<Q',data,40)[0];es,n,si=struct.unpack_from('<HHH',data,58)
sects=[struct.unpack_from('<IIQQQQIIQQ',data,sho+i*es) for i in range(n)]
ns=sects[si];names=data[ns[4]:ns[4]+ns[5]]
def cstr(b,i):return b[i:b.index(0,i)].decode()
S={cstr(names,s[0]):s for s in sects}
def at(va,n):
 ss=[s for s in sects if s[1]!=8 and s[3]<=va and va+n<=s[3]+s[5]];check(len(ss)==1,'unambiguous mapping');s=ss[0];o=s[4]+va-s[3];return data[o:o+n]
R=[]
for s in sects:
 if s[1]==4:
  check(s[9]==24,'RELA stride')
  for o in range(s[4],s[4]+s[5],24):
   dest,info,addend=struct.unpack_from('<QQq',data,o);R.append(dict(dest=dest,info=info,addend=addend,offset=o))
records=json.loads((packet/'static/records.json').read_text());commands=[];body_results=[]
h=S['.eh_frame_hdr'];hb=data[h[4]:h[4]+h[5]];check(hb[:4]==bytes([1,27,3,59]),'index encoding');cnt=struct.unpack_from('<I',hb,8)[0]
fmap={h[3]+v[0]:h[3]+v[1] for i in range(cnt) for v in [struct.unpack_from('<ii',hb,12+8*i)]}
for b in records['bodies']:
 start=int(b['start'],16);end=int(b['end_exclusive'],16);raw=at(start,end-start)
 check(sha(raw)==b['sha256'],'body hash');fv=int(b['fde_va'],16);check(fmap[start]==fv,'FDE index')
 fb=at(fv,4+struct.unpack('<I',at(fv,4))[0]);check(fb.hex()==b['fde_hex'],'FDE bytes')
 cv=fv+4-struct.unpack_from('<I',fb,4)[0];check(cv==int(b['cie_va'],16),'CIE link');cb=at(cv,4+struct.unpack('<I',at(cv,4))[0]);check(cb.hex()==b['cie_hex'],'CIE bytes')
 check(fv+8+struct.unpack_from('<i',fb,8)[0]==start and struct.unpack_from('<i',fb,12)[0]==end-start,'FDE extent')
 check(cb[8:]==bytes.fromhex(b['cie_hex'])[8:] and b'\x1b' in cb,'observed CIE encoding bytes')
 check(not any(r['dest']<end and start<r['dest']+8 for r in R),'unexpected body relocation writer')
 cmd=[os.environ.get('GNU_OBJDUMP','objdump'),'-d','-w','-M','intel',f'--start-address={start}',f'--stop-address={end}',str(target)]
 r=subprocess.run(cmd,capture_output=True);r.stdout=r.stdout.replace(str(target).encode(),b'<authenticated-node115>');r.stderr=r.stderr.replace(str(target).encode(),b'<authenticated-node115>');(a.out/(b['name']+'.gnu.stdout')).write_bytes(r.stdout);(a.out/(b['name']+'.gnu.stderr')).write_bytes(r.stderr);check(r.returncode==0,'GNU command')
 rows=[]
 for line in r.stdout.decode().splitlines():
  m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})(?:\s|$)',line)
  if m:rows.append((int(m[1],16),bytes.fromhex(m[2])))
 pos=start
 for va,bb in rows:check(va==pos,'GNU contiguity');pos+=len(bb)
 check(pos==end and b''.join(x[1] for x in rows)==raw,'GNU whole-body byte completeness');check(len(rows)==b['instructions'],'GNU instruction count')
 commands.append(dict(argv=[x.replace(str(target),"<authenticated-node115>")for x in cmd],returncode=r.returncode,stdout_sha256=sha(r.stdout),stderr_sha256=sha(r.stderr)));body_results.append(dict(name=b['name'],start=hex(start),end=hex(end),bytes=len(raw),instructions=len(rows),sha256=sha(raw)))
bindings=[]
for b in records['selected_bindings']:
 slot=int(b['slot'],16);writers=[r for r in R if r['dest']<slot+8 and slot<r['dest']+8];check(len(writers)==1,'unique whole slot writer');r=writers[0]
 check(r['dest']==slot and r['info']&0xffffffff==b['kind'] and r['info']>>32==b['symbol_index'] and r['addend']==b['addend'],'binding relation');check(data[r['offset']:r['offset']+24].hex()==b['record_hex'],'RELA bytes')
 if b['kind']==6:
  ss=S['.dynsym'];nameix=struct.unpack_from('<I',data,ss[4]+b['symbol_index']*ss[9])[0];st=sects[ss[6]];sy=cstr(data[st[4]:st[4]+st[5]],nameix);check(sy==b['symbol'],'dynamic import name')
 bindings.append(b)
for va,hexbytes in records['constants'].items():check(at(int(va,16),len(bytes.fromhex(hexbytes))).hex()==hexbytes,'constant')
check(at(0x64fdfb0,4)==b'\x03\0\0\0','once initial3')
pho=struct.unpack_from('<Q',data,32)[0];pe,pn=struct.unpack_from('<HH',data,54);ph=[struct.unpack_from('<IIQQQQQQ',data,pho+i*pe) for i in range(pn)]
bss=[p for p in ph if p[0]==1 and p[1]&2 and p[3]+p[5]<=0x64fff08 and 0x64fff10<=p[3]+p[6]];check(len(bss)==1,'cache writable zero tail')
qrows=json.loads((packet/'oracle/vectors.json').read_text());arows=json.loads((packet/'oracle/affinity-vectors.json').read_text());differences=[]
def bits(v):return struct.pack('>d',v).hex()
for i,row in enumerate(qrows):
 q,p,l=row['quota'],row['period'],row['logical']
 if p==0:expected=dict(quota_bits=None,period_bits=None,ratio_bits=None,rounded_quota=None,store=None)
 else:
  qf,pf=float(q),float(p);v=qf/pf;vceil=min((1<<64)-1,math.ceil(v));expected=dict(quota_bits=bits(qf),period_bits=bits(pf),ratio_bits=bits(v),rounded_quota=vceil,store=min(l,vceil) if vceil else None)
 if any(row[k]!=v for k,v in expected.items()):differences.append(dict(kind='quota',index=i,expected=expected,record=row))
for i,row in enumerate(arows):
 if row['mask'] is None:count=1 if row['sysconf']<2 else row['sysconf']
 else:
  count=0
  for word in row['mask']:
   while word:word &= word-1;count+=1
 result=row['cache'] if row['cache']!=0 else count
 if (row['logical'],row['cached_or_logical'])!=(count,result):differences.append(dict(kind='affinity',index=i))
check(not differences,'independent values')
N=json.loads((packet/'native/result.json').read_text());source=root/'src/node115-cpu-quota/src/lib.rs';check(saved(source)==N['source_sha256'],'native source hash')
check(len(N['correct_builds'])==4 and all(x['cases']==len(qrows)+len(arows) and x['output_sha256']==N['expected_sha256'] for x in N['correct_builds']),'recorded builds')
result=dict(status='pass',target_sha256=sha(data),reviewed_source_sha256=saved(source),contract_sha256=saved(packet/'CONTRACT.md'),bodies=body_results,body_bytes=sum(x['bytes'] for x in body_results),instructions=sum(x['instructions'] for x in body_results),relas_scanned=len(R),unique_bindings=bindings,constant_windows=len(records['constants']),quota_cases=len(qrows),affinity_cases=len(arows),independent_value_mismatches=0,value_method='CPython integer-to-double and hardware double divide plus math.ceil; Kernighan cleared-low-bit popcount and signed branch formula. No oracle imports.',fixtures={str(p.relative_to(packet)):saved(p) for p in [packet/'oracle/vectors.json',packet/'oracle/affinity-vectors.json']},native_result_sha256=saved(packet/'native/result.json'),limits=['No captured execution or instruction emulation','No independent native rebuild: existing result authenticated against current source, its execution remains author evidence','Selected FDE fields and exact CIE bytes checked, not independent full DWARF/LSDA semantics','No original num_cpus version or complete initializer/parser/Once/concurrency proof','Float review assumes ordinary RN binary64 and masked exceptions; no exception flags modeled'])
(a.out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
