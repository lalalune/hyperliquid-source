from pathlib import Path
import hashlib,json,struct,subprocess,re
R=Path('/tmp/hl-resume-20261101/formatter');O=Path(__file__).resolve().parent
raw=(R/'artifacts/node/94/hl-node').read_bytes();sha=lambda b:hashlib.sha256(b).hexdigest()
if len(raw)!=91774280 or sha(raw)!='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f':raise ValueError('target identity')
h=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
s=[struct.unpack_from('<IIQQQQIIQQ',raw,h[6]+i*h[11]) for i in range(h[12])]
ns=s[h[13]];names=raw[ns[4]:ns[4]+ns[5]]
def nm(k):return names[k:names.index(b'\0',k)].decode()
sec={nm(r[0]):r for r in s};ph=[struct.unpack_from('<IIQQQQQQ',raw,h[5]+i*h[9]) for i in range(h[10])]
def read(va,n):
 loads=[p for p in ph if p[0]==1 and p[3]<=va and va+n<=p[3]+p[5]]
 if len(loads)!=1:raise ValueError('mapping')
 p=loads[0];off=p[2]+va-p[3];return off,raw[off:off+n],p
hdr=sec['.eh_frame_hdr'];num=struct.unpack_from('<I',raw,hdr[4]+8)[0]
entries=[tuple(v+hdr[3] for v in struct.unpack_from('<ii',raw,hdr[4]+12+8*i)) for i in range(num)]
rel=[]
for q in s:
 if q[1]==4:
  if q[9]!=24 or q[5]%24:raise ValueError('rela')
  for k in range(q[4],q[4]+q[5],24):
   va,info,add=struct.unpack_from('<QQq',raw,k);rel.append({'slot':va,'type':info&0xffffffff,'symbol':info>>32,'addend':add,'record_file_offset':k})
records=[]
for start in (0x4eb6360,0x4eb64f0,0x1444a00):
 es=[e for e in entries if e[0]==start]
 if len(es)!=1:raise ValueError('unique FDE')
 _,fv=es[0];fo,_,_=read(fv,4);ln=struct.unpack_from('<I',raw,fo)[0];frame=raw[fo:fo+ln+4]
 co=fo+4-struct.unpack_from('<I',frame,4)[0];cl=struct.unpack_from('<I',raw,co)[0];cie=raw[co:co+cl+4]
 delta,size=struct.unpack_from('<iI',frame,8)
 if fv+8+delta!=start or cie[16]!=0x1b:raise ValueError('frame pointer encoding')
 off,body,load=read(start,size)
 name=hex(start)[2:]; (O/(name+'.bin')).write_bytes(body)
 argv=['/usr/bin/x86_64-linux-gnu-objdump','-D','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16','--adjust-vma='+str(start),name+'.bin']
 p=subprocess.run(argv,cwd=O,capture_output=True,check=True);(O/(name+'.stdout')).write_bytes(p.stdout);(O/(name+'.stderr')).write_bytes(p.stderr)
 rows=[]
 for line in p.stdout.decode().splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(.*)',line)
  if m:rows.append({'va':int(m[1],16),'raw':bytes.fromhex(m[2]).hex(),'asm':m[3]})
 if b''.join(bytes.fromhex(r['raw']) for r in rows)!=body:raise ValueError('complete native rows')
 calls=[r for r in rows if r['asm'].startswith('call')]
 record={'start':start,'end':start+size,'bytes':size,'file_offset':off,'sha256':sha(body),'PT_LOAD':load,'fde_va':fv,'fde_file_offset':fo,'fde_raw':frame.hex(),'cie_file_offset':co,'cie_raw':cie.hex(),'rows':rows,'calls':calls,'argv':argv,'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)}
 records.append(record)
data_records=[]
used_slots={0x576e470,0x576e118,0x576e070,0x576f580}
for va in (0x5750a78,0x5750a90,0x5750aa8):
 off,payload,_=read(va,24)
 rr=[q for q in rel if q['slot']==va]
 if len(rr)!=1 or rr[0]['type']!=8 or rr[0]['symbol']!=0:raise ValueError('Location relocation')
 source=rr[0]['addend'];length,line,column=struct.unpack_from('<QII',payload,8)
 if length>1024:raise ValueError('source path length')
 so,path,_=read(source,length);used_slots.add(va)
 data_records.append({'va':va,'file_offset':off,'raw_hex':payload.hex(),'source_va':source,'source_file_offset':so,'source_path_hex':path.hex(),'line':line,'column':column})
_,prefix,_=read(0x7166d0,2)
(O/'data.json').write_text(json.dumps({'panic_locations':data_records,'outer_prefix_literal':prefix.hex(),'relocations':[q for q in rel if q['slot'] in used_slots]},sort_keys=True,indent=2)+'\n')
(O/'records.json').write_text(json.dumps({'target_sha256':sha(raw),'target_bytes':len(raw),'functions':records,'relocations':[q for q in rel if q['slot'] in used_slots]},sort_keys=True,indent=2)+'\n')
print(json.dumps([{k:r[k] for k in ('start','end','bytes','file_offset','sha256','fde_va','calls')} for r in records],sort_keys=True))
