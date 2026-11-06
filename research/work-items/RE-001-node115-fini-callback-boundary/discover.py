from pathlib import Path
import hashlib,json,struct,subprocess,re,time
start=time.monotonic();out=Path(__file__).parent;p=Path('artifacts/node/115/hl-node');data=p.read_bytes()
digest=hashlib.sha256(data).hexdigest();assert digest=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
assert data[:6]==b'\x7fELF\x02\x01'
shoff=struct.unpack_from('<Q',data,40)[0];ents,num,ns=struct.unpack_from('<HHH',data,58)
sh=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*ents) for i in range(num)];names=data[sh[ns][4]:sh[ns][4]+sh[ns][5]]
sections={names[s[0]:].split(b'\0',1)[0].decode():s for s in sh}
fini=sections['.fini_array'];assert fini[5]==8
rels=[]
for s in sh:
 if s[1]!=4:continue
 for off in range(s[4],s[4]+s[5],s[9]):
  addr,info,addend=struct.unpack_from('<QQq',data,off)
  if addr==fini[3]:rels.append({'offset':hex(addr),'type':info&0xffffffff,'symbol':info>>32,'addend':hex(addend)})
assert len(rels)==1 and rels[0]['type']==8 and rels[0]['addend']=='0x14193a0'
cmd=['objdump','-d','--start-address=0x1419330','--stop-address=0x1419430',str(p)];native=subprocess.run(cmd,text=True,capture_output=True,timeout=20);assert native.returncode==0
(out/'selected.objdump.txt').write_text(native.stdout)
frames=subprocess.run(['readelf','--debug-dump=frames',str(p)],text=True,capture_output=True,timeout=45);assert frames.returncode==0
extents=[(int(a,16),int(b,16)) for a,b in re.findall(r'FDE.*?pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)',frames.stdout)]
res={'binary':str(p),'sha256':digest,'size':len(data),'fini_section':{'va':hex(fini[3]),'file':hex(fini[4]),'size':fini[5]},'fini_raw':hex(struct.unpack_from('<Q',data,fini[4])[0]),'relocations':rels,'native_command':cmd,'native_sha256':hashlib.sha256(native.stdout.encode()).hexdigest(),'frames_command':['readelf','--debug-dump=frames',str(p)],'fde_count':len(extents),'containing_callback_fdes':[(hex(a),hex(b)) for a,b in extents if a<=0x14193a0<b],'adjacent_fdes':[(hex(a),hex(b)) for a,b in extents if 0x1419000<=a<0x1419500 or 0x1419000<b<0x1419500],'versions':{t:subprocess.check_output([t,'--version'],text=True).splitlines()[0] for t in ['objdump','readelf']},'elapsed_seconds':time.monotonic()-start,'target_executed':False}
(out/'discovery.json').write_text(json.dumps(res,indent=2)+'\n');print(json.dumps(res,indent=2));print(native.stdout)
