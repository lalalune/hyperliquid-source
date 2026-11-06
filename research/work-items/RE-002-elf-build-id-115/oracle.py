"""Independent candidate/interval ELF-note oracle; never evaluates target instructions."""
from pathlib import Path
import struct,random,hashlib,json,gzip
P=Path(__file__).resolve().parent;R=P.parents[2]
def header(off,size,alignment=4,kind=7):
 h=bytearray(64);struct.pack_into('<I',h,4,kind);struct.pack_into('<QQ',h,24,off,size);struct.pack_into('<Q',h,48,alignment);return bytes(h)
def note(name,desc,kind=3,align=4,final_padding=True):
 a=align;out=struct.pack('<III',len(name),len(desc),kind)+name;out+=bytes((-len(out))%a);out+=desc
 if final_padding:out+=bytes((-len(out))%a)
 return out
def expected(file,heads):
 # Derive candidate descriptor intervals with integer division/concatenation;
 # Rust uses incremental slices and bit alignment instead.
 for h in heads:
  kind=struct.unpack_from('<I',h,4)[0];off,size=struct.unpack_from('<QQ',h,24);align=struct.unpack_from('<Q',h,48)[0]
  if kind!=7 or (align>4 and align!=8) or off>len(file) or size>len(file)-off:continue
  a=8 if align==8 else 4;end=off+size;cursor=off
  while cursor+12<=end:
   namesz,descsz,tag=struct.unpack_from('<III',file,cursor)
   name_end=cursor+12+namesz;desc_start=cursor+((12+namesz+a-1)//a)*a;desc_end=desc_start+descsz
   if name_end>end or desc_start>end or desc_end>end:break
   name=file[cursor+12:name_end].rstrip(b'\0')
   if (name,tag)==(b'GNU',3):return desc_start,descsz,file[desc_start:desc_end]
   cursor=cursor+((desc_end-cursor+a-1)//a)*a
 return None
def generate():
 cases=[];seen=set()
 def add(file,heads):
  flat=b''.join(heads);key=(file,flat)
  if key in seen:return
  seen.add(key);e=expected(file,heads);want='N' if e is None else f'S:{e[0]}:{e[1]}:{e[2].hex() or "-"}';cases.append(f'{file.hex() or "-"}\t{flat.hex() or "-"}\t{want}\n')
 good=note(b'GNU\0',b'build-identity')
 add(b'',[]);add(good,[])
 for align in [0,1,2,3,4,5,6,7,8,9,16,2**64-1]:
  for name in [b'',b'G',b'GN',b'GNU',b'GNU\0',b'GNU\0\0\0',b'GNUx',b'GNU\0x',b'\0GNU',bytes(12)]:
   for tag in [0,1,2,3,4,2**32-1]:
    for size in [0,1,3,4,7,8,15,16,31]:
     n=note(name,bytes(range(size)),tag,8 if align==8 else 4,False);f=b'X'*3+n+b'Z'*5
     add(f,[header(3,len(n),align)]);add(n,[header(0,len(n),align)])
 for a in [4,8]:
  for cut in range(len(good)+5):
   first=note(b'OTHER\0',b'X'*cut,2,a);second=note(b'GNU\0\0',bytes(range(cut)),3,a,False);f=first+second
   for trim in range(min(18,len(f))+1):add(f,[header(0,len(f)-trim,a)])
 for off in [0,1,3,8,15,31,2**64-1]:
  for size in [0,1,11,12,len(good),len(good)+1,2**64-1]:
   for kind in [0,1,7,8,2**32-1]:
    bad=header(off,size,4,kind);add(good,[bad,header(0,len(good))]);add(good,[bad])
 for namesz in [0,1,2,3,4,7,8,15,16,2**32-1]:
  for descsz in [0,1,7,8,31,2**32-1]:
   f=struct.pack('<III',namesz,descsz,3)+b'GNU\0'+bytes(20)
   add(f,[header(0,len(f)),header(0,0)]);add(f+good,[header(0,len(f)),header(len(f),len(good))])
 rng=random.Random(11512002)
 for _ in range(7000):
  a=rng.choice([4,8]);parts=[]
  for k in range(rng.randrange(1,5)):
   name=rng.choice([b'GNU',b'GNU\0',b'GNU\0\0',b'OTHER',b'GNUx',b'\0'*5]);desc=rng.randbytes(rng.randrange(48));parts.append(note(name,desc,rng.choice([1,2,3,3,4]),a,rng.choice([True,False]) if k==0 else True))
  f=rng.randbytes(rng.randrange(8))+b''.join(parts);off=len(f)-sum(map(len,parts));size=len(f)-off
  if rng.randrange(3)==0:size=max(0,size-rng.randrange(min(size,12)+1))
  hs=[header(off,size,a)];add(f,hs)
  if rng.randrange(2):add(f+good,hs+[header(len(f),len(good),4)])
 # Actual authenticated note bytes with file-relative coordinates rebased only
 # for these synthetic logical fixtures, not asserted original ELF addresses.
 raw=(R/'artifacts/node/115/hl-node').read_bytes()
 assert hashlib.sha256(raw).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
 shoff=struct.unpack_from('<Q',raw,40)[0];entsize,count=struct.unpack_from('<HH',raw,58)
 assert entsize==64
 for index in range(count):
  h=raw[shoff+index*64:shoff+(index+1)*64]
  if struct.unpack_from('<I',h,4)[0]==7:
   off,size=struct.unpack_from('<QQ',h,24);alignment=struct.unpack_from('<Q',h,48)[0]
   data=raw[off:off+size];add(data,[header(0,len(data),alignment)])
 return ''.join(cases).encode()
if __name__=='__main__':
 assert not (R/'src/node115-elf-build-id/src/lib.rs').exists(),'must freeze before production Rust'
 raw=generate();freeze={'rows':raw.count(b'\n'),'fixture_sha256':hashlib.sha256(raw).hexdigest(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope_sha256':hashlib.sha256((P/'scope.json').read_bytes()).hexdigest(),'production_rust_absent':True,'capture_execution_or_emulation':False};(P/'cases.tsv.gz.hex').write_text(gzip.compress(raw,mtime=0).hex()+'\n');(P/'freeze.json').write_text(json.dumps(freeze,indent=2)+'\n');print(json.dumps(freeze))
