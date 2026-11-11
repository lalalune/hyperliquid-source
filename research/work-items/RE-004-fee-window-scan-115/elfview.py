"""Read-only mmap section/FDE lookup for small discovery queries; no target execution."""
import mmap,struct
from pathlib import Path
class View:
 def __init__(self,target):
  self.file=Path(target).open('rb');self.b=mmap.mmap(self.file.fileno(),0,access=mmap.ACCESS_READ)
  b=self.b;shoff=struct.unpack_from('<Q',b,0x28)[0];ent,n,sidx=struct.unpack_from('<HHH',b,0x3a);rows=[struct.unpack_from('<IIQQQQIIQQ',b,shoff+j*ent) for j in range(n)];names=rows[sidx][4];self.sections={}
  for r in rows:
   if r[1]==8:continue
   key=b[names+r[0]:b.find(b'\0',names+r[0])].decode();self.sections[key]=(r[3],r[4],r[5])
 def offset(self,va):
  for addr,off,n in self.sections.values():
   if addr and addr<=va<addr+n:return off+va-addr
  raise ValueError(hex(va))
 def read(self,va,n):
  p=self.offset(va);return self.b[p:p+n]
 def fde(self,va):
  addr,off,n=self.sections['.eh_frame_hdr'];count=struct.unpack_from('<I',self.b,off+8)[0];lo=0;hi=count
  while lo<hi:
   mid=(lo+hi)//2;start=addr+struct.unpack_from('<i',self.b,off+12+mid*8)[0]
   if start<=va:lo=mid+1
   else:hi=mid
  start,fde=struct.unpack_from('<ii',self.b,off+12+(lo-1)*8);start+=addr;fde+=addr
  f=self.offset(fde);begin,size=struct.unpack_from('<iI',self.b,f+8);assert fde+8+begin==start and start<=va<start+size
  return start,start+size
 def locations(self,path):
  needle=path.encode();at=self.b.find(needle);assert at>=0
  pva=None
  for addr,off,n in self.sections.values():
   if off<=at<off+n:pva=addr+at-off;break
  _,off,n=self.sections['.rela.dyn'];result={}
  for p in range(off,off+n,24):
   slot,kind,add=struct.unpack_from('<QQq',self.b,p)
   if kind&0xffffffff==8 and add==pva:
    q=self.offset(slot);length,line,col=struct.unpack_from('<QII',self.b,q+8)
    if length==len(needle) and line<10000 and col<1000:result[slot]=(line,col)
  return result
