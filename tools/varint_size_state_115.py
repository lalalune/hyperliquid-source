from pathlib import Path
import sys,hashlib,json,struct
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import decimal_scaled_u64 as cpu
TARGET=ROOT/'artifacts/node/115/hl-node';SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
COUNTER=cpu.INPUT;VALUE=COUNTER+0x1000;OUT=COUNTER+0x2000;RECORD=COUNTER+0x3000
SITES=[(0x29360e0,0x293617b,64,'direct-rcx'),(0x58220e0,0x5822157,32,'inline'),(0x5822160,0x58221d7,32,'indirect'),(0x5822850,0x5822904,64,'direct-rdx'),(0x5822b90,0x5822c44,64,'direct-rdx')]
class Machine(cpu.Machine):
 def bounds(self,a,n,write=False):
  roles=[(self.counter,8),(OUT,8),(cpu.STACK+120,16)]
  if not write:roles +=[(VALUE,8),(RECORD+0x10,8)]
  if not any(lo<=a and a+n<=lo+size for lo,size in roles):raise ValueError('outside qualified size-state fields')
 def load(self,a,n):self.bounds(a,n);return super().load(a,n)
 def reload(self,r,a,n):self.bounds(a,n);return super().reload(r,a,n)
 def store(self,a,n,v):self.bounds(a,n,True);return super().store(a,n,v)
 def spill(self,a,r,n):self.bounds(a,n,True);return super().spill(a,r,n)
 def call(self,*args):raise ValueError('all size-state calls forbidden')
def put(m,a,v,n=8):
 for j,b in enumerate(v.to_bytes(n,'little')):m.mem[a+j]=b
def evaluate(image,which,value,count,flag=0):
 a,b,width,abi=SITES[which]
 if not 0<=value<1<<width or not 0<=count<=cpu.U64 or not 0<=flag<=255:raise ValueError('domain')
 m=Machine(image);m.counter=RECORD+0x10 if abi=='inline' else COUNTER
 m.set_reg(cpu.RAX,0x1234);m.set_reg(cpu.RSP,cpu.STACK+128);m.set_reg(cpu.RDI,OUT)
 put(m,m.counter,count);put(m,OUT,0x55);put(m,cpu.STACK+128,cpu.RETURN_MARK)
 if abi.startswith('direct'):
  m.set_reg(cpu.RSI,COUNTER)
  if abi=='direct-rcx':m.set_reg(cpu.RCX,value);m.set_reg(cpu.RDX,flag)
  else:m.set_reg(cpu.RDX,value)
 else:
  m.set_reg(cpu.RSI,VALUE);m.set_reg(cpu.RDX,RECORD);put(m,VALUE,value)
  if abi=='indirect':put(m,RECORD+0x10,COUNTER)
 m.pc=a
 for _ in range(64):
  if m.pc==b-6:
   lea=image.data[image.file_offset(b-13):image.file_offset(b-13)+7]
   if lea[:3]!=bytes.fromhex('488d3d') or m.get(cpu.RDI,64)!=b-6+struct.unpack_from('<i',lea,3)[0]:raise ValueError('overflow boundary Location')
   if m.load(OUT,8)!=0x55:raise ValueError('error output changed')
   return f'P\t{m.load(m.counter,8)}',m.seen
  if not a<=m.pc<b:raise ValueError('escaped owner')
  try:m.step()
  except cpu.Done as end:
   if end.how!='ret' or m.get(cpu.RSP,64)!=cpu.STACK+136:raise ValueError('return path')
   expected=0x1234 if abi=='direct-rdx' else OUT
   if m.get(cpu.RAX,64)!=expected:raise ValueError('return register qualification')
   if m.load(OUT,8)!=8:raise ValueError('success output qualification')
   return f'O\t{m.load(m.counter,8)}',m.seen
 raise ValueError('step bound')
def model(value,count):
 length=1 if value<251 else 3 if value<65536 else 5 if value<1<<32 else 9
 if count==cpu.U64:return f'P\t{count}'
 if count>cpu.U64-length:return f'P\t{count+1}'
 return f'O\t{count+length}'
if __name__=='__main__':
 data=TARGET.read_bytes();assert hashlib.sha256(data).hexdigest()==SHA;image=cpu.Image(data)
 for which,(_,_,width,_) in enumerate(SITES):
  for value in [0,250,251,65535,65536,(1<<width)-1]:
   for count in [0,cpu.U64-1,cpu.U64-2,cpu.U64-8,cpu.U64]:
    result,_=evaluate(image,which,value,count);assert result==model(value,count),(which,value,count,result)
 print('five node115 physical ABI paths: marker precommit and overflow projection PASS')
 for a,b,width,abi in SITES:
  va=b-13;op=data[image.file_offset(va):image.file_offset(va)+7];assert op[:3]==bytes.fromhex('488d3d');location=va+7+struct.unpack_from('<i',op,3)[0];raw,n,line,col=struct.unpack_from('<QQII',data,image.file_offset(location));ptr=image.slots.get(location,raw)
  print(json.dumps({'owner':hex(a),'end':hex(b),'abi':abi,'location':hex(location),'relative_addend':hex(ptr),'path':data[image.file_offset(ptr):image.file_offset(ptr)+n].decode(),'line':line,'column':col}))
