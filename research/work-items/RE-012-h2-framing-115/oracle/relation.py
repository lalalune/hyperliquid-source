"""Independent integer/slice specification, frozen before new Rust code.

Cases are value observations, not execution of captured instructions. Input bytes
are synthetic and contain no user/network data. The oracle uses predicate
regions and Python unbounded integer byte conversion; Rust will use checked
branching and byte accumulation. Both are grounded in the selected native CFG.
"""
import random,pathlib,hashlib,json,gzip,datetime
U=(1<<64)-1;I=-(1<<63)

def expect(row):
 op=row[0]
 if op=='B':
  _,width,adj,cap=row;maximum=(1<<(8*width))-1 if width<8 else U
  return f"B {min(cap,max(0,min(U,maximum+adj)))}"
 if op=='H':
  m=row[1];valid=16384<=m<=16777215
  q=(1<<24)//m if valid else 0
  return f"H {int(valid)} {max(5,q+q//4) if valid else 0}"
 _,cap,width,offset,adj,st,skip,big,state,pending,hexdata=row
 data=bytes.fromhex(hexdata);available=len(data);consumed=rd=rh=frame=0
 nextstate=state;nextlen=pending if state else 0
 def result(status):return 'D '+' '.join(map(str,[status,consumed,nextstate,nextlen,rd,rh,frame]))
 head=offset+width
 effective_skip=skip if st else head
 needhead=max(head,effective_skip)
 if state==0:
  if head>U:return result(4)
  if available<needhead:return result(0)
  if width>8:return result(5)
  value=int.from_bytes(data[offset:offset+width],'big'if big else'little')
  if value>cap:return result(2)
  if adj==I:return result(6)
  length=value+adj
  if not 0<=length<=U:return result(3)
  consumed=effective_skip;available-=consumed
  rd=max(0,length-available);nextstate=1;nextlen=length
 else:length=pending
 if available<length:return result(0)
 # Conditional successful split_to: valid stable storage and ordinary helper return.
 consumed+=length;available-=length;frame=length;nextstate=0;nextlen=0
 if head>U:return result(4)
 rh=max(0,needhead-available)
 return result(1)
