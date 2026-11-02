from random import Random
MASK=(1<<64)-1
def put(memory,address,value,width=8):
    for i,b in enumerate(value.to_bytes(width,'little')):memory[(address+i)&MASK]=b
def initial(slots,missing):
    memory={}
    for address,value,width in slots:put(memory,address,value,width)
    for address,_,width in slots:
        for a in [(address-1)&MASK,(address+width)&MASK]:memory.setdefault(a,(a*37+0xa5)&255)
    for bit,(address,_,width) in enumerate(slots):
        if missing&(1<<bit):
            for i in range(width):memory.pop((address+i)&MASK,None)
    return memory
class View:
    def __init__(self,memory):self.memory=memory;self.events=[]
    def read(self,address,width=8):
        self.events.append([0,address,width])
        return int.from_bytes(bytes(self.memory[(address+i)&MASK] for i in range(width)),'little')
    def write(self,address,value,width=8):
        self.events.append([1,address,width,value])
        for i in range(width):self.memory[(address+i)&MASK]
        put(self.memory,address,value,width)
    def patch(self,address,value):
        self.events.append([3,address,8,value]);put(self.memory,address,value)
    def finish(self,registers):
        out=[0 if registers is not None else 1,len(registers or []),*(registers or []),len(self.events)]
        for event in self.events:out.extend([len(event),*event])
        out.append(len(self.memory))
        for address,value in sorted(self.memory.items()):out.extend([address,value])
        return out

def cases():
    rows=[];r=Random(940402)
    for obj in [0x1000,MASK-0x20]:
        for before in [0x4000,(obj+8)&MASK,(obj+0x10)&MASK,MASK-0x17]:
            for after in [before,(obj+8)&MASK,1<<63]:
                for is_self in [False,True]:
                    for change in [0,1]:
                        for missing in [0,1,2,4,8,16,32,63]:
                            old_link=(before+0x18+(0 if is_self else 1))&MASK
                            new_link=(after+0x18+(0 if is_self else 1))&MASK
                            rows.append([obj,before,after,old_link,new_link,r.getrandbits(64),change,missing,0x1122334455667788,0x99aabbccddeeff00,0x8123456789abcdef])
    rows += [[0x1000,0x4000,r.choice([0x4000,0x1008,0x1010,0x8000]),r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),r.randrange(2),r.choice([0,0,1,2,4,8,16,32]),r.getrandbits(64),r.getrandbits(64),r.getrandbits(64)] for _ in range(256)]
    return rows
def expected(x):
    obj,before,after,old_link,new_link,returned,change,missing,rsi,rdx,rcx=x
    slots=[((obj+8)&MASK,before,8),((obj+0x20)&MASK,0x1122334455667788,8),((obj+0x28)&MASK,0x7f,1),((before+0x18)&MASK,old_link,8),((after+0x18)&MASK,new_link,8)]
    v=View(initial(slots,missing))
    try:
        initial_second=v.read((obj+8)&MASK)
        v.events.append([2,0x5172b00,initial_second,rsi,rdx,rcx])
        if missing&32:raise KeyError('opaque callback refused')
        if change:v.patch((obj+8)&MASK,after)
        v.write((obj+0x20)&MASK,returned)
        second=v.read((obj+8)&MASK);sentinel=(second+0x18)&MASK
        flag=int(v.read(sentinel)!=sentinel)
        v.write((obj+0x28)&MASK,flag,1)
        return v.finish([(second&~255)|flag,sentinel])
    except KeyError:return v.finish(None)
