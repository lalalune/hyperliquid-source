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
    rows=[];r=Random(940401)
    for obj in [0x1000,1<<63,MASK-0x11f0]:
        sentinel=(obj+0x11e0)&MASK
        for elem in [sentinel,0x4000,MASK-8]:
            for function in [0x4fa7e80,0x4fa7e90]:
                for output in [0xa000,(obj+0x1200)&MASK,(elem+8)&MASK,(elem+1)&MASK]:
                    for missing in [0,1,2,4,8,16,32,64,127]:
                        rows.append([obj,elem,0x8000,function,r.getrandbits(64),output,r.getrandbits(64),r.getrandbits(64),output,0x8877665544332211,1,missing])
    rows += [[0x1000,r.choice([0x21e0,0x4000]),0x8000,r.choice([0x4fa7e80,0x4fa7e90]),r.getrandbits(64),r.choice([0xa000,0x4008,0x8000,0x2200]),r.getrandbits(64),r.getrandbits(64),r.choice([0xa000,0x4008,0x2200]),r.getrandbits(64),r.randrange(2),r.choice([0,0,1,2,4,8,16,32,64])] for _ in range(256)]
    return rows
def expected(x):
    obj,elem,table,function,value,out,returned,rcx,patch,value_patch,enabled,missing=x
    slots=[((obj+0x1200)&MASK,elem,8),(elem,table,8),(table,function,8),(0x5778020,0x4fa7e80,8),((elem+8)&MASK,value,8),(out,0x1122334455667788,8)]
    v=View(initial(slots,missing))
    try:
        entry=v.read((obj+0x1200)&MASK);sentinel=(obj+0x11e0)&MASK
        if entry==sentinel:value_out=0
        else:
            virtual=v.read(v.read(entry));known=v.read(0x5778020)
            if virtual==known:value_out=v.read((entry+8)&MASK)
            else:
                v.events.append([2,virtual,entry,out,sentinel,rcx])
                if missing&64:raise KeyError('opaque callback refused')
                if enabled:v.patch(patch,value_patch)
                value_out=returned
        v.write(out,value_out)
        return v.finish([1])
    except KeyError:return v.finish(None)
