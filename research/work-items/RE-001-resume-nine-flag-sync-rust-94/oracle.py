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
    rows=[];r=Random(940403)
    for base in [0,0x1000,1<<63,MASK-0x52]:
        for flag in [0,1,1<<32,MASK]:
            for source,dest in [(0,0),(1,1),(0,1),(1,0),(MASK,1),(1<<63,MASK)]:
                for missing in [0,1,2,4,7]:rows.append([base,flag,source,dest,missing])
    rows += [[r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),r.randrange(8)] for _ in range(256)]
    return rows
def expected(x):
    base,flag,source,dest,missing=x
    slots=[(base,flag,8),((base+0x50)&MASK,source,8),((base+0x58)&MASK,dest,8)]
    v=View(initial(slots,missing))
    try:
        if v.read(base)!=0:v.write(base,0)
        value=v.read((base+0x50)&MASK)
        if value!=v.read((base+0x58)&MASK):v.write((base+0x58)&MASK,value)
        return v.finish([value])
    except KeyError:return v.finish(None)
