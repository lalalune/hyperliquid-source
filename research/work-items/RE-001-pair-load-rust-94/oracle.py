from random import Random
MASK=(1<<64)-1
def cases():
    result=[]
    for obj in [0,0x1000,MASK-0x20]:
        for base in [0x8000,1<<63,MASK-0x195,(obj+0x28-0x190)&MASK]:
            for lo,hi in [(0,0),(1,MASK),(MASK,1),(1<<63,1<<32)]:
                for missing in range(8):result.append([obj,base,lo,hi,missing])
    r=Random(940312)
    result += [[r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),r.randrange(8)] for _ in range(512)]
    return result
def expected(x):
    obj,base,lo,hi,missing=x
    memory={};events=[]
    slots=[((obj+0x28)&MASK,base),((base+0x198)&MASK,hi),((base+0x190)&MASK,lo)]
    for address,value in slots:
        for i,b in enumerate(value.to_bytes(8,'little')):memory[(address+i)&MASK]=b
    for flag,(address,_) in enumerate(slots):
        if missing&(1<<flag):
            for i in range(8):memory.pop((address+i)&MASK,None)
    def read(address):
        events.append(address)
        return int.from_bytes(bytes(memory[(address+i)&MASK] for i in range(8)),'little')
    try:
        pointer=read((obj+0x28)&MASK)
        rdx=read((pointer+0x198)&MASK)
        rax=read((pointer+0x190)&MASK)
        out=[0,rax,rdx]
    except KeyError:out=[1,0,0]
    return [*out,len(events),*events]
