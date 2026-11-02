from random import Random
MASK=(1<<64)-1
def cases():
    for delta in range(-20,21):
        for seed in [0,1,128,255]:yield [0x1000,0x2000,0x3000,0x4010,0x4000+delta,seed,0,0]
    for dest in [0x1008,0x2010,0x3008,0x3ff8,0x4000,0x4008,0x4010]:
        for mask in range(8):yield [0x1000,0x2000,0x3000,0x4010,dest,29,mask,0]
    for hole in range(16):
        for mask in [8,16]:yield [0x1000,0x2000,0x3000,0x4010,0x5000,71,mask,hole]
    for q in [0,1,15,16,MASK-7,1<<63]:
        for delta in [-15,0,1,15,16]:yield [0x1000,0x2000,0x3000,q,(q-16+delta)&MASK,117,0,0]
    # Exact pointer-slot aliases are resolved from initialized bytes, never
    # assumed consistent. Unmapped resulting reads are explicit safe refusals.
    for obj,src,mid in [(0x1000,0x1000,0x3000),(0x1000,0xff8,0x1000),(0x1000,0x2000,0x1000),(MASK-3,0x2000,0x3000)]:
        for mask in [0,1,2,4]:yield [obj,src,mid,0x4010,0x4001,203,mask,0]
    r=Random(940322)
    for _ in range(256):
        q=r.getrandbits(64);yield [0x1000,0x2000,0x3000,q,(q-16+r.randrange(-20,21))&MASK,r.randrange(256),r.choice([0,0,0,8,16]),r.randrange(16)]
def image(x):
    obj,src,mid,q,dest,seed,mask,hole=x;memory={}
    for i in range(-2,18):memory[(dest+i)&MASK]=(seed^0xa5^i)&255
    for i in range(-2,18):memory[(q-16+i)&MASK]=(seed+37*i)&255
    slots=[((obj+8)&MASK,dest),((src+16)&MASK,mid),((mid+8)&MASK,q)]
    for address,value in slots:
        for i,b in enumerate(value.to_bytes(8,'little')):memory[(address+i)&MASK]=b
    for flag,(address,_) in enumerate(slots):
        if mask&(1<<flag):
            for i in range(8):memory.pop((address+i)&MASK,None)
    if mask&8:memory.pop((q-16+hole)&MASK,None)
    if mask&16:memory.pop((dest+hole)&MASK,None)
    return memory
def expected(x):
    obj,src,*_=x;memory=image(x);events=[]
    def read(address,size):
        events.append([0 if size==8 else 1,address,size]);return bytes(memory[(address+i)&MASK] for i in range(size))
    try:
        dest=int.from_bytes(read((obj+8)&MASK,8),'little')
        mid=int.from_bytes(read((src+16)&MASK,8),'little')
        q=int.from_bytes(read((mid+8)&MASK,8),'little')
        chunk=read((q-16)&MASK,16)
        events.append([2,dest,16])
        addresses=[(dest+i)&MASK for i in range(16)]
        if any(a not in memory for a in addresses):raise KeyError()
        memory.update(zip(addresses,chunk));out=[0,1,q,src]
    except KeyError:out=[1,0,0,0]
    return [*out,len(events),*[n for e in events for n in e],len(memory),*[n for p in sorted(memory.items()) for n in p]]
