from random import Random
MASK=(1<<64)-1
def cases():
    out=[]
    for n in [0,1,2,15,16,17,255,256,257]:
        for flag in [1,255]:
            for zero in [MASK,0,max(0,n-1)]:
                for missing in [0,1,2,4]:out.append([0x1000,0x100000,n,flag,zero,0x123456789abcdef0,missing])
    for n in [9999,10000]:
        for zero in [MASK,0,n-1]:out.append([0x1000,0x100000,n,255,zero,0,0])
    for n in [10001,1<<63,MASK]:
        for returned in [0,1,0x123456789abcdef0,MASK]:
            for missing in [0,2,4,8]:out.append([0x1000,0x100000,n,1,0,returned,missing])
    for obj in [0,MASK-8,1<<63]:
        for base in [0x1000,MASK-77]:
            for n in [0,1,16,17]:out.append([obj,base,n,1,MASK,0,0])
    r=Random(940411)
    out += [[r.getrandbits(64),r.getrandbits(64),r.randrange(512),r.randrange(1,256),r.choice([MASK,0,1,17]),r.getrandbits(64),r.choice([0,0,0,1,2,4])] for _ in range(128)]
    return out
def expected(x):
    obj,base,count,flag,zero,returned,missing=x;memory={};events=[]
    def put(a,v):
        for i,b in enumerate(v.to_bytes(8,'little')):memory[(a+i)&MASK]=b
    put((obj+16)&MASK,count);put((obj+8)&MASK,base)
    if count<10001:
        for i in range(count):memory[(base+80*i+78)&MASK]=0 if i==zero else flag
    for bit,address in [(1,(obj+16)&MASK),(2,(obj+8)&MASK)]:
        if missing&bit:
            for i in range(8):memory.pop((address+i)&MASK,None)
    if missing&4:memory.pop((base+78)&MASK,None)
    def read64(a):
        events.append([0,a,0]);return int.from_bytes(bytes(memory[(a+i)&MASK] for i in range(8)),'little')
    def read8(a):events.append([1,a,0]);return memory[a]
    try:
        n=read64((obj+16)&MASK)
        if n>=10001:
            events.append([2,0x3c1ada0,0x143])
            if missing&8:raise KeyError('safe callback refusal')
            value=(returned&~255)|1
        else:
            p=read64((obj+8)&MASK);value=(16*n)&~255
            for i in range(n):
                if not read8((p+80*i+78)&MASK):break
            else:value|=1
        out=[0,value]
    except KeyError:out=[1,0]
    return [*out,len(events),*[n for e in events for n in e]]
