from random import Random
MASK=(1<<64)-1
def cases():
    out=[[0x1000,0,0x4000,0x8000,a,b,0x1234567800000000,(a<<32)|b,1,0] for a in range(256) for b in range(256)]
    for obj in [0,0x1000,MASK-8]:
        for selector in [0,1,1<<63,MASK]:
            for third in [(obj+8)&MASK,0x4000,1<<63]:
                for fourth in [0x8000,0x4000,MASK-16]:
                    for counter in [0,MASK,1<<63]:out.append([obj,selector,third,fourth,0x80,0x7f,counter,MASK,1,0])
    for missing in [1,2,4,8,16]:
        for selector,third in [(0,0x4000),(1,0x4000),(0,0x1008)]:
            out.append([0x1000,selector,third,0x8000,0xff,0x80,MASK,0,0,missing])
    r=Random(940412)
    out += [[r.getrandbits(64),r.choice([0,1]),r.getrandbits(64),r.getrandbits(64),r.randrange(256),r.randrange(256),r.getrandbits(64),r.getrandbits(64),r.randrange(2),r.choice([0,0,0,1,2,4,8,16])] for _ in range(256)]
    return out
def expected(x):
    obj,selector,third,fourth,a,b,before,after,mutate,missing=x;memory={};events=[];counter=(obj+40)&MASK
    def put(address,value):
        for i,v in enumerate(value.to_bytes(8,'little')):memory[(address+i)&MASK]=v
    def peek(address):return int.from_bytes(bytes(memory[(address+i)&MASK] for i in range(8)),'little')
    put(counter,before);memory[(third+32)&MASK]=a;memory[(fourth+32)&MASK]=b
    if missing&1:memory.pop((third+32)&MASK,None)
    if missing&2:memory.pop((fourth+32)&MASK,None)
    if missing&8:
        for i in range(8):memory.pop((counter+i)&MASK,None)
    try:
        if selector or third==(obj+8)&MASK:flag=1
        else:
            events.append([0,(third+32)&MASK]);v=memory[(third+32)&MASK]
            events.append([0,(fourth+32)&MASK]);flag=int(memory[(fourth+32)&MASK]<v)
        events.append([2,0x5660550,flag,fourth,third,(obj+8)&MASK])
        if missing&4:raise KeyError('safe callback refusal')
        if mutate:put(counter,after)
        events.append([1,counter]);value=(peek(counter)+1)&MASK
        events.append([3,counter,value])
        if missing&16:raise KeyError('safe store refusal')
        put(counter,value);out=[0,fourth]
    except KeyError:out=[1,0]
    try:present,value=1,peek(counter)
    except KeyError:present,value=0,0
    return [*out,present,value,len(events),*[n for e in events for n in [len(e),*e]]]
