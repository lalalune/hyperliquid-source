KIND='gated-byte'
from random import Random
MASK=(1<<64)-1
def cases():
    r=Random(940311)
    if KIND=='gated-byte':
        return [[b,p,g,missing] for b in [0,0x1000,MASK-0xb4] for p in [0,1,1<<32,MASK] for g in range(256) for missing in [0,1,2]]
    if KIND=='global-clamp':
        values=[0,1,2,63,64,65,127,128,129,(1<<63)-1,1<<63,MASK]
        values += [((1<<28)+d)&MASK for d in [-65,-64,-1,0,1,63,64]]
        values += [r.getrandbits(64) for _ in range(512)]
        return [[v,f] for v in values for f in [0,1,2]]
    values=[]
    for count in [0,1,2,0x7fffffff,0x80000000,0xffffffff]:
        for base in [0,0x1000,1<<63,MASK-79,MASK]:
            for delta in [-161,-81,-80,-17,-16,-15,-1,0,1,15,16,17,79,80,81,160]:
                for changed in [False,True]:
                    values.append([0x2000,count,base,(base+delta)&MASK,(base+80 if changed else base)&MASK,0x123456789abcdef0,0xfedcba9876543210,0])
    values += [[r.getrandbits(64),r.getrandbits(32),r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),r.getrandbits(64),r.randrange(5)] for _ in range(1024)]
    return values

def expected(x):
    events=[]
    def done(status,value=0,tail=()):
        return [status,value,*tail,len(events),*[n for e in events for n in e]]
    if KIND=='gated-byte':
        b,p,g,missing=x
        events.append([0,(b+0xb0)&MASK,0])
        if missing==1:return done(1)
        if p==0:return done(0)
        events.append([1,(b+0xb8)&MASK,0])
        if missing==2:return done(1)
        return done(0,int(g==0))
    if KIND=='global-clamp':
        bits,missing=x
        events.append([0,0x57881e0,0])
        if missing==1:return done(1,tail=(0,0))
        signed=bits if bits<(1<<63) else bits-(1<<64)
        selected=0 if signed<0 else max(signed,1)
        stored=0 if signed<0 else min(max(selected//64,1),0x400000)
        events.append([2,0x59afc98,stored])
        if missing==2:return done(1,tail=(0,0))
        return done(0,0x552fa70,(0x59afca0,selected))
    state,count,base,result,post,context,rdx,missing=x
    events.append([0,state,0])
    if missing==1:return done(1)
    events.append([1,(state+8)&MASK,0])
    if missing==2:return done(1)
    events.append([2,0x51c4000,base,(base+80*count)&MASK,rdx,context])
    if missing==3:return done(1)
    events.append([1,(state+8)&MASK,0])
    if missing==4:return done(1)
    bits=(result-post)&MASK
    signed=bits if bits<(1<<63) else bits-(1<<64)
    return done(0,((signed>>4)*0xcccccccd)&0xffffffff)
