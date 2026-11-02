from random import Random
def cases():
    values=[0,1,2,3,4,5,255,256,257,260,0x7fffffff,0x80000000,0xffffffff,0x100000001,0x100000004,0x8000000000000001,0xffffffff00000004,0xffffffffffffffff]
    out=[[a,b] for a in values for b in values]
    r=Random(940413)
    out += [[r.getrandbits(64),r.getrandbits(64)] for _ in range(512)]
    return out
def expected(x):
    rdi,rsi=x
    # The independent relation partitions the two low-dword domains. Any
    # incoming EAX high bits are removed by AND with zero-extended EDX=0/1.
    first=(rsi%(1<<32))==1;second=(rdi%(1<<32))==4
    return [8 if first and second else 9]
