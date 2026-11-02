from random import Random
MASK=(1<<64)-1
def cases():
    # One exhaustive byte-pair denominator per complete FDE, not a redundant
    # Cartesian product with every address and missing-view variation.
    for mode in [0,1]:
        for a in range(256):
            for b in range(256):yield [mode,0x1000,a,b,0]
        for base in [0,MASK-0x50,MASK-0xf0]:
            for a,b in [(0,0),(0,255),(1,0),(128,255),(255,1)]:
                for missing in range(4):yield [mode,base,a,b,missing]
def expected(x):
    mode,base,a,b,missing=x
    first,second=([0x58,0x68] if mode==0 else [0xd0,0xf8])
    memory={(base+first)&MASK:a,(base+second)&MASK:b}
    for flag,offset in enumerate([first,second]):
        if missing&(1<<flag):memory.pop((base+offset)&MASK,None)
    events=[]
    def read(offset):
        address=(base+offset)&MASK;events.append(address);return memory[address]
    try:
        v=read(first)
        if mode==0:result=0 if v==0 else int(read(second)==0)
        else:result=v if v else read(second)
        status=0
    except KeyError:status,result=1,0
    return [status,result,len(events),*events]
