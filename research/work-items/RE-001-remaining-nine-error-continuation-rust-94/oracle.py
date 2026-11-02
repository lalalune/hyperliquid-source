from random import Random
import struct
MASK=(1<<64)-1
def cases():
    results=[0,1,128,1<<63,(1<<64)-121,(1<<64)-120,(1<<64)-119,MASK]
    bounds=[(-2147483648,-2147483648),(-2147483648,2147483647),(-9,-1),(-3,3),(0,0),(0,5),(3,3),(7,3),(2147483647,2147483647)]
    for result in results:
        for low,high in bounds:
            rdx=int.from_bytes(struct.pack('<ii',low,high),'little')
            for value in sorted(set([low-1,low,low+1,high-1,high,high+1,0])):
                if not -2147483648<=value<=2147483647:continue
                for upper in [0,0x89abcdef]:yield [result,rdx,(upper<<32)|(value&0xffffffff)]
    r=Random(940323)
    for _ in range(512):yield [r.getrandbits(64),r.getrandbits(64),r.getrandbits(64)]
def expected(x):
    result,rdx,rsi=x
    low,high=struct.unpack('<ii',rdx.to_bytes(8,'little'))
    value=struct.unpack('<i',(rsi&0xffffffff).to_bytes(4,'little'))[0]
    # The error band is the 119 top u64 values. Threshold -120 is admitted.
    if result>=(1<<64)-119 or value<low:return [0,result,rdx,rsi]
    return [int(value<=high),result,high&MASK,rsi]
