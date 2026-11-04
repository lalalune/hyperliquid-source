"""Frozen synthetic normal-domain observations; no target execution."""
import itertools
import random

MUTANTS={
 'little-endian-header':('u32::from_be_bytes','u32::from_le_bytes'),
 'reject-equal-limit':('length > maximum','length >= maximum'),
 'truncate-u64-limit':('length > maximum','length > maximum as u32 as u64'),
 'nonzero-compression':('header.flag == 1','header.flag != 0'),
 'wrong-compression-tag':('header.flag == 1','header.flag == 2'),
 'chunk-cap-minus-one':('4_000_000','3_999_999'),
 'maximum-instead-of-minimum':('remaining.min(CHUNK_BYTES)','remaining.max(CHUNK_BYTES)'),
 'empty-read-at-equality':('completed >= length','completed > length'),
 'wrong-range-start':('Some((completed, completed + count))','Some((0, completed + count))'),
}


def corpus(parameters,relation):
    inputs=[];expected=[]
    lengths=[0,1,2,255,256,65535,65536,3999999,4000000,4000001,7999999,8000000,8000001,0x01020304,(1<<32)-1]
    def add(header,limit,done):
        observed=relation(header,limit,done,parameters)
        # Independent positional byte expansion and interval arithmetic oracle.
        n=sum(header[i]*(256**(3-i)) for i in range(4))
        if n>limit:oracle=[0,n,0,0,0,0]
        elif done>=n:oracle=[1,n,int(header[4]==1),0,0,0]
        else:
            end=min(n,done+4000000)
            oracle=[1,n,int(header[4]==1),1,done,end]
        assert observed==' '.join(map(str,oracle))
        inputs.append(f'{header.hex()} {limit} {done}');expected.append(observed)
    for n in lengths:
        limits=sorted(set([0,max(0,n-1),n,n+1,1<<32,(1<<64)-1]))
        positions=sorted(set([0,1,max(0,n-1),n,n+1,3999999,4000000,4000001,(1<<32)-1,1<<63,(1<<64)-1]))
        for flag,limit,done in itertools.product(range(256),limits,positions):
            add(n.to_bytes(4,'big')+bytes([flag]),limit,done)
    rng=random.Random(0x2b788e0)
    for _ in range(4000):
        header=rng.randbytes(5);n=int.from_bytes(header[:4],'big')
        add(header,rng.choice([rng.getrandbits(64),n,max(0,n-1)]),rng.choice([rng.getrandbits(64),rng.randrange(n+1)]))
    return '\n'.join(inputs)+'\n','\n'.join(expected)+'\n'
