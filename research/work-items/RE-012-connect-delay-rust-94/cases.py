import itertools
import random
import struct

MODEL='gossip_connect_stagger_static'
COMPONENT='node94-connect-delay'
OWNERS=[0x4740490,0x45297f0]
MUTANTS={
 'index_before_map': ('map_value.or(list_index)', 'list_index.or(map_value)'),
 'missing_peer_zero': ('unwrap_or(list_len)', 'unwrap_or(list_len.wrapping_mul(0))'),
 'no_snapshot_delay': ('if !snapshot_some', 'if snapshot_some'),
 'wrong_cap': ('if product < 0.07', 'if product < 0.7'),
 'wrong_factor': ('((x as f64) * 0.001)', '((x as f64) * 0.01)'),
 'integer_product_first': ('(k as f64) * ((x as f64) * 0.001)', '(k.wrapping_mul(x) as f64) * 0.001'),
}

def corpus(data,model):
    bound=model.analyse(data);assert bound['deadline']['cap']==0.07
    inputs,expected=[],[]
    bits=lambda v:struct.unpack('<Q',struct.pack('<d',v))[0]
    def add(some,x,m,i,n):
        k=model.k_value(m,i,n)
        expected_k=m if m is not None else i if i is not None else n
        assert k==expected_k
        value=model.delay(bool(some),x,k)
        # Explicit binary64 conversions and operation order; no tolerance.
        product=float(k)*(float(x)*0.001)
        oracle=(product if product<0.07 else 0.07) if some else 0.0
        assert bits(value)==bits(oracle)
        inputs.append(' '.join(map(str,[some,x,int(m is not None),m or 0,int(i is not None),i or 0,n])))
        expected.append(f'{k} {bits(value)}')
    points=[0,1,2,69,70,71,(1<<53)-1,1<<53,(1<<53)+1,1<<63,(1<<64)-1]
    for args in itertools.product([0,1],points,[None,*points],[None,0,1,70,(1<<64)-1],[0,1,70,(1<<64)-1]):add(*args)
    rng=random.Random(0x4740490)
    for _ in range(2000):add(rng.randrange(2),rng.getrandbits(64),rng.choice([None,rng.getrandbits(64)]),rng.choice([None,rng.getrandbits(64)]),rng.getrandbits(64))
    return '\n'.join(inputs)+'\n',expected
