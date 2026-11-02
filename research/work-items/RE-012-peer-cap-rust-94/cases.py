import itertools
import random

MODEL = 'gossip_peer_cap_static'
COMPONENT = 'node94-peer-cap'
OWNERS = [0x473f2e0]
MUTANTS = {
    'wrong_minimum': ('value.clamp(8, 100)', 'value.clamp(1, 100)'),
    'wrong_default': ('None => (8, false)', 'None => (100, false)'),
    'wrong_local_tag': ('tag & 1 != 0', 'tag == 1'),
    'count_allowed_peers': ('!allowed.contains(&key(tag, ip))', 'allowed.contains(&key(tag, ip))'),
    'inclusive_capacity': ('count < limit', 'count <= limit'),
    'invert_allowlist_bypass': ('|| allowed.contains(&key(incoming.0, incoming.1))', '|| !allowed.contains(&key(incoming.0, incoming.1))'),
}


def corpus(data, model):
    bound = model.analyse(data)['limit'];assert (bound['low'],bound['high'],bound['none_default'])==(8,100,8)
    inputs,expected=[],[]
    def add(option,peers,allowed,incoming):
        limit,clipped=model.peer_limit(option)
        count=model.counted_peers(peers,allowed)
        code=model.cap_code(peers,allowed,limit,incoming)
        canonical=lambda pair:0x7f000001 if pair[0]%2 else pair[1]
        oracle=sum(canonical(p) not in allowed for p in peers)
        assert oracle==count
        assert code==(3 if count<limit or canonical(incoming) in allowed else 0)
        words=[int(option is not None),option or 0,*incoming,len(allowed),*allowed,len(peers)]
        for pair in peers:words.extend(pair)
        inputs.append(' '.join(map(str,words)));expected.append(f'{limit} {int(clipped)} {count} {code}')
    for option,n,tag,ip,allowed in itertools.product([None,0,1,7,8,9,99,100,101,(1<<64)-1],
            [0,1,7,8,9,99,100,101],[0,1,2,3,255],[0,1,0x7f000001,0xffffffff],[[],[0x7f000001],[0,1,0xffffffff]]):
        peers=[(i%4,i) for i in range(n)];add(option,peers,allowed,(tag,ip))
    rng=random.Random(0x473f2e0)
    for _ in range(1000):
        peers=[(rng.randrange(256),rng.getrandbits(32)) for _ in range(rng.randrange(130))]
        allowed=[rng.getrandbits(32) for _ in range(5)]+([0x7f000001] if rng.randrange(2) else [])
        add(rng.choice([None,rng.getrandbits(64),rng.randrange(110)]),peers,allowed,(rng.randrange(256),rng.getrandbits(32)))
    return '\n'.join(inputs)+'\n',expected
