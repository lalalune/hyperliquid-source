import itertools, random
MODEL = 'cold_state_admission'
COMPONENT = 'node94-cold-admission'
OWNERS = [37670256, 35689552]
MUTANTS = {
 'omit_upper_half': ('incoming == local', 'incoming[..16] == local[..16]'),
 'omit_lower_half': ('incoming == local', 'incoming[16..] == local[16..]'),
 'invert_digest': ('incoming == local', 'incoming != local'),
 'wrong_optional_test': ('optional_word != 0', 'optional_word == 0'),
 'wrong_input_test': ('input_word == 0', 'input_word == 1'),
 'wrong_helper_sentinel': ('helper_result == 0x8000_0000_0000_0040', 'helper_result == 0x8000_0000_0000_0000'),
}
def corpus(data, model):
 model.build(data)
 image=model.Image(data);inputs=[];expected=[]
 labels=['digest mismatch diagnostic then trap','pre-helper assertion','post-helper unwrap trap','return fetched prefix']
 edges=[0,1,2,255,1<<63,(1<<64)-1,0x8000000000000040]
 pairs=[(bytes(32),bytes(32)),(bytes(range(32)),bytes(range(32)))]
 for i in range(256):
  a=bytes(range(32));b=bytearray(a);b[i//8]^=1<<(i%8);pairs.append((a,bytes(b)))
 def add(a,b,o,w,h):
  same=model.digest_matches(image,a,b);assert same==(a==b)
  value=model.selected_route(same,o,w,h)
  oracle=0 if a!=b else 1 if o!=0 and w==0 else 3 if h==0x8000000000000040 else 2
  assert value==labels[oracle]
  inputs.append(f'{a.hex()} {b.hex()} {o} {w} {h}');expected.append(str(oracle))
 for (a,b),o,w,h in itertools.product(pairs,edges,edges,edges):add(a,b,o,w,h)
 rng=random.Random(0x23ecd70)
 for _ in range(1000):
  a=rng.randbytes(32);b=a if rng.randrange(2) else rng.randbytes(32)
  add(a,b,rng.getrandbits(64),rng.choice(edges),rng.choice(edges))
 return '\n'.join(inputs)+'\n',expected
