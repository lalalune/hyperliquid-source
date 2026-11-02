import itertools, random
MODEL = 'host_ip_admission'
COMPONENT = 'node94-host-ip-gates'
OWNERS = [20751216]
MUTANTS = {
 'length_off_by_one': ('length > 15', 'length >= 15'),
 'low_bit_full_byte': ('parser_al & 1 != 0', 'parser_al == 1'),
 'invert_remainder': ('remaining == 0', 'remaining != 0'),
 'wrong_override_sentinel': ('override_word == (1 << 63)', 'override_word == u64::MAX'),
 'length_precedence': ('length > 15', 'length > u64::MAX - 1'),
}
def corpus(data, model):
 model.build(data);inputs=[];expected=[]
 labels=['reject_before_parser','reject_after_parser','admit_to_collection']
 edges=[0,1,14,15,16,17,255,256,1<<63,(1<<64)-1]
 def add(n,a,r,o):
  value=model.admission(n,a,r);probe=model.override_route(o)=='probe_path'
  oracle=0 if n>=16 else 2 if a%2==1 and not r else 1
  assert value==labels[oracle] and probe==(o==1<<63)
  inputs.append(f'{n} {a} {r} {o}');expected.append(f'{oracle} {int(probe)}')
 for args in itertools.product(edges,range(256),[0,1,1<<63,(1<<64)-1],[0,1,(1<<63)-1,1<<63,(1<<63)+1,(1<<64)-1]):add(*args)
 rng=random.Random(0x13ca370)
 for _ in range(1000):add(rng.getrandbits(64),rng.randrange(256),rng.getrandbits(64),rng.getrandbits(64))
 return '\n'.join(inputs)+'\n',expected
