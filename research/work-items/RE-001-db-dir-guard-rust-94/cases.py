import itertools, random
MODEL = 'owned_db_dir_guard'
COMPONENT = 'node94-db-dir-guard'
OWNERS = [22603888]
MUTANTS = {
 'wrong_needle': ('|part| part == b"checkpoint"', '|part| part == b"checkpoinx"'),
 'prefix_only': ('path.windows(10).any(|part| part == b"checkpoint")', 'path.starts_with(b"checkpoint")'),
 'suffix_only': ('path.windows(10).any(|part| part == b"checkpoint")', 'path.ends_with(b"checkpoint")'),
 'miss_exact_length': ('path.windows(10)', 'path.get(..path.len().saturating_sub(1)).unwrap_or(&[]).windows(10)'),
 'case_fold': ('part == b"checkpoint"', 'part.eq_ignore_ascii_case(b"checkpoint")'),
}
def corpus(data, model):
 report=model.build(data);needle=model.needle(model.View(data)).encode('ascii');assert needle==b'checkpoint'
 k=report['loop_constants'];inputs=[];expected=[]
 def add(s):
  starts=model.covered_starts(len(s),k)
  value=any(s[i:i+10]==needle for i in starts)
  oracle=needle in s;assert value==oracle
  inputs.append(s.hex() or '-');expected.append(str(int(value)))
 for n in list(range(161))+[255,256,257,511,512,513,1023,1024]:
  add(b'x'*n)
  for pos in range(max(0,n-9)):add(b'x'*pos+needle+b'x'*(n-pos-10))
 for i in range(10):
  for b in range(256):
   s=bytearray(needle);s[i]=b;add(bytes(s))
 for s in [b'CHECKPOINT',b'Checkpoint',b'x\0checkpoint\xff',b'checkpointcheckpoint',b'checkpoin',b'checkpoints',b'checheckpointckpoint']:add(s)
 rng=random.Random(0x158e870)
 for _ in range(1000):
  n=rng.randrange(1025);s=bytearray(rng.randbytes(n))
  if n>=10 and rng.randrange(2):pos=rng.randrange(n-9);s[pos:pos+10]=needle
  add(bytes(s))
 return '\n'.join(inputs)+'\n',expected
