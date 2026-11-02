import itertools, random
MODEL = 'state_dump_result_projection_static'
COMPONENT = 'node94-state-dump-result'
OWNERS = [22137760, 74246752]
MUTANTS = {
 'truncating_remainder': ('s.rem_euclid(86_400)', '(s % 86_400).abs()'),
 'truncating_quotient': ('s.div_euclid(86_400)', 's / 86_400'),
 'wrong_index_offset': ('+ 719_163', '+ 719_164'),
 'excluded_status_low_bit': ('status == 1', 'status & 1 == 1'),
 'zero_result_inversion': ('callee_eax == 0', 'callee_eax != 0'),
 'swap_output_fields': ('[callee_eax, remainder, retained]', '[callee_eax, retained, remainder]'),
 'wrong_low_guard': ('index < i32::MIN as i64', 'index <= i32::MIN as i64'),
 'wrong_high_guard': ('index > i32::MAX as i64', 'index >= i32::MAX as i64'),
}
def corpus(data, model):
 evidence=model.inspect(data);p=evidence['operands'];inputs=[];expected=[]
 vals=set([-(1<<63),(1<<63)-1,0,-1,1,-86401,-86400,-86399,86399,86400,86401])
 for q in [-(1<<31)-719163-1,-(1<<31)-719163,-(1<<31)-719163+1,(1<<31)-1-719163-1,(1<<31)-1-719163,(1<<31)-719163]:
  for r in [-1,0,1,86399,86400]:vals.add(q*86400+r)
 def add(s,status,retained,eax):
  v=model.projection(s,p);q,r=divmod(s,86400);idx=q+719163
  assert v['floor_quotient']==q and v['second_field']==r and v['index_guard']==(-(1<<31)<=idx<(1<<31))
  route=0 if status==1 else 1 if not v['index_guard'] else 2 if eax==0 else 3
  # Non-return arms emit no fields. The projected index is exposed only when passed to the opaque callee.
  index=v['index_argument'] if route>=2 else 0
  words=[eax,r,retained] if route==3 else [0,0,0]
  inputs.append(f'{s} {status} {retained} {eax}')
  expected.append(' '.join(map(str,[route,index,*words])))
 for args in itertools.product(sorted(vals),[0,1,2,3,255,(1<<32)-1],[0,1,0x12345678,(1<<32)-1],[0,1,0x87654321,(1<<32)-1]):add(*args)
 rng=random.Random(0x151cba0)
 for _ in range(10000):add(rng.randrange(-(1<<63),1<<63),rng.getrandbits(32),rng.getrandbits(32),rng.getrandbits(32))
 return '\n'.join(inputs)+'\n',expected
