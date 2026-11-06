#!/usr/bin/env python3
"""Validate decimal checkpoint-name intersection from native operands."""
import argparse,itertools,random
import capstone
import verify

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a))
    imm=lambda a:ins(a).operands[-1].imm
    return {'pairs':im.get(0x46ea12,200),'group_magic':imm(0x38dddde),'group_shift':64+imm(0x38dddf6),
      'group_base':imm(0x38dddfa),'small_magic':imm(0x38dde4f),'small_shift':imm(0x38dde55),
      'group_gate':imm(0x38dddd5),'group_continue':imm(0x38dde35),'pair_base':imm(0x38dde58),
      'row_stride':ins(0x3d71459).operands[-1].mem.disp,'height_offset':ins(0x38dddc1).operands[-1].mem.disp,
      'keep_zero_branch':ins(0x3d71475).mnemonic,'equality_failure_branch':ins(0x38ddf74).mnemonic}

def decimal(number,o):
    assert 0<=number<1<<64
    original=number;parts=[]
    if number>=o['group_gate']:
        while True:
            q=(number*o['group_magic'])>>o['group_shift'];r=number-q*o['group_base']
            hi=(r*0x147b)>>19;lo=r-hi*o['pair_base']
            parts.append(o['pairs'][2*hi:2*hi+2]+o['pairs'][2*lo:2*lo+2])
            old=number;number=q
            if old<=o['group_continue']:break
    if number>9:
        q=(((number>>2)&65535)*o['small_magic'])>>o['small_shift'];r=number-q*o['pair_base']
        parts.append(o['pairs'][2*r:2*r+2]);number=q
    if original==0 or number!=0:parts.append(o['pairs'][2*(number&15)+1:2*(number&15)+2])
    return b''.join(reversed(parts))

def select(rows,names,o):
    result=[]
    for height in rows:
        match=decimal(height,o) in names
        if o['equality_failure_branch']!='jne':match=not match
        if o['keep_zero_branch']!='je':match=not match
        if match:result.append(height)
    return result

def evaluate(data):
    o=operands(data)
    verify.require(o=={'pairs':b''.join(str(i).zfill(2).encode() for i in range(100)),
      'group_magic':0x346dc5d63886594b,'group_shift':75,'group_base':10000,'small_magic':0x147b,'small_shift':17,
      'group_gate':1000,'group_continue':9999999,'pair_base':100,'row_stride':32,'height_offset':24,
      'keep_zero_branch':'je','equality_failure_branch':'jne'},'native decimal/filter operands')
    rng=random.Random(79);numbers=list(range(10001))+[rng.getrandbits(64) for _ in range(2048)]
    for exponent in range(20):
        for delta in [-1,0,1]:
            n=10**exponent+delta
            if 0<=n<1<<64:numbers.append(n)
    numbers += [(1<<63)-1,1<<63,(1<<64)-1]
    for n in numbers:verify.require(decimal(n,o)==str(n).encode(),'native decimal decomposition')
    samples=[0,1,9,10,99,100,999,1000,10000,(1<<64)-1]
    name_cases=0
    for n in samples:
        s=str(n).encode()
        for name in [s,b'0'+s,b'+'+s,b'-'+s,b' '+s,s+b' ',s+b'.0',s+b'/x',s+b'\0',s+b'TAR_COMPLETE']:
            verify.require(select([n],{name},o)==([n] if name==s else []),'canonical name membership');name_cases+=1
    collection_cases=0
    for mask in range(1<<len(samples)):
        names={str(n).encode() for i,n in enumerate(samples) if mask>>i&1}
        names|={b'01',b'+1',b'000',b'1/x',b'TAR_COMPLETE'}
        for rows in [samples,list(reversed(samples)),[1,0,1,10,9,10],[]]:
            actual=select(rows,names,o);expected=[n for n in rows if str(n).encode() in names]
            verify.require(actual==expected,'preserved row order and duplicate multiplicity')
            verify.require(((actual[0],actual[-1]) if actual else None) == ((expected[0],expected[-1]) if expected else None),'first/last selection')
            collection_cases+=1
    mutants=[]
    for va,value in [(0x46ea13,ord('1')),(0x3d71475,0x75),(0x38ddf74,0x74)]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=value
        before=select([0,1,10],{b'0'},o);after=select([0,1,10],{b'0'},operands(changed))
        verify.require(before!=after,'counterfactual survived');mutants.append({'va':hex(va),'new_byte':value,'before':before,'after':after})
    return {'native_operands':{k:v.hex() if isinstance(v,bytes) else v for k,v in o.items()},'decimal_cases':len(numbers),'name_cases':name_cases,
      'collection_cases':collection_cases,'counterfactuals':mutants,
      'limits':'Valid row extents and unsigned64 heights; name-set lookup semantics taken from explicit byte/length equality. Supplied order is preserved, not an assertion of long-list sort correctness. Provider selection, filesystem effects and full archive success remain outside the claim.'}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: archive decimal-name intersection and operand counterfactuals')
