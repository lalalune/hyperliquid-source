#!/usr/bin/env python3
"""Operand-derived field projection and decimal post-normalization, without ELF execution."""
import argparse,itertools,random,struct
import capstone
import verify

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a))
    imm=lambda a:ins(a).operands[-1].imm
    disp=lambda a:ins(a).operands[-1].mem.disp
    literal=lambda a,n:im.get(a,n).decode('ascii')
    return {'filled':literal(0x91f2d1,6),'resting':literal(0x91f2e3,7),'size_key':literal(0x91f2d7,7),'price_key':literal(0x91f2de,5),
      'oid_key':literal(0x91e438,3),'cloid_key':literal(0x91e452,5),'size_offset':disp(0x518915f),'price_offset':disp(0x5189193),
      'filled_oid':disp(0x51891e2),'resting_oid':disp(0x5189287),'option_offset':disp(0x5188f54),
      'filled_count':imm(0x5188f9c),'filled_skip':ins(0x5189205).mnemonic,'resting_skip':ins(0x51892a6).mnemonic,
      'trim_byte':imm(0x44a6220),'retained_suffix':imm(0x44a6236).to_bytes(2,'little'),
      'zero_input':imm(0x44a625f).to_bytes(4,'little'),'zero_output':imm(0x44a627c).to_bytes(2,'little')+bytes([imm(0x44a6278)]),
      'cloid_bytes':imm(0x526ec0d),'cloid_buffer':imm(0x526ec08),'hex_digits':im.get(0x455d40,16),
      'hex_prefix':imm(0x2eabb62).to_bytes(2,'little'),'mode_offset':ins(0x5188f9f).operands[0].mem.disp}

def normalize(text,o):
    n=len(text)
    while n and text[n-1]==o['trim_byte']:
        if n>=2 and text[n-2:n]==o['retained_suffix']:break
        n-=1
    result=text[:n]
    return o['zero_output'] if result==o['zero_input'] else result

def reference_normalize(text):
    trimmed=text.rstrip(b'0')
    if trimmed.endswith(b'.'):trimmed+=b'0'
    return b'0.0' if trimmed==b'-0.0' else trimmed

def hex_string(value,o):
    assert len(value)==o['cloid_bytes']
    return (o['hex_prefix']+b''.join(bytes([o['hex_digits'][b>>4],o['hex_digits'][b&15]]) for b in value)).decode()

def project(kind,mode,memory,formatted,o):
    present=memory[o['option_offset']]
    assert present in [0,1] and mode in [0,1]
    fields=[]
    if kind=='filled':
        fields=[(o['size_key'],normalize(formatted[o['size_offset']],o).decode()),(o['price_key'],normalize(formatted[o['price_offset']],o).decode())]
    fields.append((o['oid_key'],struct.unpack_from('<Q',memory,o[kind+'_oid'])[0]))
    skip=o[kind+'_skip']
    if bool(present)==(skip=='je'):fields.append((o['cloid_key'],hex_string(memory[2:2+o['cloid_bytes']],o)))
    count=(o['filled_count'] if kind=='filled' else 1)+present
    return {'variant':o[kind],'container':'map' if mode else 'array','declared_count':count,
      'fields':[list(pair) for pair in fields] if mode else [value for _,value in fields]}

def evaluate(data):
    o=operands(data)
    verify.require(o['size_offset']==24 and o['price_offset']==32 and o['filled_oid']==40 and o['resting_oid']==24,'field offsets')
    verify.require(o['option_offset']==1 and o['mode_offset']==11 and o['filled_count']==3,'optional length and serializer mode')
    verify.require(o['filled_skip']==o['resting_skip']=='je','absent field omission')
    verify.require(o['cloid_bytes']==16 and o['cloid_buffer']==34 and o['hex_prefix']==b'0x','fixed-width cloid')
    rng=random.Random(80);texts=[b'',b'0',b'000',b'0.0',b'-0.0',b'-0.00000000',b'1.00000000',b'100.0000',b'1.25000000',b'NaN',b'inf',b'-inf',b'1e20']
    texts += [(str(rng.randrange(-100000,100000))+'.'+str(rng.randrange(100000)).zfill(5)+'0'*rng.randrange(9)).encode() for _ in range(2048)]
    for text in texts:verify.require(normalize(text,o)==reference_normalize(text),'decimal suffix normalization')
    values=[0,1,127,128,255,256,65535,65536,(1<<32)-1,1<<32,(1<<63)-1,1<<63,(1<<64)-1]
    cloids=[bytes(16),bytes([255])*16,bytes(range(16)),bytes(range(240,256))]+[rng.randbytes(16) for _ in range(16)]
    cases=0;fixtures=[]
    for kind,mode,present,oid,cloid in itertools.product(['filled','resting'],[0,1],[0,1],values,cloids):
        memory=bytearray(48);memory[1]=present;memory[2:18]=cloid;struct.pack_into('<Q',memory,40 if kind=='filled' else 24,oid)
        formatted={24:b'12.50000000',32:b'-0.00000000'}
        actual=project(kind,mode,memory,formatted,o)
        fields=([('totalSz','12.5'),('avgPx','0.0')] if kind=='filled' else [])+[('oid',oid)]
        if present:fields.append(('cloid','0x'+cloid.hex()))
        expected={'variant':kind,'container':'map' if mode else 'array','declared_count':len(fields),'fields':[list(pair) for pair in fields] if mode else [v for _,v in fields]}
        verify.require(actual==expected,'nested field projection');cases+=1
        if oid==0 and cloid==bytes(16):fixtures.append(actual)
    mutations=[]
    memory=bytearray(48);memory[1]=1;memory[2:18]=bytes(range(16));struct.pack_into('<Q',memory,40,255)
    formatted={24:b'12.50000000',32:b'-0.00000000'}
    for va,new in [(0x5189162,32),(0x5188f9e,2),(0x5189205,0x75),(0x44a623c,0x31)]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=new
        before=project('filled',1,memory,formatted,o);after=project('filled',1,memory,formatted,operands(changed))
        verify.require(before!=after,'operand counterfactual survived');mutations.append({'va':hex(va),'new_byte':new,'different':True})
    return {'native_operands':{k:v.hex() if isinstance(v,bytes) else v for k,v in o.items()},'normalization_cases':len(texts),'projection_cases':cases,
      'fixtures':fixtures,'counterfactuals':mutations,'limits':'Valid option flag and serializer-mode bytes only; sufficient output storage. Initial numeric formatting is an opaque boundary: supplied formatted ASCII is used to test the observed normalization. These are static operand relations, not captured-binary executions or full MessagePack encoder equivalence.'}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: order-status nested field projection and normalization counterfactuals')
