#!/usr/bin/env python3
"""Operand-bound certificate voter normalization; no target execution or emulation."""
import argparse,itertools,json,random
import capstone
import verify

def operands(data,kind):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a));imm=lambda a:ins(a).operands[-1].imm
    a=({'key':0x53e6b59,'skip':0x53e6b65,'inner':0x53e6c1c,'short':0x4de65c9,'tree':0x4de64ee,'flat':0x4de64f2,'stride':0x5b2d817,'eq':0x5b2d812} if kind=='qc' else
       {'key':0x53ea482,'skip':0x53ea48e,'inner':0x53ea556,'short':0x4dbfa0b,'tree':0x4dbf98e,'flat':0x4dbf992,'stride':0x5b2e387,'eq':0x5b2e382})
    return {k:(ins(v).mnemonic if k in ['skip','inner','flat','eq'] else imm(v)) for k,v in a.items()}

def short_sort(rows,o):
    out=list(rows)
    for i in range(1,len(out)):
        row=out[i];key=row[:o['key']];previous=out[i-1][:o['key']]
        skip=key>=previous if o['skip']=='jns' else key>previous
        if skip:continue
        j=i
        while True:
            out[j]=out[j-1];j-=1
            if j==0 or key>=out[j-1][:o['key']]:break
        out[j]=row
    return out

def compact(rows,o):
    # Same scan / first-duplicate / kept-prefix structure as the bound native bodies.
    out=list(rows);n=len(out)
    if n<2:return out
    equal=lambda a,b:(a[:20]==b[:20])==(o['eq']=='je')
    read=1
    while read<n and not equal(out[read-1],out[read]):read+=1
    if read==n:return out
    out[read-1],out[read]=out[read],out[read-1];write=read
    for read in range(read+1,n):
        if equal(out[write-1],out[read]):out[write-1],out[read]=out[read],out[write-1]
        else:out[write]=out[read];write+=1
    return out[:write]

def representation(count,o):
    flat=count<=o['tree'] if o['flat']=='jbe' else count<o['tree']
    return 'flat' if flat else 'tree'

def row(key,ordinal,stride):
    return key.to_bytes(20,'big')+ordinal.to_bytes(8,'little')+bytes([ordinal%251])*(stride-28)

def evaluate(data):
    all_ops={};short_cases=run_cases=storage_cases=0;mutants=[];rng=random.Random(83)
    for kind,stride in [('qc',96),('tc',104)]:
        o=operands(data,kind);all_ops[kind]=o
        verify.require(o=={'key':20,'skip':'jns','inner':'js','short':21,'tree':64,'flat':'jbe','stride':stride,'eq':'je'},'normalization operands')
        cases=[list(x) for n in range(8) for x in itertools.product(range(3),repeat=n)]
        cases += [[rng.randrange(10) for _ in range(n)] for n in range(8,21) for _ in range(64)]
        for keys in cases:
            rows=[row(k,i,stride) for i,k in enumerate(keys)]
            ordered=short_sort(rows,o);actual=compact(ordered,o)
            last={}
            for r in rows:last[r[:20]]=r
            expected=[last[k] for k in sorted(last)]
            verify.require(actual==expected,'short-list last decoded signer occurrence');short_cases+=1
        # No assumed long-sort behavior: test compaction on explicit post-sort inputs.
        for n in [0,1,2,20,21,63,64,65,100,128]:
            for _ in range(64):
                keys=sorted(rng.randrange(80) for _ in range(n));rows=[row(k,i,stride) for i,k in enumerate(keys)]
                expected=[list(g)[-1] for _,g in itertools.groupby(rows,key=lambda r:r[:20])]
                verify.require(compact(rows,o)==expected,'post-sort last full row per signer run');run_cases+=1
        # Deliberately nonadjacent equal keys are not a global map operation.
        rows=[row(k,i,stride) for i,k in enumerate([1,1,2,1,1,3,2])]
        verify.require(compact(rows,o)==[rows[i] for i in [1,2,4,5,6]],'adjacency boundary');run_cases+=1
        for unique in range(0,130):
            for repeats in [1,2,3,7]:
                rows=[row(k,k*repeats+j,stride) for k in range(unique) for j in range(repeats)]
                kept=compact(rows,o)
                verify.require(len(kept)==unique and representation(len(kept),o)==('flat' if unique<=64 else 'tree'),'threshold follows dedup count');storage_cases+=1
        # Distinct key byte19 is significant; signature/padding bytes after byte19 are not.
        rows=[row(1,0,stride),row(0,1,stride),row(1,2,stride)]
        verify.require(short_sort(rows,o)==[rows[1],rows[0],rows[2]],'full twenty byte sort and stable ties')
    qc=all_ops['qc'];im=verify.Image(data)
    for va,value,label,case in [(0x4de64f1,63,'flat threshold',64),(0x53e6b5a,19,'last signer byte',None),(0x53e6b65,0x7f,'stable ties',None),(0x5b2d812,0x75,'duplicate polarity',None)]:
        changed=bytearray(data);changed[im.off(va)]=value;alt=operands(changed,'qc')
        if label=='flat threshold':before,after=representation(case,qc),representation(case,alt)
        elif label=='last signer byte':
            rows=[row(1,0,96),row(0,1,96)];before,after=short_sort(rows,qc),short_sort(rows,alt)
        elif label=='stable ties':
            rows=[row(1,0,96),row(1,1,96)];before,after=compact(short_sort(rows,qc),qc),compact(short_sort(rows,alt),alt)
        else:
            rows=[row(1,0,96),row(1,1,96)];before,after=compact(rows,qc),compact(rows,alt)
        verify.require(before!=after,'changed native decision survived')
        show=lambda x:x if isinstance(x,str) else [r.hex() for r in x]
        mutants.append({'va':hex(va),'new_byte':value,'meaning':label,'before':show(before),'after':show(after)})
    return {'native_operands':all_ops,'short_list_cases':short_cases,'post_sort_run_cases':run_cases,'storage_cases':storage_cases,'counterfactuals':mutants,
      'limits':'Complete normalization for decoded vectors shorter than21. Long-sort permutation/stability and wire decoding stay opaque; >=21 compaction receives explicit post-sort rows. Flat/tree constructor internals, allocation failures and certificate validity are excluded. No captured execution/emulation.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: certificate voter normalization and representation')
