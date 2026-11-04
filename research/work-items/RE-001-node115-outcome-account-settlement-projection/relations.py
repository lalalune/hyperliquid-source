#!/usr/bin/env python3
"""Outcome account projection from authenticated native operands and lookup boundaries."""
import argparse,itertools,json,random
import capstone
import verify
MAX=(1<<64)-1

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a));imm=lambda a:ins(a).operands[-1].imm
    return {'first_prefix':imm(0x38daa4c),'second_prefix':imm(0x38daaa0),'weight_scale':imm(0x3bf2de0),
      'balance_error':imm(0x38dac26),'product_error':imm(0x38daea7),'second_product_error':imm(0x38dadfc),
      'first_balance_branch':ins(0x38dac33).mnemonic,'second_balance_branch':ins(0x38dadac).mnemonic,
      'first_product_branch':ins(0x38dac8c).mnemonic,'second_product_branch':ins(0x38dae03).mnemonic,
      'sum_branch':ins(0x38dae11).mnemonic,'sum_saturation':imm(0x38daf3a)&MAX,
      'skip_marker':imm(0x38da9f7)&MAX}

def reserved(token,prefix):return bytes([prefix])+bytes(11)+token.to_bytes(8,'big')

def project(address,ids,lookup,c,o):
    if address in [reserved(ids[0],o['first_prefix']),reserved(ids[1],o['second_prefix'])]:return {'skip':True,'lookups':[],'diagnostics':[]}
    rows=[];totals=[];products=[];calls=[];diag=[]
    for index,weight in enumerate([c,o['weight_scale']-c]):
        calls.append(ids[index]);total,held=lookup[index] or (0,0)
        if held>total:diag.append('subtraction underflow')
        available=max(total-held,0)
        reject=(available!=total) if o[['first_balance_branch','second_balance_branch'][index]]=='jne' else (available==total)
        if reject:return {'error':o['balance_error'],'lookups':calls,'diagnostics':diag}
        totals.append(total)
        if total:rows.append([ids[index],total])
        product=total*weight;high=product>>64;low=product&MAX
        overflow=high!=0
        if o[['first_product_branch','second_product_branch'][index]]!='jo':overflow=not overflow
        if overflow:return {'error':o[['product_error','second_product_error'][index]],'lookups':calls,'diagnostics':diag}
        products.append(low)
    total=products[0]+products[1]
    if total>MAX:diag.append('sum overflow');total=o['sum_saturation']
    if total:rows.append([ids[2],total])
    if not rows:return {'skip':True,'lookups':calls,'diagnostics':diag}
    return {'rows':rows,'balances':totals,'lookups':calls,'diagnostics':diag}

def reference(address,ids,lookup,c):
    if any(address==b'2'+bytes(11)+i.to_bytes(8,'big') for i in ids[:2]):return {'skip':True,'lookups':[],'diagnostics':[]}
    a,b=lookup[0] or (0,0),lookup[1] or (0,0);diag=[]
    if a[1]>a[0]:diag.append('subtraction underflow')
    if a[0]!=max(0,a[0]-a[1]):return {'error':19,'lookups':[ids[0]],'diagnostics':diag}
    if a[0]*c>MAX:return {'error':14,'lookups':[ids[0]],'diagnostics':diag}
    if b[1]>b[0]:diag.append('subtraction underflow')
    if b[0]!=max(0,b[0]-b[1]):return {'error':19,'lookups':ids[:2],'diagnostics':diag}
    if b[0]*(1000-c)>MAX:return {'error':14,'lookups':ids[:2],'diagnostics':diag}
    payout=a[0]*c+b[0]*(1000-c)
    if payout>MAX:diag.append('sum overflow')
    rows=[[k,n] for k,n in [(ids[0],a[0]),(ids[1],b[0]),(ids[2],min(payout,MAX))] if n]
    return ({'rows':rows,'balances':[a[0],b[0]],'lookups':ids[:2],'diagnostics':diag} if rows else {'skip':True,'lookups':ids[:2],'diagnostics':diag})

def evaluate(data):
    o=operands(data);verify.require(o=={'first_prefix':50,'second_prefix':50,'weight_scale':1000,'balance_error':19,'product_error':14,'second_product_error':14,'first_balance_branch':'jne','second_balance_branch':'jne','first_product_branch':'jo','second_product_branch':'jo','sum_branch':'jb','sum_saturation':MAX,'skip_marker':(1<<63)+1},'projection operands')
    address=bytes(20);ids=[11,22,33];cases=0
    balances=[None,(0,0),(0,1),(1,0),(1,1),(1,2),(100,0),(100,1),(MAX//1000,0),(MAX//500,0),(MAX,0),(MAX,MAX)]
    for c,a,b in itertools.product([0,1,2,499,500,501,999,1000],balances,balances):
        verify.require(project(address,ids,[a,b],c,o)==reference(address,ids,[a,b],c),'balance/product/error ordering');cases+=1
    rng=random.Random(85)
    for _ in range(4096):
        c=rng.randrange(1001);pairs=[]
        for weight in [c,1000-c]:
            limit=MAX//max(1,weight);total=max(0,min(MAX,limit+rng.randrange(-3,4)));held=rng.choice([0,0,0,1,total])
            pairs.append((total,held))
        verify.require(project(address,ids,pairs,c,o)==reference(address,ids,pairs,c),'u64 product boundary');cases+=1
    exclusion_cases=0
    for token in [0,1,255,256,MAX]:
        ids2=[token,22,33]
        for excluded in [reserved(token,50),reserved(22,50)]:
            verify.require(project(excluded,ids2,[(MAX,1),(MAX,1)],500,o)==reference(excluded,ids2,[(MAX,1),(MAX,1)],500),'address exclusion before balance reads');exclusion_cases+=1
            for byte in range(20):
                changed=bytearray(excluded);changed[byte]^=1
                verify.require(project(bytes(changed),ids2,[(1,0),(2,0)],500,o)==reference(bytes(changed),ids2,[(1,0),(2,0)],500),'all20addressbytes');exclusion_cases+=1
    # Logical rows are not aggregated even if token identifiers coincide.
    verify.require(project(address,[11,11,11],[(2,0),(2,0)],500,o)['rows']==[[11,2],[11,2],[11,2000]],'ordered rows not a summing map')
    mutants=[];im=verify.Image(data)
    tests=[(0x38daa50,51,reserved(11,50),[(1,0),(1,0)],500,'reserved address'),(0x38dac34,0x84,address,[(1,0),(1,0)],500,'held-balance gate'),(0x38dac8d,0x81,address,[(MAX,0),(1,1)],1000,'first product overflow'),(0x38daf3d,0xfe,address,[(MAX//500,0),(MAX//500,0)],500,'sum saturation')]
    for va,new,addr,pairs,c,label in tests:
        changed=bytearray(data);changed[im.off(va)]=new;before=project(addr,ids,pairs,c,o);after=project(addr,ids,pairs,c,operands(changed))
        verify.require(before!=after,'changed decision survived');mutants.append({'va':hex(va),'new_byte':new,'meaning':label,'before':before,'after':after})
    return {'native_operands':o,'projection_cases':cases,'exclusion_cases':exclusion_cases,'counterfactuals':mutants,
      'limits':'Map lookup values are explicit total/held boundaries; valid native container descriptors and successful allocations. Diagnostic-call continuation is conditional on those calls returning. No parallel execution, lookup algorithm, precise token units, global application or captured-code execution/emulation.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: account settlement projection')
