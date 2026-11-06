#!/usr/bin/env python3
"""Check strict throttle expiry and conditional diagnostic collection."""
import argparse,itertools,struct
import verify
import capstone

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a))
    return {'duration':struct.unpack('<d',im.get(0x458cd8,8))[0],
      'fallback':struct.unpack('<III',im.get(0x4679d0,12)),
      'first_compare':ins(0x239c015).mnemonic,'last_retention':ins(0x239c052).mnemonic,
      'diagnostic_flag':ins(0x239c14c).operands[-1].imm,
      'flat_first_compare':ins(0x24c207a).mnemonic,'flat_rest_compare':ins(0x24c238d).mnemonic,
      'flat_first_flag':ins(0x24c20dd).operands[-1].imm,'flat_rest_flag':ins(0x24c23b4).operands[-1].imm}

def signed32(x):return x if x<1<<31 else x-(1<<32)

def expired(now,deadline,o):
    if now[0]!=deadline[0]:
        return signed32(now[0])>signed32(deadline[0]) if o['first_compare']=='setg' else now[0]>deadline[0]
    if now[1]!=deadline[1]:return now[1]>deadline[1]
    return now[2]>deadline[2] if o['last_retention']=='jbe' else now[2]>=deadline[2]

def project(now,deadline,flag,o):
    remove=expired(now,deadline,o)
    return remove,remove and flag==o['diagnostic_flag']

def evaluate(data):
    o=operands(data)
    verify.require(o=={'duration':30.0,'fallback':(0x7fffd6de,86399,999999999),'first_compare':'setg','last_retention':'jbe','diagnostic_flag':1,
      'flat_first_compare':'setg','flat_rest_compare':'setg','flat_first_flag':1,'flat_rest_flag':1},'native deadline operands')
    # Constant propagation along the positive integral-f64 route: 30 has exponent
    # 1027 and mantissa bits encoding 1.875. Fractional remainder is exactly zero.
    raw=struct.unpack('<Q',struct.pack('<d',o['duration']))[0];exponent=(raw>>52)&0x7ff;mantissa=(raw&((1<<52)-1))|(1<<52)
    whole=mantissa>>(1075-exponent);remainder=(raw<<(exponent-1023))&((1<<52)-1)
    verify.require((whole,remainder)==(30,0),'native integral duration route')
    values=[0,1,2,0x7fffffff,0x80000000,0xffffffff]
    triples=list(itertools.product(values,repeat=3));comparison_cases=0
    for now,deadline in itertools.product(triples,repeat=2):
        expected=(signed32(now[0]),now[1],now[2])>(signed32(deadline[0]),deadline[1],deadline[2])
        verify.require(expired(now,deadline,o)==expected,'mixed-width strict lexicographic comparison');comparison_cases+=1
    decision_cases=0
    for flag,when in itertools.product(range(256),[(0,0,0),(1,2,2),(1,2,3),(1,2,4),(0x80000000,0,0)]):
        remove,report=project(when,(1,2,3),flag,o)
        expected=(signed32(when[0]),when[1],when[2])>(1,2,3)
        verify.require((remove,report)==(expected,expected and flag==1),'exact diagnostic flag independent of removal');decision_cases+=1
    # Collections use valid boolean row flags. Tree output byte2 is end-of-scan;
    # noncanonical flags are only single-row predicate probes above.
    collection_cases=0
    for labels in itertools.product(range(4),repeat=4):
        rows=[{'id':i,'deadline':(1,2,2 if label//2 else 4),'flag':label%2} for i,label in enumerate(labels)]
        decisions=[project((1,2,3),r['deadline'],r['flag'],o) for r in rows]
        kept=[r['id'] for r,d in zip(rows,decisions) if not d[0]]
        reports=[r['id'] for r,d in zip(rows,decisions) if d[1]]
        verify.require(kept==[i for i,label in enumerate(labels) if label<2],'retained order')
        verify.require(reports==[i for i,label in enumerate(labels) if label==3],'diagnostic order');collection_cases+=1
    mutants=[]
    for va,value,args in [(0x239c016,0x97,((0x80000000,0,0),(0,0,0),1)),
                           (0x239c052,0x72,((1,2,3),(1,2,3),1)),
                           (0x239c150,2,((1,2,4),(1,2,3),1))]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=value
        before=project(*args,o);after=project(*args,operands(changed));verify.require(before!=after,'counterfactual survived')
        mutants.append({'va':hex(va),'new_byte':value,'before':list(before),'after':list(after)})
    return {'native_operands':{**o,'fallback':list(o['fallback'])},'comparison_cases':comparison_cases,'decision_cases':decision_cases,'collection_cases':collection_cases,'duration_seconds':whole,'duration_fraction_bits':remainder,'counterfactuals':mutants,
      'limits':'Relations start at helper-derived valid deadline triples and model policy only. They do not execute/emulate captured code, prove calendar helper correctness, tree repair or scheduler cadence. Complete collection reasoning assumes boolean flags; other raw flag bytes only probe the local equality test.'}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: strict throttle expiry, flagged diagnostics and native operand controls')
