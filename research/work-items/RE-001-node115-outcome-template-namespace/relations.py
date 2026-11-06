#!/usr/bin/env python3
"""Check the anchored reserved prefix across OutcomeDeploy entry and child names."""
import argparse,itertools,struct
import capstone
import verify

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    imm=lambda a:next(cs.disasm(im.get(a,15),a)).operands[-1].imm
    return {'prefix':im.get(0x79d2d9,9),'thresholds':[imm(a) for a in [0x2c5a400,0x2c5a4a9,0x2c5a51b,0x2c5b23e]],
      'namespace_errors':[imm(a) for a in [0x2c5b273,0x2c5b283,0x2c5b293,0x2c5b267]],
      'length_limits':[imm(a) for a in [0x2c599d3,0x2c59e8c,0x2c59eb6,0x2c5b234]],
      'child_stride':imm(0x2c5b222),'error_message':im.get(0x79d2e2,42)}

def gate(name,site,o):
    if len(name)>o['length_limits'][site]:return 0x158
    if len(name)>=o['thresholds'][site] and name[:9]==o['prefix']:return o['namespace_errors'][site]
    return None

def sequence(outer,children,o):
    error=gate(outer,1,o)
    if error is not None:return 'outer',error
    # The unrelated description and child-count checks are assumed to have passed.
    for i,name in enumerate(children):
        error=gate(name,3,o)
        if error is not None:return i,error
    return 'continue',None

def evaluate(data):
    o=operands(data)
    verify.require(o=={'prefix':b'template:','thresholds':[9]*4,'namespace_errors':[0x191]*4,'length_limits':[100]*4,'child_stride':48,'error_message':b'name cannot start with the template prefix'},'native namespace operands')
    names=[b'a'*i for i in range(106)]+[b'template:'+b'a'*i for i in range(98)]
    names += [b'',b'template',b'Template:',b'xtemplate:',b'template;',b'template:'+bytes([0]),'template:é'.encode(),'étemplate:'.encode()]
    for index,value in itertools.product(range(9),range(256)):
        name=bytearray(b'template:');name[index]=value;names.append(bytes(name))
    name_cases=0
    for site,name in itertools.product(range(4),names):
        expected=0x158 if len(name)>100 else 0x191 if name.startswith(b'template:') else None
        verify.require(gate(name,site,o)==expected,'reserved prefix and prior length precedence');name_cases+=1
    examples=[b'',b'a',b'template:',b'Template:',b'a'*101,b'template:'+b'x'*92]
    sequence_cases=0
    for outer,children in itertools.product(examples,itertools.product(examples,repeat=2)):
        result=sequence(outer,children,o)
        errors=[0x158 if len(name)>100 else 0x191 if name.startswith(b'template:') else None for name in [outer,*children]]
        expected=('continue',None)
        for i,error in enumerate(errors):
            if error is not None:expected=('outer' if i==0 else i-1,error);break
        verify.require(result==expected,'first failure in supplied order');sequence_cases+=1
    mutants=[]
    for va,value in [(0x79d2e1,ord(';')),(0x2c5a403,10),(0x2c5b275,0x92)]:
        changed=bytearray(data);changed[verify.Image(data).off(va)]=value
        before=gate(b'template:',0,o);after=gate(b'template:',0,operands(changed));verify.require(before!=after,'counterfactual survived')
        mutants.append({'va':hex(va),'new_byte':value,'before':before,'after':after})
    return {'native_operands':{k:v.hex() if isinstance(v,bytes) else v for k,v in o.items()},'name_cases':name_cases,'sequence_cases':sequence_cases,'counterfactuals':mutants,
      'limits':'Raw byte names and valid extents are assumed. Passing this prefix gate means only continuing to the next handler. Existing length checks are credited context; description validation, count/duplicate policy and full deployment semantics remain opaque.'}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: reserved template namespace and operand counterfactuals')
