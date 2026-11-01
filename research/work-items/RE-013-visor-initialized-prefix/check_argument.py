#!/usr/bin/env python3
"""Bind the manual prefix argument; data substitution and Boolean tables only."""
import argparse
import copy
import itertools
import json
from pathlib import Path
from survey import DATA, Image, InvalidEvidence, format_events, json_bytes, require, sha

HERE = Path(__file__).resolve().parent
ANCHORS = {int(k, 16): bytes.fromhex(v)
           for k,v in json.loads((HERE/'anchors.json').read_bytes()).items()}

def bind(image):
    for address, expected in ANCHORS.items():
        require(image.at(address,len(expected)) == expected,
                'Manual argument anchor differs: '+hex(address))
    for label,(address,expected) in DATA.items():
        require(image.at(address,len(expected)) == expected, 'Data differs: '+label)
    image.relocations()

def request(image,label,value):
    address,raw = DATA[label]
    events = format_events(image.at(address,len(raw)),1)
    require([e['index'] for e in events if e['kind']=='argument']==[0],
            'Expected one slice argument')
    return b''.join(value if e['kind']=='argument' else bytes.fromhex(e['bytes'])
                    for e in events)

def choice(first_directory, second_directory, preparation_zero):
    if first_directory:
        return 'cham'
    if second_directory or preparation_zero:
        return 'hl'
    return 'error'

def run(binary):
    image=Image(binary.read_bytes())
    bind(image)
    fixtures=[(b'/root',b'/root/cham',b'/root/hl'),
              (b'',b'/cham',b'/hl'),
              (b'base/',b'base//cham',b'base//hl')]
    for h,a,b in fixtures:
        require(request(image,'cham-format-window',h)==a, 'Cham request differs')
        require(request(image,'hl-format-window',h)==b, 'HL request differs')
        for g in [a,b]:
            require(request(image,'code-format-window',g)==g+b'/code', 'Code request differs')
            require(request(image,'config-format-window',g+b'/code')==g+b'/code/static_config',
                    'Config context request differs')
    inputs=list(itertools.product((False,True),repeat=3))
    expected=['error','hl','hl','hl','cham','cham','cham','cham']
    require([choice(*x) for x in inputs]==expected,'Manual selection table differs')
    require(['cham' if a else ('hl' if b or c else 'error') for a,b,c in inputs]==expected,
            'Independent Boolean formula differs')
    mutants={
        'always-prefer-cham':lambda a,b,c:'cham',
        'require-both-second-checks':lambda a,b,c:'cham' if a else ('hl' if b and c else 'error'),
        'invert-preparation-zero':lambda a,b,c:'cham' if a else ('hl' if b or not c else 'error'),
    }
    witnesses={}
    for name,mutant in mutants.items():
        bad=[i for i,x in enumerate(inputs) if mutant(*x)!=expected[i]]
        require(bad,'Abstract mutant survived: '+name)
        i=bad[0];witnesses[name]={'input':list(inputs[i]),'expected':expected[i],
                                 'mutant':mutant(*inputs[i])}
    guards=[]
    for name,address in [('descriptor-selection',0x6724d6),('initializer-call',0x39d930),
                         ('global-field-copy',0x4acc97),('first-mode-branch',0x4ac729),
                         ('second-mode-branch',0x4ac7a3),('preparation-zero-branch',0x4ac7c6),
                         ('home-key',0x4a58b2),('getenv-call',0x66c2ad),
                         ('cham-stream',0x6a568),('hl-stream',0x64868),
                         ('factory-relocation',0x7e9e58),('callback-relocation',0x7ae4a8)]:
        # Data relocations have zero file words, so mutate the RELA addend itself.
        target=address
        if name.endswith('-relocation'):
            import struct
            found=[]
            for sec in image.sections:
                if sec[1]==4:
                    for offset in range(sec[4],sec[4]+sec[5],24):
                        if struct.unpack_from('<Q',image.data,offset)[0]==address:
                            found.append(offset+16)
            require(len(found)==1,'Mutation RELA absent/ambiguous')
            offset=found[0]
        else:
            offsets=[o+target-va for o,va,size in image.loads if va<=target<va+size]
            require(len(offsets)==1,'Mutation mapping ambiguous');offset=offsets[0]
        changed=bytearray(image.data);changed[offset]^=1
        lower=copy.copy(image);lower.data=bytes(changed)
        try:
            bind(lower)
        except InvalidEvidence:
            guards.append({'case':name,'result':'below-identity binding corruption refused'})
        else:
            raise InvalidEvidence('Corrupted manual binding accepted: '+name)
    return {'targetSha256':sha(image.data),'anchors':len(ANCHORS),'byteFixtures':len(fixtures),
            'abstractRows':[{'input':list(x),'choice':y} for x,y in zip(inputs,expected)],
            'abstractMutantWitnesses':witnesses,'bindingControls':guards,
            'capturedExecution':False,'instructionEvaluation':False,
            'limits':'Bindings and abstract data algebra support the addressed manual proof. '
                     'No CPU evaluation, runtime-value observation, helper/storage/concurrency proof.'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--receipt',type=Path)
    args=parser.parse_args()
    try:
        require(not args.receipt or not args.receipt.exists(),'Preserve existing receipt')
        result=run(args.binary)
        if args.receipt:args.receipt.write_bytes(json_bytes(result))
        print(json.dumps(result))
    except (InvalidEvidence,OSError,UnicodeError) as error:
        parser.exit(1,str(error)+'\n')

if __name__=='__main__':main()
