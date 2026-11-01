#!/usr/bin/env python3
"""High-level Unicode mathematical oracle + independent UTF-8 serializer."""
import hashlib
import itertools
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
HEX='0123456789ABCDEFabcdef'
DIGITS={character:value for value,character in enumerate('0123456789')}
DIGITS.update({character:10+value for value,character in enumerate('ABCDEF')})
DIGITS.update({character:10+value for value,character in enumerate('abcdef')})
SPACE='\t\n\r '
PATTERNS=[bytes(range(16)),bytes([255])*16,bytes(16),bytes.fromhex('deadbeef0123456789abcdef76543210')]
cases=[]
seen=set()
def add(text,reason,calls=4,pattern=None):
    initial=PATTERNS[len(cases)%len(PATTERNS)] if pattern is None else pattern
    key=(text,initial,calls)
    if key in seen:
        return
    # This validates the serializer's domain, not native behavior.
    text.encode('utf-8')
    seen.add(key)
    cases.append({'id':f'h{len(cases):06d}','text':text,'initial_output':initial.hex(),
                  'calls':calls,'reason':reason})

for text in ['', ' ', '\t\n\r ', 'a', 'ff', 'ab c', 'ab \t', 'ab g',
             'ab\u0080', '0x', '0X', '0x00', ' 0x00', '00 0x',
             '\x00', '\x0b', '\x0c', '\x7f', 'a\x0b', 'a\x0c', '\u00a0',
             '\u2003', '\U0001f600', 'a\U0010ffff']:
    for pattern in PATTERNS:
        add(text,'exact-write-mask-and-fusion',6,pattern)
for value in range(128):
    add(chr(value),'all-ascii-single')
for first in range(128):
    for second in range(128):
        add(chr(first)+chr(second),'all-ascii-pairs')

separators=['']+list(SPACE)+[''.join(chars) for chars in itertools.product(SPACE,repeat=2)]
separators+=['\t\n\r ',' \t \n','\r\r\r']
for first in HEX:
    for second in HEX:
        for separator in separators:
            add(first+separator+second,'all-hex-pairs-and-whitespace-loops')
for separator in separators:
    for digit in HEX:
        add(separator+digit,'first-whitespace-then-odd',5)
        add(digit+separator,'second-whitespace-then-odd',5)
for value in range(128):
    character=chr(value)
    add(' \t'+character+'f','first-loop-all-ascii-classification',5)
    add('a \t'+character,'second-loop-all-ascii-classification',5)

scalars={0x80,0x81,0x85,0xa0,0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,
         0x10fffe,0x10ffff,0x1680,0x2028,0x2029,0x202f,0x205f,0x3000}
scalars.update(range(0x2000,0x200b))
for bit in range(7,21):
    for difference in range(-2,3):
        scalars.add((1<<bit)+difference)
for base in [0x80,0x780,0x800,0xd700,0xe000,0xff80,0x10000,0x3ff80,0xffff0,0x10ff80]:
    scalars.update(range(base,base+128))
for ordinal in range(512):
    raw=hashlib.sha256(b'hex-scalar-independent-v1:'+str(ordinal).encode()).digest()
    scalars.add(int.from_bytes(raw[:4],'big')%0x110000)
scalars=sorted(value for value in scalars if 128<=value<=0x10ffff and not 0xd800<=value<=0xdfff)
for scalar in scalars:
    character=chr(scalar)
    for text in [character,' \t'+character,'a'+character,'a \t'+character,'ab '+character+'cd']:
        add(text,'unicode-full-scalar-vs-one-outer-byte',6)

for count in [1,2,3,7,16,63,64,127,128,255,256,1024,4096]:
    for whitespace in SPACE:
        add(whitespace*count,'long-first-whitespace-loop',5)
        add('a'+whitespace*count,'long-second-whitespace-loop-odd',5)
        add(whitespace*count+'a'+whitespace*count+'f','long-both-whitespace-loops',5)
for scalar in [0x80,0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff]:
    add('ab'*129+' \t'+chr(scalar)+'cd','large-original-byte-error-index',134)
all_bytes=''.join(f'{value:02x}' for value in range(256))
add(all_bytes,'all256-output-byte-values-in-one-stateful-sequence',260)
add('ab'*257+'c','byte-to-odd-after-many-calls',262)
add('ab'*257+'g','byte-to-invalid-after-many-calls',262)
for text in ['0xdeadbeef','0Xdeadbeef',' \t0xdeadbeef','00 0xdeadbeef','0x'+'0'*512]:
    add(text,'prefix-is-not-stripped-inside-leaf',8)
alphabet=list('0123456789ABCDEFabcdef \t\r\nxyz\x00\x0b\x0c')+[chr(value) for value in [0x80,0xa0,0x800,0xe000,0x10000,0x10ffff]]
for ordinal in range(1024):
    raw=hashlib.sha256(b'hex-sequence-independent-v1:'+str(ordinal).encode()).digest()
    text=''.join(alphabet[value%len(alphabet)] for value in raw[:1+ordinal%31])
    add(text,'deterministic-mixed-scalar-sequence',8)

def mathematical_trace(case):
    # This function consumes only Unicode scalar text; it never parses the raw
    # UTF-8 serializer output and never interprets a captured instruction.
    text=case['text']
    output=bytearray.fromhex(case['initial_output'])
    scalar_position=0
    cursor=0
    count=0
    halted=0
    observations=[]
    def nibble():
        nonlocal scalar_position,cursor,count
        while scalar_position<len(text):
            character=text[scalar_position]
            scalar_position+=1
            before=cursor
            # All preceding active bytes are ASCII. An invalid non-ASCII
            # scalar consumes its leading byte only; halt prevents reuse.
            cursor+=1
            count+=1
            if character in SPACE:
                continue
            if character in DIGITS:
                return ('digit',DIGITS[character],before)
            return ('invalid',ord(character),before)
        return ('end',None,None)
    for ordinal in range(1,case['calls']+1):
        if halted:
            tag=3
        else:
            first=nibble()
            if first[0]=='end':
                tag=3
            elif first[0]=='invalid':
                tag=0
                halted=1
                output[4:8]=first[1].to_bytes(4,'little')
                output[8:16]=first[2].to_bytes(8,'little')
            else:
                second=nibble()
                if second[0]=='end':
                    tag=1
                    halted=1
                elif second[0]=='invalid':
                    tag=0
                    halted=1
                    output[4:8]=second[1].to_bytes(4,'little')
                    output[8:16]=second[2].to_bytes(8,'little')
                else:
                    tag=2
                    output[4]=16*first[1]+second[1]
        output[0:4]=tag.to_bytes(4,'little')
        observations.append(f"{case['id']}|{ordinal}|{output.hex()}|{cursor}|{count}|{halted}|1")
    return observations

inputs=[]
expected=[]
tags={0:0,1:0,2:0,3:0}
for case in cases:
    # Separate standard UTF-8 serialization; no semantic plan is passed.
    inputs.append(f"{case['id']}|{case['text'].encode('utf-8').hex()}|{case['initial_output']}|{case['calls']}")
    observations=mathematical_trace(case)
    expected.extend(observations)
    for observation in observations:
        result=bytes.fromhex(observation.split('|')[2])
        tags[int.from_bytes(result[:4],'little')]+=1
proof=ROOT/'hex-iterator-proof.md'
authority={'schema':'hex-iterator953-scalar140-pre-source-v1',
           'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
           'primary_range':['0x4eb64f0','0x4eb68a9'],'supporting_scalar_range':['0x4eb6360','0x4eb63ec'],
           'proof_sha256':hashlib.sha256(proof.read_bytes()).hexdigest(),
           'cases':cases,'scalar_values':scalars,'observations':len(expected),'logical_tag_observations':tags,
           'limits':['High-level Unicode scalar plan oracle frozen before any new Rust.',
                     'Driver input only raw UTF-8, arbitrary initial16 output bytes and call count.',
                     'Constructed valid-string normal states only; invalid UTF-8 and forged/mutated physical state excluded.',
                     'No prefix stripping or outer ASCII20-byte API; related339/1334 are separate evidence.',
                     'No captured instruction evaluator/native execution/private ABI/gate/new byte-identity claim.']}
files={'hex-iterator-authority.json':(json.dumps(authority,indent=2,sort_keys=True)+'\n').encode(),
       'hex-iterator-input.txt':('\n'.join(inputs)+'\n').encode(),
       'hex-iterator-expected.txt':('\n'.join(expected)+'\n').encode()}
for name,data in files.items():
    (ROOT/name).write_bytes(data)
receipt={'schema':'hex-iterator-pre-source-freeze-v1','cases':len(cases),'observations':len(expected),
         'unicode_scalars':len(scalars),'logical_tag_observations':tags}
for name in list(files)+['hex-iterator-proof.md','generate_hex_iterator.py']:
    receipt[name+'_sha256']=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
(ROOT/'hex-iterator-freeze.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps(receipt,sort_keys=True))
