"""Audit hand-authored literal-fragment annotations, never interpret capture instructions.

Annotations name fixed immediate operands and fixed compile-time arithmetic
sites. They do not model registers, execute branches, read an input, or evaluate
captured instructions. CFG/liveness and read-operand association remain a manual
proof obligation. The candidate strings were frozen before these annotations.
"""
from pathlib import Path
import json,re,hashlib,sys

b=Path(__file__).resolve().parent
# Each fragment is input-offset,width,immediate-site[,signed-adjustment@site].
# Arithmetic here is only literal-byte reconstruction from annotated constants.
spec='''
00 0,2,4a9b00
01 0,8,4a9dd1 8,2,4a9de2
02 0,8,4a9f56 3,8,4a9f63
03 0,8,4a9b81 8,1,4a9b95
04 0,8,4a9b81,100@4a9ba2 8,1,4a9bb0
05 0,8,4a9f7a 3,8,4a9f84
06 0,8,4aa21f 8,4,4aa232
07 0,8,4aa21f 8,4,4aa24b
08 0,8,4aa21f 8,4,4aa261
09 0,2,4a9b0b
0a 0,2,4a9d9f 2,1,4a9da9
0b 0,2,4a9db8 2,1,4a9dc2
0c 0,4,4a9b66
0d 0,4,4a9b72
0e 0,8,4aa271 8,4,4aa281
0f 0,8,4aa291 8,4,4aa2a1
10 0,2,4a9b16
11 0,2,4a9b21
12 0,2,4a9b2c
13 0,8,4a9f7a,a080005@4a9fa4 3,8,4a9f84,a@4a9fae
14 0,8,4a9fc9,1030009@4a9fd3 3,8,4a9fbf,1@4a9fdd
15 0,8,4aa1ce 5,8,4aa1db,d@4aa1e5
16 0,8,4aa1f6 5,8,4aa203,4@4aa20d
17 0,8,4a9df2 8,2,4a9e03
18 0,8,4a9e13,10afb@4a9e1d 8,2,4a9e2b
19 0,8,4a9e3b 8,2,4a9e4c
1a 0,8,4a9fee 3,8,4a9ffb
1b 0,2,4a9b37
1c 0,2,4a9b42
1d 0,2,4a9b4d
1e 0,2,4a9b58
1f 0,8,4a9e13 8,2,4a9e63
20 0,8,4aa012 3,8,4aa01f
21 0,8,4a9bbd 8,1,4a9bce
22 0,8,4a9e73 8,2,4a9e84
23 0,8,4a9bdb 8,1,4a9bec
24 0,8,4a9e94 8,2,4a9ea8
25 0,8,4a9e94 8,2,4a9ebf
26 0,8,4a9fc9 3,8,4a9fbf
27 0,4,4aa0cb 3,4,4aa0d2
28 0,8,4aa0fc
29 0,8,4a9bf9 8,1,4a9c0d
2a 0,8,4a9bf9 8,1,4a9c24
2b 0,8,4a9bf9 8,1,4a9c3b
2c 0,8,4a9bf9 8,1,4a9c52
2d 0,8,4a9bf9 8,1,4a9c69
2e 0,8,4a9bf9 8,1,4a9c80
2f 0,8,4a9bf9 8,1,4a9c94
30 0,8,4aa10f,220e0ff@4aa119
31 0,8,4a9ca1,220e0ff@4a9cab 8,1,4a9cb9
32 0,8,4a9cc6 8,1,4a9cd7
33 0,8,4a9ecf 8,2,4a9ee0
34 0,8,4a9ce4 8,1,4a9cf5
35 0,8,4a9ef0 8,2,4a9f01
36 0,8,4aa046 3,8,4aa056
37 0,8,4aa046 3,8,4aa073
38 0,8,4aa046 3,8,4aa08d
39 0,8,4aa129
3a 0,8,4a9f11 8,2,4a9f22
3b 0,8,4aa0fc,-bf9ff00@4aa13c
3c 0,8,4aa0fc,-cf6f700@4aa14c
3d 0,8,4a9f32 8,2,4a9f43
3e 0,8,4aa2b1 8,4,4aa2c1
3f 0,8,4aa0a4 3,8,4aa0b1
40 0,8,4aa0fc,9@4aa15c
41 0,4,4aa0e2 3,4,4aa0e9
42 0,8,4aa10f
43 0,8,4a9ca1 8,1,4a9d0c
44 0,8,4a9ca1 8,1,4a9d23
45 0,8,4aa10f,100@4aa172
46 0,8,4a9ca1,100@4a9d30 8,1,4a9d42
47 0,8,4a9ca1,100@4a9d30 8,1,4a9d56
48 0,8,4aa10f,200@4aa182
49 0,8,4a9ca1,200@4a9d63 8,1,4a9d71
4a 0,8,4aa10f,300@4aa192
4b 0,8,4a9ca1,300@4a9d7e 8,1,4a9d8c
4c 0,8,4aa10f,1200@4aa1a2
4d 0,8,4aa10f,-2@4aa1b2
4e 0,8,4aa10f,fe@4aa1bf
'''

def require(ok,message):
    if not ok:raise ValueError(message)

original=(b/'visor-config-name-map-intake.json').read_bytes()
candidate=json.loads(original)
record={'gnu':(b/'observed/records/name-decoder.txt').read_text()}
rows={}
for line in record['gnu'].splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$',line)
    if m:rows[int(m[1],16)]={'bytes':bytes.fromhex(m[2]).hex(),'instruction':m[3].strip()}

def immediate(site):
    row=rows[site]
    require(re.match(r'(?:movabs|mov|xor|cmp)\s',row['instruction']) is not None,'Unexpected literal annotation')
    m=re.search(r',0x([0-9a-f]+)$',row['instruction'])
    require(m is not None,'Annotation does not identify an immediate operand')
    return int(m[1],16)

def annotate(code,fragments):
    item=next(r for r in candidate['map'] if r['code']==code)
    expected=bytes.fromhex(item['bytesHex']);seen={};records=[]
    for fragment in fragments:
        parts=fragment.split(',');offset,width,site=int(parts[0]),int(parts[1]),int(parts[2],16)
        value=immediate(site);adjustment=0;adjustment_site=None
        if len(parts)==4:
            delta,at=parts[3].split('@');adjustment=int(delta,16);adjustment_site=int(at,16)
            asm=rows[adjustment_site]['instruction']
            require(re.match(r'(?:add|lea)\s',asm) is not None,'Unexpected arithmetic annotation')
            expected_operand=('-0x'+format(-adjustment,'x')) if adjustment<0 else '0x'+format(adjustment,'x')
            require(expected_operand in asm,'Annotated arithmetic operand differs')
            value+=adjustment
        require(0<=value<1<<(8*width),'Literal does not fit fragment width')
        raw=value.to_bytes(width,'little')
        require(offset>=0 and offset+width<=len(expected),'Fragment extends past the admitted length')
        require(raw==expected[offset:offset+width],'Fragment bytes differ for '+item['literal'])
        for i,v in enumerate(raw):
            require(offset+i not in seen or seen[offset+i]==v,'Overlapping byte contradiction')
            seen[offset+i]=v
        records.append({'inputOffset':offset,'width':width,'literalSite':hex(site),'literalInstruction':rows[site],
            'adjustment':adjustment,'adjustmentSite':hex(adjustment_site) if adjustment_site is not None else None,
            'adjustmentInstruction':rows[adjustment_site] if adjustment_site is not None else None,'bytesHex':raw.hex()})
    require(set(seen)==set(range(len(expected))),'Not every compared input byte is covered')
    return {'code':code,'literal':item['literal'],'length':len(expected),'fragments':records,
            'comparisonContext':item['comparisonContext'],'returnValueInstruction':item['returnValueInstruction']}

audit=[]
for line in spec.splitlines():
    if not line.strip():continue
    code,*fragments=line.split();audit.append(annotate(int(code,16),fragments))
require(len(audit)==79 and {r['code'] for r in audit}==set(range(79)),'Audit inventory differs')
result={'state':'literal-annotation-audit-only','targetSha256':candidate['targetSha256'],
    'frozenMapSha256':hashlib.sha256(original).hexdigest(),'entries':audit,
    'fragments':sum(len(r['fragments']) for r in audit),
    'scope':'Fixed literal operand/constant annotations and byte overlap audit against a previously frozen manual map. Not CFG/liveness proof, captured instruction execution/evaluation, or a target behavior comparator.',
    'remaining':['Associate every annotated immediate with the actual input-read equality/branch using an addressed manual CFG/liveness proof.','Prove length dispatch, complete ordinary exits, bounded read sets, AL-only result and immutable table premises.','Freeze independent byte-boundary/negative corpus before any implementation or public submission.'],
    'capturedExecution':False,'instructionEvaluation':False,'semanticQualification':False}
require(len(sys.argv)==2,'Give one fresh output path');out=Path(sys.argv[1]);require(not out.exists(),'Preserve existing audit')
out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'state':result['state'],'entries':len(audit),'fragments':result['fragments'],'semanticQualification':False}))
