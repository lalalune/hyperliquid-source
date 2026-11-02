"""Pure byte/word/read-bound arithmetic supporting the addressed draft, no native evaluator."""
from pathlib import Path
import json,hashlib,datetime
M=(1<<64)-1;C=0x0101010101010100;H=0x8080808080808080
def nozero(raw):
    w0=int.from_bytes(raw[:8],'little');w1=int.from_bytes(raw[8:],'little')
    return ((((C-w0)&M)|w0)&(((C-w1)&M)|w1)&H)==H
def signed(byte):return byte if byte<128 else byte-256
for v in range(256):
    if bool((((-v)&255)|v)&128)!=(v!=0):raise ValueError('Nonzero byte lemma differs')
digest=hashlib.sha256();scenarios=0
def check(raw):
    global scenarios
    want=all(v!=0 for v in raw)
    if nozero(raw)!=want:raise ValueError('Declared sixteen-byte predicate differs')
    digest.update(raw+bytes([want]));scenarios+=1
for a in range(256):
    for b in range(256):check(bytes([a,b])+b'A'*14)
for fill in [1,0x7f,0x80,0xff]:
    for position in range(16):
        for value in range(256):check(bytes([fill])*position+bytes([value])+bytes([fill])*(15-position))
predicate_cases=0
for lead in range(0xc2,0xf5):
    for b in range(256):
        if lead<=0xdf:
            got=signed(b)<=signed(0xbf);want=0x80<=b<=0xbf
        elif lead==0xe0:got=(b&0xe0)==0xa0;want=0xa0<=b<=0xbf
        elif lead==0xed:got=signed(b)<=signed(0x9f);want=0x80<=b<=0x9f
        elif lead<=0xef:got=signed(b)<signed(0xc0);want=0x80<=b<=0xbf
        elif lead==0xf0:got=((b+0x70)&255)<0x30;want=0x90<=b<=0xbf
        elif lead==0xf4:got=signed(b)<=signed(0x8f);want=0x80<=b<=0x8f
        else:got=signed(b)<signed(0xc0);want=0x80<=b<=0xbf
        if got!=want:raise ValueError('Native-derived mathematical signed/wrap predicate differs from normative range')
        predicate_cases+=1
for lead in range(256):
    if (((lead+0x1f)&255)<12 or (lead&254)==0xee)!=(0xe1<=lead<=0xec or lead in (0xee,0xef)):raise ValueError('Ordinary width3 lead guard differs')
    if (((lead+15)&255)<=2)!=(0xf1<=lead<=0xf3):raise ValueError('Ordinary width4 lead guard differs')
bound_checks=0
for length in range(1025):
    for cursor in range(length+1):
        if cursor<max(length-15,0) and cursor+16>length:raise ValueError('UTF8 ASCII word-read guard permits overread')
        bound_checks+=1
alignment_checks=0
for pointer_mod8 in range(8):
    first_aligned=(-pointer_mod8)&7
    for cursor in range(64):
        if (((first_aligned-cursor)&7)==0)!=(((pointer_mod8+cursor)&7)==0):raise ValueError('Alignment predicate differs')
        alignment_checks+=1
for length in range(15,384):
    for alignment in range(8):
        for start in range(alignment,length-14,16):
            if start+16>length+1:raise ValueError('Stack NUL scan crosses n+1 bytes')
for length in range(384,1025):
    for alignment in range(8):
        for start in range(alignment,length-15,16):
            if start+16>length:raise ValueError('Heap NUL scan crosses n bytes')
result=dict(state='pure-arithmetic-support-for-file-read-manual-proof-unqualified',
 nonzeroByteLemmaInputs=256,sixteenByteScenarios=scenarios,scenarioSha256=digest.hexdigest(),secondBytePredicateChecks=predicate_cases,leadGuardInputs=256,
 utf8ReadGuardCases=bound_checks,alignmentCases=alignment_checks,
 scope='Independently authored integer formulas, normative byte ranges and read-bound inequalities. No captured opcode/register/branch state, file reads, target execution or runtime comparator.',
 qualified=False,capturedExecution=False,instructionEvaluation=False)
dest=Path(__import__('sys').argv[1])
if dest.exists():raise ValueError('Preserve formula receipt')
dest.write_text(json.dumps(result,indent=2)+'\n',newline='\n');print(json.dumps(result))
