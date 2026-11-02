"""Independent finite byte-predicate/word-formula checks, not a native evaluator."""
from pathlib import Path
import json,datetime,hashlib
M=(1<<64)-1
def special(v):return v<32 or v in (34,92)
def mask(word):
    return (((word+0xdfdfdfdfdfdfdfe0)&M)
        |(((word^0x2222222222222222)+0xfefefefefefefeff)&M)
        |(((word^0x5c5c5c5c5c5c5c5c)+0xfefefefefefefeff)&M))&(~word&M)&0x8080808080808080
def first(raw):
    bits=mask(int.from_bytes(raw,'little'))
    return ((bits&-bits).bit_length()-1)//8 if bits else None
def check(raw):
    expected=next((i for i,v in enumerate(raw) if special(v)),None)
    if first(raw)!=expected:raise ValueError('Word formula disagrees with independent byte predicate')
    return expected
# Before the first special lane, both equality additions have carry1 and the
# control addition has carry1. Low-lane constants are FE+1 and DF+1 already.
# Check every possible next byte under this inductive precondition.
for v in range(256):
    sums=[(v^34)+255,(v^92)+255,v+224]
    flagged=bool((sums[0]|sums[1]|sums[2])&(~v&255)&128)
    if flagged!=special(v):raise ValueError('First-special byte lemma differs')
    if not special(v) and not all(s>=256 for s in sums):raise ValueError('Ordinary-byte carry induction fails')
digest=hashlib.sha256();cases=0
for a in range(256):
    for c in range(256):
        raw=bytes([a,c])+b'AAAAAA';expected=check(raw)
        digest.update(raw+bytes([255 if expected is None else expected]));cases+=1
for fill in [0x20,0x7f,0x80,0xff]:
    for position in range(8):
        for value in range(256):
            raw=bytes([fill])*position+bytes([value])+bytes([fill])*(7-position)
            expected=check(raw)
            digest.update(raw+bytes([255 if expected is None else expected]));cases+=1
result={
 'state':'manual-word-lemma-with-abstract-checks-unqualified',

 'byteLemmaCases':256,'wordScenarioChecks':cases,'wordScenarioDigest':digest.hexdigest(),
 'relation':'The first flagged byte lane equals the first byte below32 or equal to34/92, or there is no flag when all eight bytes are ordinary.',
 'proofIdea':'Prior ordinary lanes force all three addition carries to1. At the first special lane the corresponding high bit is set. No prior lane is flagged; later borrow/carry artifacts cannot change the least flagged lane.',
 'limits':['This independently authored integer formula is checked as mathematics; no captured instruction/register/branch state is interpreted.',
   'Addressed native liveness, TZCNT precondition, cursor offsets, read bounds, scalar tail and below-identity controls remain manual proof/qualification obligations.',
   'Finite scenarios support the manual carry induction; they are not exhaustive2^64 words or a target runtime comparator.'],
 'capturedExecution':False,'instructionEvaluation':False,'semanticQualification':False,
}
dest=Path(__import__('sys').argv[1])
if dest.exists():raise ValueError('Preserve original formula check')
dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({k:result[k] for k in ['byteLemmaCases','wordScenarioChecks','wordScenarioDigest','semanticQualification']}))
