"""Audit manually selected native table/store patterns; no CPU state or trace evaluator."""
from pathlib import Path
import json,re,hashlib,datetime

base=Path(__file__).resolve().parent
from native_view import SUMMARY,ranges,table
source=base/'observed/summary.json'
record={'targetSha256':SUMMARY['targetSha256'],'ranges':ranges(),
        'tables':[table(0x87a78,79),table(0x87bb4,79)]}
native=next(row for row in record['ranges'] if row['start']=='0x4a7cf0')
rows={}
for line in native['gnu'].splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$',line)
    if m:
        rows[int(m[1],16)]={'bytes':m[2].split(),'instruction':m[3].strip()}

def require(condition,message):
    if not condition:raise ValueError(message)

def at(va,expected):
    require(va in rows,'Expected instruction boundary')
    require(rows[va]['instruction']==expected,'Native annotation mismatch at '+hex(va)+': '+rows[va]['instruction'])
    return va+len(rows[va]['bytes'])

def branch(va,op,dest):
    require(rows[va]['instruction'].split()[:2]==[op,format(dest,'x')],'Native edge annotation differs at '+hex(va))
    return va+len(rows[va]['bytes'])

entries=[]
for code,(direct,obj) in enumerate(zip(record['tables'][0]['destinations'],record['tables'][1]['destinations'])):
    d=int(direct,16);o=int(obj,16)
    v=at(d,'mov    BYTE PTR [rbx+0x1],'+hex(code))
    branch(v,'jmp',0x4a8bad)
    v=at(o,'test   r14,r14')
    v=at(v,'mov    rdi,r13')
    if code==0x44:
        branch(v,'je',0x4a8bc3)
        # The false edge falls through the shared nonzero-result block.
        require(v+len(rows[v]['bytes'])==0x4a8b20,'Exceptional fallthrough differs')
        v=at(0x4a8bc3,'mov    r12b,0x1')
    else:
        v=branch(v,'jne',0x4a8b20)
        if code!=1:
            v=at(v,'mov    r12b,0x1')
        else:
            require(v==0x4a8626,'Unexpected code1 reordered-flag block')
    v=at(v,'xor    eax,eax' if code==0 else 'mov    al,'+hex(code))
    v=at(v,'xor    ebp,ebp')
    if code==1:
        v=at(v,'mov    r12b,0x1')
    v=at(v,'cmp    BYTE PTR [rdi+0x48],0x0')
    v=branch(v,'je',0x4a8b29)
    branch(v,'jmp',0x4a8b3b)
    entries.append({'decodedCode':code,'directStore':direct,'objectEntry':obj,'directOutputByte':code,'objectZeroResultOutputByte':code})
require(len(entries)==79,'Dispatch inventory differs')
output={
    'state':'conditional-static-pattern-intake-only-unqualified',

    'sourceReceipt':source.name,'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
    'targetSha256':record['targetSha256'],'entries':entries,
    'tableBytes':632,'nativePatternChecks':158,
    'observations':[
        'Both 79-entry signed-relative tables route admitted decoded code c to an immediate c result byte; the object table first tests the opaque unit-result qword for zero.',
        'The code0x44 object table entry inverts the zero branch and uses the shared late block. This exception is checked explicitly.',
        'The code1 object block reorders its explicit r12b=1 assignment to4a862a after the AL assignment and EBP clear; both original failed handwritten patterns are retained and their premature explanation is explicitly superseded.',
        'The direct table joins tag0 at4a8bad. Object zero-result paths additionally pass the shared depth bookkeeping and closing-brace path; these suffix conditions are not proved by this pattern audit.',
        'Unit helper4ab530 has an explicit n,u,l,l comparison corridor and zero return, but error-helper results and complete cursor/error behavior remain unqualified.'
    ],
    'limits':[
        'This is a static table/store audit, not an instruction interpreter, semantic equivalence proof or target execution.',
        'Decoded index range0..78 is a premise; its producer4a8d80 and quoted-string decoder64f440 are not semantically closed.',
        'No complete JSON grammar, string escape/UTF8 handling, object acceptance iff, malformed-input behavior, allocation, panic or original ABI claim.',
        'No implementation, branch, PR, recovered-byte count or full-scope gate is created by this intake.'
    ],
    'capturedExecution':False,'instructionEvaluation':False,'semanticQualification':False,
}
destination=Path(__import__('sys').argv[1])
require(not destination.exists(),'Preserve existing intake rather than overwrite')
destination.write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({'entries':len(entries),'tableBytes':632,'nativePatternChecks':158,'qualified':False}))
