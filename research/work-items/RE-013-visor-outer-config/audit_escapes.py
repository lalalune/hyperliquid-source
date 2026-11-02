"""Match an independently written one-byte escape map to raw dispatch and stores."""
from pathlib import Path
import json,re,struct,hashlib,datetime
b=Path(__file__).resolve().parent
from native_view import SUMMARY,ranges,data
deps={'targetSha256':SUMMARY['targetSha256'],'ranges':ranges()}
leaves={'table':data(0xbb970)}
r=next(x for x in deps['ranges'] if x['start']=='0x64ea20')
rows={}
for line in r['gnu'].splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$',line)
    if m:rows[int(m[1],16)]=(len(m[2].split()),m[3].strip())
def require(ok,msg):
    if not ok:raise ValueError(msg)
def exact(va,asm):
    require(rows[va][1]==asm,'Exact native annotation differs at '+hex(va))
    return va+rows[va][0]
expected={
    0x22:(0x64ea65,0x64ea7b,0x22),0x2f:(0x64eaff,0x64eb15,0x2f),
    0x5c:(0x64eae2,0x64eaf8,0x5c),0x62:(0x64eac5,0x64eadb,0x08),
    0x66:(0x64ea85,0x64ea9b,0x0c),0x6e:(0x64eaa5,0x64eabb,0x0a),
    0x72:(0x64eb1c,0x64eb32,0x0d),0x74:(0x64eb39,0x64eb4f,0x09),
}
exact(0x64ea3f,'inc    rcx')
exact(0x64ea42,'mov    QWORD PTR [rdi+0x10],rcx')
exact(0x64ea49,'add    eax,0xffffffde')
exact(0x64ea4c,'cmp    eax,0x53')
require(rows[0x64ea4f][1].split()[:2]==['ja','64ebae'],'Unsigned table guard differs')
exact(0x64ea5c,'movsxd rax,DWORD PTR [rcx+rax*4]')
raw=bytes.fromhex(leaves['table']['bytes']);require(len(raw)==336,'Expected84 signed dwords')
cases=[]
for byte in range(256):
    if 0x22<=byte<=0x75:
        destination=0xbb970+struct.unpack_from('<i',raw,(byte-0x22)*4)[0]
    else:
        destination=0x64ebae
    want=expected[byte][0] if byte in expected else 0x64ebc9 if byte==0x75 else 0x64ebae
    require(destination==want,'Dispatch differs for byte '+hex(byte))
    cases.append({'inputByte':byte,'kind':'one-byte-append' if byte in expected else 'unicode-tail' if byte==0x75 else 'diagnostic',
                  'destination':hex(destination),'outputByte':expected[byte][2] if byte in expected else None})
for byte,(entry,store,out) in expected.items():
    require(entry in rows,'Table destination is not an instruction boundary')
    exact(store,'mov    BYTE PTR [rax+r14*1],'+hex(out))
    nextva=store+rows[store][0]
    if nextva!=0x64eb54:require(rows[nextva][1].split()[:2]==['jmp','64eb54'],'Append join differs')
exact(0x64eb54,'inc    r14')
exact(0x64eb57,'mov    QWORD PTR [rbx+0x10],r14')
exact(0x64eb5b,'xor    eax,eax')
require(rows[0x64ebd3][1].split()[:2]==['jmp','64ebe0'],'Unicode tail binding differs')
result={
 'state':'conditional-static-simple-escape-intake-unqualified',
 'targetSha256':deps['targetSha256'],'tableSha256':hashlib.sha256(raw).hexdigest(),'tableBytes':336,'cases':cases,
 'ordinaryOneByteMappings':8,'unicodeTailMappings':1,'diagnosticInputBytes':247,
 'premises':['Called after a consumed backslash with at least one remaining byte. Absent-input error helper remains opaque.',
   'Stable valid state/vector storage, valid length/capacity and normal preserving capacity-helper behavior. This audit does not prove allocation or alias safety.'],
 'limits':['Static table/store binding only; not full string acceptance, a target comparator or an instruction-state evaluator.',
   'Unicode64ebe0/hex64f7f0, whole scanner masks and diagnostic nonzero returns are not yet qualified.',
   'No implementation, publication, recovered-byte credit or gate is established.'],
 'capturedExecution':False,'instructionEvaluation':False,'semanticQualification':False,
}
dest=Path(__import__('sys').argv[1])
require(not dest.exists(),'Do not overwrite original audit')
dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({k:result[k] for k in ['ordinaryOneByteMappings','unicodeTailMappings','diagnosticInputBytes','tableBytes','semanticQualification']}))
