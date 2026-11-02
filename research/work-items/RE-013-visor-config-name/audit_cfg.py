"""Build a static CFG and audit annotated length-group read extents; no execution."""
from pathlib import Path
import json,re,struct,hashlib,collections,sys

b=Path(__file__).resolve().parent
def require(ok,message):
    if not ok:raise ValueError(message)
mapping=json.loads((b/'visor-config-name-map-intake.json').read_bytes())
record={'gnu':(b/'observed/records/name-decoder.txt').read_text()}
rows={}
for line in record['gnu'].splitlines():
    m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$',line)
    if m:
        va=int(m[1],16);raw=bytes.fromhex(m[2]);asm=m[3].strip();rows[va]={'bytes':raw.hex(),'instruction':asm,'size':len(raw)}
sizes={'BYTE':1,'WORD':2,'DWORD':4,'QWORD':8}
allowed={'mov','movabs','movzx','movsxd','lea','xor','or','add','cmp','je','jne','ja','jmp','ret'}
edges={};input_reads={};return_sites=set();mnemonics=collections.Counter()
table_targets={int(r['destination'],16) for r in mapping['lengthDispatch']}
for va,row in rows.items():
    asm=row['instruction'];op=asm.split()[0];mnemonics[op]+=1
    require(op in allowed,'Unexpected instruction family')
    # This invariant is syntactic; the full original instructions remain bound.
    if op not in {'cmp','ret','je','jne','ja','jmp'}:
        first=asm.split(None,1)[1].split(',')[0].strip()
        require(first not in {'rdi','edi','di','dil'},'Input pointer register is modified')
        require('PTR [' not in first,'Unexpected memory write')
    reads=[]
    for match in re.finditer(r'\b(QWORD|DWORD|WORD|BYTE) PTR \[rdi(?:\+0x([0-9a-f]+))?\]',asm):
        reads.append({'offset':int(match[2],16) if match[2] else 0,'width':sizes[match[1]]})
    if reads:input_reads[va]=reads
    next_va=va+row['size']
    if op=='ret':
        return_sites.add(va);edges[va]=[]
    elif op in {'je','jne','ja'}:
        target=int(asm.split()[1],16);edges[va]=[next_va,target]
    elif op=='jmp':
        require(va==0x4a9afe and asm=='jmp    rdx','Unexpected indirect branch')
        edges[va]=sorted(table_targets)
    else:edges[va]=[next_va]
    require(all(dest in rows for dest in edges[va]),'CFG edge leaves full FDE or instruction boundaries')
require(return_sites=={int(r['returnValueInstruction'],16)+2 for r in mapping['map']}|{0x4aa21e},'Ordinary return inventory differs')
require(len(rows)==564 and sum(r['size'] for r in rows.values())==2246,'Full extent inventory differs')
require(rows[0x4a9ae0]['instruction']=='mov    al,0x4f','Default byte differs')
require(rows[0x4a9ae2]['instruction']=='add    rsi,0xfffffffffffffffe','Unsigned length normalization differs')
require(rows[0x4a9ae6]['instruction']=='cmp    rsi,0xb','Length guard differs')
require(rows[0x4a9aea]['instruction'].startswith('ja     4aa21e '),'Length guard edge differs')
require(rows[0x4a9af7]['instruction']=='movsxd rdx,DWORD PTR [rcx+rsi*4]','Table index/load differs')
groups=[]
for group in mapping['lengthDispatch']:
    n=group['length'];start=int(group['destination'],16);seen=set();stack=[start]
    while stack:
        va=stack.pop()
        if va in seen:continue
        seen.add(va);stack.extend(edges[va])
    for va in seen:
        for read in input_reads.get(va,[]):require(read['offset']+read['width']<=n,'Read exceeds annotated length group')
    terminals=sorted(return_sites&seen)
    groups.append({'length':n,'entry':hex(start),'reachableInstructions':len(seen),'inputReadInstructions':sum(va in input_reads for va in seen),
        'returns':[hex(va) for va in terminals],'maximumReadEnd':max((read['offset']+read['width'] for va in seen for read in input_reads.get(va,[])),default=0)})
    if n in {5,6}:require(seen=={0x4aa21e},'Empty length bucket unexpectedly reads input')
reachable=set();stack=[0x4a9ae0]
while stack:
    va=stack.pop()
    if va in reachable:continue
    reachable.add(va);stack.extend(edges[va])
require(reachable==set(rows),'Unexpected unreachable instruction extent')
# A DFS on static edges checks acyclicity; it is not a concrete input trace.
active=set();done=set()
def acyclic(va):
    require(va not in active,'Static CFG cycle')
    if va in done:return
    active.add(va)
    for dest in edges[va]:acyclic(dest)
    active.remove(va);done.add(va)
acyclic(0x4a9ae0)
result={'state':'static-cfg-read-extent-audit-only','targetSha256':mapping['targetSha256'],'range':mapping['range'],
    'sourceReceiptSha256':hashlib.sha256((b/'observed/records/name-decoder.txt').read_bytes()).hexdigest(),
    'mnemonics':dict(sorted(mnemonics.items())),'instructions':len(rows),'ordinaryReturnSites':len(return_sites),
    'allInstructionsReachableInConservativeCFG':True,'acyclic':True,'inputPointerNeverWritten':True,'memoryWrites':0,'calls':0,
    'groups':groups,'scope':'Static edges, syntactic pointer/write invariants and length-group read bounds; no concrete captured instruction evaluation. Branch predicates and literal/register liveness still require the addressed manual proof.',
    'capturedExecution':False,'instructionEvaluation':False,'semanticQualification':False}
require(len(sys.argv)==2,'Give one fresh output path');out=Path(sys.argv[1]);require(not out.exists(),'Preserve existing CFG audit')
out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:result[k] for k in ['state','instructions','ordinaryReturnSites','acyclic','memoryWrites','calls']}))
