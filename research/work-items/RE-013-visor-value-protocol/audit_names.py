"""Bind fixed literal annotations and conservative read bounds; no CPU evaluator."""
from pathlib import Path
import json,re,struct,sys
from survey import require,json_bytes
from native_view import SUMMARY,data
HERE=Path(__file__).resolve().parent
annotations=json.loads((HERE/'name-annotations.json').read_bytes())
rows={int(r['va'],16):dict(r,size=len(bytes.fromhex(r['bytes'])))
      for f in SUMMARY['ranges'] if f['start']=='0x4a8d80' for r in f['rows']}
entries=annotations['entries']
require(len(entries)==79 and {e['code'] for e in entries}==set(range(79)),'Name inventory differs')
sites=set();fragments=0
for e in entries:
    assembled={}
    for f in e['fragments']:
        site=int(f['literalSite'],16);sites.add(site);fragments+=1
        fixed=f['literalInstruction'];current=rows[site]
        require(fixed['instruction']==current['instruction'] and fixed['bytes']==current['bytes'],'Literal operand binding differs')
        match=re.search(r',0x([0-9a-f]+)$',current['instruction'])
        require(match is not None,'Fixed immediate annotation is absent')
        value=int(match[1],16)+f['adjustment']
        raw=value.to_bytes(f['width'],'little')
        require(raw.hex()==f['bytesHex'],'Literal fragment differs')
        if f['adjustmentSite']:
            adjustment=int(f['adjustmentSite'],16);sites.add(adjustment)
            require(adjustment in rows,'Missing adjustment boundary')
        for i,v in enumerate(raw,f['offset']):
            require(i not in assembled or assembled[i]==v,'Overlapping fragments disagree');assembled[i]=v
    require(set(assembled)==set(range(e['length'])),'Fragment coverage differs')
    require(bytes(assembled[i] for i in range(e['length']))==e['expectedLiteral'].encode(),'Frozen name differs')
    edge=e['edge'];va=int(edge['comparisonEdge'],16);accept=int(edge['accept'],16)
    op=rows[va]['instruction'].split()
    require(op[0]==edge['operation'],'Comparison edge polarity differs')
    require((op[0]=='je' and int(op[1],16)==accept) or
            (op[0]=='jne' and int(op[1],16)==0x4a95c6 and va+rows[va]['size']==accept),'Comparison edge role differs')
    for instruction in ['mov    BYTE PTR [rax+0x1],'+hex(e['code']),'xor    ecx,ecx','mov    BYTE PTR [rax],cl','ret']:
        require(rows[accept]['instruction']==instruction,'Tag/code return suffix differs');accept+=rows[accept]['size']
require(len(sites)==123 and fragments==134,'Literal denominator differs')
raw=bytes.fromhex(data(0x87cf0)['bytes']);require(len(raw)==48,'Wrong length table')
destinations=[0x87cf0+struct.unpack_from('<i',raw,i*4)[0] for i in range(12)]
edges={};returns=[];calls=[];reads=[]
for va,row in rows.items():
    asm=row['instruction'];op=asm.split()[0];nxt=va+row['size']
    if op=='ret':edges[va]=[];returns.append(va)
    elif op=='jmp':
        require(va==0x4a8d9f and asm=='jmp    rcx','Unexpected indirect jump');edges[va]=sorted(set(destinations))
    elif op in {'je','jne','ja'}:edges[va]=[nxt,int(asm.split()[1],16)]
    else:
        edges[va]=[nxt]
        if op=='call':calls.append(hex(va))
    require(all(v in rows for v in edges[va]),'Static CFG edge leaves retained body')
    for m in re.finditer(r'\b(QWORD|DWORD|WORD|BYTE) PTR \[rsi(?:\+0x([0-9a-f]+))?\]',asm):
        reads.append((va,int(m[2],16) if m[2] else 0,{'BYTE':1,'WORD':2,'DWORD':4,'QWORD':8}[m[1]]))
groups=[]
for length,start in enumerate(destinations,2):
    seen=set();stack=[start]
    while stack:
        va=stack.pop()
        if va in seen:continue
        seen.add(va);stack.extend(edges[va])
    selected=[r for r in reads if r[0] in seen]
    require(all(offset+width<=length for _,offset,width in selected),'Direct read exceeds admitted length')
    codes=sorted(e['code'] for e in entries if int(e['edge']['accept'],16) in seen)
    require(codes==sorted(e['code'] for e in entries if e['length']==length),'Length dispatch codes differ')
    groups.append({'length':length,'entry':hex(start),'directReadInstructions':len(selected),'successCodes':codes})
require(len(returns)==80 and calls==['0x4a95df'],'Normal return/call inventory differs')
result={'names':79,'literalSites':123,'fragments':134,'ordinaryReturns':80,'groups':groups,
 'code22EdgeRole':'JNE error; fallthrough success; equality condition ZF=1',
 'scope':'Static annotations and conservative direct-read bounds support MANUAL-PROOF.md; not a semantic interpreter or native comparator.',
 'capturedExecution':False,'instructionEvaluation':False}
out=Path(sys.argv[1]);require(not out.exists(),'Preserve prior receipt');out.write_bytes(json_bytes(result));print(json.dumps(result))
