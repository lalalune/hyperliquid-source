"""Frozen static byte-view expectations, authored before the new Rust."""
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
SOURCE = ROOT / 'src/node94-sentinel-read'
MASK = (1 << 64) - 1
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END, BODY, FRAME_ROWS = (85240752, 85240803, 'f30f1efa488b82001200004881c2e01100004839d07411488b4030488906b801000000c30f1f400031c0488906b801000000c3', [(2728192, 85240752, 85240803), (2728212, 85240816, 85240849)])
def require(value, message):
    if not value: raise ValueError(message)
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def module(name):
    sys.path.insert(0, str(ROOT / 'tools'))
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    obj = importlib.util.module_from_spec(spec); spec.loader.exec_module(obj); return obj
def body_checks(data):
    from elf_index import sections
    secs = sections(data)
    def read(va, size):
        found = [s for s in secs if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(found) == 1, 'Ambiguous mapping')
        s = found[0]; off = s['offset'] + va - s['address']; return data[off:off+size]
    require(read(START, END-START) == bytes.fromhex(BODY), 'Instruction body changed')
    eh = next(s for s in secs if s['name'] == '.eh_frame')
    frames = []
    for offset, start, end in FRAME_ROWS:
        address = eh['address'] + offset
        length = struct.unpack('<I', read(address, 4))[0]
        require(16 <= length + 4 <= 128, 'FDE length')
        raw = read(address, length+4)
        cie = offset + 4 - struct.unpack_from('<I', raw, 4)[0]
        require(cie == 0, 'Unexpected FDE CIE')
        require(read(eh['address'],24) == bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'), 'CIE changed')
        pc = address + 8 + struct.unpack_from('<i', raw, 8)[0]
        require((pc, pc + struct.unpack_from('<I', raw,12)[0]) == (start,end), 'FDE PC range')
        frames.append({'section_offset':hex(offset),'start':hex(start),'end':hex(end),'raw':raw.hex()})
    return {'windows':[[START,END,hashlib.sha256(bytes.fromhex(BODY)).hexdigest()]],'frames':frames}
def admit(binary):
    data = Path(binary).read_bytes()
    require(len(data)==91774280 and hashlib.sha256(data).hexdigest()==SHA,'Wrong node94 capture')
    name = 'foundation_sentinel_field_read'; legacy = module(name)
    if hasattr(legacy,'inspect'):
        facts=legacy.inspect(binary)
    else:
        evidence=ROOT/'research/work-items/foundation-sentinel-field-read-94/evidence.json'
        ev=json.loads(evidence.read_text())
        body=legacy.check_packet(ev,str(evidence.parent)); legacy.check_binary(ev,str(binary),body)
        facts=ev
    return {'target_sha256':SHA,'legacy_checker':name,'legacy_checker_sha256':digest(ROOT/'tools'/(name+'.py')),
            'legacy_facts':json.loads(json.dumps(facts)),**body_checks(data)}
def vector_bytes():
    rows=[]
    for i,w in enumerate(corpus()):
        expected=registers(w)
        require(expected==closed(w),'Static formulations disagree '+str(i))
        rows.append(str(i)+'\t'+','.join(map(str,w))+'\t'+','.join(map(str,expected)))
    return ('\n'.join(rows)+'\n').encode()
def freeze(binary):
    require(not (SOURCE/'lib.rs').exists(),'Rust already exists: freeze forbidden')
    directory=PACKET/'preparation'; directory.mkdir()
    facts=admit(binary); vectors=vector_bytes()
    (directory/'vectors.tsv').write_bytes(vectors)
    record={'base':'966865f1637a29ce75b019e1bf11d5529cc6f519','kind':'sentinel-read','cases':len(corpus()),
       'contract_sha256':digest(__file__),'vectors_sha256':hashlib.sha256(vectors).hexdigest(),
       'new_rust_exists_at_freeze':False,'equation_mismatches':0,'full_domain_formal_proof':False,'admitted':facts}
    (directory/'ORACLE-FREEZE.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8',newline='\n')
    return record

def finish(tag, regs, events, memory):
    out=[tag,*regs,len(events)]
    for event in events: out.extend(event)
    out.append(len(memory))
    for address,byte in sorted(memory.items()): out.extend([address,byte])
    return out

def byte_view_rule(w):
    """Register-oriented ordered operations, including explicit view refusals."""
    memory=image(w); events=[]
    def read(a):
        a &= MASK; events.append([0,a,0])
        return int.from_bytes(bytes(memory[(a+i)&MASK] for i in range(8)),'little')
    def write(a,v,size):
        a &= MASK; events.append([1 if size==8 else 2,a,v])
        addresses=[(a+i)&MASK for i in range(size)]
        if not all(x in memory for x in addresses): raise KeyError('unmapped write')
        for x,b in zip(addresses,v.to_bytes(size,'little')):memory[x]=b
    try:
        base,entry,out,field,flags=w
        rax=read(base+0x1200); rdx=(base+0x11e0)&MASK
        if rax==rdx:rax=0
        else:rax=read(rax+0x30)
        write(out,rax,8); rax=1; regs=[rax,rdx,out]
    except KeyError:
        return finish(1,[0,0,0],events,memory)
    return finish(0,regs,events,memory)

def polynomial_rule(w):
    """Separately expressed scalar equations and byte-polynomial observations."""
    memory=image(w); events=[]
    def get(a):
        a %= 1<<64; events.append([0,a,0])
        return sum(memory[(a+i)%(1<<64)]*256**i for i in range(8))
    def put(a,v,n):
        a %= 1<<64; events.append([1 if n==8 else 2,a,v])
        keys=[(a+i)%(1<<64) for i in range(n)]
        if any(k not in memory for k in keys):raise KeyError('missing output')
        memory.update({key:(v//256**i)%256 for i,key in enumerate(keys)})
    try:
        root,_,output,_,_=w
        pointer=get(root+4608); sentinel=(root+4576)%(1<<64)
        answer=0 if pointer==sentinel else get(pointer+48)
        put(output,answer,8); regs=[1,sentinel,output]
    except KeyError:
        return finish(1,[0,0,0],events,memory)
    return finish(0,regs,events,memory)

registers=byte_view_rule
closed=polynomial_rule

def image(w):
    root,entry,out,field,flags=w
    memory={}
    def put(a,v):
        for i in range(8):memory[(a+i)&MASK]=(v>>(8*i))&255
    # Map output first, then actual source bytes. Read/write aliases are allowed.
    if not flags&4:put(out,0xa55a5aa5ff00ff00)
    if not flags&1:put((root+0x1200)&MASK,entry)
    if not flags&2:put((entry+0x30)&MASK,field)
    memory.setdefault((out-1)&MASK,0xa5);memory.setdefault((out+8)&MASK,0x5a)
    return memory
def corpus():
    edges=[0,1,255,256,(1<<32)-1,1<<32,1<<63,MASK]
    rows=set()
    for root in edges:
        for field in edges:
            for flags in range(8):
                rows.add((root,(root+0x11e0)&MASK,0x9000,field,flags))
                rows.add((root,0x6000,0x9000,field,flags))
    for shift in range(-7,8):
        for field in edges:
            rows.add((0x1000,0x6000,(0x6030+shift)&MASK,field,0))
            rows.add((0x1000,0x6000,(0x2200+shift)&MASK,field,0))
            rows.add((0x1000,0x21e0,(0x2200+shift)&MASK,field,2))
    for bit in range(64):
        rows.add((0x1000,0x6000,0x9000,1<<bit,0))
        rows.add((1<<bit,0x6000,0x9000,MASK,0))
    for byte in range(256):rows.add((MASK-0x11ff,0x6000,MASK-3,byte*0x0101010101010101,0))
    rng=random.Random(2026110207)
    for _ in range(1024):
        root=rng.getrandbits(64);entry=rng.getrandbits(64);out=rng.getrandbits(64)
        rows.add((root,entry,out,rng.getrandbits(64),rng.randrange(8)))
    return sorted(rows)

if __name__=="__main__":
    print(json.dumps(freeze(Path(sys.argv[1])),indent=2))
