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
SOURCE = ROOT / 'src/node94-self-link'
MASK = (1 << 64) - 1
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END, BODY, FRAME_ROWS = (83435232, 83435259, 'f30f1efa488d571048c74708000000004889f8488917c6471000c3', [(2660476, 83435232, 83435259), (2660496, 83435264, 83435532)])
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
    name = 'foundation_self_link_init'; legacy = module(name)
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
    record={'base':'966865f1637a29ce75b019e1bf11d5529cc6f519','kind':'self-link','cases':len(corpus()),
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
        base=w[0]; rdx=(base+16)&MASK
        write(base+8,0,8); rax=base; write(base,rdx,8); write(base+16,0,1)
        regs=[rax,rdx,0]
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
        x=w[0]; head=(x+16)%(1<<64)
        for address,value,size in [(x+8,0,8),(x,head,8),(x+16,0,1)]:put(address,value,size)
        regs=[x,head,0]
    except KeyError:
        return finish(1,[0,0,0],events,memory)
    return finish(0,regs,events,memory)

registers=byte_view_rule
closed=polynomial_rule

def image(w):
    base,seed,missing=w
    memory={(base+i)&MASK:(seed+i*37)%256 for i in range(-2,24)}
    for bit in range(17):
        if missing&(1<<bit):memory.pop((base+bit)&MASK,None)
    return memory
def corpus():
    edges=[0,1,7,8,15,16,255,256,(1<<32)-1,1<<32,1<<63,MASK-16,MASK-8,MASK]
    masks=[0,(1<<17)-1,0xff,0xff00,1<<16]+[1<<b for b in range(17)]
    rows={(base,seed,mask) for base in edges for seed in [0,1,127,255] for mask in masks}
    rows.update((base,seed,0) for base in range(256) for seed in range(0,256,17))
    for bit in range(64):rows.add((1<<bit,165,0))
    rng=random.Random(2026110206)
    rows.update((rng.getrandbits(64),rng.getrandbits(8),0) for _ in range(1024))
    return sorted(rows)

if __name__=="__main__":
    print(json.dumps(freeze(Path(sys.argv[1])),indent=2))
