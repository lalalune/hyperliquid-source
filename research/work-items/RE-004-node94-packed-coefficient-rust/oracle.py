"""Pre-Rust integer-prefix and affine-matrix oracle for normalized coefficient steps."""
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
STARTS = [0x565ec20, 0x565ecc0]
LOCK_SHA = 'a6f6eff0dd7960e2851fe749fbb14a3437d61f9e106321fbcc5feb64812dcbab'
WORD = 2**64


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def mapping(data):
    secs = sections(data)
    for name in ('.text', '.eh_frame', '.rela.dyn'):
        require(sum(s['name'] == name for s in secs) == 1, 'Ambiguous section ' + name)

    def offset(va, size):
        found = [s for s in secs if s['type'] != 8 and s['address'] <= va
                 and va + size <= s['address'] + s['size']]
        require(len(found) == 1, 'VA mapping is not unique')
        return found[0]['offset'] + va - found[0]['address']
    return secs, offset


def structure(data):
    require(digest(PACKET / 'static-lock.json') == LOCK_SHA, 'Static lock changed')
    contract = json.loads((PACKET / 'static-lock.json').read_text())
    secs, offset = mapping(data)
    read = lambda va, size: data[offset(va, size):offset(va, size) + size]
    _, frames = eh_frame_records(data)
    bodies = []
    for item in contract['bodies']:
        start, end = item['start'], item['end']
        overlapping = [f for f in frames if f['start'] < end and start < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (start, end), 'Unique complete FDE changed')
        raw = read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == item['body_sha256'], 'Complete body changed')
        for record in item['frames'].values():
            encoded = bytes.fromhex(record['hex'])
            require(read(record['va'], len(encoded)) == encoded, 'FDE/CIE changed')
        fde, cie = item['frames']['fde'], item['frames']['cie']
        encoded = bytes.fromhex(fde['hex'])
        pc = fde['va'] + 8 + struct.unpack_from('<i', encoded, 8)[0]
        extent = struct.unpack_from('<I', encoded, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE extent changed')
        require(fde['va'] + 4 - struct.unpack_from('<I', encoded, 4)[0] == cie['va'], 'CIE pointer changed')
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, start))
        require(b''.join(i.bytes for i in decoded) == raw, 'Incomplete linear decode')
        rows = [{'va': hex(i.address), 'hex': i.bytes.hex(), 'mnemonic': i.mnemonic,
                 'operands': i.op_str} for i in decoded]
        if start in STARTS:
            require(not any(i.mnemonic == 'call' for i in decoded), 'Closure acquired a callee')
            edges = [(i.address, i.mnemonic, i.op_str) for i in decoded if i.mnemonic.startswith('j')]
            expected = [(0x565ecae, 'jmp', '0x565ecc0')] if start == STARTS[0] else [(0x565ed2c, 'jne', '0x565ece2')]
            require(edges == expected, 'Tail/loop edge changed')
            require(decoded[-1].address == end - 2 and decoded[-1].mnemonic == 'repz ret', 'Return closure changed')
            memory = [i for i in decoded if '[' in i.op_str and i.mnemonic != 'lea']
            require(len(memory) == (8 if start == STARTS[0] else 0), 'Memory closure changed')
            require(all(i.mnemonic == 'mov' and '[rsi' in i.op_str for i in memory), 'Snapshot reads changed')
        sites = {i.address: i for i in decoded}
        for site, target in item['sites']:
            require(site in sites and sites[site].mnemonic in ('call','jmp') and sites[site].op_str == hex(target), 'Caller/tail boundary changed')
        bodies.append({**item, 'instructions': rows})
    for pad in contract['padding']:
        raw = bytes.fromhex(pad['hex'])
        require(read(pad['start'], len(raw)) == raw, 'Alignment padding changed')
    relocation_count = 0
    for section in secs:
        require(section['type'] != 9, 'Unexpected REL table')
        if section['type'] == 4:
            require(section['size'] % 24 == 0, 'Malformed RELA extent')
            for address, info, addend in struct.iter_unpack('<QQq', read(section['address'], section['size'])):
                require((info & 0xffffffff) in (1, 6, 7, 8, 18), 'Unknown relocation width')
                require(addend not in STARTS, 'Unexpected naming relocation')
                for body in contract['bodies']:
                    require(not (address < body['end'] and address + 8 > body['start']), 'Body relocation appeared')
                for pad in contract['padding']:
                    require(not (address < pad['start'] + len(bytes.fromhex(pad['hex'])) and address + 8 > pad['start']), 'Padding relocation appeared')
                relocation_count += 1
    text = next(s for s in secs if s['name'] == '.text')
    code, scans = read(text['address'], text['size']), {}
    for start in STARTS:
        scan = {}
        for opcode, width in ((b'\xe8', 5), (b'\xe9', 5), (b'\xeb', 2)):
            hits, pos = [], 0
            while (pos := code.find(opcode, pos)) >= 0:
                if pos + width <= len(code):
                    displacement = struct.unpack_from('<b' if width == 2 else '<i', code, pos + 1)[0]
                    if text['address'] + pos + width + displacement == start:
                        hits.append(text['address'] + pos)
                pos += 1
            scan[opcode.hex()] = hits
        scans[hex(start)] = scan
    require(scans == contract['scans'], 'Incoming pattern scan changed')
    return {'target_sha256': TARGET_SHA, 'bodies': bodies, 'incoming_candidates': scans,
            'relocation_records': relocation_count, 'naming_relocations': 0,
            'text_scan_bytes': len(code), 'capstone_version': capstone_version,
            'static_lock_sha256': LOCK_SHA, 'complete_xref_census': False}


def admit():
    raw = TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == TARGET_SHA, 'Target identity changed')
    return structure(raw)



BIAS = 0x7fffffff7fffffff
INITIAL = [0x7fffffff80000000, 0x800000007fffffff, BIAS]
LOW = 2**31-1


def normalize(a,b):
    x=sum(a[i]*WORD**i for i in range(4)); y=sum(b[i]*WORD**i for i in range(4))
    rank=max(0,((x|y).bit_length()-1)//64)
    if rank == 0:
        shift=0; high_x=a[0] & (WORD-1-LOW); high_y=b[0] & (WORD-1-LOW)
    else:
        width=((x|y)//WORD**rank).bit_length(); shift=(-width)%64
        window_x=(x//WORD**(rank-1))%(WORD**2)
        window_y=(y//WORD**(rank-1))%(WORD**2)
        high_x=((window_x*2**shift)//WORD)%WORD & (WORD-1-LOW)
        high_y=((window_y*2**shift)//WORD)%WORD & (WORD-1-LOW)
    return (a[0]&LOW)|high_x, (b[0]&LOW)|high_y, high_x,high_y,rank,shift


def matrix_product(a,b):
    return [[sum(a[i][k]*b[k][j] for k in range(3)) for j in range(3)] for i in range(3)]


def coefficients(matrix):
    return tuple(sum(row[j]*INITIAL[j] for j in range(3))%WORD for row in matrix[:2])


def relation(mode,a,b,raw_count):
    if mode:
        x,y,r9,r11,rank,shift=normalize(a,b)
    else:
        x,y,r9,r11=a[0],b[0],a[1],b[1];rank=shift=-1
    remaining=raw_count%2**32 or 2**32
    matrix=[[1,0,0],[0,1,0],[0,0,1]]
    explicit=0; swaps=0
    while remaining and x:
        u,v=coefficients(matrix);last=(x,y,u,v)
        old_potential=x.bit_length()+y.bit_length()
        if x%2 == 0:
            transition=[[1,0,0],[0,2,-1],[0,0,1]];x=x//2
        elif x>=y:
            transition=[[1,-1,1],[0,2,-1],[0,0,1]];x=(x-y)//2
        else:
            transition=[[-1,1,1],[2,0,-1],[0,0,1]];x,y=(y-x)//2,x;swaps+=1
        require(x.bit_length()+y.bit_length()<old_potential,'Potential did not descend')
        matrix=matrix_product(transition,matrix);remaining-=1;explicit+=1
        require(explicit<=128,'Derived descent bound violated')
    u,v=coefficients(matrix)
    stable=remaining
    if remaining:
        before=(BIAS+(v-BIAS)*pow(2,remaining-1,WORD))%WORD
        last=(0,y,u,before)
        v=(BIAS+(v-BIAS)*pow(2,remaining,WORD))%WORD
    # RAX,RBX,RCX,RDX,RBP,R8,R9,R10,R11,R12,R13,R14,R15.
    output=(last[0],last[1],(u//2**32-LOW)%WORD,(u%2**32-LOW)%WORD,
            last[2],x,r9,y,r11,(v%2**32-LOW)%WORD,(v//2**32-LOW)%WORD,last[3],LOW)
    return output,{'explicit':explicit,'stable':stable,'swaps':swaps,'rank':rank,'shift':shift}


def fixture_bytes():
    cases=set()
    def add(mode,a,b,count):cases.add((mode,*(x%WORD for x in (*a,*b,count))))
    counts=[0,1,2,3,30,31,32,33,63,64,65,66,127,128,129,191,192,193,255,256,257,2**31,2**32-1,2**32,2**32+1,WORD-1]
    edges=[0,1,2,3,2**31-1,2**31,2**32-1,2**32,2**63-1,2**63,WORD-2,WORD-1]
    for x in edges:
        for y in edges:
            for n in counts:add(0,[x,x^0xdeadbeef,0,0],[y,y^0x12345678,0,0],n)
    for rank in range(4):
        for bit in range(64):
            for delta in (-1,0,1):
                a=[0]*4;b=[0]*4;a[rank]=(2**bit+delta)%WORD
                a[0]|=0x1234567;b[0]=0x7654321
                for order in (0,1):
                    add(1,a if order==0 else b,b if order==0 else a,counts[(rank+bit+delta+order)%len(counts)])
    for a in ([0]*4,[WORD-1]*4,[1,0,0,0],[0,0,0,1],[0xaaaaaaaaaaaaaaaa]*4):
        for b in ([0]*4,[WORD-1]*4,[2,0,0,0],[0,1,0,0]):
            for n in counts:add(1,a,b,n)
    rng=random.Random(STARTS[0])
    for _ in range(1024):
        mode=rng.randrange(2);a=[rng.getrandbits(64) for _ in range(4)];b=[rng.getrandbits(64) for _ in range(4)]
        if not mode:a[2:]=[0,0];b[2:]=[0,0]
        add(mode,a,b,rng.choice(counts))
    inputs=[];expected=[]
    coverage={'cases':len(cases),'by_entry':[0,0],'random_seed':hex(STARTS[0]),'zero_low32_counts':0,
              'high_count_bits':0,'stable_tail_cases':0,'stable_tail_at_least64':0,
              'max_explicit_steps':0,'swap_cases':0,'normalization_ranks':[],'normalization_shift_counts':[]}
    ranks=set();shifts=set()
    for mode,*words in sorted(cases):
        a,b,count=words[:4],words[4:8],words[8];out,trace=relation(mode,a,b,count)
        inputs.append('\t'.join([str(mode),*(f'{w:016x}' for w in words)]));expected.append(','.join(f'{w:016x}' for w in out))
        coverage['by_entry'][mode]+=1;coverage['zero_low32_counts']+=count%2**32==0;coverage['high_count_bits']+=count>=2**32
        coverage['stable_tail_cases']+=trace['stable']>0;coverage['stable_tail_at_least64']+=trace['stable']>=64
        coverage['max_explicit_steps']=max(coverage['max_explicit_steps'],trace['explicit']);coverage['swap_cases']+=trace['swaps']>0
        if mode:ranks.add(trace['rank']);shifts.add(trace['shift'])
    coverage['normalization_ranks']=sorted(ranks);coverage['normalization_shift_counts']=sorted(shifts)
    return ('\n'.join(inputs)+'\n').encode(), ('\n'.join(expected)+'\n').encode(), coverage


def freeze():
    require(not (ROOT / 'src/node94-packed-coefficient').exists(), 'Rust already exists')
    folder = PACKET / 'frozen'
    require(not (folder / 'ORACLE-FREEZE.json').exists(), 'Freeze already exists')
    facts = admit()
    inputs, output, coverage = fixture_bytes()
    for name, raw in (('inputs.tsv', inputs), ('expected.txt', output)):
        (folder / (name + '.gz')).write_bytes(gzip.compress(raw, mtime=0))
    record = {'frozen_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_base_commit': '56c0ec672bd8fdcfaa80f2db700a61e6240b3663',
              'rust_source_present': False, 'oracle_source_sha256': digest(__file__),
              'inputs_sha256': hashlib.sha256(inputs).hexdigest(),
              'expected_sha256': hashlib.sha256(output).hexdigest(), 'coverage': coverage,
              'static_facts': facts}
    (folder / 'ORACLE-FREEZE.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'oracle_source_sha256': record['oracle_source_sha256'], 'coverage': coverage}, indent=2))


if __name__ == '__main__':
    freeze()
