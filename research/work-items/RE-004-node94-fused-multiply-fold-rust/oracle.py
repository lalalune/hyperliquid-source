"""Pre-Rust whole-integer oracle for the raw-register fused multiply/fold closure."""
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
STARTS = [0x565d440]
LOCK_SHA = '360f48c2ef90fee8714272490a2c167f2d13eac751d255631c57f51650d10a3b'
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
            require(not edges, 'Straight-line body changed')
            require(decoded[-1].address == end - 2 and decoded[-1].mnemonic == 'repz ret', 'Return closure changed')
            memory = [i for i in decoded if '[' in i.op_str and i.mnemonic != 'lea']
            require(len(memory) == 40, 'Memory access census changed')
            require(all(not (i.mnemonic == 'mov' and i.op_str.startswith('qword ptr [')) for i in memory[:-4]), 'Unexpected early store')
            require(all(i.mnemonic == 'mov' and i.op_str.startswith('qword ptr [rsi') for i in memory[-4:]), 'Four final stores changed')
            require([(i.address,i.op_str) for i in memory if 'rsp' in i.op_str] == [(0x565d6b5,'rsi, qword ptr [rsp + 8]')], 'Supplied output-address slot changed')
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


IMAGE_SIZE = 128
INPUT_SIZE = OUTPUT_SIZE = 240


def arithmetic(seeds, a, later_b, modulus, output_address):
    # Prepared raw registers are independent, including u=RAX and w=R15.
    u, z0, z1, v1, v2, v3, w, factor = seeds
    state = z0 + WORD*(z1+u*v1) + WORD**2*w*v2 + WORD**3*w*v3
    require(0 <= state < WORD**5, 'Initial whole-prefix bound')
    folds = []
    quotients = []
    wraps = 0
    folded_carries = 0
    def fold(value):
        low = value % WORD
        q = (low*factor) % WORD
        product = low+q*(modulus % WORD)
        full_residue = product % WORD + product//WORD
        residue = full_residue % WORD
        return value//WORD + q*(modulus//WORD) + residue, q, residue, full_residue >= WORD
    for digit in later_b:
        wide = state + WORD*a*digit
        wraps += wide >= WORD**6
        state,q,residue,dropped = fold(wide % WORD**6)
        folded_carries += dropped
        require(state < WORD**5+WORD**4-WORD**3, 'Intermediate fold bound')
        folds.append(residue)
        quotients.append(q)
    before = state
    state,q,last_residue,dropped = fold(before)
    folded_carries += dropped
    require(state < 2*WORD**4, 'Final five-word bound')
    last_carry = ((before//WORD) % WORD**3 + q*(modulus//WORD) + last_residue)//WORD**3
    require(last_carry < WORD, 'Last observed carry bound')
    difference = (state-modulus) % WORD**5
    selected = state if state < modulus else difference
    word = lambda value,i: value//WORD**i % WORD
    registers = (word(state,0), last_carry, word(state,1), word(state,3),
                 folds[2], output_address, word(selected,3), word(difference,4),
                 q, word(state,2), word(selected,0), word(selected,1), word(selected,2))
    output = (selected % WORD**4).to_bytes(32,'little')
    return registers,output,{'wraps':wraps,'selected_subtraction':state >= modulus,
                            'final_high':state//WORD**4,
                            'fold_wraps':folded_carries}


def relation(row):
    seeds = row[:8]
    base, ap, bp, mp, output_address, length, raw = row[8:]
    if base+length > WORD:
        return (0,)*14,raw,{'refused':True}
    def read(address,width):
        offset = address-base
        if offset < 0 or offset+width > length:
            raise IndexError
        return raw[offset:offset+width]
    try:
        a = int.from_bytes(read(ap,32),'little')
        later = read((bp+8)%WORD,24)
        b = tuple(int.from_bytes(later[i:i+8],'little') for i in range(0,24,8))
        modulus = int.from_bytes(read(mp,32),'little')
        read(output_address,32)
    except IndexError:
        return (0,)*14,raw,{'refused':True}
    registers,output,facts = arithmetic(seeds,a,b,modulus,output_address)
    offset = output_address-base
    result = raw[:offset]+output+raw[offset+32:]
    facts.update(refused=False,overlap=any(start < output_address+32 and output_address < start+size
                                        for start,size in [(ap,32),((bp+8)%WORD,24),(mp,32)]))
    return (1,*registers),result,facts


def corpus():
    cases = set()
    def add(seeds,a,b,m,base=0,ao=0,bo=32,mo=64,oo=96,length=128,salt=0):
        raw = bytearray((i*67+salt)%256 for i in range(128))
        for offset,value,size in [(ao,a,32),(bo+8,sum(x*WORD**i for i,x in enumerate(b)),24),(mo,m,32)]:
            if 0 <= offset and offset+size <= 128:
                raw[offset:offset+size] = value.to_bytes(size,'little')
        cases.add((*seeds,base,(base+ao)%WORD,(base+bo)%WORD,(base+mo)%WORD,(base+oo)%WORD,length,bytes(raw)))
    full = WORD**4
    allmax = [WORD-1]*8
    coeffs = [0,1,2,3,WORD//2-1,WORD//2,WORD-2,WORD-1,0x5555555555555555,0xaaaaaaaaaaaaaaaa]
    # Independent prepared-register bits; no caller consistency restriction.
    for index in range(8):
        for bit in range(64):
            for delta in [-1,0,1]:
                seeds = allmax.copy()
                seeds[index] = ((1<<bit)+delta)%WORD
                add(seeds,full-1,[WORD-1]*3,full-1,salt=index)
                other = [0]*8
                other[index] = seeds[index]
                other[-1] = WORD-1
                add(other,full-1,[WORD-1]*3,full-1,salt=index)
    for bit in range(256):
        for delta in [-1,0,1]:
            v = ((1<<bit)+delta)%full
            for factor in [0,1,WORD-1]:
                seeds = allmax.copy();seeds[-1] = factor
                add(seeds,v,[WORD-1]*3,full-1)
                add(seeds,full-1,[WORD-1]*3,v)
    for factor in coeffs:
        for m in [0,1,full//2,full-1,WORD,WORD**3,WORD**3-1]:
            for seed in [[0]*8,allmax,[1]*8]:
                seeds = seed.copy();seeds[-1] = factor
                add(seeds,full-1,[WORD-1]*3,m)
    rng = random.Random(0x565d440)
    for i in range(2200):
        add([rng.getrandbits(64) for _ in range(8)],rng.getrandbits(256),
            [rng.getrandbits(64) for _ in range(3)],rng.getrandbits(256),salt=i)
    # Consistent wrapper-prepared examples are a subset, not the domain.
    for i in range(320):
        a,b = rng.getrandbits(256),rng.getrandbits(256)
        aw = [a//WORD**j%WORD for j in range(4)]
        bw = [b//WORD**j%WORD for j in range(4)]
        initial = aw[0]*bw[0]
        seeds = [bw[0],initial%WORD,initial//WORD,aw[1],aw[2],aw[3],bw[0],rng.getrandbits(64)]
        add(seeds,a,bw[1:],rng.getrandbits(256))
    # Input roles may alias each other; output aliases any byte of any role.
    for ao,bo,mo in [(0,32,64),(0,-8,0),(8,8,8),(32,0,48),(64,40,0)]:
        for oo in range(97):
            add(allmax,rng.getrandbits(256),[rng.getrandbits(64) for _ in range(3)],rng.getrandbits(256),
                ao=ao,bo=bo,mo=mo,oo=oo,salt=oo)
    for base in [0,1,0x1000,WORD-128,WORD-64]:
        for length in [0,23,24,31,32,63,64,95,96,127,128]:
            for ao,bo,mo,oo in [(0,32,64,96),(0,-8,0,32),(0,0,0,0),(-1,32,64,96),(0,32,64,97)]:
                add(allmax,full-1,[WORD-1]*3,full-1,base,ao,bo,mo,oo,length)
    return sorted(cases)


def fixture_bytes():
    inputs = bytearray();expected = bytearray()
    coverage = {'cases':0,'admitted':0,'refusals':0,'overlap_admitted':0,
                'accumulation_wrap_cases':0,'folded_carry_drop_cases':0,'selected_subtraction_cases':0,'final_high_one_cases':0}
    for row in corpus():
        registers,image,facts = relation(row)
        inputs.extend(struct.pack('<14Q',*row[:-1])+row[-1])
        expected.extend(struct.pack('<14Q',*registers)+image)
        coverage['cases'] += 1
        if facts['refused']:
            coverage['refusals'] += 1
        else:
            coverage['admitted'] += 1
            coverage['overlap_admitted'] += facts['overlap']
            coverage['accumulation_wrap_cases'] += facts['wraps'] > 0
            coverage['folded_carry_drop_cases'] += facts['fold_wraps'] > 0
            coverage['selected_subtraction_cases'] += facts['selected_subtraction']
            coverage['final_high_one_cases'] += facts['final_high'] == 1
    return bytes(inputs),bytes(expected),coverage


def main():
    require(not (ROOT/'src/node94-fused-multiply-fold').exists(),'Freeze must precede Rust source')
    facts = admit()
    inputs,expected,coverage = fixture_bytes()
    folder = PACKET/'frozen';folder.mkdir()
    for name,raw in [('inputs.bin',inputs),('expected.bin',expected)]:
        (folder/(name+'.gz')).write_bytes(gzip.compress(raw,mtime=0))
    record = {'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'oracle_source_sha256':digest(__file__),'static_facts':facts,'coverage':coverage,
              'inputs_sha256':hashlib.sha256(inputs).hexdigest(),'expected_sha256':hashlib.sha256(expected).hexdigest(),
              'rust_source_existed':False,'captured_execution':False}
    (folder/'ORACLE-FREEZE.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:v for k,v in record.items() if k != 'static_facts'},indent=2))


if __name__ == '__main__':
    main()
