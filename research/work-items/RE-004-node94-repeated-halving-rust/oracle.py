"""Pre-Rust closed-form repeated-halving oracle, without an iteration loop."""
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
STARTS = [0x565dbc0]
LOCK_SHA = '2a8c3c60db0db387182ca1ba872d9d988e88070a0700a1f5fb7c01ac59296e05'
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
        require(start in STARTS and not any(i.mnemonic == 'call' for i in decoded), 'Leaf closure changed')
        require([(i.address, i.mnemonic, i.op_str) for i in decoded if i.mnemonic.startswith('j')] == [(0x565dc3d, 'jne', '0x565dbd9')], 'Loop edge changed')
        require(decoded[-1].address == end - 2 and decoded[-1].mnemonic == 'repz ret', 'Return closure changed')
        writes = [i for i in decoded if i.op_str.startswith('qword ptr [rdi')]
        require(len(writes) == 4 and all(i.mnemonic == 'mov' for i in writes), 'Destination stores changed')
        require(not any('[' in i.op_str and '[rsp' not in i.op_str and not i.op_str.startswith('qword ptr [rdi')
                        for i in decoded if i.address > writes[0].address), 'Input read follows output store')
        require(not any('[rip' in i.op_str for i in decoded), 'Static data edge appeared')
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
    require(scans == contract['scans'] == {hex(a): {'e8': [], 'e9': [], 'eb': []} for a in STARTS}, 'Incoming pattern scan changed')
    return {'target_sha256': TARGET_SHA, 'bodies': bodies, 'incoming_candidates': scans,
            'relocation_records': relocation_count, 'naming_relocations': 0,
            'text_scan_bytes': len(code), 'capstone_version': capstone_version,
            'static_lock_sha256': LOCK_SHA, 'complete_xref_census': False}


def admit():
    raw = TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == TARGET_SHA, 'Target identity changed')
    return structure(raw)



WIDE = WORD**4
IMAGE_SIZE = 128


def closed_value(x, m, raw_count):
    n = raw_count % 2**32 or 2**32
    if m == 0:
        return x // 2**min(n, 256)
    if x == 0:
        return 0
    d = m if m % 2 else m - 1
    if n <= 256:
        radix = 2**n
        t = (-x * pow(d, -1, radix)) % radix
        return (x + d * t) // radix
    if d == 1:
        return 1
    residue = (x * pow(2, -n, d)) % d
    return residue or d


def relation(destination, left, correction, raw_count, image):
    if any(o < 0 or o + 32 > len(image) for o in (destination,left,correction)):
        return (0,) * 8, image, {'refused': True}
    x, m = (int.from_bytes(image[o:o+32], 'little') for o in (left,correction))
    value = closed_value(x, m, raw_count)
    require(0 <= value < WIDE, 'Output outside four-word domain')
    words = [(value // WORD**i) % WORD for i in range(4)]
    top = 2**63
    # RAX, RDX, RSI, R8, R9, R10, R11; all are determined by the last result.
    registers = (words[3] & top, 0, words[2] & top, words[0] % top, *words[1:])
    updated = image[:destination] + value.to_bytes(32, 'little') + image[destination+32:]
    return (1, *registers), updated, {'refused': False, 'x_zero': x==0, 'm_zero': m==0,
       'm_one': m==1, 'm_even_nonzero': m!=0 and m%2==0,
       'unreduced_x': m>0 and x>(m if m%2 else m-1), 'n':raw_count%2**32 or 2**32}


def fixture_bytes():
    cases=set()
    def add(x,m,count,offsets=(96,0,40),salt=0):
        image=bytearray((i*37+salt)%256 for i in range(IMAGE_SIZE))
        for o,value in zip(offsets[1:],(x,m)):
            if o+32<=IMAGE_SIZE:image[o:o+32]=(value%WIDE).to_bytes(32,'little')
        cases.add((*offsets,count%WORD,bytes(image)))
    counts=[0,1,2,3,31,32,63,64,65,127,128,129,255,256,257,258,511,512,1024,
            2**31-1,2**31,2**32-1,2**32,2**32+1,WORD-1]
    edges=[0,1,2,3,WORD-1,WORD,WORD**2,WORD**3,WIDE//2-1,WIDE//2,WIDE-2,WIDE-1]
    for x in edges:
        for m in edges:
            for count in counts:add(x,m,count)
    for bit in range(256):
        for delta in (-1,0,1):
            x=(2**bit+delta)%WIDE
            for j,m in enumerate((0,1,2,WIDE-2,WIDE-1)):
                add(x,m,counts[(bit+delta+j)%len(counts)])
    layouts=[(d,0,40) for d in (0,1,7,15,31,32,39,40,41,63,71,95,96)]
    layouts += [(0,0,0),(7,1,3),(96,95,96)]
    for i,layout in enumerate(layouts):
        for j,x in enumerate(edges):
            add(x,edges[-1-j],counts[(i+j)%len(counts)],layout,i)
    rng=random.Random(STARTS[0])
    for _ in range(256):add(rng.getrandbits(256),rng.getrandbits(256),rng.choice(counts),rng.choice(layouts),rng.randrange(256))
    for lane in range(3):
        for bad in (97,128,WORD-1):
            offsets=[96,0,40];offsets[lane]=bad
            for count in (0,1,WORD-1):add(1,0,count,tuple(offsets))
    inputs=[];expected=[]
    coverage={'cases':len(cases),'random_seed':hex(STARTS[0]),'refusals':0,
      'x_zero':0,'m_zero':0,'m_one':0,'m_even_nonzero':0,'unreduced_x':0,
      'count_zero_low32':0,'count_high32_nonzero':0,'accelerated_counts':0,
      'output_input_alias':0,'input_input_alias':0,'raw_count_classes':sorted(counts)}
    for d,a,m,count,image in sorted(cases):
        output,updated,facts=relation(d,a,m,count,image)
        inputs.append('\t'.join([str(d),str(a),str(m),f'{count:016x}',image.hex()]))
        expected.append(','.join([str(output[0]),*(f'{x:016x}' for x in output[1:]),updated.hex()]))
        if facts['refused']:coverage['refusals']+=1;continue
        for key in ('x_zero','m_zero','m_one','m_even_nonzero','unreduced_x'):coverage[key]+=facts[key]
        coverage['count_zero_low32']+=count%2**32==0
        coverage['count_high32_nonzero']+=count>=2**32
        coverage['accelerated_counts']+=facts['n']>256
        coverage['output_input_alias']+=any(d<x+32 and x<d+32 for x in (a,m))
        coverage['input_input_alias']+=a<m+32 and m<a+32
    return ('\n'.join(inputs)+'\n').encode(), ('\n'.join(expected)+'\n').encode(), coverage


def freeze():
    require(not (ROOT / 'src/node94-repeated-halving').exists(), 'Rust already exists')
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
