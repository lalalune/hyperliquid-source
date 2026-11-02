"""Pre-Rust whole-integer arithmetic and immutable-image correction-family oracle."""
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
STARTS = [0x565da40, 0x565dd00, 0x565dde0, 0x565de80]
LOCK_SHA = '6069b2a68f96a82e97d1896056792967ffa56c6201f183b2915f8940259c89d5'
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
        require(start in STARTS and not any(i.mnemonic == 'call' or i.mnemonic.startswith('j') for i in decoded), 'Branchless closure changed')
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
IMAGE_SIZE = 160


def relation(mode, destination, left, right, correction, image):
    offsets = (destination, left, right, correction)
    if any(o < 0 or o + 32 > len(image) for o in offsets):
        return (0,) * 8, image, {'refused': True}
    # Read from one immutable byte image, then make one whole-integer overlay.
    a, b, m = (int.from_bytes(image[o:o + 32], 'little') for o in offsets[1:])
    if mode % 2 == 0:
        total = a + b
        residue = total % WIDE
        carry = total // WIDE
        borrow = int(residue < m)
        result = (total - m if total >= m else total) % WIDE
        rax, rsi = residue % WORD, (residue // WORD) % WORD
        rdx = (-carry - borrow) % WORD
        applied = total >= m
    else:
        borrow = int(a < b)
        result = (a - b + borrow * m) % WIDE
        rax, rsi = borrow * (m % WORD), borrow * ((m // WORD) % WORD)
        rdx = (-borrow) % WORD
        carry = 0
        applied = bool(borrow)
    limbs = [(result // WORD**i) % WORD for i in range(4)]
    r8, r9, r10, r11 = limbs
    if mode >= 2:
        rax = int(result != 0)
        r8 = r8 | r9 | r10 | r11
        r10 |= r11
    updated = image[:destination] + result.to_bytes(32, 'little') + image[destination + 32:]
    return (1, rax, rdx, rsi, r8, r9, r10, r11), updated, {
        'refused': False, 'carry': carry, 'borrow': borrow, 'applied': applied,
        'zero': result == 0, 'unchanged': updated == image}


def fixture_bytes():
    cases = set()
    def add(mode, a, b, m, offsets=(120, 0, 40, 80), salt=0):
        image = bytearray((i * 37 + salt) % 256 for i in range(IMAGE_SIZE))
        for offset, value in zip(offsets[1:], (a, b, m)):
            if offset + 32 <= IMAGE_SIZE:
                image[offset:offset + 32] = (value % WIDE).to_bytes(32, 'little')
        cases.add((mode, *offsets, bytes(image)))
    edges = [0, 1, 2, WORD - 1, WORD, WORD**2 - 1, WORD**3,
             WIDE // 2 - 1, WIDE // 2, WIDE - 2, WIDE - 1]
    for a in edges:
        for b in edges:
            for m in (0, 1, WIDE - 1, (a + b) % WIDE, (a + b + 1) % WIDE):
                for mode in range(4):add(mode, a, b, m)
    for bit in range(256):
        for delta in (-1, 0, 1):
            v = (2**bit + delta) % WIDE
            for mode in range(4):
                add(mode, v, WIDE - 1 - v, v)
                add(mode, WIDE - 1, v, (v + 1) % WIDE)
    layouts = [(d, 0, 40, 80) for d in (0, 1, 7, 15, 31, 32, 39, 40, 47, 71, 79, 80, 81, 111, 120, 128)]
    layouts += [(0, 0, 0, 0), (7, 1, 3, 11), (63, 33, 34, 35), (128, 128, 128, 128)]
    for offsets in layouts:
        for i in range(len(edges)):
            for mode in range(4):add(mode, edges[i], edges[-1-i], edges[(3*i)%len(edges)], offsets, i)
    rng = random.Random(STARTS[0])
    for _ in range(1024):
        offsets = rng.choice(layouts)
        a, b, m = (rng.getrandbits(256) for _ in range(3))
        for mode in range(4):add(mode, a, b, m, offsets, rng.randrange(256))
    for lane in range(4):
        for bad in (129, 160, WORD - 1):
            offsets = [120, 0, 40, 80]; offsets[lane] = bad
            for mode in range(4):add(mode, 1, 2, 3, tuple(offsets))
    inputs, expected = [], []
    coverage = {'cases': len(cases), 'random_seed': hex(STARTS[0]), 'by_mode': [0]*4,
                'refusals': 0, 'addition_carry': 0, 'subtraction_borrow': 0,
                'correction_applied': [0]*4, 'zero_results': [0]*4,
                'output_overlaps_input': 0, 'input_windows_overlap': 0}
    for mode, d, a, b, m, image in sorted(cases):
        out, updated, facts = relation(mode, d, a, b, m, image)
        inputs.append('\t'.join([str(mode), *(str(x) for x in (d,a,b,m)), image.hex()]))
        expected.append(','.join([str(out[0]), *(f'{x:016x}' for x in out[1:]), updated.hex()]))
        coverage['by_mode'][mode] += 1
        if facts['refused']:
            coverage['refusals'] += 1; continue
        coverage['addition_carry'] += facts['carry']
        coverage['subtraction_borrow'] += mode%2 == 1 and facts['borrow']
        coverage['correction_applied'][mode] += facts['applied']
        coverage['zero_results'][mode] += facts['zero']
        coverage['output_overlaps_input'] += any(d < x+32 and x < d+32 for x in (a,b,m))
        coverage['input_windows_overlap'] += any(x < y+32 and y < x+32 for x,y in ((a,b),(a,m),(b,m)))
    return ('\n'.join(inputs) + '\n').encode(), ('\n'.join(expected) + '\n').encode(), coverage


def freeze():
    require(not (ROOT / 'src/node94-conditional-correction').exists(), 'Rust already exists')
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
