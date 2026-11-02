#!/usr/bin/env python3
"""Read-only peer verification; standard library only, no oracle imports/execution.

Usage: python3 -O verify_independent.py /path/to/hyperliquid-source
Expected bytes are derived by immutable source/destination interval selection.
This does not run Rust, captured instructions, or an instruction emulator.
"""
import collections
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

N = 1 << 64
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODIES = [
    (0x53b1120, bytes.fromhex('f30f1efa488b87d80200004885c0741980bfb8000000007410488b5020488b40604889561048894618c3'), 6, 0x57648b0),
    (0x53b1150, bytes.fromhex('f30f1efa80bfb8000000007410f30f7e46100f1646180f1187b8020000c3'), 2, 0x57648b8),
]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def authenticate(raw):
    require(len(raw) == 91774280 and sha(raw) == TARGET, 'target identity')
    require(raw[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian')
    require(struct.unpack_from('<HH', raw, 16) == (3, 62), 'ET_DYN x86-64')
    phoff, shoff = struct.unpack_from('<QQ', raw, 32)
    phsize, phnum, shsize, shnum, strindex = struct.unpack_from('<5H', raw, 54)
    require(phsize == 56 and shsize == 64, 'ELF table record sizes')
    segments = [struct.unpack_from('<II6Q', raw, phoff+i*phsize) for i in range(phnum)]
    sections = [struct.unpack_from('<II4QII2Q', raw, shoff+i*shsize) for i in range(shnum)]
    st = sections[strindex]
    names = raw[st[4]:st[4]+st[5]]
    named = {names[s[0]:].split(b'\0', 1)[0].decode(): s for s in sections}
    def mapped(address, size):
        matches = [s for s in segments if s[0] == 1 and s[3] <= address and address+size <= s[3]+s[5]]
        require(len(matches) == 1, 'unique file-backed PT_LOAD')
        s = matches[0]
        offset = s[2]+address-s[3]
        return raw[offset:offset+size], offset, s[1]
    records = []
    for address, body, pad, slot in BODIES:
        data, offset, flags = mapped(address, len(body)+pad)
        require(flags & 1 and data == body+b'\xcc'*pad, 'complete executable body/padding')
        slotdata, slotoffset, slotflags = mapped(slot, 8)
        require(slotdata == bytes(8) and slotflags & 2, 'raw zero writable slot')
        section = named['.data.rel.ro']
        require(section[3] <= slot and slot+8 <= section[3]+section[5], 'slot section')
        records.append({'entry': hex(address), 'bytes': len(body), 'body_sha256': sha(body), 'file_offset': offset, 'slot': hex(slot), 'slot_file_offset': slotoffset})
    # Parse all frame extents directly. All three actual CIEs specify 0x1b:
    # PC-relative signed-four-byte initial location; unsigned-four-byte range.
    frames = []
    cies = {}
    section = named['.eh_frame']
    pos, end = section[4], section[4]+section[5]
    while pos < end:
        length, = struct.unpack_from('<I', raw, pos)
        if not length:
            require(not any(raw[pos:end]), 'nonzero bytes after frame terminator')
            break
        require(length != 0xffffffff and pos+4+length <= end, 'bounded normal frame record')
        pointer, = struct.unpack_from('<I', raw, pos+4)
        va = section[3]+pos-section[4]
        if pointer == 0:
            value = raw[pos:pos+4+length]
            if value[8:12] == b'\x01zR\0':
                require(value[12:16] == b'\x01\x78\x10\x01' and value[16] == 0x1b, 'zR CIE encoding')
            else:
                require(value[8:15] == b'\x01zPLR\0\x01' and value[15:19] == b'\x78\x10\x07\x9b' and value[23:25] == b'\x1b\x1b', 'zPLR CIE encoding')
            cies[va] = sha(value)
        else:
            cie = va+4-pointer
            require(cie in cies, 'known backward CIE')
            relative, extent = struct.unpack_from('<iI', raw, pos+8)
            start = va+8+relative
            frames.append((start, start+extent, va, cie, raw[pos:pos+4+length].hex()))
        pos += length+4
    for record, (address, body, _, _) in zip(records, BODIES):
        overlaps = [f for f in frames if f[0] < address+len(body) and address < f[1]]
        require(len(overlaps) == 1 and overlaps[0][:2] == (address, address+len(body)), 'unique complete FDE')
        record['frame'] = overlaps[0]
        record['cie_sha256'] = cies[overlaps[0][3]]
    writers = {slot: [] for _, _, _, slot in BODIES}
    naming = []
    count = 0
    for s in sections:
        require(s[1] != 9, 'unsupported REL section')
        if s[1] != 4:
            continue
        require(s[9] == 24 and s[5] % 24 == 0, 'RELA record shape')
        for off in range(s[4], s[4]+s[5], 24):
            dst, info, add = struct.unpack_from('<QQq', raw, off)
            require(info & 0xffffffff in (1, 6, 7, 8, 18), 'known eight-byte relocation writer')
            item = [off, dst, info, add]
            count += 1
            if add in [b[0] for b in BODIES]:
                naming.append(item)
            for slot in writers:
                if dst < slot+8 and slot < dst+8:
                    writers[slot].append(item)
            for address, body, pad, _ in BODIES:
                require(not (dst < address+len(body)+pad and address < dst+8), 'body/padding writer')
    expected = [[1707224, 0x57648b0, 8, 0x53b1120], [1707248, 0x57648b8, 8, 0x53b1150]]
    require(naming == expected, 'all naming RELA records')
    for record in expected:
        require(writers[record[1]] == [record], 'unique complete symbol-zero RELATIVE writer')
    return {'bodies': records, 'fde_count': len(frames), 'cie_count': len(cies), 'rela_count': count, 'slot_writers': expected}

def derive(row):
    member, base, obj, ext, rax, rdx, length = struct.unpack_from('<7Q', row)
    data = row[56:]
    require(member < 2 and length <= 800 and len(data) == 800, 'input descriptor')
    refused = struct.pack('<3Q', 0, 0, 0)+data
    if base+length > N:
        return refused, 'image-wrap', None
    # Every action is a (destination offset, source offset, width) interval.
    # Read only the initial bytes; derive final bytes by interval membership,
    # rather than executing stores or mutating a byte-address dictionary.
    def interval(address, width):
        offset = address-base
        if offset < 0 or width > length-offset:
            raise IndexError
        return offset
    def integer(offset):
        return sum(data[offset+i] * 256**i for i in range(8))
    gate = None
    try:
        if member == 0:
            ptr = integer(interval((obj+728) % N, 8))
            if ptr == 0:
                return struct.pack('<3Q', 1, 0, rdx)+data, 'null-pointer', None
            gate = data[interval((obj+184) % N, 1)]
            if gate == 0:
                return struct.pack('<3Q', 1, ptr, rdx)+data, 'gate-closed-out', gate
            sources = [interval((ptr+32) % N, 8), interval((ptr+96) % N, 8)]
            actions = [(interval((ext+16) % N, 8), sources[0], 8), (interval((ext+24) % N, 8), sources[1], 8)]
            result = (1, integer(sources[1]), integer(sources[0]))
        else:
            gate = data[interval((obj+184) % N, 1)]
            if gate == 0:
                return struct.pack('<3Q', 1, rax, rdx)+data, 'gate-closed-in', gate
            sources = [interval((ext+16) % N, 8), interval((ext+24) % N, 8)]
            destination = interval((obj+696) % N, 16)
            actions = [(destination, sources[0], 8), (destination+8, sources[1], 8)]
            result = (1, rax, rdx)
    except IndexError:
        return refused, 'missing-selected-span', gate
    output = []
    for i, original in enumerate(data):
        matching = [(d, s, w) for d, s, w in actions if d <= i < d+w]
        output.append(data[matching[-1][1]+i-matching[-1][0]] if matching else original)
    return struct.pack('<3Q', *result)+bytes(output), 'copy-'+str(member), gate

def main():
    root = Path(sys.argv[1]).resolve()
    packet = root/'research/work-items/RE-004-gated-field-pair-rust-94'
    inputs = gzip.decompress((packet/'inputs.bin.gz').read_bytes())
    expected = gzip.decompress((packet/'expected.bin.gz').read_bytes())
    frozen = json.loads((packet/'frozen.json').read_bytes())
    require(sha(inputs) == frozen['inputs_sha256'] and sha(expected) == frozen['expected_sha256'], 'frozen raw hashes')
    require(sha((packet/'oracle.py').read_bytes()) == frozen['oracle_sha256_at_freeze'], 'original oracle hash')
    require(sha((packet/'static.json').read_bytes()) == frozen['static_sha256_at_freeze'], 'frozen static hash')
    require(len(inputs) % 856 == 0 and len(expected) == len(inputs)//856*824, 'fixture dimensions')
    digest = hashlib.sha256()
    paths = collections.Counter()
    gates = [set(), set()]
    counts = [0, 0]
    for i in range(len(inputs)//856):
        row = inputs[i*856:(i+1)*856]
        result, path, gate = derive(row)
        require(result == expected[i*824:(i+1)*824], 'independent expectation '+str(i))
        digest.update(result)
        paths[path] += 1
        member, = struct.unpack_from('<Q', row)
        counts[member] += struct.unpack_from('<Q', result)[0]
        if gate is not None:
            gates[member].add(gate)
    require(counts == frozen['admitted_per_member'] and all(len(g) == 256 for g in gates), 'admission and every gate byte')
    hashes = {str(p.relative_to(root)): sha(p.read_bytes()) for p in [root/'src/node94-gated-field-pair/lib.rs', root/'src/node94-gated-field-pair/input_only_driver.rs', packet/'PROOF.md', packet/'oracle.py', packet/'static.json', packet/'frozen.json']}
    report = {'reviewed_hashes': hashes, 'independent_script_sha256': sha(Path(__file__).read_bytes()), 'cases': len(inputs)//856, 'admitted_per_member': counts, 'path_counts': dict(sorted(paths.items())), 'gate_values_per_member': [len(g) for g in gates], 'independent_expected_sha256': digest.hexdigest(), 'static': authenticate((root/'artifacts/node/94/hl-node').read_bytes()), 'blockers': [], 'limitations': ['Read-only mathematical/static review; no independent native Rust rerun.', 'Finite fixtures supplement the all-input argument; they are not exhaustive image coverage.', 'Original exceptions, concurrent observations, MMIO, flags, XMM0 output and native ABI remain outside the stated projection.', 'None and atomic refusal are new safe-API behavior, not recovered target faults.', 'Relocation identity is complete for these slots; indirect-reference census is not claimed.'], 'captured_execution': False, 'instruction_emulation': False}
    print(json.dumps(report, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
