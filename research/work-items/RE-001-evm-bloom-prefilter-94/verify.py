#!/usr/bin/env python3
"""Authenticate and rederive the selected node94 bloom-prefilter evidence.

No captured executable is run. Existing ELF/FDE readers provide coordinates;
fixed instruction encodings and dynamic relocations bind the new claims.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from evm_amount_scale import Image, SHA256, BINARY  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

START, END = 0x27c1710, 0x27c347f
BODY_SHA = '0e458cee6c7265701c1e620bf20c415b3f77fb1eb3f30c87b6ffa046077e5ea0'
# Every instruction below was checked in the complete GNU objdump export.
ANCHORS = {
    0x27c1c86: ('488d0440', 'group count times three'),
    0x27c1c92: ('488d04c2', 'group end = base + count * 24'),
    0x27c1ca3: ('48c1e108', 'flat mask count times 256'),
    0x27c1cd0: ('4d8db42498030000', 'advance record by 0x398'),
    0x27c1ce5: ('4883bc248006000002', 'record tag 2 ends this record walk'),
    0x27c1cee: ('0f84a6050000', 'tag 2 jumps to 0x27c229a'),
    0x27c1d29: ('48837c243000', 'flat count zero test'),
    0x27c1d2f: ('0f84de010000', 'empty flat list proceeds to groups'),
    0x27c1d50: ('4d85ff', 'flat remaining byte count test'),
    0x27c1d53: ('0f84f7030000', 'exhausted nonempty flat list skips candidate'),
    0x27c1d59: ('ba00010000', 'copy 256 bytes'),
    0x27c1d5e: ('4c89ef', 'copy destination = scratch'),
    0x27c1d61: ('488db42470070000', 'copy source = record at stack + 0xf0'),
    0x27c1d69: ('ffd3', 'copy through cached memcpy binding'),
    0x27c1ee8: ('498dac2400010000', 'next flat mask = mask + 256'),
    0x27c1ef0: ('ba00010000', 'compare 256 bytes'),
    0x27c1ef5: ('4c89ef', 'compare argument 1 = AND result'),
    0x27c1ef8: ('4c89e6', 'compare argument 2 = original mask'),
    0x27c1efb: ('ff1577c4fa02', 'bcmp at GOT 0x576e378'),
    0x27c1f01: ('4981c700ffffff', 'subtract 256 remaining bytes'),
    0x27c1f08: ('4989ec', 'advance flat mask'),
    0x27c1f0b: ('85c0', 'test bcmp result'),
    0x27c1f0d: ('0f853dfeffff', 'inequality retries flat alternatives'),
    0x27c1f18: ('4883bc245001000000', 'group count zero test'),
    0x27c1f21: ('0f8439020000', 'no groups proceeds to downstream helper'),
    0x27c1f40: ('4983c718', 'next group stride 24'),
    0x27c1f44: ('4c3bbc2458010000', 'compare group pointer with end'),
    0x27c1f4c: ('0f840e020000', 'all groups passed: downstream helper'),
    0x27c1f52: ('498b6f10', 'group mask count at +16'),
    0x27c1f56: ('4885ed', 'test group mask count'),
    0x27c1f59: ('74e5', 'empty group proceeds to next group'),
    0x27c1f5b: ('4d8b6708', 'group mask pointer at +8'),
    0x27c1f5f: ('48c1e508', 'group mask count times 256'),
    0x27c1f70: ('4885ed', 'remaining group mask bytes test'),
    0x27c1f73: ('0f84c7010000', 'exhausted nonempty group skips candidate'),
    0x27c1f79: ('ba00010000', 'copy 256 bytes'),
    0x27c1f7e: ('4c89ef', 'copy destination = scratch'),
    0x27c1f81: ('488db42470070000', 'same candidate bloom source'),
    0x27c1f89: ('ffd3', 'copy through cached memcpy binding'),
    0x27c2108: ('4d8db42400010000', 'next group mask = mask + 256'),
    0x27c2110: ('ba00010000', 'compare 256 bytes'),
    0x27c2115: ('4c89ef', 'compare argument 1 = AND result'),
    0x27c2118: ('4c89e6', 'compare argument 2 = original mask'),
    0x27c211b: ('ff1557c2fa02', 'bcmp at GOT 0x576e378'),
    0x27c2121: ('4881c500ffffff', 'subtract 256 remaining bytes'),
    0x27c2128: ('4d89f4', 'advance group mask'),
    0x27c212b: ('85c0', 'test bcmp result'),
    0x27c212d: ('0f853dfeffff', 'inequality retries this group'),
    0x27c2133: ('e908feffff', 'equality proceeds to next group'),
    0x27c2140: ('b001', 'group failure skip marker'),
    0x27c2145: ('eb5e', 'group failure bypasses downstream helper'),
    0x27c2150: ('b001', 'flat failure skip marker'),
    0x27c2155: ('eb53', 'flat failure bypasses downstream helper'),
    0x27c2198: ('ff152ae8fa02', 'passing prefilter calls slot 0x57709c8'),
    0x27c219e: ('c7042400000000', 'clear skip marker after helper'),
    0x27c1cb7: ('488b1d22c3fa02', 'cache memcpy slot 0x576dfe0 in rbx'),
    0x27c1caf: ('4c8dbc2480060000', 'record copy destination'),
    0x27c1cbe: ('4c8dac2440030000', 'mask scratch destination'),
    0x27c1cd8: ('ba98030000', 'record copy size 0x398'),
    0x27c1cdd: ('4c89ff', 'record copy destination argument'),
    0x27c1ce0: ('4c89e6', 'record copy source argument'),
    0x27c1ce3: ('ffd3', 'record copy through memcpy'),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def relocation(img, slot):
    """Resolve only actual .rela.dyn records, never raw unrelocated GOT words."""
    _, off, size = img.section('.rela.dyn')
    matches = [r for r in struct.iter_unpack('<QQq', img.data[off:off + size]) if r[0] == slot]
    require(len(matches) == 1, f'unique relocation required at {slot:#x}')
    _, info, addend = matches[0]
    kind, symbol = info & 0xffffffff, info >> 32
    if kind == 8:
        require(symbol == 0, 'RELATIVE relocation has symbol')
        return {'kind': 'R_X86_64_RELATIVE', 'target': hex(addend)}
    require(kind == 6 and addend == 0, 'expected zero-addend GLOB_DAT')
    _, so, ss = img.section('.dynsym')
    _, no, ns = img.section('.dynstr')
    require(symbol * 24 + 24 <= ss, 'symbol outside dynsym')
    name = struct.unpack_from('<I', img.data, so + symbol * 24)[0]
    require(name < ns, 'symbol name outside dynstr')
    end = img.data.find(b'\0', no + name, no + ns)
    require(end >= 0, 'unterminated symbol name')
    return {'kind': 'R_X86_64_GLOB_DAT', 'symbol': img.data[no + name:end].decode('ascii')}


def vector_body():
    """Encode the observed 16 load/AND/store lanes; no inferred mask bits."""
    raw = bytearray()
    for pair in range(8):
        for lane in range(2):
            d = pair * 32 + lane * 16
            reg = lane * 8
            if pair == 7:
                raw += bytes([0xf3, 0x41, 0x0f, 0x6f, 0x84 + reg, 0x24]) + struct.pack('<I', d)
            elif d == 0:
                raw += bytes.fromhex('410f100424')
            elif d < 128:
                raw += bytes([0x41, 0x0f, 0x10, 0x44 + reg, 0x24, d])
            else:
                raw += bytes([0x41, 0x0f, 0x10, 0x84 + reg, 0x24]) + struct.pack('<I', d)
        for opcode in ('and', 'store'):
            for lane in range(2):
                d = 0x340 + pair * 32 + lane * 16
                if pair == 7:
                    raw += bytes([0x66, 0x0f, 0xdb if opcode == 'and' else 0x7f])
                else:
                    raw += bytes([0x0f, 0x54 if opcode == 'and' else 0x29])
                raw += bytes([0x84 + lane * 8, 0x24]) + struct.pack('<I', d)
    return bytes(raw)


def observe(data):
    """Structural checks run before the whole-image digest, for useful controls."""
    img = Image(data)
    anchors = []
    for va, (expected, meaning) in ANCHORS.items():
        raw = bytes.fromhex(expected)
        require(img.read(va, len(raw)) == raw, f'instruction changed at {va:#x}')
        anchors.append({'va': hex(va), 'bytes': expected, 'observation': meaning})
    vector = vector_body()
    require(len(vector) == 381, 'unexpected vector encoding length')
    for va in (0x27c1d6b, 0x27c1f8b):
        require(img.read(va, len(vector)) == vector, f'vector lanes changed at {va:#x}')
    bindings = {}
    for slot, expected in (
        (0x576dfe0, {'kind': 'R_X86_64_GLOB_DAT', 'symbol': 'memcpy'}),
        (0x576e378, {'kind': 'R_X86_64_GLOB_DAT', 'symbol': 'bcmp'}),
        (0x57709c8, {'kind': 'R_X86_64_RELATIVE', 'target': '0x1647680'}),
    ):
        actual = relocation(img, slot)
        require(actual == expected, f'helper binding changed at {slot:#x}')
        bindings[hex(slot)] = actual
    locations = []
    relocs = img.relative_relocs()
    for lea, slot, ptr, path, line, col in (
        (0x27c3185, 0x56c3058, 0x1fa305, 'evm_rpc/src/evm_store.rs', 102, 27),
        (0x27c3166, 0x56c3608, 0x1f693a, 'evm_rpc/src/evm_rpc.rs', 272, 87),
    ):
        raw = img.read(lea, 7)
        require(raw[:3] == bytes.fromhex('488d3d') and lea + 7 + struct.unpack('<i', raw[3:])[0] == slot,
                f'Location LEA changed at {lea:#x}')
        name = ('/home/ubuntu/hl/code_Mainnet/' + path).encode()
        require(relocs.get(slot) == ptr and img.read(ptr, len(name)) == name
                and struct.unpack('<QII', img.read(slot + 8, 16)) == (len(name), line, col),
                f'Location record changed at {slot:#x}')
        locations.append({'lea': hex(lea), 'slot': hex(slot), 'path': path, 'line': line, 'column': col})
    _, fdes = eh_frame_records(data)
    matches = [f for f in fdes if f['start'] == START]
    require(len(matches) == 1 and matches[0]['end'] == END, 'owner FDE changed')
    fde = matches[0]
    require(hashlib.sha256(img.read(START, END - START)).hexdigest() == BODY_SHA, 'owner body changed')
    return {
        'schema': 1, 'target_sha256': SHA256, 'coordinate_system': 'ELF virtual addresses; exclusive ends',
        'owner': {'start': hex(START), 'end': hex(END), 'file_offset': hex(img.off(START)),
                  'bytes': END - START, 'sha256': BODY_SHA, 'fde': hex(fde['fde']), 'cie': hex(fde['cie'])},
        'source_locations': locations, 'helper_bindings': bindings, 'instructions': anchors,
        'vector_bodies': [{'start': hex(va), 'end': hex(va + len(vector)), 'lanes': 16, 'lane_bytes': 16,
                           'sha256': hashlib.sha256(vector).hexdigest()} for va in (0x27c1d6b, 0x27c1f8b)],
        'predicate': '(flat.empty || any(contains(block,m) for m in flat)) && all(g.empty || any(contains(block,m) for m in g) for g in groups)',
        'contains': 'For each of 256 bytes: (block[i] & mask[i]) == mask[i]',
        'captured_binary_executed': False,
        'limits': 'Selected prefilter only; no complete handler identity, mask construction, exact log matching, original ABI, runtime or compiled-code equivalence.',
    }


def build(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'wrong node94 SHA-256')
    return observe(data)


def verify_export(data):
    """Bind every retained instruction row to contiguous authenticated bytes.

    The GNU mnemonic rendering remains a review aid, not the source of the
    semantic checks above, which validate explicit encodings independently.
    """
    img = Image(data)
    cursor, starts = START, set()
    for line in (PACKET / 'owner.objdump.txt').read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\t([0-9a-f ]+)\t', line)
        if match:
            va, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(va == cursor and 1 <= len(raw) <= 15, 'export gap, overlap or invalid instruction size')
            require(img.read(va, len(raw)) == raw, f'export bytes differ at {va:#x}')
            starts.add(va)
            cursor += len(raw)
    require(cursor == END, 'incomplete owner export')
    require(set(ANCHORS) <= starts, 'anchor not at an exported instruction start')
    return len(starts)


def verify_manifest():
    for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        path = (ROOT / name).resolve()
        require(path.is_relative_to(ROOT), 'manifest path outside repository')
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'manifest mismatch: ' + name)


def controls(data):
    img = Image(data)
    cases = [(0x27c1d30, 1, 'empty flat branch'), (0x27c1f5a, 1, 'empty group branch'),
             (0x27c212e, 1, 'group retry polarity'), (0x27c1f43, 1, 'group stride'),
             (0x27c1ef1, 1, 'comparison length'), (0x27c1ee0, 1, 'last SIMD lane'),
             (0x27c211d, 1, 'comparison GOT displacement')]
    # Retarget the actual RELATIVE slot while keeping code unchanged.
    _, off, size = img.section('.rela.dyn')
    reloc_off = next(p for p in range(off, off + size, 24) if struct.unpack_from('<Q', data, p)[0] == 0x57709c8)
    offsets = [(img.off(va), bit, name) for va, bit, name in cases] + [(reloc_off + 16, 1, 'downstream relocation')]
    rejected = []
    for offset, bit, name in offsets:
        altered = bytearray(data)
        altered[offset] ^= bit
        try:
            observe(altered)  # Deliberately bypass only the whole-input digest gate.
        except ValueError as exc:
            rejected.append({'control': name, 'rejection': str(exc)})
        else:
            raise ValueError('accepted mutation: ' + name)
    try:
        build(data[:-1])
    except ValueError as exc:
        rejected.append({'control': 'truncated image', 'rejection': str(exc)})
    else:
        raise ValueError('accepted truncated image')
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / BINARY)
    parser.add_argument('--write', action='store_true', help='regenerate records.json from authenticated input')
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    data = args.binary.read_bytes()
    report = build(data)
    rendered = json.dumps(report, indent=2) + '\n'
    target = PACKET / 'records.json'
    if args.write:
        target.write_text(rendered, encoding='utf-8', newline='\n')
    else:
        require(target.read_bytes() == rendered.encode(), 'records.json differs from regenerated evidence')
        verify_manifest()
    count = verify_export(data)
    if args.controls:
        print(json.dumps(controls(data), indent=2))
    print(f'PASS: authenticated node94; {count} retained instruction rows; 16 lanes in each loop; branch, helper, Location and FDE bindings verified.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        sys.exit(str(error))
