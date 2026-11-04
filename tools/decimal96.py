#!/usr/bin/env python3
"""Static Node115 Decimal96 scalar relation. Never executes or emulates captures."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node115-decimal96-normalize'
COMPONENT = ROOT / 'src/node115-decimal96-normalize'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
U32, U64 = (1 << 32)-1, (1 << 64)-1
START, END, CUT, STOP = 0x3be4ba0, 0x3be502b, 0x3be4c25, 0x3be4d57

def need(ok, message):
    if not ok:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def mapped(data, secs, va, size):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va+size <= s['address']+s['size']]
    need(len(matches) == 1, 'ambiguous or unmapped image VA')
    s = matches[0]
    off = s['offset']+va-s['address']
    return off, data[off:off+size]

# Entire raw scalar cut is authenticated against records.json, not just anchors.
ANCHORS = {
    0x3be4c4a: '0f84ea000000',  # zero -> shared stores
    0x3be4c52: 'c1ef10',        # flags >> 16
    0x3be4c65: '81e7ff000000',  # 8-bit scale
    0x3be4c6b: '0f84c9000000',  # initial scale0 -> original flags
    0x3be4c71: '41b9cdcccccc',
    0x3be4c77: '49ba9a99999999999919',
    0x3be4c81: '49bbcdcccccccccccccc',
    0x3be4ca7: '49c1e823',
    0x3be4ce5: '48d1ce',
    0x3be4ceb: '7336',          # unsigned >= threshold rejects division
    0x3be4cf6: 'ffcf75a6',
    0x3be4d33: '2500000080',
    0x3be4d3a: '898424b8000000',
    0x3be4d41: '44898424bc000000',
    0x3be4d49: '899424c0000000',
    0x3be4d50: '898c24c4000000',
}

def analyze(data, authenticate=True):
    if authenticate:
        need(len(data) == 105896032 and digest(data) == SHA, 'target identity mismatch')
    secs = sections(data)
    off, body = mapped(data, secs, START, END-START)
    _, cut = mapped(data, secs, CUT, STOP-CUT)
    fdes = eh_frame_records(data, secs)[1]
    frame = next((f for f in fdes if f['start'] == START), None)
    need(frame is not None and frame['end'] == END, 'actual enclosing FDE mismatch')
    anchors = []
    for va, expected in ANCHORS.items():
        fileoff, raw = mapped(data, secs, va, len(bytes.fromhex(expected)))
        need(raw.hex() == expected, 'operand/instruction mismatch at '+hex(va))
        anchors.append({'va': hex(va), 'file_offset': hex(fileoff), 'bytes_hex': expected})
    # A real relative relocation, not the raw on-disk GOT word, binds the converter.
    bindings = []
    for s in secs:
        if s['type'] == 4:
            need(s['size'] % 24 == 0, 'invalid RELA section')
            for r in range(s['offset'], s['offset']+s['size'], 24):
                where, info, addend = struct.unpack_from('<QQq', data, r)
                if where == 0x64e4d00:
                    need(info == 8 and addend == START, 'converter relocation mismatch')
                    bindings.append({'slot_va': hex(where), 'type': 8,
                                     'target_va': hex(addend), 'record_file_offset': hex(r)})
    need(len(bindings) == 1, 'converter requires one actual RELA binding')
    return {'target_sha256': SHA, 'coordinate_system': 'ELF image virtual address',
            'start': hex(START), 'end': hex(END), 'bytes': len(body),
            'file_offset': hex(off), 'body_sha256': digest(body), 'fde': frame,
            'cut_start': hex(CUT), 'cut_end': hex(STOP), 'cut_bytes': len(cut),
            'cut_sha256': digest(cut), 'anchors': anchors, 'converter_binding': bindings,
            'scope': 'Scalar value relation after opaque parsers and before opaque formatter; not whole function or original ABI'}

def parameters(data):
    secs = sections(data)
    take = lambda va, size: int.from_bytes(mapped(data, secs, va, size)[1], 'little')
    return take(0x3be4c73, 4), take(0x3be4c79, 8), take(0x3be4c83, 8)

def limb_relation(lo, mid, hi, flags, params):
    """Hand-authored scalar equations for the selected path, not an emulator."""
    if not (lo | mid | hi):
        return (0, 0, 0, 0)
    scale = (flags >> 16) & 255
    if not scale:
        return flags, hi, lo, mid
    m32, m64, inverse5 = params
    while scale:
        qhi = (hi*m32) >> 35
        nmid = ((hi-10*qhi) << 32) | mid
        qmid = (nmid*m64) >> 64
        nlo = (((mid-10*qmid) & U32) << 32) | lo
        qlo = (nlo*m64) >> 64
        value = (nlo*inverse5) & U64
        rotated = (value >> 1) | ((value & 1) << 63)
        if rotated >= m64:
            break
        hi, mid, lo = qhi, qmid, qlo
        scale -= 1
    return (flags & 0x80000000) | (scale << 16), hi, lo, mid

def string_spec(lo, mid, hi, flags):
    n = (hi << 64) | (mid << 32) | lo
    if not n:
        return (0, 0, 0, 0)
    scale = (flags >> 16) & 255
    if not scale:
        return flags, hi, lo, mid
    text = str(n)
    removed = min(scale, len(text)-len(text.rstrip('0')))
    value = int(text[:-removed]) if removed else n
    return ((flags & 0x80000000) | ((scale-removed) << 16),
            value >> 64, value & U32, (value >> 32) & U32)

def cases():
    maximum = (1 << 96)-1
    values = set(range(101))
    for edge in [1 << k for k in (16, 31, 32, 33, 63, 64, 65, 95, 96)]+[10**k for k in range(1, 29)]:
        values.update(n for n in range(edge-2, edge+3) if 0 <= n <= maximum)
    values.update((maximum, maximum-1, maximum//10*10))
    flags = [0, 0x80000000, 0x40000001, 0xc0000001]
    flags += [(s << 16) | sign | reserved for s in (1, 2, 8, 27, 28, 29, 255)
              for sign in (0, 0x80000000) for reserved in (0, 0x40000001)]
    pairs = {(n, f) for n in values for f in flags}
    state = 0x3be4ca0
    for _ in range(1024):
        state = (state*6364136223846793005+1442695040888963407) & ((1 << 128)-1)
        pairs.add((state & maximum, (state >> 96) & U32))
    for n, f in sorted(pairs):
        yield n & U32, (n >> 32) & U32, n >> 64, f

def fixture(data):
    params = parameters(data)
    rows = []
    for inputs in cases():
        result = limb_relation(*inputs, params)
        need(result == string_spec(*inputs), 'static limb/string specifications disagree')
        rows.append('\t'.join(map(str, (*inputs, *result)))+'\n')
    return ''.join(rows).encode()

def validate(binary):
    data = Path(binary).read_bytes()
    record = analyze(data)
    need(record == json.loads((PACKET/'records.json').read_text()), 'frozen native records differ')
    expected = fixture(data)
    need(expected == (COMPONENT/'target-vectors.tsv').read_bytes(), 'frozen vectors differ')
    return {'status': 'PASS', 'target_sha256': SHA, 'cases': len(expected.splitlines()),
            'fixture_sha256': digest(expected), 'captured_execution_or_emulation': False}

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT/'artifacts/node/115/hl-node')
    args = p.parse_args()
    print(json.dumps(validate(args.binary), indent=2))
