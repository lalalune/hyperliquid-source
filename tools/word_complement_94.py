#!/usr/bin/env python3
"""Authenticate and decode the node #94 budgeted 32-byte complement leaf."""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END, NEXT = 0x243cd00, 0x243cd64, 0x243cd70
FDE_OFFSET = 0x7e290
BODY_HASH = '9b945698d564e97eeb44f5c2789b3b6e1b88440baae44ca96e69b103f2ad4dbc'

# This is an intentionally narrow decoder: each accepted instruction form is
# exact, including ModRM/SIB, widths, and immediates. Branch displacements are
# decoded from the bytes and checked against instruction boundaries below.
FORMS = [
 ('488b87e0010000', 'mov rax, qword [rdi+0x1e0]'),
 ('4883f802', 'cmp rax, 2'),
 ('7647', 'jbe 0x243cd54'),
 ('4883c0fd', 'add rax, -3'),
 ('488987e0010000', 'mov qword [rdi+0x1e0], rax'),
 ('488b8728010000', 'mov rax, qword [rdi+0x128]'),
 ('4885c0', 'test rax, rax'),
 ('7438', 'je 0x243cd5c'),
 ('488b8f20010000', 'mov rcx, qword [rdi+0x120]'),
 ('48c1e005', 'shl rax, 5'),
 ('660f76c0', 'pcmpeqd xmm0, xmm0'),
 ('f30f6f4c01e0', 'movdqu xmm1, [rcx+rax-0x20]'),
 ('f30f6f5401f0', 'movdqu xmm2, [rcx+rax-0x10]'),
 ('660fefc8', 'pxor xmm1, xmm0'),
 ('f30f7f4c01e0', 'movdqu [rcx+rax-0x20], xmm1'),
 ('660fefd0', 'pxor xmm2, xmm0'),
 ('f30f7f5401f0', 'movdqu [rcx+rax-0x10], xmm2'),
 ('c3', 'ret'),
 ('c687f301000050', 'mov byte [rdi+0x1f3], 0x50'),
 ('c3', 'ret'),
 ('c687f30100005b', 'mov byte [rdi+0x1f3], 0x5b'),
 ('c3', 'ret'),
]


def decode(body):
    if len(body) != END - START:
        raise ValueError('wrong body length')
    pos = 0
    rows = []
    branches = []
    for encoded, instruction in FORMS:
        expected = bytes.fromhex(encoded)
        actual = bytes(body[pos:pos + len(expected)])
        if actual != expected:
            raise ValueError(f'unsupported instruction at {START + pos:#x}')
        pc = START + pos
        if actual[0] in (0x74, 0x76):
            dest = pc + 2 + struct.unpack('b', actual[1:2])[0]
            branches.append({'site': hex(pc), 'target': hex(dest),
                             'condition': 'equal' if actual[0] == 0x74 else 'unsigned_below_or_equal'})
            if instruction.rsplit(' ', 1)[-1] != hex(dest):
                raise ValueError('branch target mismatch')
        rows.append((pc, actual.hex(), instruction))
        pos += len(expected)
    if pos != len(body) or any(int(b['target'], 16) not in {r[0] for r in rows} for b in branches):
        raise ValueError('instruction coverage or branch target mismatch')
    return rows, branches


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected ELF64 little endian')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    ent, count, names = struct.unpack_from('<HHH', data, 58)
    if ent != 64 or not count or names >= count or shoff + ent * count > len(data):
        raise ValueError('invalid ELF section table')
    all_rows = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * ent) for i in range(count)]
    st = all_rows[names]
    table = data[st[4]:st[4] + st[5]]
    result = {}
    for row in all_rows:
        no, kind, flags, va, off, size = row[:6]
        if no >= len(table) or off + size > len(data) and kind != 8:
            raise ValueError('invalid section')
        end = table.find(b'\0', no)
        if end < 0:
            raise ValueError('invalid section name')
        name = table[no:end].decode('ascii')
        if name in ('.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn', '.data.rel.ro'):
            if name in result:
                raise ValueError('duplicate section')
            result[name] = {'va': va, 'offset': off, 'size': size, 'flags': flags, 'type': kind, 'entry_size': row[9]}
    if len(result) != 5:
        raise ValueError('missing section')
    return result


def parse_fde(record, frame_va, expected_offset=FDE_OFFSET):
    if len(record) < 20:
        raise ValueError('short FDE')
    length, cie_delta, pc_delta, extent = struct.unpack_from('<IIiI', record)
    cie = expected_offset + 4 - cie_delta
    start = frame_va + expected_offset + 8 + pc_delta
    if length != 0x10 or cie != 0 or start != START or extent != END - START or record[16:20] != b'\0' * 4:
        raise ValueError('FDE association mismatch')
    return {'section_offset': hex(expected_offset), 'cie_section_offset': hex(cie),
            'record_length': length, 'start': hex(start), 'end_exclusive': hex(start + extent)}


def check_index(data, hdr, frame):
    off, va, size = hdr['offset'], hdr['va'], hdr['size']
    if data[off:off + 4] != b'\x01\x1b\x03\x3b':
        raise ValueError('unsupported unwind index')
    frame_ptr, count = struct.unpack_from('<iI', data, off + 4)
    if va + 4 + frame_ptr != frame['va'] or 12 + 8 * count > size:
        raise ValueError('invalid unwind index')
    lo, hi = 0, count
    while lo < hi:
        mid = (lo + hi) // 2
        delta = struct.unpack_from('<i', data, off + 12 + 8 * mid)[0]
        if va + delta < START: lo = mid + 1
        else: hi = mid
    if lo + 1 >= count:
        raise ValueError('missing unwind index entry')
    delta, fde_delta = struct.unpack_from('<ii', data, off + 12 + 8 * lo)
    next_delta = struct.unpack_from('<i', data, off + 12 + 8 * (lo + 1))[0]
    if (va + delta, va + fde_delta, va + next_delta) != (START, frame['va'] + FDE_OFFSET, NEXT):
        raise ValueError('unwind index association mismatch')


def callers(data, text):
    start, end = text['offset'], text['offset'] + text['size']
    out = []
    for op, kind in ((b'\xe8', 'call'), (b'\xe9', 'jump')):
        p = start
        while True:
            p = data.find(op, p, end - 4)
            if p == -1: break
            site = text['va'] + p - start
            disp = struct.unpack_from('<i', data, p + 1)[0]
            if site + 5 + disp == START:
                out.append({'site': hex(site), 'kind': kind})
            p += 1
    return sorted(out, key=lambda x: int(x['site'], 16))


def relocation_slots(data, rela, target_section):
    if rela['type'] != 4 or rela['entry_size'] != 24 or rela['size'] % 24:
        raise ValueError('unsupported relocation section')
    slots = []
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if addend == START:
            if info != 8 or not target_section['va'] <= slot <= target_section['va'] + target_section['size'] - 8:
                raise ValueError('unexpected relocation target or type')
            slots.append(hex(slot))
    return slots


def exact_matches(data, text, body):
    start, end = text['offset'], text['offset'] + text['size']
    pos = start
    result = []
    while True:
        pos = data.find(body, pos, end)
        if pos == -1:
            return result
        result.append(hex(text['va'] + pos - start))
        pos += 1


def model(budget, count, last):
    """Pure field model, assuming a valid disjoint 32-byte last element."""
    if not 0 <= budget < 2**64 or not 0 <= count < 2**64 or len(last) != 32:
        raise ValueError('invalid model input')
    if budget <= 2:
        return budget, 0x50, last
    budget -= 3
    if count == 0:
        return budget, 0x5b, last
    return budget, None, bytes(x ^ 0xff for x in last)


def collect(data, expected_digest=DIGEST):
    if hashlib.sha256(data).hexdigest() != expected_digest or expected_digest != DIGEST:
        raise ValueError('target digest mismatch')
    sec = sections(data)
    t, frame = sec['.text'], sec['.eh_frame']
    if not t['flags'] & 4 or not t['va'] <= START < END <= NEXT <= t['va'] + t['size']:
        raise ValueError('window outside executable .text')
    check_index(data, sec['.eh_frame_hdr'], frame)
    cie = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
    if data[frame['offset']:frame['offset'] + len(cie)] != cie:
        raise ValueError('unexpected CIE encoding')
    f = frame['offset'] + FDE_OFFSET
    fde = parse_fde(data[f:f + 20], frame['va'])
    pos = t['offset'] + START - t['va']
    body = data[pos:pos + END - START]
    if hashlib.sha256(body).hexdigest() != BODY_HASH:
        raise ValueError('body hash mismatch')
    rows, branches = decode(body)
    pad = data[pos + len(body):pos + NEXT - START]
    if pad != b'\xcc' * (NEXT - END):
        raise ValueError('padding mismatch')
    slots = relocation_slots(data, sec['.rela.dyn'], sec['.data.rel.ro'])
    expected_slots = [hex(0x56a8050 + n * 0x800) for n in range(30)]
    if slots != expected_slots:
        raise ValueError('relocation census mismatch')
    matches = exact_matches(data, t, body)
    if matches != ['0x243cd00', '0x3256d50', '0x3256dc0', '0x4c903f0', '0x4e78d90']:
        raise ValueError('exact body match census mismatch')
    xrefs = callers(data, t)
    if xrefs:
        raise ValueError('unexpected direct-reference candidates')
    rec = {'artifact': {'name': 'node #94', 'sha256': DIGEST},
           'window': {'start': hex(START), 'end_exclusive': hex(END), 'size_bytes': len(body),
                      'body_sha256': BODY_HASH, 'fde': fde,
                      'padding': {'bytes': len(pad), 'hex': pad.hex(), 'next_fde_start': hex(NEXT)}},
           'branches': branches, 'callees': [], 'direct_reference_candidates': xrefs,
           'exact_body_matches_in_text': matches,
           'relative_relocation_slots': slots,
           'instruction_count': len(rows),
           'rule': {'budget_offset': '0x1e0', 'count_offset': '0x128', 'base_offset': '0x120',
                    'status_offset': '0x1f3', 'cost': 3, 'low_budget_max': 2,
                    'element_bytes': 32, 'chunk_bytes': 16,
                    'low_budget_status': '0x50', 'empty_status': '0x5b'}}
    walk = ''.join(f'{pc:#x}  {encoded:<16}  {ins}\n' for pc, encoded, ins in rows)
    return rec, walk


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=BINARY)
    args = parser.parse_args()
    with args.binary.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record, walk = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    (args.out / 'walk.txt').write_text(walk, encoding='utf-8')


if __name__ == '__main__':
    main()
