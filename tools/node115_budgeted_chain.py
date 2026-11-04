#!/usr/bin/env python3
"""Bind a bounded chain walk from node #115 without executing it."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-node115-budgeted-chain'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x35bd510, 0x35bd563
FDE, CIE = 0xddd718, 0xca6ed8
TEXT_START, TEXT_END, TEXT_OFFSET = 0x1419300, 0x63f0a00, 0x1418300
# Every byte of the body is consumed as one strictly checked x86-64 instruction.
FORMS = [
 ('4889f8', 'mov rax,rdi'),
 ('6683beca02000000', 'cmp word [rsi+0x2ca],0'),
 ('751c', 'jne 0x35bd539'), ('0f1f00', 'nop [rax]'),
 ('4885d2', 'test rdx,rdx'), ('742a', 'je 0x35bd54f'),
 ('488bb6d0020000', 'mov rsi,[rsi+0x2d0]'), ('48ffca', 'dec rdx'),
 ('6683beca02000000', 'cmp word [rsi+0x2ca],0'),
 ('74e7', 'je 0x35bd520'), ('48897008', 'mov [rax+8],rsi'),
 ('48895010', 'mov [rax+0x10],rdx'),
 ('48c7401800000000', 'mov qword [rax+0x18],0'),
 ('31c9', 'xor ecx,ecx'), ('488908', 'mov [rax],rcx'), ('c3', 'ret'),
 ('48897008', 'mov [rax+8],rsi'), ('0f57c0', 'xorps xmm0,xmm0'),
 ('0f114010', 'movups [rax+0x10],xmm0'), ('b901000000', 'mov ecx,1'),
 ('488908', 'mov [rax],rcx'), ('c3', 'ret')]


def decode(body):
    pos, rows = 0, []
    branches = {2: 0x35bd539, 5: 0x35bd54f, 9: 0x35bd520}
    for i, (encoding, operation) in enumerate(FORMS):
        ins = bytes.fromhex(encoding)
        if body[pos:pos+len(ins)] != ins:
            raise ValueError('unexpected instruction at %#x' % (START + pos))
        if i in branches and START + pos + 2 + struct.unpack('b', ins[1:])[0] != branches[i]:
            raise ValueError('branch target mismatch')
        rows.append({'address': START + pos, 'bytes': ins.hex(), 'operation': operation})
        pos += len(ins)
    if pos != len(body):
        raise ValueError('instruction coverage mismatch')
    return rows


def frame(fde, cie):
    if cie != bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'):
        raise ValueError('unexpected CIE')
    if len(fde) != 20:
        raise ValueError('unexpected FDE length')
    length, delta, rel, size = struct.unpack_from('<IIiI', fde)
    if (length, FDE+4-delta, FDE+8+rel, size, fde[16:]) != (16, CIE, START, END-START, b'\0'*4):
        raise ValueError('unexpected FDE')
    return {'fde_va': FDE, 'fde_file_offset': FDE, 'fde_bytes': fde.hex(),
            'cie_va': CIE, 'cie_file_offset': CIE, 'cie_bytes': cie.hex(),
            'augmentation': 'zR', 'lsda': None}


def target(site, ins):
    if len(ins) != 5 or ins[0] not in (0xe8, 0xe9):
        raise ValueError('not rel32 call or jump')
    return site + 5 + struct.unpack_from('<i', ins, 1)[0]


def check_call(site, ins):
    if target(site, ins) != START:
        raise ValueError('wrong call target')


def scan(data):
    result = []
    lo, hi = TEXT_OFFSET, TEXT_OFFSET + TEXT_END - TEXT_START
    for op in (b'\xe8', b'\xe9'):
        pos = lo
        while True:
            pos = data.find(op, pos, hi-4)
            if pos < 0:
                break
            va = TEXT_START + pos - lo
            ins = data[pos:pos+5]
            if target(va, ins) == START:
                result.append({'site': va, 'opcode': op.hex(), 'bytes': ins.hex(), 'target': START})
            pos += 1
    result.sort(key=lambda x: x['site'])
    if [(x['site'], x['opcode']) for x in result] != [(0x3d6ec82, 'e8')]:
        raise ValueError('unexpected direct reference census')
    return result


def decode_context(raw):
    forms = [
        ('488b7508', 'mov rsi,[rbp+8]'), ('4885f6', 'test rsi,rsi'),
        ('0f849c000000', 'je 0x3d6ed12'), ('488b5510', 'mov rdx,[rbp+0x10]'),
        ('b901000000', 'mov ecx,1'), ('4c89ef', 'mov rdi,r13')]
    pos, rows = 0, []
    for encoding, operation in forms:
        ins = bytes.fromhex(encoding)
        if raw[pos:pos+len(ins)] != ins:
            raise ValueError('caller instruction mismatch')
        if ins[:2] == b'\x0f\x84' and 0x3d6ec69+pos+6+struct.unpack_from('<i', ins, 2)[0] != 0x3d6ed12:
            raise ValueError('caller branch target mismatch')
        rows.append({'address': 0x3d6ec69+pos, 'bytes': ins.hex(), 'operation': operation})
        pos += len(ins)
    if pos != len(raw):
        raise ValueError('caller instruction coverage mismatch')
    return rows


def sections(data):
    if data[:16] != bytes.fromhex('7f454c46020101000000000000000000'):
        raise ValueError('unsupported ELF')
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names = struct.unpack_from('<HHH', data, 58)
    if size != 64 or names >= count or offset+size*count > len(data):
        raise ValueError('invalid section table')
    hdrs = [struct.unpack_from('<IIQQQQIIQQ', data, offset+i*size) for i in range(count)]
    table = hdrs[names]
    strings = data[table[4]:table[4]+table[5]]
    found = {}
    for h in hdrs:
        if h[0] >= len(strings):
            raise ValueError('bad section name')
        end = strings.find(b'\0', h[0])
        if end < 0:
            raise ValueError('unterminated section name')
        name = strings[h[0]:end]
        if name in (b'.text', b'.eh_frame'):
            if name in found:
                raise ValueError('duplicate section')
            found[name] = h
    if set(found) != {b'.text', b'.eh_frame'}:
        raise ValueError('missing section')
    if found[b'.text'][2:6] != (6, TEXT_START, TEXT_OFFSET, TEXT_END-TEXT_START):
        raise ValueError('unexpected text geometry')
    if found[b'.eh_frame'][3:6] != (CIE, CIE, 0x77137c):
        raise ValueError('unexpected frame geometry')


def inspect(data):
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node #115 size or digest mismatch')
    sections(data)
    body = data[START-0x1000:END-0x1000]
    walk = decode(body)
    unwind = frame(data[FDE:FDE+20], data[CIE:CIE+24])
    padding = data[END-0x1000:0x35bd570-0x1000]
    if padding != b'\xcc'*13:
        raise ValueError('padding mismatch')
    next_fde = data[FDE+20:FDE+20+76]
    length, delta, rel, extent = struct.unpack_from('<IIiI', next_fde)
    if (length, FDE+24-delta, FDE+28+rel, extent) != (72, CIE, 0x35bd570, 0xe3):
        raise ValueError('next FDE mismatch')
    refs = scan(data)
    context = bytes.fromhex('488b75084885f60f849c000000488b5510b9010000004c89ef')
    site = 0x3d6ec82
    context_walk = decode_context(data[site-0x1000-len(context):site-0x1000])
    check_call(site, data[site-0x1000:site-0x1000+5])
    caller_fde = 0x126017c
    caller_frame = data[caller_fde:caller_fde+84]
    length, delta, rel, extent = struct.unpack_from('<IIiI', caller_frame)
    if (length, caller_fde+4-delta, caller_fde+8+rel, extent) != (80, 0x103d604, 0x3d6e9d0, 0x3fd):
        raise ValueError('caller FDE mismatch')
    return {'target': {'sha256': SHA, 'size': len(data)},
            'window': {'start': START, 'end': END, 'file_offset': START-0x1000,
                       'size': len(body), 'body_sha256': hashlib.sha256(body).hexdigest(),
                       'body_hex': body.hex(), 'padding_hex': padding.hex(), 'next_fde_start': 0x35bd570,
                       'frame': unwind, 'next_fde_bytes': next_fde.hex()},
            'instructions': walk, 'callees': [],
            'direct_rel32_candidates': refs,
            'scan': {'start': TEXT_START, 'end': TEXT_END, 'method': 'every byte e8/e9 rel32'},
            'caller_context': {'start': 0x3d6ec69, 'bytes': context.hex(), 'instructions': context_walk,
                               'enclosing_fde_start': 0x3d6e9d0, 'enclosing_fde_end': 0x3d6edcd,
                               'fde_va': caller_fde, 'cie_va': 0x103d604, 'fde_bytes': caller_frame.hex()},
            'rule': {'flag_offset': 714, 'link_offset': 720, 'output_size': 32}}


def model(nodes, start, budget):
    """Model only valid, nonaliasing node/output memory; nodes map keys to (u16, next)."""
    if not 0 <= budget < 2**64:
        raise ValueError('budget is not a u64')
    current = start
    while True:
        flag, successor = nodes[current]
        if not 0 <= flag < 2**16:
            raise ValueError('flag is not a u16')
        if flag:
            return (0, current, budget, 0)
        if budget == 0:
            return (1, current, 0, 0)
        current = successor
        budget -= 1


def generate(binary, out):
    with binary.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        record = inspect(data)
    out.mkdir(parents=True, exist_ok=True)
    (out/'records.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    for name in ('README.md', 'verify.py'):
        (out/name).write_bytes((PACKET/name).read_bytes())
    names = ('README.md', 'records.json', 'verify.py')
    (out/'MANIFEST.sha256').write_text(''.join(hashlib.sha256((out/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names), encoding='ascii')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    generate(args.binary, args.out)


if __name__ == '__main__':
    main()
