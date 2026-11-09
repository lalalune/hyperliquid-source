#!/usr/bin/env python3
"""Bind the owners of node #115 daily line writers (eighth stage).

Continues the line writer packets. The seventh stage found the daily writer
constructor 0x1546700 (slot 0x64e0f98, 32 calls) and the hourly constructor
0x1546000 (slot 0x64e0fa0, 27 calls). This tool binds, for each of the 32
daily calls:

1. the name argument: a static string (`lea rsi, [rip+x]` and `mov edx, n`
   just before the call) or a value passed in a register (built at run time);
2. the output buffer (`lea rdi, [rsp+d]` or `mov rdi, rbx`);
3. whether the next call is the hourly constructor with that buffer as its
   second argument, and whether a `mov byte [rsp+d+0xaa], 1` follows it.

It also binds that the hourly constructor takes the writer in rsi and
stores the date at +0x98 and 1 at +0xa8 of that input writer, and maps the
writer move in the two mixed functions 0x2af45f0 and 0x2cc1120: the hourly
`mempool_txs` writer is split into its first qword and a 0xa8-byte tail and
rebuilt at +0x18 of a stack struct that is passed to 0x5a81ed0 (slot
0x64e74d8).

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-line-writer-owners-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

DAILY_SLOT, DAILY = 0x64e0f98, 0x1546700
HOURLY_SLOT, HOURLY = 0x64e0fa0, 0x1546000
CONSUMER_SLOT, CONSUMER = 0x64e74d8, 0x5a81ed0
MEMCPY_SLOT = 0x64df508
FLUSH_BYTE = 0xaa


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def slot_calls(data, slot):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
            out.append(base + i)
    return out




def _disp(raw, at, width):
    return struct.unpack_from('<b' if width == 1 else '<i', raw, at)[0]


def decode(raw):
    """Decode one of the argument-setting shapes at the start of raw; return (kind, value, length) or None."""
    b = raw
    if b[:3] == b'\x48\x8d\x35':
        return 'name_rip', _disp(b, 3, 4), 7
    if b[:1] == b'\xba':
        return 'len', struct.unpack_from('<I', b, 1)[0], 5
    for reg, m8, m32 in (('rdi', 0x7c, 0xbc), ('rsi', 0x74, 0xb4)):
        if b[:2] == b'\x48\x8d' and b[2] == m8 and b[3] == 0x24:
            return reg, 'rsp+%#x' % _disp(b, 4, 1), 5
        if b[:2] == b'\x48\x8d' and b[2] == m32 and b[3] == 0x24:
            return reg, 'rsp+%#x' % _disp(b, 4, 4), 8
    if b[0] in (0x48, 0x4c) and b[1] == 0x8d and b[2] & 0xc7 in (0x44, 0x84) and b[3] == 0x24:
        width = 1 if b[2] & 0xc0 == 0x40 else 4
        return 'other', None, 4 + width
    if b[:3] == b'\x48\x89\xdf':
        return 'rdi', 'rbx', 3
    if b[:3] == b'\x48\x89\xe7':
        return 'rdi', 'rsp+0x0', 3
    if b[:3] == b'\x48\x89\xde':
        return 'rsi', 'rbx', 3
    if b[0] in (0x48, 0x4c) and b[1] == 0x89 and b[2] & 0xc7 == 0xc6:
        return 'name_reg', ((b[2] >> 3) & 7) | ((b[0] & 4) << 1), 3
    if b[:3] == b'\x48\x8b\x54' and b[3] == 0x24:
        return 'len_stack', 'rsp+%#x' % _disp(b, 4, 1), 5
    if b[:3] == b'\x48\x8b\x94' and b[3] == 0x24:
        return 'len_stack', 'rsp+%#x' % _disp(b, 4, 4), 8
    return None


def args_before(data, call):
    """Walk back over up to four decodable instructions that end at the call."""
    found, end = {}, call
    for _ in range(4):
        hit = None
        for length in (3, 5, 7, 8):
            raw = read_va(data, end - length, 8)
            got = decode(raw)
            if got and got[2] == length:
                hit = got
                break
        if hit is None:
            break
        kind, value, length = hit
        if kind == 'name_rip':
            value = end + value
        found.setdefault(kind, value)
        end -= length
    return found


def args_after(data, start, limit=3):
    """Decode up to `limit` instructions forward; return (args, address of the first undecoded byte)."""
    found, pos = {}, start
    for _ in range(limit):
        got = decode(read_va(data, pos, 8))
        if got is None or got[0] not in ('rdi', 'rsi'):
            break
        found.setdefault(got[0], got[1])
        pos += got[2]
    return found, pos


def slot_call_at(data, va, slot):
    raw = read_va(data, va, 6)
    return raw[:2] == b'\xff\x15' and va + 6 + struct.unpack_from('<i', raw, 2)[0] == slot


def site(data, call):
    before = args_before(data, call)
    if 'name_rip' in before and 'len' in before:
        name = read_va(data, before['name_rip'], before['len']).decode()
        kind = 'static'
    elif 'name_reg' in before:
        name, kind = None, 'register'
    else:
        raise ValueError(f'daily call {call:#x}: name argument not decoded')
    out = before.get('rdi')
    if out is None:
        raise ValueError(f'daily call {call:#x}: output buffer not decoded')
    after, pos = args_after(data, call + 6)
    row = {'call': hex(call), 'name_kind': kind, 'name': name, 'out': out, 'hourly': None}
    if kind == 'static':
        row['name_at'] = hex(before['name_rip'])
    if slot_call_at(data, pos, HOURLY_SLOT):
        if after.get('rsi') != out:
            raise ValueError(f'hourly call {pos:#x} does not take the daily writer')
        hourly = {'call': hex(pos), 'out': after.get('rdi'), 'flush_byte_set': False}
        raw = read_va(data, pos + 6, 8)
        if raw[:3] == b'\xc6\x84\x24' and raw[7] == 1 and hourly['out'] and hourly['out'].startswith('rsp+'):
            if _disp(raw, 3, 4) == int(hourly['out'][4:], 16) + FLUSH_BYTE:
                hourly['flush_byte_set'] = True
        row['hourly'] = hourly
    return row


FIXED = {
    # hourly constructor: rbx = rsi (the daily writer); date and hourly byte stored into it
    0x1546011: '4889f3',                # mov rbx, rsi
    0x154603f: '4489bb98000000',        # mov [rbx+0x98], r15d
    0x1546046: 'c683a800000001',        # mov byte [rbx+0xa8], 1
    # 0x2af45f0: hourly mempool_txs writer at rsp+0x150 -> struct rsp+0x640 +0x18
    0x2af5a02: 'c68424fa01000001',      # mov byte [rsp+0x1fa], 1   (+0xaa)
    0x2af5a0a: '4c8bbc2450010000',      # mov r15, [rsp+0x150]      (first qword)
    0x2af5a12: '488db42458010000',      # lea rsi, [rsp+0x158]
    0x2af5a1a: '488dbc2420090000',      # lea rdi, [rsp+0x920]
    0x2af5a22: 'baa8000000',            # mov edx, 0xa8             (tail)
    0x2af5aa0: '4c89bc2458060000',      # mov [rsp+0x658], r15
    0x2af5aa8: '488dbc2460060000',      # lea rdi, [rsp+0x660]
    0x2af5ab0: '488db42420090000',      # lea rsi, [rsp+0x920]
    0x2af5ab8: 'baa8000000',            # mov edx, 0xa8
    0x2af5aee: '488dbc2440060000',      # lea rdi, [rsp+0x640]      (struct)
    # 0x2cc1120: hourly mempool_txs writer at rsp+0x16b0 -> struct rsp+0x7d0 +0x18
    0x2cc271f: 'c684245a17000001',      # mov byte [rsp+0x175a], 1  (+0xaa)
    0x2cc2727: '4c8bbc24b0160000',      # mov r15, [rsp+0x16b0]
    0x2cc272f: '488db424b8160000',      # lea rsi, [rsp+0x16b8]
    0x2cc2737: '488dbc2440140000',      # lea rdi, [rsp+0x1440]
    0x2cc273f: 'baa8000000',            # mov edx, 0xa8
    0x2cc27c3: '4c89bc24e8070000',      # mov [rsp+0x7e8], r15
    0x2cc27cb: '488dbc24f0070000',      # lea rdi, [rsp+0x7f0]
    0x2cc27d3: '488db42440140000',      # lea rsi, [rsp+0x1440]
    0x2cc27db: 'baa8000000',            # mov edx, 0xa8
    0x2cc280a: '488dbc24d0070000',      # lea rdi, [rsp+0x7d0]      (struct)
}
REFERENCES = (
    (0x2af5a27, b'\xff\x15', 6, MEMCPY_SLOT),
    (0x2af5abd, b'\xff\x15', 6, MEMCPY_SLOT),
    (0x2af5b03, b'\xff\x15', 6, CONSUMER_SLOT),
    (0x2cc2744, b'\xff\x15', 6, MEMCPY_SLOT),
    (0x2cc27e0, b'\xff\x15', 6, MEMCPY_SLOT),
    (0x2cc281f, b'\xff\x15', 6, CONSUMER_SLOT),
)
MOVES = {
    '0x2af45f0': {'hourly_writer': 'rsp+0x150', 'struct': 'rsp+0x640', 'writer_at': '+0x18',
                  'via': 'first qword in r15; 0xa8 tail through rsp+0x920', 'consumer_call': '0x2af5b03'},
    '0x2cc1120': {'hourly_writer': 'rsp+0x16b0', 'struct': 'rsp+0x7d0', 'writer_at': '+0x18',
                  'via': 'first qword in r15; 0xa8 tail through rsp+0x1440', 'consumer_call': '0x2cc281f'},
}


def bind(data):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in ((DAILY_SLOT, DAILY), (HOURLY_SLOT, HOURLY), (CONSUMER_SLOT, CONSUMER)):
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')

    daily = slot_calls(data, DAILY_SLOT)
    hourly = slot_calls(data, HOURLY_SLOT)
    rows = [site(data, call) for call in daily]
    paired = sorted(int(r['hourly']['call'], 16) for r in rows if r['hourly'])
    if paired != hourly:
        raise ValueError('an hourly call does not follow a daily call')
    moves = {k: dict(v) for k, v in MOVES.items()}
    for move in moves.values():
        row = next(r for r in rows if r['hourly'] and r['hourly']['out'] == move['hourly_writer']
                   and r['name'] == 'mempool_txs' and r['hourly']['flush_byte_set'])
        move['daily_call'] = row['call']
    static = [r for r in rows if r['name_kind'] == 'static']
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'daily_calls': len(daily),
        'hourly_calls': len(hourly),
        'static_names': len(static),
        'register_names': len(rows) - len(static),
        'hourly_after_daily': len(paired),
        'flush_byte_set_after_hourly': sum(1 for r in rows if r['hourly'] and r['hourly']['flush_byte_set']),
        'hourly_constructor': 'rbx = rsi (input writer) at 0x1546011; [rbx+0x98] = date at 0x154603f; '
                              '[rbx+0xa8] = 1 at 0x1546046',
        'sites': rows,
        'mixed_function_moves': moves,
        'consumer': '%s -> %s (not mapped)' % (hex(CONSUMER_SLOT), hex(CONSUMER)),
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(f"daily={result['daily_calls']} static={result['static_names']} hourly={result['hourly_after_daily']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
