#!/usr/bin/env python3
"""Bind the node #115 observer's window-record sink 0x1546570 (fourth stage).

Continues the observer packets for 0x1547530 (first to third stage). The
third stage found that the observer passes a stack record and its state
+0x98 to slot 0x64e0f80 (-> 0x1546570) at 0x15488a3. This tool binds:

1. the sink 0x1546570: what it reads from the record (a date dword at +0x0
   and an hour derived from the dword at +0x4), what it reads from the
   writer state it gets in rsi, the two path templates it formats, the three
   formatters, and the layout of its Option result;
2. the hour helper 0x1567ad0 (slot 0x64e0f58): seconds-of-day / 3600;
3. what the observer does with the result: rotate an open writer at
   state +0xe0 to the new path, cache date/hour at +0x130/+0x140/+0x141,
   write the record, store its time at +0x134, and call a slot when
   +0x142 and a global byte are both set.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-record-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

OBSERVER = (0x1547530, 0x1548ba3)
SINK = (0x1546570, 0x15466f3)
SINK_SLOT = 0x64e0f80
HOUR = (0x1567ad0, 0x1567b94)
HOUR_SLOT = 0x64e0f58
FORMAT_SLOT = 0x64df6e8
FORMAT = 0x141e3a0
DATE_FMT_SLOT = 0x64e0b68
DATE_FMT = 0x150ce90
U8_FMT_SLOT = 0x64e0b70
U8_FMT = 0x150cf50
STR_FMT = 0x15ebba0
HOURLY_TEMPLATE = 0x43ab07
DAILY_TEMPLATE = 0x43aa84
TEMPLATES = {
    HOURLY_TEMPLATE: bytes.fromhex('c008') + b'/hourly/' + bytes.fromhex('c001') + b'/'
                     + bytes.fromhex('c000'),
    DAILY_TEMPLATE: bytes.fromhex('c001') + b'/' + bytes.fromhex('c000'),
}
DATE_PATTERN = 0x465bc9                 # b'%Y%m%d', length 6
DIGITS = 0x46ea12                       # two-digit table b'000102...'
OPEN_SLOT = 0x64e0020
OPEN = (0x14c3b30, 0x14c3c86)
OPEN_LOCATION = 0x63f8e28               # panic Location: base/src/liner.rs:28:38
DROP_OLD = 0x154f2a0
WRITE = 0x14c3370
FLUSH_SLOT = 0x64e0038
FLUSH = 0x14c3c90
GLOBAL_SLOT = 0x64e0f88
GLOBAL = 0x64ffe50
FREE_SLOT = 0x64df4a0
NONE = 0x8000000000000000

SINK_FIXED = {
    0x1546580: '8b2a',                  # mov ebp, [rdx]            (record +0x0: date)
    0x1546582: '80bea800000001',        # cmp byte [rsi+0xa8], 1    (hourly mode)
    0x154658f: '450fb6bea9000000',      # movzx r15d, byte [r14+0xa9] (cached hour)
    0x1546597: '4889d7',                # mov rdi, rdx              (record -> hour helper)
    0x15465a5: '413bae98000000',        # cmp ebp, [r14+0x98]       (cached date, hourly)
    0x15465b2: '410f104608',            # movups xmm0, [r14+0x8]    (directory str, hourly)
    0x1546634: '892b',                  # mov [rbx], ebp            (result +0x0 date)
    0x1546636: 'c6430401',              # mov byte [rbx+4], 1       (result +0x4 hourly)
    0x154663a: '44887305',              # mov [rbx+5], r14b         (result +0x5 hour)
    0x1546643: '413bae98000000',        # cmp ebp, [r14+0x98]       (cached date, daily)
    0x154664c: '48b80000000000000080',  # movabs rax, 0x8000000000000000
    0x1546656: '48894308',              # mov [rbx+8], rax          (result None)
    0x154665f: '410f104608',            # movups xmm0, [r14+0x8]    (directory str, daily)
    0x15466c4: '892b',                  # mov [rbx], ebp
    0x15466c6: 'c6430400',              # mov byte [rbx+4], 0
}
SINK_REFERENCES = (
    (0x154659a, b'\xff\x15', 6, HOUR_SLOT),
    (0x15465ce, b'\x48\x8d\x0d', 7, STR_FMT),
    (0x15465e4, b'\x48\x8b\x0d', 7, DATE_FMT_SLOT),
    (0x15465fa, b'\x48\x8b\x0d', 7, U8_FMT_SLOT),
    (0x1546606, b'\x48\x8d\x35', 7, HOURLY_TEMPLATE),
    (0x154661a, b'\xff\x15', 6, FORMAT_SLOT),
    (0x1546677, b'\x48\x8d\x05', 7, STR_FMT),
    (0x154668d, b'\x48\x8b\x05', 7, DATE_FMT_SLOT),
    (0x1546699, b'\x48\x8d\x35', 7, DAILY_TEMPLATE),
    (0x15466aa, b'\xff\x15', 6, FORMAT_SLOT),
)
FORMATTER_FIXED = {
    0x150cebe: '48c744243806000000',    # mov qword [rsp+0x38], 6  (pattern length)
    0x15ebba3: '488b37',                # mov rsi, [rdi]           (str ptr)
    0x15ebba6: '488b5708',              # mov rdx, [rdi+8]         (str len)
}
FORMATTER_REFERENCES = (
    (0x150ceb2, b'\x48\x8d\x05', 7, DATE_PATTERN),
    (0x150cf78, b'\x48\x8d\x3d', 7, DIGITS),
)
HOUR_FIXED = {
    0x1567ad5: '8b4f04',                # mov ecx, [rdi+4]         (seconds of day)
    0x1567ae2: 'b8c5b3a291',            # mov eax, 0x91a2b3c5
    0x1567ae7: '480fafc2',              # imul rax, rdx
    0x1567aeb: '48c1e82b',              # shr rax, 0x2b
    0x1567af3: '81f9905f0100',          # cmp ecx, 90000
    0x1567af9: '732b',                  # jae (out of range)
    0x1567b00: 'c3',
}
HOUR_LIMIT = 90000
OBSERVER_FIXED = {
    0x154888a: '49bf0000000000000080',  # movabs r15, NONE
    0x1548894: '488db398000000',        # lea rsi, [rbx+0x98]      (writer state)
    0x154889b: '488d7c2460',            # lea rdi, [rsp+0x60]      (result)
    0x15488a0: '4889e2',                # mov rdx, rsp             (record)
    0x15488a9: '488b742468',            # mov rsi, [rsp+0x68]      (result +0x8)
    0x15488ae: '4c39bbe0000000',        # cmp [rbx+0xe0], r15      (writer present?)
    0x15488b5: '751c',                  # jne -> open-writer path
    0x15488b7: '4c39fe',                # cmp rsi, r15             (no writer: no rotation?)
    0x15488c9: '488b7c2470',            # mov rdi, [rsp+0x70]      (path ptr)
    0x15488d3: '4c8db3e0000000',        # lea r14, [rbx+0xe0]
    0x15488da: '4c39fe',                # cmp rsi, r15             (writer: no rotation?)
    0x1548975: '89ab30010000',          # mov [rbx+0x130], ebp     (cached date)
    0x154897b: '4488a340010000',        # mov [rbx+0x140], r12b    (hourly)
    0x1548982: '4488ab41010000',        # mov [rbx+0x141], r13b    (cached hour)
    0x15489c4: '89833c010000',          # mov [rbx+0x13c], eax     (last time, high)
    0x15489ce: '48898334010000',        # mov [rbx+0x134], rax     (last time, low)
    0x15489d5: '80bb4201000000',        # cmp byte [rbx+0x142], 0
    0x154864f: '31d2',                  # xor edx, edx             (free the path)
}
OBSERVER_REFERENCES = (
    (0x15488a3, b'\xff\x15', 6, SINK_SLOT),
    (0x15488ba, b'\x0f\x84', 6, 0x1548657),
    (0x15488ce, b'\xe9', 5, 0x154864f),
    (0x15488dd, b'\x0f\x84', 6, 0x1548989),
    (0x1548651, b'\xff\x15', 6, FREE_SLOT),
    (0x154891f, b'\xff\x15', 6, OPEN_SLOT),
    (0x1548928, b'\xe8', 5, DROP_OLD),
    (0x15489bb, b'\xe8', 5, WRITE),
    (0x15489e2, b'\x48\x8b\x05', 7, GLOBAL_SLOT),
    (0x1548a00, b'\xff\x15', 6, FLUSH_SLOT),
)
OPEN_LOCATION_LEA = 0x14c3bd9


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return off, data[off:off + size]


def rip_target(data, va, prefix, length):
    _, raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2)[1] != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def relative_relocations(data):
    rows = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rows[va] = addend
    return rows


def frame(fdes, va):
    rows = [(f['start'], f['end']) for f in fdes if f['start'] <= va < f['end']]
    if len(rows) != 1:
        raise ValueError(f'expected one FDE at {va:#x}')
    return rows[0]


def slot_census(data, target, slot):
    """E8/E9 rel32 to `target` and FF15/FF25 rip-relative through `slot` in .text."""
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, raw = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    direct, through = [], []
    for opcode, width, dest, out in ((b'\xe8', 5, target, direct), (b'\xe9', 5, target, direct),
                                     (b'\xff\x15', 6, slot, through), (b'\xff\x25', 6, slot, through)):
        start = 0
        while True:
            index = raw.find(opcode, start)
            if index < 0 or index + width > len(raw):
                break
            start = index + 1
            if base + index + width + struct.unpack_from('<i', raw, index + len(opcode))[0] == dest:
                out.append(base + index)
    return sorted(direct), sorted(through)


def bind(data, fdes):
    rel = relative_relocations(data)
    for slot, target in ((SINK_SLOT, SINK[0]), (HOUR_SLOT, HOUR[0]), (FORMAT_SLOT, FORMAT),
                         (DATE_FMT_SLOT, DATE_FMT), (U8_FMT_SLOT, U8_FMT), (OPEN_SLOT, OPEN[0]),
                         (FLUSH_SLOT, FLUSH), (GLOBAL_SLOT, GLOBAL)):
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} changed')
    for va, span in ((SINK[0], SINK), (HOUR[0], HOUR), (OPEN[0], OPEN), (0x15488a3, OBSERVER)):
        if frame(fdes, va) != span:
            raise ValueError(f'FDE at {va:#x} changed')

    # Part 1: the sink.
    for va, expect in {**SINK_FIXED, **FORMATTER_FIXED, **HOUR_FIXED, **OBSERVER_FIXED}.items():
        fixed(data, va, expect)
    for va, prefix, length, expect in SINK_REFERENCES + FORMATTER_REFERENCES + OBSERVER_REFERENCES:
        if rip_target(data, va, prefix, length) != expect:
            raise ValueError(f'reference at {va:#x} changed')
    for va, expect in TEMPLATES.items():
        if read_va(data, va, len(expect))[1] != expect:
            raise ValueError(f'template at {va:#x} changed')
    if read_va(data, DATE_PATTERN, 6)[1] != b'%Y%m%d':
        raise ValueError('date pattern changed')
    if read_va(data, DIGITS, 8)[1] != b'00010203':
        raise ValueError('digit table changed')
    sink_direct, sink_calls = slot_census(data, SINK[0], SINK_SLOT)
    if sink_direct or 0x15488a3 not in sink_calls:
        raise ValueError('sink call census changed')
    hour_direct, hour_calls = slot_census(data, HOUR[0], HOUR_SLOT)
    if hour_direct or 0x154659a not in hour_calls:
        raise ValueError('hour helper call census changed')

    # Part 2: the hour helper is seconds / 3600 below 90000.
    magic = struct.unpack('<I', bytes.fromhex(HOUR_FIXED[0x1567ae2])[1:])[0]
    shift = bytes.fromhex(HOUR_FIXED[0x1567aeb])[-1]
    if any((s * magic) >> shift != s // 3600 for s in range(HOUR_LIMIT)):
        raise ValueError('hour arithmetic is not seconds / 3600')

    # Part 3: the open callee panics at base/src/liner.rs.
    if rip_target(data, OPEN_LOCATION_LEA, b'\x4c\x8d\x05', 7) != OPEN_LOCATION:
        raise ValueError('open callee Location lea changed')
    _, loc = read_va(data, OPEN_LOCATION, 24)
    name_len, line, col = struct.unpack_from('<QII', loc, 8)
    name = read_va(data, rel[OPEN_LOCATION], name_len)[1]
    if (name, line, col) != (b'base/src/liner.rs', 28, 38):
        raise ValueError('open callee Location changed')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'sink': {
            'fde': [hex(v) for v in SINK], 'slot': hex(SINK_SLOT),
            'slot_calls': len(sink_calls), 'direct_calls': len(sink_direct),
            'arguments': {'rdi': 'result (0x20 bytes)', 'rsi': 'writer state',
                          'rdx': 'record; only +0x0 (dword) and +0x4 (via hour helper) are read'},
            'writer_state': {'+0x8': 'directory (ptr, len), Display via %s' % hex(STR_FMT),
                             '+0x98': 'cached date dword', '+0xa8': 'hourly mode byte (1 = hourly)',
                             '+0xa9': 'cached hour byte'},
            'decision': {'hourly': 'None when hour(record) == +0xa9 and date == +0x98, else Some',
                         'daily': 'None when date == +0x98, else Some'},
            'templates': {hex(va): raw.hex() for va, raw in TEMPLATES.items()},
            'paths_inferred': {'hourly': '{dir}/hourly/{date:%Y%m%d}/{hour}',
                               'daily': '{dir}/{date:%Y%m%d}'},
            'formatters': {'dir': hex(STR_FMT), 'date': hex(DATE_FMT) + ' (pattern %Y%m%d at '
                           + hex(DATE_PATTERN) + ')', 'hour': hex(U8_FMT) + ' (u8 decimal)'},
            'result': {'+0x0': 'date dword', '+0x4': 'hourly byte', '+0x5': 'hour byte (hourly only)',
                       '+0x8': 'path String (cap, ptr, len); cap %s = None' % hex(NONE)},
        },
        'hour_helper': {'fde': [hex(v) for v in HOUR], 'slot': hex(HOUR_SLOT),
                        'slot_calls': len(hour_calls), 'reads': 'record +0x4 (seconds of day)',
                        'returns': 'seconds / 3600 for seconds < %d (checked exhaustively)' % HOUR_LIMIT},
        'observer_use': {
            'call_va': '0x15488a3', 'writer_state': 'state +0x98',
            'writer': {'offset': '+0xe0 (writer +0x48)', 'none': hex(NONE)},
            'no_writer': 'a new path is freed (0x154864f) and nothing is written',
            'writer_no_rotation': 'jump to the write at 0x1548989',
            'rotation': {'open': hex(OPEN[0]) + ' via ' + hex(OPEN_SLOT),
                         'open_panic_location': 'base/src/liner.rs:28:38',
                         'drop_old': hex(DROP_OLD),
                         'cache': {'+0x130': 'date', '+0x140': 'hourly', '+0x141': 'hour'}},
            'write': hex(WRITE), 'last_time': '+0x134 (12 bytes from record +0x0)',
            'optional_call': {'slot': hex(FLUSH_SLOT), 'target': hex(FLUSH),
                              'when': 'byte +0x142 != 0 and byte at %s != 0' % hex(GLOBAL)},
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
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
    print(f"sink_calls={result['sink']['slot_calls']} hour_calls={result['hour_helper']['slot_calls']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
