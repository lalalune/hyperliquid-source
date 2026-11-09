#!/usr/bin/env python3
"""Bind what the node #115 bucket_guard constants do (RE-008, after the bucket_guard names).

The bucket_guard getters (0x26d4660, 0x3704070, 0x4770930, 0x51eaff0) take
a closure with a name and two f64 pointers, a and b. This tool binds:

1. the getter vacant path: *a goes to the observer constructor in xmm0;
   after it returns, the getter writes 1 at +0x0 and *b at +0x8, copies
   0x238 bytes, writes 10 at +0x238 and copies +0x240..+0x25f, so the
   stored value differs from the constructed one in exactly +0x0, +0x8 and
   +0x238 (the constructor wrote 0, nothing and 1000);
2. the constructor: it multiplies its xmm0 input by the selector 0x15474d0
   (configuration byte +0x48 indexes the table 0x4671d0, mapped in
   RE-015-scheduled-observer-115) and stores the result at +0x218;
3. the record entry 0x1547530 (rbx = observer): no operand with base rbx
   (or r11) and displacement 0x8 or 0x218, in any encoding, over its whole
   FDE; one with 0x238, a compare against the count +0x58 that gates a call
   to 0x1570f30 (time + 600.0 s) whose 12-byte result is overwritten before
   the window record reaches the writer 0x14c3370;
4. the 50 bucket_guard record calls: each passes the getter's return in rdi
   and count 1 in esi.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; FDE ends are exclusive.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-bucket-guard-constants-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

RECORD = (0x1547530, 0x1548ba3)
CTOR = (0x1548bb0, 0x1548f3d)
SELECT = 0x15474d0
ROLL = (0x1570f30, 0x157104e)
WRITER = 0x14c3370
TABLE = 0x4671d0
SLOTS = {0x64e1008: SELECT, 0x64e1010: RECORD[0], 0x64e1018: ROLL[0], 0x64e1020: CTOR[0]}
MEMCPY_GOT = 0x64df508
SECONDS = 0x459568  # binary64 600.0

# getter: FDE, closure loads, a spill/reload offset, a reload, lea rdi, constructor call,
# X (constructed value at [rsp+X]), D (stored value at [rsp+D]), b register
GETTERS = (
    (0x26d4660, (0x26d4660, 0x26d47fb), 0x26d46ae, 0x00, 0x26d46f8, 0x26d46f1, 0x26d4700, 0x58, 0x2b8, 'r14'),
    (0x3704070, (0x3704070, 0x370420b), 0x37040be, 0x00, 0x3704108, 0x3704101, 0x3704110, 0x58, 0x2b8, 'r14'),
    (0x4770930, (0x4770930, 0x4770c21), 0x4770982, 0x58, 0x47709cd, 0x47709c6, 0x47709d6, 0x60, 0x2c8, 'r15'),
    (0x51eaff0, (0x51eaff0, 0x51eb18b), 0x51eb03e, 0x00, 0x51eb088, 0x51eb081, 0x51eb090, 0x58, 0x2b8, 'r14'),
)
GETTER_CALLS = {0x26d4660: 11, 0x3704070: 8, 0x4770930: 1, 0x51eaff0: 30}

CTOR_PINS = (
    (0x1548bc7, 'f20f11442410'),              # movsd [rsp+0x10], xmm0 (input a)
    (0x1548cb6, 'ff154c83f904'),              # call [0x64e1008] -> selector 0x15474d0
    (0x1548cbc, 'f20f10542410'),              # movsd xmm2, [rsp+0x10]
    (0x1548cc2, 'f20f59d0'),                  # mulsd xmm2, xmm0
    (0x1548d25, 'f20f11542410'),              # movsd [rsp+0x10], xmm2
    (0x1548dcc, 'f20f10442410'),              # movsd xmm0, [rsp+0x10]
    (0x1548dd2, 'f2410f118618020000'),        # movsd [r14+0x218], xmm0
    (0x1548e12, '49c70600000000'),            # mov qword [r14], 0
    (0x1548e30, '49c78638020000e8030000'),    # mov qword [r14+0x238], 1000
)
SELECT_PINS = (
    (0x15474d5, '488b1d3c94f904'),            # mov rbx, [0x64e0918]
    (0x15474e3, '0fb64348'),                  # movzx eax, byte [rbx+0x48]
    (0x15474e7, '488d0de2fcf1fe'),            # lea rcx, [0x4671d0]
    (0x15474ee, 'f20f1004c1'),                # movsd xmm0, [rcx+rax*8]
)
RECORD_PINS = (
    (0x154754d, '4889fb'),                    # mov rbx, rdi
    (0x1547f47, '4c8b6358'),                  # mov r12, [rbx+0x58]
    (0x1547f4b, '4983fc0a'),                  # cmp r12, 10
    (0x1547f4f, '0f8202070000'),              # jb 0x1548657 (no window record)
    (0x15486ee, '4c3ba338020000'),            # cmp r12, [rbx+0x238]
    (0x15486f5, '761b'),                      # jbe 0x1548712
    (0x15486f7, '488dbc24d8000000'),          # lea rdi, [rsp+0xd8]
    (0x15486ff, '488d742460'),                # lea rsi, [rsp+0x60]
    (0x1548704, 'f20f10055c0ef1fe'),          # movsd xmm0, [0x459568]
    (0x154870c, 'ff150689f904'),              # call [0x64e1018] -> 0x1570f30
    (0x1548764, '48898424d8000000'),          # mov [rsp+0xd8], rax
    (0x1548771, 'f20f118424e0000000'),        # movsd [rsp+0xe0], xmm0
    (0x15489bb, 'e8b0a9f7ff'),                # call 0x14c3370 (writer)
)
ROLL_PINS = (
    (0x1570f37, '4889fb'),                    # mov rbx, rdi
    (0x157103a, '894308'),                    # mov [rbx+0x8], eax
    (0x1571040, '488903'),                    # mov [rbx], rax
)
DEAD = (0x1548712, 0x1548764)  # no [rsp+0xd8..0xe3] operand between the call's return and the overwrite


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return off, data[off:off + size]


def pinned(data, pin):
    va, text = pin
    raw = bytes.fromhex(text)
    if read_va(data, va, len(raw))[1] != raw:
        raise ValueError(f'instruction at {va:#x} changed')
    return raw


def rip(data, pin, imm=0):
    """Target of a rip-relative operand whose disp32 sits imm bytes before the instruction end."""
    raw = pinned(data, pin)
    return pin[0] + len(raw) + struct.unpack_from('<i', raw, len(raw) - 4 - imm)[0]


def relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def frame(fdes, va):
    rows = [(f['start'], f['end']) for f in fdes if f['start'] <= va < f['end']]
    if len(rows) != 1:
        raise ValueError(f'expected one FDE at {va:#x}')
    return rows[0]


def direct_calls(data, targets):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, raw = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    out, start = {t: [] for t in targets}, 0
    while True:
        i = raw.find(b'\xe8', start)
        if i < 0 or i + 5 > len(raw):
            return out
        start = i + 1
        target = base + i + 5 + struct.unpack_from('<i', raw, i + 1)[0]
        if target in out:
            out[target].append(base + i)


def base_operands(raw, base, disp):
    """Every byte offset that could start a ModRM [base+disp] operand (base 3 = rbx/r11, 4 = rsp SIB).

    The scan runs over every offset, not over decoded instructions, so it
    over-reports and never misses: a real operand must contain these bytes.
    """
    hits = []
    for i in range(len(raw) - 6):
        m = raw[i]
        if base == 3:
            if m & 0xC7 in (0x43, 0x83):
                mod, at = m >> 6, i + 1
            elif m & 0xC7 in (0x44, 0x84) and raw[i + 1] & 7 == 3:
                mod, at = m >> 6, i + 2
            else:
                continue
        else:
            if m & 0xC7 not in (0x44, 0x84) or raw[i + 1] != 0x24:
                continue
            mod, at = m >> 6, i + 2
        value = raw[at] if mod == 1 else struct.unpack_from('<I', raw, at)[0]
        if value in disp:
            hits.append(i)
    return hits


def le32(value):
    return struct.pack('<I', value).hex()


def bind_getter(data, fdes, row):
    getter, fde, loads, spill, reload, lea, ctor, x, d, breg = row
    if frame(fdes, getter) != fde:
        raise ValueError(f'FDE of {getter:#x} changed')
    sp = 'f20f110424' if spill == 0 else f'f20f114424{spill:02x}'
    rl = 'f20f100424' if spill == 0 else f'f20f104424{spill:02x}'
    bload = {'r14': '4c8b7610', 'r15': '4c8b7e10'}[breg]
    bread = {'r14': 'f2410f1006', 'r15': 'f2410f1007'}[breg]
    pins = (
        (loads, '488b4e08'), (loads + 4, bload), (loads + 8, 'f20f1001'), (loads + 12, sp),  # a = *[rsi+8]; b ptr
        (reload, rl), (lea, f'488d7c24{x:02x}'),
        (ctor + 0x06, bread),
        (ctor + 0x0b, f'48c74424{x:02x}01000000'),          # +0x0 = 1
        (ctor + 0x14, f'f20f114424{x + 8:02x}'),            # +0x8 = b
        (ctor + 0x1a, '488dbc24' + le32(d)), (ctor + 0x22, f'488d7424{x:02x}'),
        (ctor + 0x27, 'ba38020000'),                         # memcpy 0x238 bytes
        (ctor + 0x32, '0f108424' + le32(x + 0x240)), (ctor + 0x3a, '0f108c24' + le32(x + 0x250)),
        (ctor + 0x42, '0f118424' + le32(d + 0x240)), (ctor + 0x4a, '0f118c24' + le32(d + 0x250)),
        (ctor + 0x52, '48c78424' + le32(d + 0x238) + '0a000000'),  # +0x238 = 10
    )
    for pin in pins:
        pinned(data, pin)
    if rip(data, (ctor, 'ff15' + read_va(data, ctor + 2, 4)[1].hex())) != 0x64e1020:
        raise ValueError(f'constructor call at {ctor:#x} changed')
    if rip(data, (ctor + 0x2c, 'ff15' + read_va(data, ctor + 0x2e, 4)[1].hex())) != MEMCPY_GOT:
        raise ValueError(f'memcpy call at {ctor + 0x2c:#x} changed')
    return {'getter': hex(getter), 'constructed_at': f'rsp+{x:#x}', 'stored_at': f'rsp+{d:#x}',
            'a_to_constructor': hex(reload), 'b_register': breg,
            'writes': {'+0x0': 1, '+0x8': 'b', '+0x238': 10},
            'copied': ['+0x0..+0x237 after the +0x0 and +0x8 writes', '+0x240..+0x25f'],
            'pins': [hex(p[0]) for p in pins] + [hex(ctor), hex(ctor + 0x2c)]}


def bind(data, fdes):
    rel = relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} no longer relocates to {target:#x}')
    for start, end in (RECORD, CTOR, ROLL):
        if frame(fdes, start) != (start, end):
            raise ValueError(f'FDE {start:#x} changed')
    for pin in CTOR_PINS + SELECT_PINS + RECORD_PINS + ROLL_PINS:
        pinned(data, pin)
    if rip(data, CTOR_PINS[1]) != 0x64e1008 or rip(data, RECORD_PINS[9]) != 0x64e1018:
        raise ValueError('slot call changed')
    if rip(data, SELECT_PINS[2]) != TABLE:
        raise ValueError('factor table changed')
    if rip(data, RECORD_PINS[8]) != SECONDS or struct.unpack('<d', read_va(data, SECONDS, 8)[1])[0] != 600.0:
        raise ValueError('rollover seconds changed')
    if 0x15489bb + 5 + struct.unpack_from('<i', pinned(data, RECORD_PINS[12]), 1)[0] != WRITER:
        raise ValueError('writer call changed')

    _, rec = read_va(data, RECORD[0], RECORD[1] - RECORD[0])
    scan = {f'{d:#x}': [hex(RECORD[0] + i) for i in base_operands(rec, 3, {d})] for d in (0x8, 0x218, 0x238)}
    if scan != {'0x8': [], '0x218': [], '0x238': ['0x15486f0']}:
        raise ValueError(f'record operand scan changed: {scan}')
    _, gap = read_va(data, DEAD[0], DEAD[1] - DEAD[0])
    if base_operands(gap, 4, set(range(0xd8, 0xe4))):
        raise ValueError('rollover result read before overwrite')
    getters = [bind_getter(data, fdes, row) for row in GETTERS]

    census = direct_calls(data, set(GETTER_CALLS))
    records = []
    for getter, calls in sorted(census.items()):
        if len(calls) != GETTER_CALLS[getter]:
            raise ValueError(f'getter {getter:#x} call census changed')
        for call in calls:
            _, window = read_va(data, call + 5, 0x30)
            at = next((i for i in range(len(window) - 6) if window[i:i + 2] == b'\xff\x15' and
                       call + 5 + i + 6 + struct.unpack_from('<i', window, i + 2)[0] == 0x64e1010), None)
            if at is None:
                raise ValueError(f'no record call after {call:#x}')
            before = window[:at]
            if b'\xbe\x01\x00\x00\x00' not in before or b'\x48\x89\xc7' not in before:
                raise ValueError(f'record call after {call:#x} lost rdi = getter result or esi = 1')
            records.append({'getter_call': hex(call), 'record_call': hex(call + 5 + at), 'count': 1})
    return {
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'slots': {hex(k): hex(v) for k, v in SLOTS.items()},
        'getters': getters,
        'constructor': {'fde': [hex(CTOR[0]), hex(CTOR[1])], 'a_times_factor_at': '+0x218',
                        'factor': {'selector': hex(SELECT), 'config_byte': '+0x48', 'table': hex(TABLE),
                                   'mapped_in': 'RE-015-scheduled-observer-115'},
                        'zero_at': '+0x0', 'limit_default': {'+0x238': 1000},
                        'pins': [hex(p[0]) for p in CTOR_PINS]},
        'record': {'fde': [hex(RECORD[0]), hex(RECORD[1])], 'observer_register': 'rbx',
                   'rbx_operand_modrm_bytes': scan,
                   'count_gate': {'count': '+0x58', 'minimum': 10, 'at': '0x1547f4b', 'skip_to': '0x1548657'},
                   'limit_compare': {'at': '0x15486ee', 'call_when_count_above': '+0x238',
                                     'callee': hex(ROLL[0]), 'seconds': 600.0, 'result': 'rsp+0xd8',
                                     'overwritten_at': ['0x1548764', '0x1548771'],
                                     'no_read_between': [hex(DEAD[0]), hex(DEAD[1])],
                                     'writer_call': '0x15489bb'},
                   'pins': [hex(p[0]) for p in RECORD_PINS]},
        'rollover_helper': {'fde': [hex(ROLL[0]), hex(ROLL[1])], 'stores': {'0x157103a': 'dword [rdi+0x8]', '0x1571040': 'qword [rdi]'},
                            'bytes_written': 12},
        'record_calls': {'total': len(records), 'by_getter': {hex(g): len(c) for g, c in sorted(census.items())},
                         'count_argument': sorted({r['count'] for r in records}), 'sites': records},
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
    print(f"getters={len(result['getters'])} record_calls={result['record_calls']['total']} "
          f"scan={result['record']['rbx_operand_modrm_bytes']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
