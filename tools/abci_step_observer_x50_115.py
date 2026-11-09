#!/usr/bin/env python3
"""Bind who sets and who reads the node #115 shared value observer's x50 flag (third stage).

Continues the observer packets for 0x1547530 (slot 0x64e1010) and its
constructor 0x1548bb0 (slot 0x64e1020). This tool binds three things:

1. the two byte stores to +0x25c that follow indirect calls (0x47832e9,
   0x47849a8): both write 0, inside the FnOnce/Fn methods of one boxed
   closure type whose vtable is 0x6497668; the closure calls an inner boxed
   factory through its vtable slot +0x28 and then clears the flag;
2. the five constructor call sites that write +0x25c = 1: the observer name
   each one formats first (template 0x44c834 "profiled_mutex/..." at four
   sites, template 0x432e2d "profiled_rw_lock/..." at one);
3. every byte read of +0x25c in .text: two, both in the observer (the x50
   checked multiply and a copy into a stack record).

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-x50-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

FLAG = 0x25c

OBSERVER = 0x1547530
OBSERVER_END = 0x1548ba3
CTOR = 0x1548bb0
CTOR_SLOT = 0x64e1020
CTOR_FLAG_STORE = 0x1548e0a          # constructor writes +0x25c = 0

# Part 1: the flag-clearing closure.
VTABLE = 0x6497668
DROP = 0x47837f0
CALL_ONCE = 0x47832b0
CALL_ONCE_END = 0x4783383
CALL = 0x4784980                      # both call_mut (+0x20) and call (+0x28)
CALL_END = 0x47849b8
BUILDER = 0x4784750
BUILDER_END = 0x4784978
BUILDER_SLOT = 0x64eb1c0
BUILDER_CALLER = 0x567bbac
BUILDER_CALLER_FRAME = (0x567bb70, 0x567bc40)
VTABLE_LEA = 0x4784830

CLOSURE_FIXED = {
    0x47832b9: '4989fe',              # mov r14, rdi            (output, kept)
    0x47832bc: '488b1e',              # mov rbx, [rsi]          (inner data)
    0x47832bf: '4c8b7e08',            # mov r15, [rsi+8]        (inner vtable)
    0x47832e2: '4889de',              # mov rsi, rbx
    0x47832e5: '41ff5728',            # call [r15+0x28]         (inner Fn::call)
    0x47832e9: '41c6865c02000000',    # mov byte [r14+0x25c], 0
    0x47832f1: '498b07',              # mov rax, [r15]          (inner drop)
    0x4784985: '4889fb',              # mov rbx, rdi            (output, kept)
    0x4784998: '488b06',              # mov rax, [rsi]          (inner data)
    0x478499b: '488b4e08',            # mov rcx, [rsi+8]        (inner vtable)
    0x47849a2: '4889c6',              # mov rsi, rax
    0x47849a5: 'ff5128',              # call [rcx+0x28]         (inner Fn::call)
    0x47849a8: 'c6835c02000000',      # mov byte [rbx+0x25c], 0
    0x47849af: '4889d8',              # mov rax, rbx
    0x47849b7: 'c3',
}

BUILDER_FIXED = {
    0x4784761: '4889f3',              # mov rbx, rsi            (input)
    0x4784764: '4989fe',              # mov r14, rdi            (output)
    0x4784798: '4c8b23',              # mov r12, [rbx]          (inner data)
    0x478479b: '4c8b6b08',            # mov r13, [rbx+8]        (inner vtable)
    0x47847d3: 'bf10000000',          # mov edi, 0x10           (box of 16 bytes)
    0x47847ea: '4c8920',              # [box] = inner data
    0x47847ed: '4c896808',            # [box+8] = inner vtable
    0x478482d: '4d893e',              # [out] = box
    0x4784837: '49894608',            # [out+8] = vtable 0x6497668
}

# Part 2: the five flag setters. (template lea, format call, ctor call, xmm0 load or None,
# flag store, name pointer move, template)
FORMAT_SLOT = 0x64df6e8
FORMAT = 0x141e3a0
ONE = 0x4592b0                        # f64 1.0
MUTEX_TEMPLATE = 0x44c834
RW_LOCK_TEMPLATE = 0x432e2d
TEMPLATES = {
    MUTEX_TEMPLATE: bytes.fromhex('0f') + b'profiled_mutex/' + bytes.fromhex('c009')
                    + b'/compute/' + bytes.fromhex('c000'),
    RW_LOCK_TEMPLATE: bytes.fromhex('11') + b'profiled_rw_lock/' + bytes.fromhex('c001')
                      + b'/' + bytes.fromhex('c000'),
}
SETTERS = (
    (0x16eee7c, 0x16eee8b, 0x16eeeaf, 0x16eee9f, 0x16eeeca, 0x16eeeac, MUTEX_TEMPLATE),
    (0x250342c, 0x250343b, 0x250345f, 0x250344f, 0x250347a, 0x250345c, MUTEX_TEMPLATE),
    (0x477168c, 0x477169b, 0x47716bf, 0x47716af, 0x47716da, 0x47716bc, MUTEX_TEMPLATE),
    (0x47728d4, 0x47728e8, 0x4772914, None, 0x477292d, 0x4772911, RW_LOCK_TEMPLATE),
    (0x5ab252c, 0x5ab253b, 0x5ab255f, 0x5ab254f, 0x5ab257a, 0x5ab255c, MUTEX_TEMPLATE),
)
ESI_ZERO = {
    0x16eeeca: 0x16eeeaa,
    0x250347a: 0x250345a,
    0x47716da: 0x47716ba,
    0x477292d: 0x4772909,
    0x5ab257a: 0x5ab255a,
}
SETTER_FRAMES = {
    0x16eeeca: (0x16eee50, 0x16eef3f),
    0x250347a: (0x2503400, 0x25034ef),
    0x47716da: (0x4771660, 0x477174f),
    0x477292d: (0x4772530, 0x47729e3),
    0x5ab257a: (0x5ab2500, 0x5ab25ef),
}

# Part 3: the two flag reads.
READ_MULTIPLY = 0x15475b1
READ_RECORD = 0x15486e6
SATURATE = 0x1548a0b
AFTER_MULTIPLY = 0x15475dc
RECORD_SINK_SLOT = 0x64e0f80
RECORD_SINK = 0x1546570
READ_FIXED = {
    0x15475b1: '80bb5c02000001',      # cmp byte [rbx+0x25c], 1
    0x15475b8: '751c',                # jne 0x15475d6           (flag 0: no multiply)
    0x15475ba: 'b932000000',          # mov ecx, 50
    0x15475bf: '4c89f0',              # mov rax, r14            (u64 sample weight)
    0x15475c2: '48f7e1',              # mul rcx
    0x15475d1: '4989c6',              # mov r14, rax
    0x1548a0b: '49c7c6ffffffff',      # mov r14, -1             (u64::MAX on overflow)
    0x15486e6: '440fb6bb5c020000',    # movzx r15d, byte [rbx+0x25c]
    0x1548873: '4488bc247c010000',    # mov [rsp+0x17c], r15b
    0x1548894: '488db398000000',      # lea rsi, [rbx+0x98]
    0x15488a0: '4889e2',              # mov rdx, rsp            (record)
}
READ_REFERENCES = (
    (0x15475cb, b'\x0f\x80', 6, SATURATE),          # jo SATURATE
    (0x1548a12, b'\xe9', 5, AFTER_MULTIPLY),
    (0x15488a3, b'\xff\x15', 6, RECORD_SINK_SLOT),
)
# Instructions between the second read and the record store do not write r15.
R15_LIVE = (0x15486ee, 0x1548873)


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


def relocations(data):
    rows = []
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        rows.extend(struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]))
    return rows


def frame(fdes, va):
    rows = [(f['start'], f['end']) for f in fdes if f['start'] <= va < f['end']]
    if len(rows) != 1:
        raise ValueError(f'expected one FDE at {va:#x}')
    return rows[0]


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def rel_census(data, target, slot):
    """E8/E9 rel32 to `target`; FF15/FF25 through `slot`; 7-byte rip-relative LEA to `target`."""
    base, raw = text(data)
    direct, through_slot, lea = [], [], []
    for opcode, width, dest, out in ((b'\xe8', 5, target, direct), (b'\xe9', 5, target, direct),
                                     (b'\xff\x15', 6, slot, through_slot),
                                     (b'\xff\x25', 6, slot, through_slot)):
        start = 0
        while True:
            index = raw.find(opcode, start)
            if index < 0 or index + width > len(raw):
                break
            start = index + 1
            if base + index + width + struct.unpack_from('<i', raw, index + len(opcode))[0] == dest:
                out.append(base + index)
    for rex in (0x48, 0x4c):
        start = 0
        while True:
            index = raw.find(bytes([rex, 0x8d]), start)
            if index < 0 or index + 7 > len(raw):
                break
            start = index + 1
            modrm = raw[index + 2]
            if modrm & 0xc7 != 0x05:
                continue
            if base + index + 7 + struct.unpack_from('<i', raw, index + 3)[0] == target:
                lea.append(base + index)
    return sorted(direct), sorted(through_slot), sorted(lea)


def flag_accesses(data):
    """Byte accesses with mod=10 and disp32 0x25c in .text, optional REX.

    Stores: C6 /0 (imm8) and 88 (r8). Reads: 80 /7 (cmp imm8), 0F B6 (movzx),
    F6 /0 (test imm8), 8A (mov r8), 38/3A (cmp r8), 84 (test r8).
    """
    base, raw = text(data)
    pattern = struct.pack('<I', FLAG)
    stores, reads = set(), set()
    start = 0
    while True:
        index = raw.find(pattern, start)
        if index < 0:
            break
        start = index + 1
        if index < 3:
            continue
        modrm = raw[index - 1]
        if modrm >> 6 != 2 or modrm & 7 == 4:
            continue
        reg = (modrm >> 3) & 7
        op = raw[index - 2]
        if raw[index - 3:index - 1] == b'\x0f\xb6':
            begin, kind = index - 3, reads
        elif op == 0xc6 and reg == 0 or op == 0x88:
            begin, kind = index - 2, stores
        elif op == 0x80 and reg == 7 or op == 0xf6 and reg == 0 or op in (0x8a, 0x38, 0x3a, 0x84):
            begin, kind = index - 2, reads
        else:
            continue
        if begin and raw[begin - 1] in (0x40, 0x41, 0x44, 0x45):
            begin -= 1
        kind.add(base + begin)
    return sorted(stores), sorted(reads)


def writes_r15(raw):
    """Conservative scan: any REX.B/REX.R prefixed register-direct write whose target is r15."""
    hits = []
    for i in range(len(raw) - 2):
        rex, op, modrm = raw[i], raw[i + 1], raw[i + 2]
        if rex & 0xf0 != 0x40:
            continue
        # mov/movzx/xor/add/sub/lea/pop with r15 as destination
        if rex & 0x1 and op in (0x89, 0x31, 0x01, 0x29, 0xc7, 0x8f) and modrm >> 6 == 3 and modrm & 7 == 7:
            hits.append(i)
        if rex & 0x4 and op in (0x8b, 0x8d, 0x33, 0x03, 0x2b) and (modrm >> 3) & 7 == 7:
            hits.append(i)
        if rex & 0x1 and op == 0x5f:
            hits.append(i)
    return hits


def bind(data, fdes):
    relocs = relocations(data)
    reloc_at = {va: addend for va, info, addend in relocs if info & 0xffffffff == 8}

    # Part 1: vtable layout and the closure methods.
    _, raw_vtable = read_va(data, VTABLE, 48)
    size, align = struct.unpack_from('<QQ', raw_vtable, 8)
    slots = {VTABLE: DROP, VTABLE + 0x18: CALL_ONCE, VTABLE + 0x20: CALL, VTABLE + 0x28: CALL}
    for va, target in slots.items():
        if reloc_at.get(va) != target:
            raise ValueError(f'vtable slot {va:#x} changed')
    if (size, align) != (0x10, 8):
        raise ValueError('closure size or alignment changed')
    if frame(fdes, CALL_ONCE) != (CALL_ONCE, CALL_ONCE_END) or frame(fdes, CALL) != (CALL, CALL_END):
        raise ValueError('closure method FDE changed')
    if frame(fdes, BUILDER) != (BUILDER, BUILDER_END):
        raise ValueError('builder FDE changed')
    for va, expect in {**CLOSURE_FIXED, **BUILDER_FIXED}.items():
        fixed(data, va, expect)
    vt_direct, _, vt_lea = rel_census(data, VTABLE, 0)
    vt_relocs = [va for va, addend in reloc_at.items() if addend == VTABLE]
    if vt_lea != [VTABLE_LEA] or vt_direct or vt_relocs:
        raise ValueError('vtable reference census changed')
    b_direct, b_slot, _ = rel_census(data, BUILDER, BUILDER_SLOT)
    b_relocs = sorted(va for va, addend in reloc_at.items() if addend == BUILDER)
    if b_direct or b_slot != [BUILDER_CALLER] or b_relocs != [BUILDER_SLOT]:
        raise ValueError('builder reference census changed')
    if frame(fdes, BUILDER_CALLER) != BUILDER_CALLER_FRAME:
        raise ValueError('builder caller FDE changed')

    # Part 2: the five setters and their observer names.
    if reloc_at.get(FORMAT_SLOT) != FORMAT or reloc_at.get(CTOR_SLOT) != CTOR:
        raise ValueError('format or constructor slot changed')
    one = struct.unpack('<d', read_va(data, ONE, 8)[1])[0]
    if one != 1.0:
        raise ValueError('f64 1.0 constant changed')
    templates = {}
    for va, expect in TEMPLATES.items():
        got = read_va(data, va, len(expect))[1]
        if got != expect:
            raise ValueError(f'template at {va:#x} changed')
        templates[va] = got
    setters = []
    for lea_va, fmt_va, call_va, xmm_va, store_va, rdx_va, template in SETTERS:
        if rip_target(data, lea_va, b'\x48\x8d\x35', 7) != template:
            raise ValueError(f'template lea at {lea_va:#x} changed')
        if rip_target(data, fmt_va, b'\xff\x15', 6) != FORMAT_SLOT:
            raise ValueError(f'format call at {fmt_va:#x} changed')
        if rip_target(data, call_va, b'\xff\x15', 6) != CTOR_SLOT:
            raise ValueError(f'constructor call at {call_va:#x} changed')
        fixed(data, rdx_va, '4c89e2')               # mov rdx, r12 (formatted name pointer)
        fixed(data, ESI_ZERO[store_va], '31f6')     # xor esi, esi (byte stored at +0x25d)
        if xmm_va is not None and rip_target(data, xmm_va, b'\xf2\x0f\x10\x05', 8) != ONE:
            raise ValueError(f'xmm0 load at {xmm_va:#x} changed')
        if frame(fdes, store_va) != SETTER_FRAMES[store_va]:
            raise ValueError(f'setter FDE at {store_va:#x} changed')
        start, end = SETTER_FRAMES[store_va]
        setters.append({
            'function': {'start_va': hex(start), 'end_va': hex(end)},
            'template_lea_va': hex(lea_va), 'template_va': hex(template),
            'name_inferred': 'profiled_mutex/{}/compute/{}' if template == MUTEX_TEMPLATE
                    else 'profiled_rw_lock/{}/{}',
            'format_call_va': hex(fmt_va), 'constructor_call_va': hex(call_va),
            'xmm0': 1.0 if xmm_va is not None else 'f64 from [rsp+0x58]',
            'esi': 0, 'flag_store_va': hex(store_va),
        })

    # Part 3: every byte access to +0x25c in .text.
    stores, reads = flag_accesses(data)
    expected_stores = sorted([CTOR_FLAG_STORE] + [s[4] for s in SETTERS] + [0x47832e9, 0x47849a8])
    if stores != expected_stores:
        raise ValueError('byte-store census of +0x25c changed')
    if reads != [READ_MULTIPLY, READ_RECORD]:
        raise ValueError('byte-read census of +0x25c changed')
    if not all(frame(fdes, va) == (OBSERVER, OBSERVER_END) for va in reads):
        raise ValueError('a flag read left the observer')
    for va, expect in READ_FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, expect in READ_REFERENCES:
        if rip_target(data, va, prefix, length) != expect:
            raise ValueError(f'reference at {va:#x} changed')
    if reloc_at.get(RECORD_SINK_SLOT) != RECORD_SINK:
        raise ValueError('record sink slot changed')
    _, live = read_va(data, R15_LIVE[0], R15_LIVE[1] - R15_LIVE[0])
    if writes_r15(live):
        raise ValueError('r15 is written between the flag read and the record store')

    _, closure_bytes = read_va(data, CALL_ONCE, CALL_ONCE_END - CALL_ONCE)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'flag_clearing_closure': {
            'vtable_va': hex(VTABLE),
            'vtable': {'drop': hex(DROP), 'size': size, 'align': align,
                       'call_once': hex(CALL_ONCE), 'call_mut': hex(CALL), 'call': hex(CALL)},
            'call_once': {'fde': [hex(CALL_ONCE), hex(CALL_ONCE_END)],
                          'sha256': hashlib.sha256(closure_bytes).hexdigest(),
                          'inner_call_va': '0x47832e5', 'flag_store_va': '0x47832e9',
                          'then': 'drops the inner box through its vtable'},
            'call': {'fde': [hex(CALL), hex(CALL_END)],
                     'inner_call_va': '0x47849a5', 'flag_store_va': '0x47849a8'},
            'inner': 'closure state is (data, vtable) of a boxed factory; both methods call '
                     'the factory vtable slot +0x28 with the output pointer in rdi, then '
                     'write 0 to output +0x25c',
            'builder': {'fde': [hex(BUILDER), hex(BUILDER_END)], 'vtable_lea_va': hex(VTABLE_LEA),
                        'boxes': 'input +0x0/+0x8 into a new 16-byte box stored at output +0x0, '
                                 'vtable at output +0x8',
                        'slot': hex(BUILDER_SLOT), 'slot_calls': [hex(BUILDER_CALLER)],
                        'caller_fde': [hex(v) for v in BUILDER_CALLER_FRAME],
                        'direct_calls': 0},
            'vtable_references': {'lea': [hex(v) for v in vt_lea], 'relocations': 0, 'direct': 0},
        },
        'flag_setters': {
            'format_slot': {'va': hex(FORMAT_SLOT), 'target': hex(FORMAT)},
            'templates': {hex(va): raw.hex() for va, raw in templates.items()},
            'sites': setters,
        },
        'flag_reads': {
            'census': [hex(v) for v in reads],
            'multiply': {'va': hex(READ_MULTIPLY), 'factor': 50,
                         'overflow': 'jo to %s sets the weight to u64::MAX' % hex(SATURATE)},
            'record': {'read_va': hex(READ_RECORD), 'store_va': '0x1548873',
                       'record_offset': '0x17c', 'sink_call_va': '0x15488a3',
                       'sink_slot': hex(RECORD_SINK_SLOT), 'sink': hex(RECORD_SINK),
                       'sink_arguments': {'rsi': 'state +0x98', 'rdx': 'record at rsp'}},
        },
        'flag_stores': {
            'census': [hex(v) for v in stores],
            'value_0': [hex(CTOR_FLAG_STORE), '0x47832e9', '0x47849a8'],
            'value_1': [hex(s[4]) for s in SETTERS],
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
    print(f"stores={len(result['flag_stores']['census'])} reads={len(result['flag_reads']['census'])} "
          f"setters={len(result['flag_setters']['sites'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
