#!/usr/bin/env python3
"""Bind the node #115 block-step timer specialization and the five sites that call it.

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
PACKET = ROOT / 'research/work-items/RE-008-abci-step-timer-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Recorder: second specialization of node/src/group_and_seq_sampler.rs:169:10.
RECORDER = 0x5b2a130
RECORDER_END = 0x5b2aa61
WINDOW_END = 0x5b2a252  # the instruction after the slot call at 0x5b2a24c

NOW = 0x5c842e0
NOW_END = 0x5c843a9
SUB = 0x5c84210
SUB_END = 0x5c842d6
CLOCK_SLOT = 0x64e1248
KEYED = 0x4dc50c0
HOST = 0x4da7e20
LOCATION = 0x64bca88
LOCATION_PATH = 0x431e32
SINK_SLOT = 0x64e1010
SINK = 0x1547530
U64_HI = 0x451210
U64_BIAS = 0x450170
NANOS = 0x458d50
INFINITY = 0x459010

# (va, opcode prefix, instruction length, expected target)
REFERENCES = (
    (0x5b2a155, b'\xe8', 5, NOW),
    (0x5b2a18e, b'\xe8', 5, SUB),
    (0x5b2a1b1, b'\x0f\x14\x0d', 7, U64_HI),
    (0x5b2a1b8, b'\x66\x0f\x5c\x0d', 8, U64_BIAS),
    (0x5b2a1cc, b'\xf2\x0f\x5e\x05', 8, NANOS),
    (0x5b2a1d8, b'\x66\x0f\x2e\x05', 8, INFINITY),
    (0x5b2a1f1, b'\xe8', 5, NOW),
    (0x5b2a21a, b'\xe8', 5, KEYED),
    (0x5b2a232, b'\xe8', 5, HOST),
    (0x5b2a237, b'\x48\x8d\x15', 7, LOCATION),
    (0x5b2a24c, b'\xff\x15', 6, SINK_SLOT),
)

# Exact non-reference instructions this packet reads.
FIXED = {
    0x5b2a141: '4989d6',            # mov r14, rdx   (checkpoint pointer)
    0x5b2a144: '89f5',              # mov ebp, esi   (tag)
    0x5b2a146: '4889fb',            # mov rbx, rdi   (state)
    0x5b2a150: 'bf01000000',        # mov edi, 1     (first clock id)
    0x5b2a193: '807c240800',        # cmp byte [rsp+8], 0
    0x5b2a198: '660f57db',          # xorpd xmm3, xmm3
    0x5b2a1a0: '7536',              # jne 0x5b2a1d8  (non-zero tag keeps 0.0)
    0x5b2a1a2: 'f20f104c2410',      # movsd xmm1, [rsp+0x10]  (seconds)
    0x5b2a1ab: 'f20f2a442418',      # cvtsi2sd xmm0, dword [rsp+0x18]  (nanoseconds)
    0x5b2a1e0: '7404',              # je 0x5b2a1e6   (equal to +inf keeps 0.0)
    0x5b2a1e2: '660f28d8',          # movapd xmm3, xmm0
    0x5b2a1e6: 'f20f115c2470',      # movsd [rsp+0x70], xmm3
    0x5b2a1ec: 'bf01000000',        # mov edi, 1     (second clock id)
    0x5b2a1f6: '498906',            # mov [r14], rax
    0x5b2a1f9: '41895608',          # mov [r14+8], edx
    0x5b2a1fd: '4088ac24e0000000',  # mov [rsp+0xe0], bpl
    0x5b2a212: '4c89f7',            # mov rdi, r14 (r14 = rsp+8 here)
    0x5b2a215: '4889de',            # mov rsi, rbx
    0x5b2a218: '89ea',              # mov edx, ebp
    0x5b2a21f: '488db424e0000000',  # lea rsi, [rsp+0xe0]  (tag byte for the host)
    0x5b2a23e: 'be01000000',        # mov esi, 1
    0x5b2a243: '4889c7',            # mov rdi, rax  (host result)
    0x5b2a246: 'f20f10442470',      # movsd xmm0, [rsp+0x70]
}

SUB_ORDERED = {
    0x5c8427e: '48894b08',        # mov [rbx+8], rcx
    0x5c84282: '894310',          # mov [rbx+0x10], eax
    0x5c84285: '48c70300000000',  # mov qword [rbx], 0
}

# The host reads the tag through rsi: movzx eax, byte [rsi] at 0x4da7e67.
HOST_TAG_LOAD = (0x4da7e67, '0fb606')

# The five direct call sites, in address order.
SITES = (
    {'site': 0x5486544, 'fde': (0x54864a0, 0x548660e), 'tag_insn': (0x5486542, '31f6'),
     'checkpoint_lea': (0x548653d, '488d542460'), 'tag': 0},
    {'site': 0x5a067ec, 'fde': (0x5a06600, 0x5a07eb6), 'tag_insn': (0x5a067e7, 'be01000000'),
     'checkpoint_lea': (0x5a067df, '488d9424b8010000'), 'tag': 1},
    {'site': 0x5a06b29, 'fde': (0x5a06600, 0x5a07eb6), 'tag_insn': (0x5a06b24, 'be02000000'),
     'checkpoint_lea': (0x5a06b1c, '488d9424b8010000'), 'tag': 2},
    {'site': 0x5a06e11, 'fde': (0x5a06600, 0x5a07eb6), 'tag_insn': (0x5a06e0c, 'be03000000'),
     'checkpoint_lea': (0x5a06e04, '488d9424b8010000'), 'tag': 3},
    {'site': 0x5a0784c, 'fde': (0x5a06600, 0x5a07eb6), 'tag_insn': (0x5a07847, 'be04000000'),
     'checkpoint_lea': (0x5a0783f, '488d9424b8010000'), 'tag': 4},
)
# Each site: add rdi, 0x12a0 right before the checkpoint lea; a cmp with 0x8000000000000001 guards it.
ADD_RDI = '4881c7a0120000'
GUARDS = {
    0x5486544: (0x548652d, '483987a0120000', 0x5486523, '48b80100000000000080'),
    0x5a067ec: (0x5a067ca, '483987a0120000', 0x5a067b2, '48b80000000000000080'),
    0x5a06b29: (0x5a06b04, '483987a0120000', None, None),
    0x5a06e11: (0x5a06df4, '483987a0120000', None, None),
    0x5a0784c: (0x5a0782f, '483987a0120000', None, None),
}
# Checkpoint creation in each caller: mov edi,1; call NOW; store rax/edx.
CHECKPOINTS = (
    {'fde': 0x54864a0, 'call': 0x54864ba, 'stores': (0x54864bf, '4889442460', 0x54864c4, '89542468')},
    {'fde': 0x5a06600, 'call': 0x5a06624, 'stores': (0x5a06629, '48898424b8010000', 0x5a06631, '899424c0010000')},
)


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


def relocations(data):
    rows = []
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        rows.extend(struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]))
    return rows


def dynamic_symbol(data, index):
    by_name = {s['name']: s for s in sections(data)}
    sym, strtab = by_name['.dynsym'], by_name['.dynstr']
    name_off = struct.unpack_from('<I', data, sym['offset'] + 24 * index)[0]
    raw = data[strtab['offset'] + name_off:strtab['offset'] + strtab['size']]
    return raw[:raw.index(b'\0')].decode('ascii')


def direct_branches(data, target):
    """E8/E9 rel32 instructions in .text whose target is `target`."""
    text = next(s for s in sections(data) if s['name'] == '.text')
    raw = data[text['offset']:text['offset'] + text['size']]
    hits = []
    for opcode in (b'\xe8', b'\xe9'):
        start = 0
        while True:
            index = raw.find(opcode, start)
            if index < 0 or index + 5 > len(raw):
                break
            start = index + 1
            site = text['address'] + index
            if site + 5 + struct.unpack_from('<i', raw, index + 1)[0] == target:
                hits.append((site, opcode.hex()))
    return sorted(hits)


def f64(data, va):
    return struct.unpack('<d', read_va(data, va, 8)[1])[0]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2)[1] != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def frame(fdes, va):
    rows = [(f['start'], f['end']) for f in fdes if f['start'] <= va < f['end']]
    if len(rows) != 1:
        raise ValueError(f'expected one FDE at {va:#x}')
    return rows[0]


def bind_recorder(data, fdes):
    if frame(fdes, RECORDER) != (RECORDER, RECORDER_END):
        raise ValueError('recorder FDE changed')
    for va, prefix, length, expect in REFERENCES:
        if rip_target(data, va, prefix, length) != expect:
            raise ValueError(f'reference at {va:#x} changed')
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    if frame(fdes, NOW) != (NOW, NOW_END) or frame(fdes, SUB) != (SUB, SUB_END):
        raise ValueError('clock helper FDE changed')
    # Difference helper, ordered path: seconds at +8, nanoseconds at +0x10, result byte 0 at +0.
    for va, expect in SUB_ORDERED.items():
        fixed(data, va, expect)
    if rip_target(data, NOW + 0xd, b'\xff\x15', 6) != CLOCK_SLOT:
        raise ValueError('clock call slot changed')
    relocs = relocations(data)
    clock = [(info, addend) for slot, info, addend in relocs if slot == CLOCK_SLOT]
    if len(clock) != 1 or clock[0][0] & 0xffffffff != 6 or clock[0][1] != 0:
        raise ValueError('clock relocation changed')
    clock_name = dynamic_symbol(data, clock[0][0] >> 32)
    if clock_name != 'clock_gettime':
        raise ValueError('clock import changed')
    sink = [(info, addend) for slot, info, addend in relocs if slot == SINK_SLOT]
    if sink != [(8, SINK)]:
        raise ValueError('sink relocation changed')
    location = [(info, addend) for slot, info, addend in relocs if slot == LOCATION]
    if location != [(8, LOCATION_PATH)]:
        raise ValueError('location relocation changed')
    _, loc = read_va(data, LOCATION, 24)
    length, line, column = struct.unpack_from('<QII', loc, 8)
    path = read_va(data, LOCATION_PATH, length)[1]
    if (path, length, line, column) != (b'node/src/group_and_seq_sampler.rs', 33, 169, 10):
        raise ValueError('location record changed')
    fixed(data, *HOST_TAG_LOAD)
    if (f64(data, NANOS), repr(f64(data, INFINITY))) != (1e9, 'inf'):
        raise ValueError('conversion constants changed')
    _, window = read_va(data, RECORDER, WINDOW_END - RECORDER)
    return {
        'fde': {'start_va': hex(RECORDER), 'end_va': hex(RECORDER_END)},
        'window': {'start_va': hex(RECORDER), 'end_va': hex(WINDOW_END),
                   'bytes': len(window), 'sha256': hashlib.sha256(window).hexdigest()},
        'entry': {'rdi': 'state (saved in rbx)', 'esi': 'tag (saved in ebp)',
                  'rdx': 'checkpoint pointer (saved in r14): qword +0, dword +8'},
        'clock': {'helper_va': hex(NOW), 'edi': 1, 'slot_va': hex(CLOCK_SLOT), 'import': clock_name,
                  'calls': ['0x5b2a155', '0x5b2a1f1']},
        'difference': {'helper_va': hex(SUB), 'call_va': '0x5b2a18e',
                       'nonzero_result_byte': 'keeps 0.0',
                       'value': 'qword [rsp+0x10] as unsigned f64 + dword [rsp+0x18] / 1e9',
                       'u64_conversion_constants_va': [hex(U64_HI), hex(U64_BIAS)],
                       'nanos_divisor': f64(data, NANOS),
                       'equal_to_or_unordered_with_inf': 'keeps 0.0',
                       'stored_at': 'rsp+0x70'},
        'checkpoint_reset': {'call_va': '0x5b2a1f1', 'stores': ['0x5b2a1f6 qword +0', '0x5b2a1f9 dword +8']},
        'keyed_call': {'va': '0x5b2a21a', 'target_va': hex(KEYED),
                       'args': 'rdi=rsp+8, rsi=state, edx=tag'},
        'host_call': {'va': '0x5b2a232', 'target_va': hex(HOST),
                      'args': 'rdi=rsp+8, rsi=&tag byte at rsp+0xe0, rdx=rsp+0x98',
                      'host_tag_load': {'va': hex(HOST_TAG_LOAD[0]), 'bytes': HOST_TAG_LOAD[1]}},
        'sink_call': {'va': '0x5b2a24c', 'slot_va': hex(SINK_SLOT), 'target_va': hex(SINK),
                      'args': 'rdi=host result, esi=1, rdx=Location, xmm0=value at rsp+0x70'},
        'location': {'va': hex(LOCATION), 'path_va': hex(LOCATION_PATH),
                     'path': path.decode('ascii'), 'line': line, 'column': column},
    }


def bind_sites(data, fdes):
    recorder_calls = direct_branches(data, RECORDER)
    if recorder_calls != [(s['site'], 'e8') for s in SITES]:
        raise ValueError('recorder call census changed')
    if direct_branches(data, HOST) != [(0x5b2a232, 'e8')]:
        raise ValueError('host call census changed')
    relocs = relocations(data)
    if any(addend in (RECORDER, HOST) for _, info, addend in relocs if info & 0xffffffff == 8):
        raise ValueError('a relocation now names the recorder or the host')
    rows = []
    for row in SITES:
        if frame(fdes, row['site']) != row['fde']:
            raise ValueError(f"site {row['site']:#x} FDE changed")
        fixed(data, *row['tag_insn'])
        fixed(data, *row['checkpoint_lea'])
        tag_va, tag_hex = row['tag_insn']
        tag = 0 if tag_hex == '31f6' else struct.unpack('<I', bytes.fromhex(tag_hex)[1:])[0]
        if tag != row['tag'] or tag_va + len(tag_hex) // 2 != row['site']:
            raise ValueError(f"site {row['site']:#x} tag changed")
        lea_va, lea_hex = row['checkpoint_lea']
        fixed(data, lea_va - 7, ADD_RDI)
        cmp_va, cmp_hex, const_va, const_hex = GUARDS[row['site']]
        fixed(data, cmp_va, cmp_hex)
        if const_va is not None:
            fixed(data, const_va, const_hex)
        rows.append({'site_va': hex(row['site']), 'fde': [hex(v) for v in row['fde']], 'tag': tag,
                     'tag_insn_va': hex(tag_va), 'checkpoint_lea_va': hex(lea_va),
                     'state_offset': '0x12a0', 'guard_cmp_va': hex(cmp_va)})
    # The tag-0 guard compares with an inline imm64; the block FDE builds 0x8000000000000000 + 1 once
    # (mov rax, imm64; inc rax at 0x5a067bf) and reuses it from [rsp+0x118].
    fixed(data, 0x5a067bf, '48ffc0')
    fixed(data, 0x5a067c2, '48898424' + '18010000')
    for va in (0x5a06afc, 0x5a06dec, 0x5a07827):
        fixed(data, va, '488b842418010000')
    checkpoints = []
    for row in CHECKPOINTS:
        call = row['call']
        fixed(data, call - 5, 'bf01000000')
        if rip_target(data, call, b'\xe8', 5) != NOW:
            raise ValueError(f'checkpoint call {call:#x} changed')
        a, ah, b, bh = row['stores']
        fixed(data, a, ah)
        fixed(data, b, bh)
        checkpoints.append({'fde_start_va': hex(row['fde']), 'clock_call_va': hex(call),
                            'store_vas': [hex(a), hex(b)]})
    return rows, checkpoints


def bind(data, fdes):
    recorder = bind_recorder(data, fdes)
    sites, checkpoints = bind_sites(data, fdes)
    tags = sorted(row['tag'] for row in sites)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'recorder': recorder,
        'sites': sites,
        'checkpoints': checkpoints,
        'census': {
            'recorder_direct_calls': len(sites),
            'recorder_relative_relocations': 0,
            'host_direct_calls': 1,
            'host_relative_relocations': 0,
            'encodings': 'E8/E9 rel32 in .text; R_X86_64_RELATIVE addends',
            'tags_passed': tags,
            'tag_5_passed': 5 in tags,
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
    print(f"{result['recorder']['fde']['start_va']} sites={len(result['sites'])} tags={result['census']['tags_passed']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
