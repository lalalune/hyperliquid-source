#!/usr/bin/env python3
"""Bind the node #115 fast_abci_engine step: snapshot trigger and block-step sampler gate (16th stage).

Continues the output-flag packets. The 15th stage found that the engine value
built by 0x5a6bfb0 holds the box (the 0x4e38 allocation with the output
setter's result at +0x7c0) at +0x450, and that 0x5a08720 tests box+0x28 for a
multiple of 10000. This tool binds:

1. the rest of that test in 0x5a08720: an optional freeze height at box
   +0x1c58 (tag dword, 1 = present) / +0x1c60; a freeze height below box+0x28
   panics with "assertion failed: freeze_height >= self.locus.context.height()"
   at l1/src/exchange/exchange.rs:607:17; the label "freeze" (6 bytes) is
   chosen at the freeze height and "periodic" (8 bytes) otherwise; an engine
   tag dword of 2 returns the None niche; when neither trigger holds, the
   engine tests box+0x28 against the divisor at box+0x4538;
2. the call chain 0x56186c0 -> 0x5a06600 -> 0x5a08720, with call censuses;
3. the five block-step sampler sites (#4718: tags 0-4 to 0x5b2a130): each
   compares object+0x12a0 with 0x8000000000000001 and skips the sampler when
   equal; at the tag-1 site the object is loaded from the engine value +0x450;
4. the output setter (0x51cf360): when its byte +0x18 is clear it stores
   rbp+1 with rbp = 0x8000000000000000 as the first qword of both optional
   values; when set it stores 0 and the f64 15.0.

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
PACKET = ROOT / 'research/work-items/RE-008-fast-abci-engine-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

STEP, DRIVER, WRAPPER, TAG0_FN, SAMPLER = 0x5a08720, 0x5a06600, 0x56186c0, 0x54864a0, 0x5b2a130
FREEZE = (0x93a687, b'freeze')
PERIODIC = (0x458f30, b'periodic')
ASSERTION = (0x929b14, b'assertion failed: freeze_height >= self.locus.context.height()')
EXCHANGE_SOURCE = (0x4318d3, b'l1/src/exchange/exchange.rs')
ASSERT_LOCATION = 0x64aa278
PANIC_SLOT = 0x64df730
SAMPLER_NONE = 0x8000000000000001
FIFTEEN = 15.0
SAMPLER_SITES = {0x5486544: 0, 0x5a067ec: 1, 0x5a06b29: 2, 0x5a06e11: 3, 0x5a0784c: 4}

FIXED = {
    # 0x5a08720: box, height, freeze option, periodic test
    0x5a08737: '488bb650040000',        # mov rsi, [rsi+0x450]          (box)
    0x5a0873e: '4c8b7e28',              # mov r15, [rsi+0x28]           (height)
    0x5a08763: '83be581c000001',        # cmp dword [rsi+0x1c58], 1     (freeze present)
    0x5a0876c: '4c39be601c0000',        # cmp [rsi+0x1c60], r15
    0x5a08773: '0f824a060000',          # jb 0x5a08dc3                  (freeze < height -> panic)
    0x5a08779: '400f94c5',              # sete bpl                      (freeze == height)
    0x5a0877d: '41833e02',              # cmp dword [r14], 2
    0x5a08785: '40b501',                # mov bpl, 1                    (height % 10000 == 0)
    0x5a0878e: '48b80000000000000080',  # movabs rax, 0x8000000000000000
    0x5a08798: '488903',                # mov [rbx], rax                (tag 2 -> None)
    0x5a087a8: '83be581c000001',        # cmp dword [rsi+0x1c58], 1
    0x5a087b1: '4c39be601c0000',        # cmp [rsi+0x1c60], r15
    0x5a087be: '410f94c5',              # sete r13b                     (at freeze height)
    0x5a087e0: '4084ed',                # test bpl, bpl
    0x5a087e5: '488b8e38450000',        # mov rcx, [rsi+0x4538]         (second divisor)
    0x5a087fd: '48f7f1',                # div rcx
    0x5a08800: '4885d2',                # test rdx, rdx
    0x5a08803: '0f85a8030000',          # jne 0x5a08bb1                 (not a multiple -> skip)
    0x5a08853: '4489e8',                # mov eax, r13d
    0x5a08856: '3401',                  # xor al, 1
    0x5a0885b: '488d0c4506000000',      # lea rcx, [rax*2+6]            (len 6 or 8)
    0x5a08871: '4584ed',                # test r13b, r13b
    0x5a08874: '480f45d0',              # cmovne rdx, rax               (freeze label)
    0x5a08dd1: 'be3e000000',            # mov esi, 62                   (assertion length)
    # 0x5a06600: engine value in r15, box reads, tag-1 sampler site
    0x5a06614: '4989f7',                # mov r15, rsi
    0x5a06687: '498b8f50040000',        # mov rcx, [r15+0x450]
    0x5a0668e: '4c8b89581c0000',        # mov r9, [rcx+0x1c58]
    0x5a06695: '4c8b91601c0000',        # mov r10, [rcx+0x1c60]
    0x5a067a0: '498d9f50040000',        # lea rbx, [r15+0x450]
    0x5a067b2: '48b80000000000000080',  # movabs rax, 0x8000000000000000
    0x5a067bc: '488b3b',                # mov rdi, [rbx]                (box)
    0x5a067bf: '48ffc0',                # inc rax                       (0x8000000000000001)
    0x5a067ca: '483987a0120000',        # cmp [rdi+0x12a0], rax
    0x5a067d6: '7419',                  # je 0x5a067f1                  (None -> skip sampler)
    0x5a067d8: '4881c7a0120000',        # add rdi, 0x12a0
    0x5a067e7: 'be01000000',            # mov esi, 1
    0x5a06b15: '4881c7a0120000',
    0x5a06b24: 'be02000000',
    0x5a06dfd: '4881c7a0120000',
    0x5a06e0c: 'be03000000',
    0x5a07838: '4881c7a0120000',
    0x5a07847: 'be04000000',
    0x5a06af1: '4c89f6',                # mov rsi, r14                  (object pointer to tag-0 fn)
    0x5a077de: '4c89fe',                # mov rsi, r15                  (engine value to 0x5a08720)
    # 0x54864a0: tag-0 sampler site
    0x5486520: '498b3e',                # mov rdi, [r14]
    0x5486523: '48b80100000000000080',  # movabs rax, 0x8000000000000001
    0x548652d: '483987a0120000',        # cmp [rdi+0x12a0], rax
    0x5486534: '7413',                  # je 0x5486549
    0x5486536: '4881c7a0120000',        # add rdi, 0x12a0
    0x5486542: '31f6',                  # xor esi, esi                  (tag 0)
    # 0x51cf360 setter: byte +0x18 copy at rsp+0x13 selects Some or None
    0x51cfde6: '48bd0000000000000080',  # movabs rbp, 0x8000000000000000
    0x51d0856: '807c241300',            # cmp byte [rsp+0x13], 0
    0x51d085b: '745f',                  # je 0x51d08bc
    0x51d0874: '48b80000000000002e40',  # movabs rax, 15.0
    0x51d087e: '4889842438020000',      # mov [rsp+0x238], rax
    0x51d08a5: '4889842470020000',      # mov [rsp+0x270], rax
    0x51d08b8: '31c0',                  # xor eax, eax                  (Some)
    0x51d08bc: '488d4501',              # lea rax, [rbp+1]              (None)
    0x51d08c5: '4889842418020000',      # mov [rsp+0x218], rax          (first optional)
    0x51d08cd: '4889842450020000',      # mov [rsp+0x250], rax          (second optional)
}
REFERENCES = (
    (0x5a08863, b'\x48\x8d\x05', 7, FREEZE[0]),
    (0x5a0886a, b'\x48\x8d\x15', 7, PERIODIC[0]),
    (0x5a08dc3, b'\x48\x8d\x3d', 7, ASSERTION[0]),
    (0x5a08dca, b'\x48\x8d\x15', 7, ASSERT_LOCATION),
    (0x5a08dd6, b'\xff\x15', 6, PANIC_SLOT),
    (0x5a08773, b'\x0f\x82', 6, 0x5a08dc3),
    (0x5a087b8, b'\x0f\x82', 6, 0x5a08ddc),
    (0x5618710, b'\xe8', 5, DRIVER),
    (0x5a077e1, b'\xe8', 5, STEP),
    (0x5a06af4, b'\xe8', 5, TAG0_FN),
) + tuple((va, b'\xe8', 5, SAMPLER) for va in SAMPLER_SITES)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


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


def direct_callers(data, target):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    code, base = data[sec['offset']:sec['offset'] + sec['size']], sec['address']
    out = []
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code) and base + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == target:
            out.append(base + i)
    return out


def disp_count(data, lo, hi, disp):
    return read_va(data, lo, hi - lo).count(struct.pack('<I', disp))


FUNCTIONS = {DRIVER: 0x5a07eb6, STEP: 0x5a08f7c, TAG0_FN: 0x548660e}


def bind(data):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, text in (FREEZE, PERIODIC, ASSERTION, EXCHANGE_SOURCE):
        if read_va(data, va, len(text)) != text:
            raise ValueError(f'string at {va:#x} changed')
    if struct.unpack('<d', bytes.fromhex(FIXED[0x51d0874])[2:])[0] != FIFTEEN:
        raise ValueError('15.0 constant changed')
    if struct.unpack('<Q', bytes.fromhex(FIXED[0x5486523])[2:])[0] != SAMPLER_NONE:
        raise ValueError('sampler None niche changed')
    if struct.unpack('<Q', bytes.fromhex(FIXED[0x51cfde6])[2:])[0] + 1 != SAMPLER_NONE:
        raise ValueError('setter None niche changed')

    rel = relative_relocations(data)
    if rel.get(ASSERT_LOCATION) != EXCHANGE_SOURCE[0]:
        raise ValueError('assertion Location file changed')
    length, line, col = struct.unpack('<QII', read_va(data, ASSERT_LOCATION + 8, 16))
    if length != len(EXCHANGE_SOURCE[1]):
        raise ValueError('assertion Location length changed')
    panic = rel.get(PANIC_SLOT)

    callers = {hex(t): [hex(v) for v in direct_callers(data, t)] for t in (STEP, DRIVER, TAG0_FN, SAMPLER)}
    if callers[hex(SAMPLER)] != [hex(v) for v in sorted(SAMPLER_SITES)]:
        raise ValueError('sampler call census changed')
    if callers[hex(DRIVER)] != [hex(0x5618710)] or callers[hex(TAG0_FN)] != [hex(0x5a06af4)]:
        raise ValueError('driver call census changed')
    if callers[hex(STEP)] != [hex(0x5a077e1), hex(0x5a6c16a)]:
        raise ValueError('step call census changed')

    disps = {hex(lo): {'0x12a0': disp_count(data, lo, hi, 0x12a0), '0x12d8': disp_count(data, lo, hi, 0x12d8)}
             for lo, hi in FUNCTIONS.items()}
    if any(v['0x12d8'] for v in disps.values()):
        raise ValueError('a +0x12d8 displacement appeared')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'step_0x5a08720': {
            'box': hex(0x5a08737) + ' engine value +0x450; height = box +0x28',
            'periodic': 'height % 10000 == 0 (#5916)',
            'freeze_option': 'box +0x1c58 dword == 1 present, value box +0x1c60',
            'freeze_below_height_panics': '%s %r at %s:%d:%d (panic slot %s -> %s)'
                                          % (hex(ASSERTION[0]), ASSERTION[1].decode(),
                                             EXCHANGE_SOURCE[1].decode(), line, col,
                                             hex(PANIC_SLOT), hex(panic) if panic else None),
            'label': '%r (%d) at the freeze height, else %r (%d)'
                     % (FREEZE[1].decode(), len(FREEZE[1]), PERIODIC[1].decode(), len(PERIODIC[1])),
            'engine_tag_2': hex(0x5a08798) + ' stores 0x8000000000000000 to the result and returns',
            'no_trigger': 'height % box[+0x4538]; nonzero -> skip to ' + hex(0x5a08bb1),
        },
        'call_chain': [hex(WRAPPER) + ' calls ' + hex(DRIVER) + ' at 0x5618710',
                       hex(DRIVER) + ' calls ' + hex(STEP) + ' at 0x5a077e1 (rsi = r15)'],
        'direct_callers': callers,
        'sampler_sites': {hex(v): t for v, t in sorted(SAMPLER_SITES.items())},
        'sampler_gate': 'object +0x12a0 == %s -> skip; else 0x5b2a130(object+0x12a0, tag, checkpoint)'
                        % hex(SAMPLER_NONE),
        'tag1_object': '%s mov r15, rsi; %s lea rbx, [r15+0x450]; %s mov rdi, [rbx]'
                       % (hex(0x5a06614), hex(0x5a067a0), hex(0x5a067bc)),
        'displacement_counts': disps,
        'setter_optionals': {
            'test': hex(0x51d0856) + ' byte [rsp+0x13] (setter +0x18)',
            'some': 'first qword 0, f64 %s at +0x20 of each' % FIFTEEN,
            'none': 'first qword rbp+1 = %s' % hex(SAMPLER_NONE),
            'stores': [hex(0x51d08c5) + ' rsp+0x218', hex(0x51d08cd) + ' rsp+0x250'],
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
    print(f"sampler_sites={len(result['sampler_sites'])} step_callers={len(result['direct_callers'][hex(STEP)])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
