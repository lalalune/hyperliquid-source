#!/usr/bin/env python3
"""Bind the node #115 ExchangeMisc pmc update in begin_block A and the tce range check (stage 94).

Continues #6103 (ExchangeMisc readers). This tool binds:

1. begin_block A 0x54b66b0 copies a 12-byte date-time from [[rsp+0x2e8]+0x8]
   to rsp+0x1b8, then to rsp+0x430 (the pmc candidate);
2. pmc (box +0x39f0) is reset to the unset value 0xf6401a / 0 when box
   +0x4270 == 0 or box +0x710 == 0;
3. otherwise a loop stores a 20-byte cursor at box +0x42b1 and sets box
   +0x42b0 = 1; the cursor seen at entry is saved at rsp+0x310;
4. when pmc is set, pmc + 600.0 s is computed with the #5861 helpers
   (seconds 0x15ed960, time add 0x162a9a0, date add 0x16290d0) and the date-add
   result is not stored: eax is overwritten by the next instruction;
5. when +0x42b0 bit 0 is set and memcmp(box+0x42b1, saved cursor, 20) <= 0, the
   candidate date-time at rsp+0x430 is written to pmc;
6. tce handler 0x57c9f60: [arg+0x48] must be in 5..=10080 (else error tag
   0xd1 with the value); [arg+0x38] / 10000 must be below Locus cls length
   (box +0x7d0), indexing 0x510-byte elements at box +0x7c8.

The captured binary is not executed. Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import fixed, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-misc-deadlines-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

FIXED = {
    # candidate date-time from the begin_block argument
    0x54b8b86: '488b8424e8020000',      # mov rax, [rsp+0x2e8]
    0x54b8b8e: '488b4008',              # mov rax, [rax+0x8]
    0x54b8b92: '8b4808',                # mov ecx, [rax+0x8]
    0x54b8b9c: '488b08',                # mov rcx, [rax]
    0x54bfdd7: '8b8424c0010000',        # mov eax, [rsp+0x1c0]
    0x54bfdde: '89842438040000',        # mov [rsp+0x438], eax
    0x54bfded: '4889842430040000',      # mov [rsp+0x430], rax
    # reset gate
    0x54bfdf5: '4983bf7042000000',      # cmp qword [r15+0x4270], 0
    0x54bfdfd: '743d',                  # je reset
    0x54bfdff: '4983bf1007000000',      # cmp qword [r15+0x710], 0
    0x54bfe07: '7433',                  # je reset
    0x54bfe10: '4d8db7b1420000',        # lea r14, [r15+0x42b1]
    0x54bfe17: '4180bfb042000001',      # cmp byte [r15+0x42b0], 1
    0x54bfe31: '660f29842410030000',    # movapd [rsp+0x310], xmm0 (saved cursor)
    # reset
    0x54bfe3c: '41c787f839000000000000',  # mov dword [r15+0x39f8], 0
    0x54bfe47: '49c787f03900001a40f600',  # mov qword [r15+0x39f0], 0xf6401a
    # cursor store
    0x54c008f: 'c680b042000001',        # mov byte [rax+0x42b0], 1
    0x54c009d: '41894610',              # mov [r14+0x10], eax
    # pmc + 600 s
    0x54c018d: '8b99f0390000',          # mov ebx, [rcx+0x39f0]
    0x54c01a1: '81f21a40f600',          # xor edx, 0xf6401a (unset test)
    0x54c01ab: '0f84c3000000',          # je 0x54c0274 (unset -> skip)
    0x54c01d6: 'b900ca9a3b',            # mov ecx, 1000000000
    0x54c0274: '488b442418',            # mov rax, [rsp+0x18] (date-add result dropped)
    # conditional pmc store
    0x54c0279: 'f680b042000001',        # test byte [rax+0x42b0], 1
    0x54c028a: 'ba14000000',            # mov edx, 20
    0x54c028f: '4c89f7',                # mov rdi, r14
    0x54c0298: '85c0',                  # test eax, eax
    0x54c029a: '7f20',                  # jg skip (store when <= 0)
    0x54c02a1: '4805f0390000',          # add rax, 0x39f0
    0x54c02ae: '894808',                # mov [rax+0x8], ecx
    0x54c02b9: '488908',                # mov [rax], rcx
    # tce handler range check and index
    0x57c9f71: '80b9fd39000000',        # cmp byte [rcx+0x39fd], 0
    0x57c9f7a: '488b4648',              # mov rax, [rsi+0x48]
    0x57c9f7e: '4c8d809fd8ffff',        # lea r8, [rax-0x2761]
    0x57c9f85: '4981f8a4d8ffff',        # cmp r8, -0x275c
    0x57c9f8c: '7318',                  # jae ok
    0x57c9f8e: '66c707d100',            # mov word [rdi], 0xd1
    0x57c9f93: '48894708',              # mov [rdi+0x8], rax
    0x57c9fb0: '488b5e38',              # mov rbx, [rsi+0x38]
    0x57c9fb4: '48ba4b598638d6c56d34',  # movabs rdx, 0x346dc5d63886594b (/10000)
    0x57c9fc7: '49c1ec0b',              # shr r12, 11
    0x57c9fcb: '4c3ba1d0070000',        # cmp r12, [rcx+0x7d0]
    0x57c9ff9: '4c8bb9c8070000',        # mov r15, [rcx+0x7c8]
    0x57ca000: '4d69f410050000',        # imul r14, r12, 0x510
}
REFERENCES = (
    (0x54c01c6, b'\xf2\x0f\x10\x05', 8, 0x459568),   # 600.0
    (0x54c01ce, b'\xff\x15', 6, 0x64e0f70),
    (0x54c022b, b'\xff\x15', 6, 0x64e0f78),
    (0x54c026e, b'\xff\x15', 6, 0x64e0aa0),
    (0x54c0292, b'\xff\x15', 6, 0x64dfb50),           # memcmp GLOB_DAT
)
SLOTS = {0x64e0f70: 0x15ed960, 0x64e0f78: 0x162a9a0, 0x64e0aa0: 0x16290d0}


def in_range(x):
    """Model of 0x57c9f7e..0x57c9f8c: accept when (x - 0x2761) mod 2^64 >= 2^64 - 0x275c."""
    return ((x - 0x2761) % (1 << 64)) >= (1 << 64) - 0x275c


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} changed')
    seconds = struct.unpack('<d', read_va(data, 0x459568, 8))[0]
    if seconds != 600.0:
        raise ValueError('600 s constant changed')
    if 0x346dc5d63886594b != -(-(1 << 75) // 10000):
        raise ValueError('divisor model changed')
    accepted = [x for x in range(0, 10100) if in_range(x)]
    if (accepted[0], accepted[-1], len(accepted)) != (5, 10080, 10076):
        raise ValueError('range model changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'pmc_begin_block_a': {
            'candidate': '[[rsp+0x2e8]+0x8] 12-byte date-time -> rsp+0x1b8 (0x54b8b86) -> rsp+0x430 (0x54bfded)',
            'reset': 'box +0x4270 == 0 or box +0x710 == 0 -> pmc = 0xf6401a / 0 (0x54bfe3c, 0x54bfe47)',
            'cursor': '20 bytes at box +0x42b1, flag box +0x42b0 = 1 (0x54c008f); entry value saved at rsp+0x310',
            'deadline': 'pmc set -> pmc + %.1f s via 0x15ed960 / 0x162a9a0 / 0x16290d0; date-add result '
                        'not stored (eax overwritten at 0x54c0274)' % seconds,
            'store': 'box +0x42b0 bit0 and memcmp(box+0x42b1, saved cursor, 20) <= 0 -> pmc = candidate '
                     '(0x54c02ae, 0x54c02b9)',
        },
        'tce_handler': {
            'fn': '0x57c9f60',
            'gate': 'box +0x39fd == 0 -> tag 0xdd',
            'range': '[arg+0x48] in %d..=%d else tag 0xd1 with the value at [out+0x8]'
                     % (accepted[0], accepted[-1]),
            'index': '[arg+0x38] / 10000 < box +0x7d0 (Locus cls length); element = box +0x7c8 + idx*0x510',
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
    print(result['tce_handler']['range'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
