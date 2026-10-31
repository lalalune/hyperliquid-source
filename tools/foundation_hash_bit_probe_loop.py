#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 hash bit-probe loop packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a hash bit-probe loop: given a struct pointer in rdi and a key
in rsi, it computes a 64-byte-block offset from the key and a struct field,
then probes one bit per round (the first probe from the key's high dword, each
later probe from that value multiplied by 0x9e3779b9, 32-bit wrap) and returns
1 exactly when every probed bit is set, else 0. What the struct fields mean,
and what the probed table holds, is not claimed anywhere.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x538ca50, 0x538cad3
PAD_END = 0x538cae0
MASK = (1 << 64) - 1
CONST = 0x9E3779B9
BODY = bytes.fromhex(
    'f30f1efa8b57144989f189f6448b471049c1e920488b4f08c1ea064489c8480fafd648c1ea2048c1e2064585c07e454489ce488d3c1149c1e91ac1ee17420fbe0c0f83e6070fa3f1733631f6eb18669089c189c2c1e91ac1ea170fbe0c0f83e2070fa3d1731a83c60169c0b979379e4139f075dcb801000000c3660f1f44000031c0c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000d4382b00607c3f0483000000')
NEXT = bytes.fromhex('10000000e8382b00dc7c3f0411000000')
# FDE section offsets; the pcrel field VA is .eh_frame address + offset + 8.
FDE_OFF, NEXT_OFF = 0x2B38D0, 0x2B38E4
NAMING_SLOT = 0x5763838
# Fixed instruction offsets inside the window, for the offset/branch locks.
INSTR = {
    0x538ca50: 'f30f1efa',        # endbr64
    0x538ca54: '8b5714',          # mov 0x14(%rdi),%edx
    0x538ca57: '4989f1',          # mov %rsi,%r9
    0x538ca5a: '89f6',            # mov %esi,%esi (dead zero-extend; see README)
    0x538ca5c: '448b4710',        # mov 0x10(%rdi),%r8d
    0x538ca60: '49c1e920',        # shr $0x20,%r9
    0x538ca64: '488b4f08',        # mov 0x8(%rdi),%rcx
    0x538ca68: 'c1ea06',          # shr $0x6,%edx
    0x538ca6b: '4489c8',          # mov %r9d,%eax
    0x538ca6e: '480fafd6',        # imul %rsi,%rdx
    0x538ca72: '48c1ea20',        # shr $0x20,%rdx
    0x538ca76: '48c1e206',        # shl $0x6,%rdx
    0x538ca7a: '4585c0',          # test %r8d,%r8d
    0x538ca7d: '7e45',            # jle 0x538cac4 (return 1)
    0x538ca7f: '4489ce',          # mov %r9d,%esi
    0x538ca82: '488d3c11',        # lea (%rcx,%rdx,1),%rdi
    0x538ca86: '49c1e91a',        # shr $0x1a,%r9
    0x538ca8a: 'c1ee17',          # shr $0x17,%esi
    0x538ca8d: '420fbe0c0f',      # movsbl (%rdi,%r9,1),%ecx
    0x538ca92: '83e607',          # and $0x7,%esi
    0x538ca95: '0fa3f1',          # bt %esi,%ecx
    0x538ca98: '7336',            # jae 0x538cad0 (return 0)
    0x538ca9a: '31f6',            # xor %esi,%esi
    0x538ca9c: 'eb18',            # jmp 0x538cab6
    0x538ca9e: '6690',            # xchg %ax,%ax (dead alignment pad)
    0x538caa0: '89c1',            # mov %eax,%ecx
    0x538caa2: '89c2',            # mov %eax,%edx
    0x538caa4: 'c1e91a',          # shr $0x1a,%ecx
    0x538caa7: 'c1ea17',          # shr $0x17,%edx
    0x538caaa: '0fbe0c0f',        # movsbl (%rdi,%rcx,1),%ecx
    0x538caae: '83e207',          # and $0x7,%edx
    0x538cab1: '0fa3d1',          # bt %edx,%ecx
    0x538cab4: '731a',            # jae 0x538cad0 (return 0)
    0x538cab6: '83c601',          # add $0x1,%esi
    0x538cab9: '69c0b979379e',    # imul $0x9e3779b9,%eax,%eax
    0x538cabf: '4139f0',          # cmp %esi,%r8d
    0x538cac2: '75dc',            # jne 0x538caa0
    0x538cac4: 'b801000000',      # mov $0x1,%eax
    0x538cac9: 'c3',              # ret
    0x538caca: '660f1f440000',    # nopw (dead pad after ret)
    0x538cad0: '31c0',            # xor %eax,%eax
    0x538cad2: 'c3',              # ret
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def block_offset(field14, key):
    """Byte offset of the probed 64-byte block, exactly as the bytes do it.

    ((field14 >> 6) * key) is a wrapping 64-bit product; its high dword,
    shifted left 6, is the offset. field14 is the zero-extended u32 at
    [rdi+0x14]; key is the full 64-bit rsi.
    """
    product = ((field14 >> 6) * key) & MASK
    return (product >> 32) << 6


def probe_all(table, offset, key, count):
    """Decoded probe rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. table is a bytes-like block base;
    offset is the block offset from block_offset; key is the full 64-bit
    rsi; count is the signed 32-bit value at [rdi+0x10]. Returns 1 exactly
    when every probed bit is set, else 0. A non-positive count returns 1
    without probing (the observed jle path).
    """
    if count <= 0:
        return 1
    high = (key >> 32) & 0xFFFFFFFF
    value = high
    for _ in range(count):
        byte = table[offset + (value >> 26)]
        bit = (value >> 23) & 7
        if not (byte >> bit) & 1:
            return 0
        value = (value * CONST) & 0xFFFFFFFF
    return 1


def parse_fde(raw, field_va):
    """Read one 16-byte zR pcrel sdata4 FDE record; return (pc, range)."""
    length, cie_ptr, init, rng = struct.unpack_from('<IIiI', raw, 0)
    require(length == 0x10, 'unexpected FDE length')
    require(cie_ptr != 0, 'unexpected CIE pointer')
    return (field_va + init) & MASK, rng


def inspect(target_path):
    data = Path(target_path).read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA256,
            'target digest mismatch')
    secs = {s['name']: s for s in sections(data)}
    text = secs['.text']
    base = text['offset'] + START - text['address']
    require(bytes(data[base:base + len(BODY)]) == BODY,
            'window bytes mismatch')
    pad = bytes(data[base + len(BODY):base + (PAD_END - START)])
    require(len(pad) == 13 and all(b == 0xCC for b in pad),
            'padding mismatch')
    for va, raw in INSTR.items():
        off = text['offset'] + va - text['address']
        require(bytes(data[off:off + len(raw) // 2]) == bytes.fromhex(raw),
                f'instruction mismatch at {hex(va)}')
    eh = secs['.eh_frame']
    require(bytes(data[eh['offset']:eh['offset'] + len(CIE0)]) == CIE0,
            'CIE0 mismatch')
    field_va = eh['address'] + FDE_OFF + 8
    pc, rng = parse_fde(bytes(data[eh['offset'] + FDE_OFF:
                                  eh['offset'] + FDE_OFF + 16]), field_va)
    require((pc, rng) == (START, 0x83), 'window FDE mismatch')
    require(bytes(data[eh['offset'] + FDE_OFF:
                       eh['offset'] + FDE_OFF + 16]) == FDE,
            'window FDE bytes mismatch')
    npc, nrng = parse_fde(bytes(data[eh['offset'] + NEXT_OFF:
                                    eh['offset'] + NEXT_OFF + 16]),
                          eh['address'] + NEXT_OFF + 8)
    require((npc, nrng) == (PAD_END, 0x11), 'next FDE mismatch')
    require(bytes(data[eh['offset'] + NEXT_OFF:
                       eh['offset'] + NEXT_OFF + 16]) == NEXT,
            'next FDE bytes mismatch')
    # Incoming direct-call scan over the whole .text section.
    tbytes = data[text['offset']:text['offset'] + text['size']]
    callers = []
    for i in range(len(tbytes) - 5):
        if tbytes[i] == 0xE8:
            rel = struct.unpack_from('<i', tbytes, i + 1)[0]
            if text['address'] + i + 5 + rel == START:
                callers.append(text['address'] + i)
    # Relocation scan: every entry of every .rela.* section.
    slots = []
    for name, sec in secs.items():
        if not name.startswith('.rela'):
            continue
        for j in range(sec['size'] // 24):
            roff, info, add = struct.unpack_from(
                '<QQq', data, sec['offset'] + j * 24)
            if add == START:
                slots.append((name, roff, info & 0xFFFFFFFF))
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(BODY).hexdigest(),
        'padding_bytes': 13,
        'direct_callers': callers,
        'relocation_slots': slots,
        'fde': (pc, rng),
        'next_fde': (npc, nrng),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', metavar='EVIDENCE')
    parser.add_argument('--binary', default=str(TARGET))
    args = parser.parse_args()
    result = inspect(args.binary)
    require(result['direct_callers'] == [], 'unexpected direct callers')
    require(result['relocation_slots'] == [('.rela.dyn', NAMING_SLOT, 8)],
            'unexpected naming relocation set')
    if args.check:
        evidence = json.loads(Path(args.check).read_text())
        require(evidence['window']['start_va'] == hex(START), 'evidence start')
        require(evidence['window']['end_va_exclusive'] == hex(END),
                'evidence end')
        require(evidence['window']['body_sha256'] == result['body_sha256'],
                'evidence body hash')
        require(evidence['window']['padding_bytes'] == 13, 'evidence pad')
        require(evidence['incoming_calls']['direct_sites'] == [],
                'evidence callers')
        require(evidence['naming_relocation']['slots'] == [hex(NAMING_SLOT)],
                'evidence slots')
        require(evidence['naming_relocation']['type'] == 'R_X86_64_RELATIVE',
                'evidence slot type')
    print('Foundation hash-bit-probe-loop evidence reproduces exactly.')


if __name__ == '__main__':
    main()
