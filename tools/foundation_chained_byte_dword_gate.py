#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 chained byte/dword gate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads byte [rdi+0x28a], byte [rdi+0x290], byte [rdi+0x289],
dword [rdi+0x9c] and dword [rdi+0x98]: a nonzero first byte returns 0; else a
nonzero second byte returns that byte; else a zero third byte returns 0; else
the window returns 1 exactly when dword+0x9c is unsigned-less-than
dword+0x98. The meaning of the fields, of the two naming slots, and of the
nearby cluster windows is not claimed anywhere.
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
START, END = 0x5382d50, 0x5382d8b
PAD_END = 0x5382d90
BODY = bytes.fromhex(
    'f30f1efa31c080bf8a02000000750b0fb6879002000084c07406c30f1f4400'
    '000fb6878902000084c074ef8b879800000039879c0000000f92c0c3')
PAD = bytes.fromhex('cc' * 5)
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000842f2b00b0e83e043b00000000000000')
FDE_OFFSET = 0x2b2f80
NEXT_FDE_OFFSET = 0x2b2f94
NEXT_FDE_HEAD = bytes.fromhex('10000000982f2b00dce83e044200000000000000')
NEXT_START = 0x5382d90
NEXT_END = 0x5382dd2
# Exactly two R_X86_64_RELATIVE slots name this window as addend. This is a
# slot list, not a single naming slot, and nothing about the tables that hold
# these slots is claimed.
NAMING_SLOTS = [
    {'offset': '0x57632a8', 'section': '.rela.dyn'},
    {'offset': '0x5778ae8', 'section': '.rela.dyn'},
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gate(b28a, b290, b289, d9c, d98):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. All byte and dword inputs are
    unsigned values as read from the struct fields.
    """
    if b28a != 0:
        return 0
    if b290 != 0:
        return b290
    if b289 == 0:
        return 0
    return 1 if d9c < d98 else 0


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    body = read(START, END - START)
    require(body == BODY, 'Chained byte/dword gate instruction window changed')
    require(hashlib.sha256(body).hexdigest()
            == 'b0848f8935293d721a79c0ebabaabab3e2f6ffa3534162b1b57b85de5f33cde9',
            'Window body hash changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    eh_base = eh['offset']

    def eh_bytes(off, size):
        return data[eh_base + off:eh_base + off + size]

    require(eh_bytes(0, len(CIE)) == CIE, 'CIE changed')
    require(eh_bytes(FDE_OFFSET, len(FDE)) == FDE, 'Window FDE changed')
    require(eh_bytes(NEXT_FDE_OFFSET, len(NEXT_FDE_HEAD)) == NEXT_FDE_HEAD,
            'Next FDE changed')
    # Full .rela.* scan: exactly the two locked slots name this window.
    naming = []
    counts = {}
    for name in ('.rela.dyn', '.rela.plt'):
        s = by_name[name]
        n = s['size'] // 24
        counts[name] = n
        for i in range(n):
            off, _info, add = struct.unpack_from('<QQq', data, s['offset'] + i * 24)
            if add == START:
                naming.append({'offset': hex(off), 'section': name})
    require(naming == NAMING_SLOTS, 'Naming slot list changed')
    require(counts['.rela.dyn'] == 80022, 'rela.dyn count changed')
    require(counts['.rela.plt'] == 278, 'rela.plt count changed')
    # Whole .text direct-e8 scan for this window (not a complete xref census).
    text = by_name['.text']
    base, off, size = text['address'], text['offset'], text['size']
    hits = []
    for i in range(size - 5):
        if data[off + i] == 0xe8:
            rel = struct.unpack_from('<i', data, off + i + 1)[0]
            if base + i + 5 + rel == START:
                hits.append(base + i)
    require(hits == [], 'Incoming direct-call scan changed')
    # Rule edges.
    require(gate(1, 0, 1, 0, 1) == 0, 'Nonzero first-byte edge changed')
    require(gate(0, 0x41, 1, 0, 1) == 0x41, 'Second-byte return edge changed')
    require(gate(0, 0, 0, 0, 1) == 0, 'Zero third-byte edge changed')
    require(gate(0, 0, 1, 3, 4) == 1, 'Dword less-than edge changed')
    require(gate(0, 0, 1, 4, 4) == 0, 'Dword equal edge changed')
    require(gate(0, 0, 1, 5, 4) == 0, 'Dword greater edge changed')
    require(gate(0, 0xff, 0, 0, 0) == 0xff, 'Second-byte priority edge changed')
    return {
        'body_hex': BODY.hex(),
        'body_sha256': hashlib.sha256(BODY).hexdigest(),
        'fde_offset': hex(FDE_OFFSET),
        'incoming_direct_calls': len(hits),
        'naming_relocations': naming,
        'next_fde_end': hex(NEXT_END),
        'next_fde_offset': hex(NEXT_FDE_OFFSET),
        'next_fde_start': hex(NEXT_START),
        'padding_bytes': len(PAD),
        'padding_end': hex(PAD_END),
        'rela_dyn_count': counts['.rela.dyn'],
        'rela_plt_count': counts['.rela.plt'],
        'rule': {
            'dword_greater': 0,
            'dword_less': 1,
            'first_byte_offset': '0x28a',
            'first_byte_rule': 'nonzero returns 0',
            'second_byte_offset': '0x290',
            'second_byte_rule': 'nonzero returns that byte',
            'third_byte_offset': '0x289',
            'third_byte_rule': 'zero returns 0',
        },
        'target': 'node #94',
        'target_sha256': SHA256,
        'target_size': len(data),
        'text_size': size,
        'window_end': hex(END),
        'window_size': END - START,
        'window_start': hex(START),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', required=True)
    args = parser.parse_args()
    data = Path(args.binary).read_bytes()
    got = analyze(data)
    want = json.loads(Path(args.check).read_text())
    require(got == want, 'Regenerated evidence does not match retained JSON')
    print('Foundation chained-byte-dword-gate evidence reproduces exactly.')


if __name__ == '__main__':
    main()
