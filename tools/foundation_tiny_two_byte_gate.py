#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 tiny two-byte gate packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads byte [rdi+0x58] and byte [rdi+0x68]: a zero first byte
returns 0; else it returns 1 exactly when the second byte is zero, and 0
otherwise. The meaning of the fields, of the two naming slots, and of any
other use of the window is not claimed anywhere.
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
START, END = 0x51647b0, 0x51647c4
PAD_END = 0x51647d0
BODY = bytes.fromhex('f30f1efa0fb6475884c07407807f68000f94c0c3')
PAD = bytes.fromhex('cc' * 12)
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000098b52900fc7c1e041400000000000000')
FDE_OFFSET = 0x29b594
NEXT_FDE_OFFSET = 0x29b5a8
NEXT_FDE_HEAD = bytes.fromhex('10000000acb52900087d1e040a00000000000000')
NEXT_START = 0x51647d0
NEXT_END = 0x51647da
# Exactly two R_X86_64_RELATIVE slots name this window as addend. This is a
# slot list, not a single naming slot, and nothing about the tables holding
# these slots is claimed.
NAMING_SLOTS = [
    {'offset': '0x575b240', 'section': '.rela.dyn'},
    {'offset': '0x57783d0', 'section': '.rela.dyn'},
]
R_X86_64_RELATIVE = 8


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gate(first, second):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The movzbl zero-extends the
    first byte, so the sete low byte is the whole return value; there is no
    stale-high-byte caveat.
    """
    if first == 0:
        return 0
    return 1 if second == 0 else 0


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
    require(body == BODY, 'Tiny two-byte gate instruction window changed')
    require(hashlib.sha256(body).hexdigest()
            == '8acb062d0034f8914a86c97022991b342d425cb3f4a6a0a0850264bdfb5d5ba8',
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
            off, info, add = struct.unpack_from('<QQq', data, s['offset'] + i * 24)
            if add == START and (info & 0xffffffff) == R_X86_64_RELATIVE:
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
    require(gate(0, 0) == 0, 'Zero-first edge changed')
    require(gate(0, 0xff) == 0, 'Zero-first priority edge changed')
    require(gate(1, 0) == 1, 'Second-zero edge changed')
    require(gate(0xff, 0) == 1, 'Second-zero max-first edge changed')
    require(gate(1, 1) == 0, 'Both-nonzero edge changed')
    require(gate(0xff, 0xff) == 0, 'Both-max edge changed')
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
            'first_byte_offset': '0x58',
            'first_zero_result': 0,
            'second_byte_offset': '0x68',
            'second_zero_result': 1,
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
    print('Foundation tiny-two-byte-gate evidence reproduces exactly.')


if __name__ == '__main__':
    main()
