#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 cursor/state machine packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads byte [rdi+0x1f0], qword [rdi+0x1e0], and the cursor
[rdi+0x1d0]: a zero flag byte stores marker 0x67 at [rdi+0x1f3] and returns;
else a counter at most 1 (unsigned) stores marker 0x50 at [rdi+0x1f3] and
returns; else the counter drops by 2 and the cursor advances by the
sign-extended byte-swapped u16 length at the old cursor, plus 2. The meaning
of the fields, of the marker bytes, of the fifteen naming slots, and of any
return value is not claimed anywhere.
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
START, END = 0x47d6b90, 0x47d6be2
PAD_END = 0x47d6bf0
BODY = bytes.fromhex(
    '80bff0010000007439488b87e00100004883f80176344883c0fe488987e001'
    '0000488b87d00100000fb70866c1c108480fbfc94801c84883c002488987d0'
    '010000c3c687f301000067c3c687f301000050c3')
PAD = bytes.fromhex('cc' * 14)
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000d4c92100a08c8d035200000000000000')
FDE_OFFSET = 0x21c9d0
NEXT_FDE_OFFSET = 0x21c9e4
NEXT_FDE_HEAD = bytes.fromhex('10000000e8c92100ec8c8d030a00000000000000')
NEXT_START = 0x47d6bf0
NEXT_END = 0x47d6bfa
# Exactly fifteen R_X86_64_RELATIVE slots name this window as addend, spaced
# 0x800 apart. This is a pointer-table slot list, not a single naming slot,
# and nothing about the table that holds these slots is claimed.
NAMING_SLOTS = [
    {'offset': '0x5721d88', 'section': '.rela.dyn'},
    {'offset': '0x5722588', 'section': '.rela.dyn'},
    {'offset': '0x5722d88', 'section': '.rela.dyn'},
    {'offset': '0x5723588', 'section': '.rela.dyn'},
    {'offset': '0x5723d88', 'section': '.rela.dyn'},
    {'offset': '0x5724588', 'section': '.rela.dyn'},
    {'offset': '0x5724d88', 'section': '.rela.dyn'},
    {'offset': '0x5725588', 'section': '.rela.dyn'},
    {'offset': '0x5725d88', 'section': '.rela.dyn'},
    {'offset': '0x5726588', 'section': '.rela.dyn'},
    {'offset': '0x5726d88', 'section': '.rela.dyn'},
    {'offset': '0x5727588', 'section': '.rela.dyn'},
    {'offset': '0x5727d88', 'section': '.rela.dyn'},
    {'offset': '0x5728588', 'section': '.rela.dyn'},
    {'offset': '0x5728d88', 'section': '.rela.dyn'},
]
R_X86_64_RELATIVE = 8


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bswap16(word):
    """Byte-swap a u16: the window's rol $0x8 on the 16-bit register."""
    return ((word & 0xff) << 8) | ((word >> 8) & 0xff)


def step(flag, counter, length_word):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Returns (marker, new_counter,
    cursor_delta): marker is the byte stored at [rdi+0x1f3] or None when no
    marker is stored, and cursor_delta is None unless the advance path runs.
    Flag and counter are unsigned values as read from the struct fields.
    """
    if flag == 0:
        return (0x67, counter, None)
    if counter <= 1:
        return (0x50, counter, None)
    swapped = bswap16(length_word)
    signed = swapped - 0x10000 if swapped >= 0x8000 else swapped
    return (None, counter - 2, signed + 2)


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
    require(body == BODY, 'Cursor/state machine instruction window changed')
    require(hashlib.sha256(body).hexdigest()
            == 'efae6e7037a52d6bbfdea1342560d793424130881ca9446bc9462526cd4164ba',
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
    # Full .rela.* scan: exactly the fifteen locked slots name this window.
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
    require(step(0, 7, 0x1234) == (0x67, 7, None), 'Zero-flag edge changed')
    require(step(1, 0, 0x1234) == (0x50, 0, None), 'Counter-zero edge changed')
    require(step(1, 1, 0x1234) == (0x50, 1, None), 'Counter-one edge changed')
    require(step(1, 2, 0x0001) == (None, 0, 258), 'Length 0x0001 edge changed')
    require(step(1, 2, 0x0100) == (None, 0, 3), 'Length 0x0100 edge changed')
    require(step(1, 3, 0xffff) == (None, 1, 1), 'Length 0xffff edge changed')
    require(step(1, 3, 0x0080) == (None, 1, -32766), 'Length 0x0080 edge changed')
    require(step(0xff, 0xffffffffffffffff, 0x0000)[1] == 0xfffffffffffffffd,
            'Counter wrap edge changed')
    require(step(0, 0, 0x0000) == (0x67, 0, None), 'Flag priority edge changed')
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
            'counter_gate': 'unsigned <= 1 stores 0x50 marker',
            'counter_offset': '0x1e0',
            'counter_subtract': 2,
            'cursor_offset': '0x1d0',
            'cursor_step': 'sign-extended byte-swapped u16 length plus 2',
            'flag_offset': '0x1f0',
            'flag_zero_marker': '0x67',
            'marker_offset': '0x1f3',
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
    print('Foundation cursor-state-machine evidence reproduces exactly.')


if __name__ == '__main__':
    main()
