#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 magic-tag tail dispatch packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads first = byte [rdi] and second = qword [rdi+8]: first == 0 and
second == 0x800000000000002a tail-jumps to 0x434b140 with rdi + 0x10; any other
combination tail-jumps to 0x434aa10 with rdi + 8. There is no plain return
path. The meaning of the tag values, of the struct fields, and of the tail
targets is not claimed anywhere.
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
START, END = 0x4340e00, 0x4340e29
PAD_END = 0x4340e30
BODY = bytes.fromhex(
    '488d4708803f00751848b92a0000000000008048390875094883c710e91fa30000'
    '4889c7e9e79b0000')
PAD = bytes.fromhex('cc' * 7)
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000543c1e0090bc47032900000000000000')
FDE_OFFSET = 0x1e3c50
NEXT_FDE_OFFSET = 0x1e3c64
NEXT_FDE_HEAD = bytes.fromhex('40000000683c1e00acbc47032801000000420e10')
NEXT_START = 0x4340e30
NEXT_END = 0x4340f58
CALLER = 0x4386969
CALLER_BYTES = bytes.fromhex('e892a4fbff')
CALLER_SETUP = bytes.fromhex('488dbc24e0020000')
CALLER_FDE_OFFSET = 0x55611c
CALLER_FDE_HEAD = bytes.fromhex('580000000c9a2700b4d2140346210000045fcd8f')
CALLER_RANGE = (0x43848f0, 0x4386a36)
MAGIC = 0x800000000000002a
TAIL_TARGETS = (
    (0x434aa10, 0x1e3e60, bytes.fromhex('1c000000643e1e00905648037b00000000410e10'),
     (0x434aa10, 0x434aa8b), 0x8),
    (0x434b140, 0x5513b0, bytes.fromhex('7c000000a04c2700708811031e01000004ff9b8f'),
     (0x434b140, 0x434b25e), 0x10),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def dispatch(first, second):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. It returns ('tail', target, add)
    for a tail jump with rdi advanced by add. There is no return path: every
    input tail-jumps somewhere. The tail targets themselves are never modeled.
    """
    if first == 0 and second == MAGIC:
        return ('tail', 0x434b140, 0x10)
    return ('tail', 0x434aa10, 0x8)


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
    require(body == BODY, 'Magic-tag tail dispatch instruction window changed')
    require(hashlib.sha256(body).hexdigest()
            == '51686b4c56ad77c88ff4065fb4e5794834c9787914244da46cf922ec920a7f61',
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
    require(eh_bytes(CALLER_FDE_OFFSET, len(CALLER_FDE_HEAD)) == CALLER_FDE_HEAD,
            'Caller FDE changed')
    for target, off, head, _rng, _add in TAIL_TARGETS:
        require(eh_bytes(off, len(head)) == head,
                'Tail-target FDE changed for %#x' % target)
    # Caller call bytes and the lea 0x2e0(%rsp),%rdi setup immediately before it.
    require(read(CALLER, len(CALLER_BYTES)) == CALLER_BYTES, 'Caller call changed')
    require(read(CALLER - 8, len(CALLER_SETUP)) == CALLER_SETUP,
            'Caller argument setup changed')
    # Full .rela.* scan: no record names this window, counts locked.
    naming = []
    counts = {}
    for name in ('.rela.dyn', '.rela.plt'):
        s = by_name[name]
        n = s['size'] // 24
        counts[name] = n
        for i in range(n):
            _, _, add = struct.unpack_from('<QQq', data, s['offset'] + i * 24)
            if add == START:
                naming.append((name, i))
    require(not naming, 'Unexpected naming relocation for this window')
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
    require(hits == [CALLER], 'Incoming direct-call scan changed')
    # Rule edges.
    require(dispatch(0, MAGIC) == ('tail', 0x434b140, 0x10),
            'Magic-tag edge changed')
    require(dispatch(0, 0) == ('tail', 0x434aa10, 0x8),
            'Zero-tag zero-second edge changed')
    require(dispatch(0, 0x2a) == ('tail', 0x434aa10, 0x8),
            'Zero-tag low-magic edge changed')
    require(dispatch(1, MAGIC) == ('tail', 0x434aa10, 0x8),
            'Nonzero-tag magic-second edge changed')
    require(dispatch(1, 0) == ('tail', 0x434aa10, 0x8),
            'Nonzero-tag zero-second edge changed')
    require(dispatch(255, MAGIC) == ('tail', 0x434aa10, 0x8),
            'High-tag magic-second edge changed')
    require(dispatch(255, 0) == ('tail', 0x434aa10, 0x8),
            'High-tag zero-second edge changed')
    return {
        'body_hex': BODY.hex(),
        'body_sha256': hashlib.sha256(BODY).hexdigest(),
        'caller': hex(CALLER),
        'caller_bytes': CALLER_BYTES.hex(),
        'caller_fde_end': hex(CALLER_RANGE[1]),
        'caller_fde_offset': hex(CALLER_FDE_OFFSET),
        'caller_fde_start': hex(CALLER_RANGE[0]),
        'caller_setup': 'lea 0x2e0(%rsp),%rdi',
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
            'else': 'rdi += 8, jmp 0x434aa10',
            'first_offset': '0x0',
            'magic': hex(MAGIC),
            'magic_path': 'rdi += 0x10, jmp 0x434b140',
            'otherwise': 'rdi += 8, jmp 0x434aa10',
            'second_offset': '0x8',
        },
        'tail_targets': [
            {'add': hex(add), 'fde_end': hex(rng[1]), 'fde_offset': hex(off),
             'fde_start': hex(rng[0]), 'target': hex(target)}
            for target, off, _head, rng, add in TAIL_TARGETS
        ],
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
    print('Foundation magic-tag-tail-dispatch evidence reproduces exactly.')


if __name__ == '__main__':
    main()
