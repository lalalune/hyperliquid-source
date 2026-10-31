#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 multi-path tail dispatcher packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads t = byte [rdi+0x29d0]: t == 3 tail-jumps to 0x4341ef0 with
rdi + 0xdc0; t == 0 dispatches on u = byte [rdi+0x55]: u == 4 tail-jumps to
0x44c6e70 with rdi + 0xb8, u == 3 with bytes [rdi+0xdb0] and [rdi+0xda8] both
== 3 tail-jumps to 0x43439c0 with rdi + 0xc8; anything else returns. The
meaning of the tag values, of the struct fields, and of the tail targets is
not claimed anywhere.
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
START, END = 0x4341b60, 0x4341bb5
PAD_END = 0x4341bc0
BODY = bytes.fromhex(
    '0fb687d029000085c0741183f80375384881c7c00d0000e974030000'
    '0fb6475583f804742483f803751e80bfb00d000003751580bfa80d'
    '000003750c4881c7c8000000e9181e0000c34881c7b8000000e9bb521800')
PAD = bytes.fromhex('cc' * 11)
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000803d1e00c4c847035500000000000000')
FDE_OFFSET = 0x1e3d7c
NEXT_FDE_OFFSET = 0x54f618
NEXT_FDE_HEAD = bytes.fromhex('54000000082f270088101103e1020000')
NEXT_START = 0x4341bc0
NEXT_END = 0x4341ea1
CALLER = 0x439ec38
CALLER_BYTES = bytes.fromhex('e8232ffaff')
CALLER_SETUP = bytes.fromhex('488b7c2450')
CALLER_FDE_OFFSET = 0x556f98
CALLER_FDE_HEAD = bytes.fromhex('5c00000088a82700383616039d310000044bd18f')
CALLER_RANGE = (0x439baf0, 0x439ec8d)
TAIL_TARGETS = (
    (0x4341ef0, 0x54f690, bytes.fromhex('44000000802f270040131103e3000000045fa28f'),
     (0x4341ef0, 0x4341fd3), 0xdc0),
    (0x43439c0, 0x550138, bytes.fromhex('38000000283a2700682311039c00000004c79d8f'),
     (0x43439c0, 0x4343a5c), 0xc8),
    (0x44c6e70, 0x56bbac, bytes.fromhex('500000009cf42800a49d2703ec000000044f688f'),
     (0x44c6e70, 0x44c6f5c), 0xb8),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def dispatch(tag, second, conf_a, conf_b):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. It returns ('tail', target, add)
    for a tail jump with rdi advanced by add, or ('ret',) for a plain return.
    The tail targets themselves are never modeled.
    """
    if tag == 3:
        return ('tail', 0x4341ef0, 0xdc0)
    if tag == 0:
        if second == 4:
            return ('tail', 0x44c6e70, 0xb8)
        if second == 3 and conf_a == 3 and conf_b == 3:
            return ('tail', 0x43439c0, 0xc8)
    return ('ret',)


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
    require(body == BODY, 'Multi-path tail dispatcher instruction window changed')
    require(hashlib.sha256(body).hexdigest()
            == '71dfa21bf37e81a3462a267bab56426a9250cbf3ec234583e3bcc3470e26a649',
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
    # Caller call bytes and the mov 0x50(%rsp),%rdi setup immediately before it.
    require(read(CALLER, len(CALLER_BYTES)) == CALLER_BYTES, 'Caller call changed')
    require(read(CALLER - 5, len(CALLER_SETUP)) == CALLER_SETUP,
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
    require(dispatch(3, 0, 0, 0) == ('tail', 0x4341ef0, 0xdc0),
            'Three-tag edge changed')
    require(dispatch(3, 4, 3, 3) == ('tail', 0x4341ef0, 0xdc0),
            'Three-tag ignores second dispatch')
    require(dispatch(0, 4, 0, 0) == ('tail', 0x44c6e70, 0xb8),
            'Zero-tag four edge changed')
    require(dispatch(0, 3, 3, 3) == ('tail', 0x43439c0, 0xc8),
            'Zero-tag confirmed three edge changed')
    require(dispatch(0, 3, 3, 2) == ('ret',),
            'Zero-tag second-confirm unconfirmed edge changed')
    require(dispatch(0, 3, 2, 3) == ('ret',),
            'Zero-tag first-confirm unconfirmed edge changed')
    require(dispatch(0, 3, 0, 0) == ('ret',), 'Zero-tag unconfirmed edge changed')
    require(dispatch(0, 2, 3, 3) == ('ret',), 'Zero-tag other-second edge changed')
    require(dispatch(0, 5, 3, 3) == ('ret',), 'Zero-tag five-second edge changed')
    require(dispatch(1, 0, 0, 0) == ('ret',), 'One-tag edge changed')
    require(dispatch(2, 0, 0, 0) == ('ret',), 'Two-tag edge changed')
    require(dispatch(4, 0, 0, 0) == ('ret',), 'Four-tag edge changed')
    require(dispatch(255, 0, 0, 0) == ('ret',), 'High-tag edge changed')
    return {
        'body_hex': BODY.hex(),
        'body_sha256': hashlib.sha256(BODY).hexdigest(),
        'caller': hex(CALLER),
        'caller_bytes': CALLER_BYTES.hex(),
        'caller_fde_end': hex(CALLER_RANGE[1]),
        'caller_fde_offset': hex(CALLER_FDE_OFFSET),
        'caller_fde_start': hex(CALLER_RANGE[0]),
        'caller_setup': 'mov 0x50(%rsp),%rdi',
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
            'confirm_offsets': ['0xdb0', '0xda8'],
            'confirm_value': 3,
            'first_offset': '0x29d0',
            'otherwise': 'ret',
            'second_offset': '0x55',
            'tag_three': 'rdi += 0xdc0, jmp 0x4341ef0',
            'tag_zero_four': 'rdi += 0xb8, jmp 0x44c6e70',
            'tag_zero_three_confirmed': 'rdi += 0xc8, jmp 0x43439c0',
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
    print('Foundation multi-path-tail-dispatcher evidence reproduces exactly.')


if __name__ == '__main__':
    main()
