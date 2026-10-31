#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 quirky tag gate evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads t = byte [rdi+0x30]: t == 0 tail-jumps to 0x22429e0 with
rdi + 0x18; t == 3 with byte [rdi+0x10] != 2 tail-jumps to the same target
with rdi unchanged; anything else returns. The meaning of the tag values,
of the struct fields, and of the tail target is not claimed anywhere.
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
START, END = 0x223e3a0, 0x223e3c1
PAD_END = 0x223e3d0
BODY = bytes.fromhex(
    '0fb6473085c0741083f803750a807f10020f8529460000c34883c718e91f460000')
PAD = bytes.fromhex('cc' * 15)
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000004c920500383c50012100000000000000')
FDE_OFFSET = 0x59248
NEXT_FDE_OFFSET = 0x5925c
NEXT_FDE_HEAD = bytes.fromhex('1800000060920500543c500130000000')
NEXT_START = 0x223e3d0
NEXT_END = 0x223e400
CALLER = 0x22b45c9
CALLER_BYTES = bytes.fromhex('e8d29df8ff')
CALLER_SETUP = bytes.fromhex('4c89ff')
CALLER_FDE_OFFSET = 0x3bbf98
CALLER_FDE_HEAD = bytes.fromhex('5c00000088f80d00c83b21013f370000')
CALLER_RANGE = (0x22b1080, 0x22b47bf)
TAIL_TARGET = 0x22429e0
TAIL_FDE_OFFSET = 0x3b2f0c
TAIL_FDE_HEAD = bytes.fromhex('38000000fc670d00b4e51a01fc000000')
TAIL_RANGE = (0x22429e0, 0x2242adc)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def quirky(tag, confirm):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. It returns ('tail', offset) for
    a tail jump to 0x22429e0 with rdi advanced by offset, or ('ret',) for a
    plain return. The tail target itself is never modeled.
    """
    if tag == 0:
        return ('tail', 0x18)
    if tag == 3 and confirm != 2:
        return ('tail', 0)
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
    require(body == BODY, 'Quirky tag gate instruction window changed')
    require(hashlib.sha256(body).hexdigest()
            == '4794da4ed129dacddccb23c640e1442ba4bf9993e94b5778510f82b07f91b7f4',
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
    require(eh_bytes(TAIL_FDE_OFFSET, len(TAIL_FDE_HEAD)) == TAIL_FDE_HEAD,
            'Tail-target FDE changed')
    # Caller call bytes and the mov %r15,%rdi setup immediately before it.
    require(read(CALLER, len(CALLER_BYTES)) == CALLER_BYTES, 'Caller call changed')
    require(read(CALLER - 3, len(CALLER_SETUP)) == CALLER_SETUP,
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
    require(quirky(0, 0) == ('tail', 0x18), 'Zero-tag edge changed')
    require(quirky(0, 2) == ('tail', 0x18), 'Zero-tag ignores confirm byte')
    require(quirky(3, 0) == ('tail', 0), 'Confirmed three-tag edge changed')
    require(quirky(3, 1) == ('tail', 0), 'Three-tag nonzero confirm edge changed')
    require(quirky(3, 2) == ('ret',), 'Three-tag unconfirmed edge changed')
    require(quirky(1, 0) == ('ret',), 'Other-tag edge changed')
    require(quirky(4, 0) == ('ret',), 'Four-tag edge changed')
    require(quirky(255, 0) == ('ret',), 'High-tag edge changed')
    return {
        'body_hex': BODY.hex(),
        'body_sha256': hashlib.sha256(BODY).hexdigest(),
        'caller': hex(CALLER),
        'caller_bytes': CALLER_BYTES.hex(),
        'caller_fde_end': hex(CALLER_RANGE[1]),
        'caller_fde_offset': hex(CALLER_FDE_OFFSET),
        'caller_fde_start': hex(CALLER_RANGE[0]),
        'caller_setup': 'mov %r15,%rdi',
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
            'add': '0x18',
            'check_offset': '0x10',
            'check_value': 2,
            'otherwise': 'ret',
            'tag_offset': '0x30',
            'tag_three_not_two': 'jmp tail with rdi unchanged',
            'tag_zero': 'rdi += 0x18, jmp tail',
        },
        'tail_fde_end': hex(TAIL_RANGE[1]),
        'tail_fde_offset': hex(TAIL_FDE_OFFSET),
        'tail_fde_start': hex(TAIL_RANGE[0]),
        'tail_target': hex(TAIL_TARGET),
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
    print('Foundation quirky-tag-gate evidence reproduces exactly.')


if __name__ == '__main__':
    main()
