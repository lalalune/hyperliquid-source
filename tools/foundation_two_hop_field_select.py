#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 two-hop field select evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window loads p = [rdi+0x8], then q = [p+0x1e0]; when q is nonzero it
returns [q+0x8], otherwise it returns [p+0x178]. The meaning of the struct
fields, of the loaded values, and of the callers is not claimed anywhere.
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
START, END = 0x5361710, 0x5361738
PAD_END = 0x5361738
BODY = bytes.fromhex(
    'f30f1efa488b5708488b82e00100004885c0740c488b4008c30f1f8000000000'
    '488b8278010000c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000001c2a2b00d8d73c0428000000')
FDE_OFFSET = 0x2b2a18
NEXT_FDE_OFFSET = 0x65342c
NEXT_FDE_HEAD = bytes.fromhex('20000000602e0300eccd02049e000000')
NEXT_START = 0x5361738
NEXT_END = 0x53617d6
CALLERS = (0x5380fb7, 0x538265a)
CALLER_BYTES = (bytes.fromhex('e85407feff'), bytes.fromhex('e8b1f0fdff'))
CALLER_FDE_OFFSETS = (0x654500, 0x65466c)
CALLER_FDE_HEADS = (
    bytes.fromhex('50000000343f030030b5040480050000'),
    bytes.fromhex('50000000a040030064ca040456060000'),
)
CALLER_RANGES = ((0x5380f50, 0x53814d0), (0x53825f0, 0x5382c46))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def two_hop(p_block, q_block):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. p_block maps field offsets to
    values for the struct at p; q_block maps offsets for the struct at q
    (None stands for a null q). The window returns [q+0x8] when q is
    non-null, else [p+0x178].
    """
    if q_block is not None:
        return q_block[0x8]
    return p_block[0x178]


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
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
    require(body == BODY, 'Two-hop field select instruction window changed')
    require(END == PAD_END, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    record = read(eh['address'] + FDE_OFFSET, len(FDE))
    require(record == FDE, 'FDE record changed')
    pc = eh['address'] + FDE_OFFSET + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require((pc, pc + extent) == (START, END), 'FDE PC/range changed')
    # The next FDE starts exactly at the FDE end (zero padding); its
    # PC/range are locked here (its full record is retained in frames.txt).
    nxt = read(eh['address'] + NEXT_FDE_OFFSET, len(NEXT_FDE_HEAD))
    require(nxt == NEXT_FDE_HEAD, 'Next FDE record changed')
    npc = eh['address'] + NEXT_FDE_OFFSET + 8 + struct.unpack_from('<i', nxt, 8)[0]
    nextent = struct.unpack_from('<I', nxt, 12)[0]
    require((npc, npc + nextent) == (NEXT_START, NEXT_END),
            'Next FDE PC/range changed')
    # Caller FDEs: lock each record head and computed PC/range. Their CIE
    # differs from the window's; only the FDE heads and PC/ranges are locked.
    for off, head, (cstart, cend) in zip(CALLER_FDE_OFFSETS, CALLER_FDE_HEADS,
                                         CALLER_RANGES):
        chead = read(eh['address'] + off, len(head))
        require(chead == head, 'Caller FDE record changed')
        cpc = eh['address'] + off + 8 + struct.unpack_from('<i', chead, 8)[0]
        cent = struct.unpack_from('<I', chead, 12)[0]
        require((cpc, cpc + cent) == (cstart, cend),
                'Caller FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5361710.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'endbr64 changed')
    require(body[4:8] == bytes.fromhex('488b5708'), 'First hop changed')
    require(body[8:15] == bytes.fromhex('488b82e0010000'), 'Second hop changed')
    require(body[15:18] == bytes.fromhex('4885c0'), 'Null test changed')
    require(body[18:20] == bytes.fromhex('740c'), 'Null branch changed')
    require(body[20:24] == bytes.fromhex('488b4008'), 'Nonzero load changed')
    require(body[24:25] == bytes.fromhex('c3'), 'First return changed')
    require(body[25:32] == bytes.fromhex('0f1f8000000000'),
            'Alignment nopw changed')
    require(body[32:39] == bytes.fromhex('488b8278010000'),
            'Fallback load changed')
    require(body[39:40] == bytes.fromhex('c3'), 'Final return changed')
    # Caller call bytes: each confirmed caller calls the window directly.
    for caller, callbytes in zip(CALLERS, CALLER_BYTES):
        require(read(caller, 5) == callbytes, 'Caller call bytes changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend. The full-section scan counts are locked
    # so a truncated scan cannot pass silently.
    naming = []
    rela_counts = {}
    for relname in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[relname]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        rela_counts[relname] = len(raw) // 24
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                naming.append(address)
    require(naming == [], 'Naming slots changed')
    require(rela_counts == {'.rela.dyn': 80022, '.rela.plt': 278},
            'RELA section counts changed')
    # Incoming calls: exactly two direct e8 calls, the confirmed callers.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == list(CALLERS), 'Incoming direct calls changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(two_hop({0x178: 7}, {0x8: 42}) == 42, 'Nonzero-q edge changed')
    require(two_hop({0x178: 7}, None) == 7, 'Null-q edge changed')
    require(two_hop({0x178: 0}, {0x8: 0}) == 0, 'Zero-value edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'callers': CALLERS,
        'rela_counts': rela_counts,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 two-hop '
                    'field select evidence packet.')
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        retained = json.loads(Path(args.check).read_text())
        require(retained['target_sha256'] == SHA256, 'Retained digest changed')
        require(retained['function']['start_va'] == hex(START), 'Retained start changed')
        require(retained['function']['end_va_exclusive'] == hex(END), 'Retained end changed')
        require(retained['function']['bytes'] == END - START, 'Retained size changed')
        require(retained['function']['sha256'] == result['body_sha256'],
                'Retained body hash changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] == [hex(c) for c in CALLERS],
                'Retained callers changed')
        require(retained['data_edge']['relative_slots_naming_window'] == [],
                'Retained naming slots changed')
        print('Foundation two-hop-field-select evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
