#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 three-way unsigned clamp evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it reads four fields, applies one of three
unsigned rules selected by a tag, and returns a single value in rax. The
meaning of the tag and of the four fields is not claimed anywhere.
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
START, END = 0x15e4f70, 0x15e4fb5
PAD_END = 0x15e4fc0
BODY = bytes.fromhex(
    '488b074885c0741f83f801752a488b4f1031c0482b4f18480f43c1488b4f284839c1480f42c1c3488b4718488b4f284839c1480f42c1c331c0488b4f284839c1480f42c1c3')
PAD = b'\xcc' * 11
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000f4e1010060588e004500000000000000')
CALLER_FDE = bytes.fromhex(
    '50000000dc3b0300042e5f0003030000041fe794ff410e10420e18420e20420e28420e30410e38440eb00183078c068d058e048f03860203fe010e38410e30420e28420e20420e18420e10410e08410eb0010000')
CALLER_START, CALLER_END = 0x15e4610, 0x15e4913
CALL_SITE = 0x15e482d
SETUP = bytes.fromhex('4889f74889d3e83e070000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def clamp(tag, field_10, field_18, field_28):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. All arithmetic is modulo 2**64.
    The tag-0 test reads the full 64-bit tag (test rax,rax); the tag-1 test
    reads only the low 32 bits (cmp $0x1,%eax), so a tag such as
    0x100000001 takes the tag-1 path while 0x100000000 falls through to 0.
    """
    if tag == 0:
        return min(field_18, field_28)
    if (tag & 0xffffffff) == 1:
        diff = (field_10 - field_18) % (1 << 64) if field_10 >= field_18 else 0
        return min(diff, field_28)
    return 0


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
    require(body == BODY, 'Unsigned-clamp instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x1e1f0, FDE, START, END),
                                    (0x3102ec, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x15e4f70.
    require(body[0:3] == bytes.fromhex('488b07'), 'Tag load changed')
    require(body[3:6] == bytes.fromhex('4885c0'), 'Tag-zero test changed')
    require(body[6:8] == bytes.fromhex('741f'), 'Tag-zero branch changed')
    require(0x15e4f78 + body[7] == 0x15e4f97, 'Tag-zero branch target changed')
    require(body[8:11] == bytes.fromhex('83f801'), 'Tag-one compare changed')
    require(body[11:13] == bytes.fromhex('752a'), 'Tag-one branch changed')
    require(0x15e4f7d + body[12] == 0x15e4fa7, 'Tag-one branch target changed')
    require(body[13:17] == bytes.fromhex('488b4f10'), 'Field+0x10 load changed')
    require(body[17:19] == bytes.fromhex('31c0'), 'Difference clear changed')
    require(body[19:23] == bytes.fromhex('482b4f18'), 'Saturating subtract changed')
    require(body[23:27] == bytes.fromhex('480f43c1'), 'Saturating gate changed')
    require(body[27:31] == bytes.fromhex('488b4f28'), 'Cap load changed')
    require(body[31:34] == bytes.fromhex('4839c1'), 'Cap compare changed')
    require(body[34:38] == bytes.fromhex('480f42c1'), 'Cap gate changed')
    require(body[38] == 0xc3, 'Tag-one return changed')
    require(body[39:43] == bytes.fromhex('488b4718'), 'Tag-zero field+0x18 load changed')
    require(body[43:47] == bytes.fromhex('488b4f28'), 'Tag-zero cap load changed')
    require(body[47:50] == bytes.fromhex('4839c1'), 'Tag-zero cap compare changed')
    require(body[50:54] == bytes.fromhex('480f42c1'), 'Tag-zero cap gate changed')
    require(body[54] == 0xc3, 'Tag-zero return changed')
    require(body[55:57] == bytes.fromhex('31c0'), 'Other-tag clear changed')
    require(body[57:61] == bytes.fromhex('488b4f28'), 'Other-tag cap load changed')
    require(body[61:64] == bytes.fromhex('4839c1'), 'Other-tag cap compare changed')
    require(body[64:68] == bytes.fromhex('480f42c1'), 'Other-tag cap gate changed')
    require(body[68] == 0xc3, 'Other-tag return changed')
    # Caller call bytes and argument setup come before the incoming scan, so
    # a mutated call site reports its own check rather than the scan's.
    setup = read(CALL_SITE - 6, 11)
    require(setup == SETUP, 'Caller setup and call bytes changed')
    require(setup[0:3] == bytes.fromhex('4889f7'), 'Caller rdi setup changed')
    require(setup[3:6] == bytes.fromhex('4889d3'), 'Caller rbx save changed')
    call = setup[6:11]
    require(call[0] == 0xe8, 'Caller call opcode changed')
    require(CALL_SITE + 5 + struct.unpack_from('<i', call, 1)[0] == START,
            'Caller call target changed')
    # Incoming calls: exactly one direct e8 call, no indirect slot calls.
    # No relocation maps any slot to this window, so no ff15/ff25 path exists.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    window_slots = [a for a, (info, addend) in rels.items() if info == 8 and addend == START]
    require(window_slots == [], 'Unexpected slot maps to window')
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [CALL_SITE], 'Incoming direct calls changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(clamp(0, 99, 5, 7) == 5, 'Tag-0 min edge changed')
    require(clamp(0, 99, 9, 3) == 3, 'Tag-0 cap edge changed')
    require(clamp(1, 10, 4, 100) == 6, 'Tag-1 difference edge changed')
    require(clamp(1, 3, 9, 100) == 0, 'Tag-1 saturating edge changed')
    require(clamp(1, 10, 4, 2) == 2, 'Tag-1 cap edge changed')
    require(clamp(2, 10, 4, 100) == 0, 'Other-tag edge changed')
    require(clamp(0x100000001, 10, 4, 100) == 6, 'Low-32 tag-1 edge changed')
    require(clamp(0x100000000, 10, 4, 100) == 0, 'Low-32 tag-0 edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_site': CALL_SITE,
        'tag_edges': {'tag_0': 'min(field+0x18, field+0x28)',
                      'tag_1': 'min(saturating_sub(field+0x10, field+0x18), field+0x28)',
                      'other': 0},
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 unsigned-clamp '
                    'evidence packet.')
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
        require(retained['incoming_pattern_scan']['e8_candidates'] == [hex(CALL_SITE)],
                'Retained callers changed')
        print('Foundation unsigned-clamp evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
