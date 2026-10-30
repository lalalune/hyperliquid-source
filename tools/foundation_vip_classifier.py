#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 keyword-classifier evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it only writes two bytes and returns. The
meaning of the leading byte 9 and of the tags 0/1/2 is not claimed anywhere.

This window is bound ALONE. It shares packet #15's two-byte output shape
(byte 0 = 9, byte 1 = tag) but is a different window with different strings
("mm" / "vip" here, "until" / "required_matches" there) and a different tag
mapping; it is never presented as part of a classifier family.
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
START, END = 0x1e6d560, 0x1e6d5a6
PAD_END = 0x1e6d5b0
BODY = bytes.fromhex(
    '4889f84883fa0274244883fa0375250fb70e81f1766900000fb6560283f2706609ca751031c9'
    '884801c60009c366813e6d6d7409b102884801c60009c3b101884801c60009c3')
PAD = b'\xcc' * 10
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000c4cd030080f214014600000000000000')
CALLER_CIE = bytes.fromhex(
    '1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000')
CALLER_FDE = bytes.fromhex(
    '50000000348d04001c4e71007d19000004139694ff410e10420e18420e20420e28420e30410e384'
    '70e800383078c068d058e048f038602036f0b0e38410e30420e28420e20420e18420e10410e084'
    '10e80030000')
CALLER_START, CALLER_END = 0x171b780, 0x171d0fd
CALL_SITE = 0x171c697


def require(condition, message):
    if not condition:
        raise ValueError(message)


def classify(string):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Length is tested as a 64-bit
    value; the window reads exactly len bytes on the two matching paths.
    """
    if len(string) == 2 and string == b'mm':
        return 1
    if len(string) == 3 and string == b'vip':
        return 0
    return 2


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
    require(body == BODY, 'Keyword-classifier instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    require(read(eh['address'] + 0x2dc714, len(CALLER_CIE)) == CALLER_CIE,
            'Caller CIE changed')
    for offset, raw, start, end in [(0x3cdc0, FDE, START, END),
                                    (0x325444, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x1e6d560.
    require(body[0:3] == bytes.fromhex('4889f8'), 'Output-pointer move changed')
    require(body[3:7] == bytes.fromhex('4883fa02'), 'Length-2 compare changed')
    require(body[7:9] == bytes.fromhex('7424'), 'Length-2 branch changed')
    require(START + 7 + 2 + struct.unpack_from('<b', body, 8)[0] == 0x1e6d58d,
            'Length-2 branch target changed')
    require(body[9:13] == bytes.fromhex('4883fa03'), 'Length-3 compare changed')
    require(body[13:15] == bytes.fromhex('7525'), 'Length-3 branch changed')
    require(START + 13 + 2 + struct.unpack_from('<b', body, 14)[0] == 0x1e6d594,
            'Length-3 branch target changed')
    require(body[15:18] == bytes.fromhex('0fb70e'), 'First-two-bytes load changed')
    require(body[18:24] == bytes.fromhex('81f176690000'), 'Vi xor changed')
    require(body[24:28] == bytes.fromhex('0fb65602'), 'Third-byte load changed')
    require(body[28:31] == bytes.fromhex('83f270'), 'Third-byte xor changed')
    require(body[31:34] == bytes.fromhex('6609ca'), 'Vi or changed')
    require(body[34:36] == bytes.fromhex('7510'), 'Vi branch changed')
    require(START + 34 + 2 + struct.unpack_from('<b', body, 35)[0] == 0x1e6d594,
            'Vi branch target changed')
    require(body[36:45] == bytes.fromhex('31c9884801c60009c3'), 'Tag-0 store changed')
    require(body[45:50] == bytes.fromhex('66813e6d6d'), 'Mm compare changed')
    require(body[50:52] == bytes.fromhex('7409'), 'Mm branch changed')
    require(START + 50 + 2 + struct.unpack_from('<b', body, 51)[0] == 0x1e6d59d,
            'Mm branch target changed')
    require(body[52:61] == bytes.fromhex('b102884801c60009c3'), 'Tag-2 store changed')
    require(body[61:70] == bytes.fromhex('b101884801c60009c3'), 'Tag-1 store changed')
    # Caller call bytes and argument setup come before the incoming scan, so
    # a mutated call site reports its own check rather than the scan's.
    call = read(CALL_SITE, 5)
    require(call == bytes.fromhex('e8c40e7500'), 'Caller call bytes changed')
    require(CALL_SITE + 5 + struct.unpack_from('<i', call, 1)[0] == START,
            'Caller call target changed')
    require(read(0x171c688, 5) == bytes.fromhex('488b742438'),
            'Caller string-pointer setup changed')
    require(read(0x171c68d, 5) == bytes.fromhex('488b542440'),
            'Caller length setup changed')
    require(read(0x171c692, 5) == bytes.fromhex('488d7c2410'),
            'Caller output-pointer setup changed')
    # Incoming calls: exactly one direct e8 call, no indirect slot calls.
    # No relocation of any type maps a slot to this window.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    window_slots = [a for a, (info, addend) in rels.items() if addend == START]
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
    require(classify(b'vip') == 0, 'Vip edge changed')
    require(classify(b'mm') == 1, 'Mm edge changed')
    require(classify(b'') == 2, 'Empty edge changed')
    require(classify(b'm') == 2, 'Length-1 edge changed')
    require(classify(b'vi') == 2, 'Length-2 non-mm edge changed')
    require(classify(b'mmx') == 2, 'Length-3 non-vip edge changed')
    require(classify(b'vix') == 2, 'Length-3 third-byte edge changed')
    require(classify(b'vipx') == 2, 'Length-4 edge changed')
    require(classify(b'MM') == 2, 'Case edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_site': CALL_SITE,
        'tag_edges': {'vip': 0, 'mm': 1, 'other': 2},
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 keyword-classifier '
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
        print('Foundation vip-classifier evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
