#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 keyword-classifier evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it only writes two bytes and returns. The
meaning of the leading byte 9 and of the tags 0/1/2 is not claimed anywhere.
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
START, END = 0x1437b90, 0x1437be4
PAD_END = 0x1437bf0
BODY = bytes.fromhex(
    '4889f84883fa1074214883fa057533b9756e7469330e0fb6560483f26c09ca752131c98848'
    '01c60009c3f30f6f06660f74054acfdcfe660fd7c881f9ffff00007409b102884801c60009c3'
    'b101884801c60009c3')
PAD = b'\xcc' * 12
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000b0950000c4d074005400000000000000')
CALLER_FDE = bytes.fromhex(
    '50000000007b0000303e3f00ba19000004279395ff410e10420e18420e20420e28420e30410'
    'e38470e800383078c068d058e048f0386020353080e38410e30420e28420e20420e18420e104'
    '10e08410e80030000')
CALLER_START, CALLER_END = 0x13b9560, 0x13baf1a
CALL_SITE = 0x13ba4c6
CONSTANT_VA = 0x204b10
CONSTANT = b'required_matches'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def classify(string):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary.
    """
    if len(string) == 16 and string == CONSTANT:
        return 1
    if len(string) == 5 and string == b'until':
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
    for offset, raw, start, end in [(0x95ac, FDE, START, END),
                                    (0x2e4210, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # The 16-byte comparand is read from the target's own bytes, not assumed.
    require(read(CONSTANT_VA, 16) == CONSTANT, 'Keyword constant changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x1437b90.
    require(body[0:3] == bytes.fromhex('4889f8'), 'Output-pointer move changed')
    require(body[3:7] == bytes.fromhex('4883fa10'), 'Length-16 compare changed')
    require(body[7:9] == bytes.fromhex('7421'), 'Length-16 branch changed')
    require(body[9:13] == bytes.fromhex('4883fa05'), 'Length-5 compare changed')
    require(body[13:15] == bytes.fromhex('7533'), 'Length-5 branch changed')
    require(body[15:20] == bytes.fromhex('b9756e7469'), 'Until immediate changed')
    require(body[20:22] == bytes.fromhex('330e'), 'Until xor changed')
    require(body[22:26] == bytes.fromhex('0fb65604'), 'Fifth-byte load changed')
    require(body[26:29] == bytes.fromhex('83f26c'), 'Fifth-byte xor changed')
    require(body[29:31] == bytes.fromhex('09ca'), 'Until or changed')
    require(body[31:33] == bytes.fromhex('7521'), 'Until branch changed')
    require(body[33:35] == bytes.fromhex('31c9'), 'Tag-0 clear changed')
    require(body[35:42] == bytes.fromhex('884801c60009c3'), 'Tag-0 store changed')
    require(body[42:46] == bytes.fromhex('f30f6f06'), '16-byte load changed')
    require(body[46:54] == bytes.fromhex('660f74054acfdcfe'), '16-byte compare changed')
    require(0x1437bc6 + struct.unpack_from('<i', body[50:54], 0)[0] == CONSTANT_VA,
            '16-byte compare target changed')
    require(body[54:58] == bytes.fromhex('660fd7c8'), '16-byte mask changed')
    require(body[58:64] == bytes.fromhex('81f9ffff0000'), '16-byte mask compare changed')
    require(body[64:66] == bytes.fromhex('7409'), '16-byte branch changed')
    require(body[66:75] == bytes.fromhex('b102884801c60009c3'), 'Tag-2 store changed')
    require(body[75:84] == bytes.fromhex('b101884801c60009c3'), 'Tag-1 store changed')
    # Caller call bytes and argument setup come before the incoming scan, so
    # a mutated call site reports its own check rather than the scan's.
    call = read(CALL_SITE, 5)
    require(call == bytes.fromhex('e8c5d60700'), 'Caller call bytes changed')
    require(CALL_SITE + 5 + struct.unpack_from('<i', call, 1)[0] == START,
            'Caller call target changed')
    require(read(0x13ba4b1, 8) == bytes.fromhex('488bb424d8000000'),
            'Caller string-pointer setup changed')
    require(read(0x13ba4b9, 8) == bytes.fromhex('488b9424e0000000'),
            'Caller length setup changed')
    require(read(0x13ba4c1, 5) == bytes.fromhex('488d7c2470'),
            'Caller output-pointer setup changed')
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
    require(classify(b'until') == 0, 'Until edge changed')
    require(classify(b'required_matches') == 1, 'Required-matches edge changed')
    require(classify(b'') == 2, 'Empty edge changed')
    require(classify(b'untilx') == 2, 'Length-6 edge changed')
    require(classify(b'required_matchex') == 2, 'Length-17 edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'constant': CONSTANT.decode(),
        'call_site': CALL_SITE,
        'tag_edges': {'until': 0, 'required_matches': 1, 'other': 2},
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
        require(retained['constant']['bytes'] == 'required_matches',
                'Retained constant changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] == [hex(CALL_SITE)],
                'Retained callers changed')
        print('Foundation keyword-classifier evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
