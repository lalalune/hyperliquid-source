#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 keyword-classifier evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it only writes two bytes and returns. The
meaning of the leading byte 9 and of the tags 0/1/2 is not claimed anywhere.
The keywords are immediates inside the window itself, not a separate constant.
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
START, END = 0x25903d0, 0x2590426
PAD_END = 0x2590430
BODY = bytes.fromhex(
    '4889f84883fa0974214883fa057535b9696e7075330e0fb6560483f27409ca752331c98848'
    '01c60009c348b96761735f6c696d6948330e0fb656084883f2744809ca7409b102884801c6'
    '0009c3b101884801c60009c3')
PAD = b'\xcc' * 10
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000007435090040b981015600000000000000')
CALLER_FDE = bytes.fromhex(
    '50000000ac0d050064af8e009218000004fbcb94ff410e10420e18420e20420e28420e30410'
    'e38470e900383078c068d058e048f0386020365080e38410e30420e28420e20420e18420e104'
    '10e08410e90030000')
CALLER_START, CALLER_END = 0x18f9940, 0x18fb1d2
CALL_SITE = 0x18fa9ee


def require(condition, message):
    if not condition:
        raise ValueError(message)


def classify(string):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Length 9 is tested first, then
    length 5; any other length, or a length match with a byte mismatch, is
    tag 2.
    """
    if len(string) == 9 and string == b'gas_limit':
        return 1
    if len(string) == 5 and string == b'input':
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
    for offset, raw, start, end in [(0x93570, FDE, START, END),
                                    (0x32d4bc, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # The next FDE starts exactly at the stride end; its PC is locked here
    # (its full record is retained in frames.txt, not re-decoded).
    require(read(eh['address'] + 0x3ed644, 4) == bytes.fromhex('60000000'),
            'Next FDE record changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x25903d0.
    require(body[0:3] == bytes.fromhex('4889f8'), 'Output-pointer move changed')
    require(body[3:7] == bytes.fromhex('4883fa09'), 'Length-9 compare changed')
    require(body[7:9] == bytes.fromhex('7421'), 'Length-9 branch changed')
    require(body[9:13] == bytes.fromhex('4883fa05'), 'Length-5 compare changed')
    require(body[13:15] == bytes.fromhex('7535'), 'Length-5 branch changed')
    require(body[15:20] == bytes.fromhex('b9696e7075'), 'Input immediate changed')
    require(body[20:22] == bytes.fromhex('330e'), 'Input xor changed')
    require(body[22:26] == bytes.fromhex('0fb65604'), 'Fifth-byte load changed')
    require(body[26:29] == bytes.fromhex('83f274'), 'Fifth-byte xor changed')
    require(body[29:31] == bytes.fromhex('09ca'), 'Input or changed')
    require(body[31:33] == bytes.fromhex('7523'), 'Input branch changed')
    require(body[33:35] == bytes.fromhex('31c9'), 'Tag-0 clear changed')
    require(body[35:42] == bytes.fromhex('884801c60009c3'), 'Tag-0 store changed')
    require(body[42:52] == bytes.fromhex('48b96761735f6c696d69'),
            'Gas-limit immediate changed')
    require(body[52:55] == bytes.fromhex('48330e'), 'Gas-limit xor changed')
    require(body[55:59] == bytes.fromhex('0fb65608'), 'Ninth-byte load changed')
    require(body[59:63] == bytes.fromhex('4883f274'), 'Ninth-byte xor changed')
    require(body[63:66] == bytes.fromhex('4809ca'), 'Gas-limit or changed')
    require(body[66:68] == bytes.fromhex('7409'), 'Gas-limit branch changed')
    require(body[68:77] == bytes.fromhex('b102884801c60009c3'), 'Tag-2 store changed')
    require(body[77:86] == bytes.fromhex('b101884801c60009c3'), 'Tag-1 store changed')
    # The immediates decode to the keywords only in little-endian order:
    # 0x75706e69 is "inpu" plus byte 4 xor 0x74 ('t'); 0x696d696c5f736167
    # is "gas_limi" plus byte 8 xor 0x74 ('t').
    require(struct.unpack('<I', body[16:20])[0].to_bytes(4, 'little') == b'inpu',
            'Input first-four-bytes changed')
    require(struct.unpack('<Q', body[44:52])[0].to_bytes(8, 'little') == b'gas_limi',
            'Gas-limit first-eight-bytes changed')
    # Caller call bytes and argument setup come before the incoming scan, so
    # a mutated call site reports its own check rather than the scan's.
    call = read(CALL_SITE, 5)
    require(call == bytes.fromhex('e8dd59c900'), 'Caller call bytes changed')
    require(CALL_SITE + 5 + struct.unpack_from('<i', call, 1)[0] == START,
            'Caller call target changed')
    require(read(0x18fa9e0, 4) == bytes.fromhex('8b742410'),
            'Caller string-pointer setup changed')
    require(read(0x18fa9e4, 5) == bytes.fromhex('488b542418'),
            'Caller length setup changed')
    require(read(0x18fa9e9, 5) == bytes.fromhex('488d7c2430'),
            'Caller output-pointer setup changed')
    # Incoming calls: exactly one direct e8 call, no indirect slot calls.
    # No relocation in any .rela.* section names this window as addend.
    for relname in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[relname]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            require(addend != START, 'Unexpected relocation names window')
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
    require(classify(b'input') == 0, 'Input edge changed')
    require(classify(b'gas_limit') == 1, 'Gas-limit edge changed')
    require(classify(b'') == 2, 'Empty edge changed')
    require(classify(b'inputx') == 2, 'Length-6 edge changed')
    require(classify(b'gas_limix') == 2, 'Length-10 edge changed')
    require(classify(b'gas_limitx') == 2, 'Length-10 gas edge changed')
    require(classify(b'xxxxx') == 2, 'Length-5 mismatch edge changed')
    require(classify(b'xxxxxxxxx') == 2, 'Length-9 mismatch edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_site': CALL_SITE,
        'tag_edges': {'input': 0, 'gas_limit': 1, 'other': 2},
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
        print('Foundation keyword-classifier-gas evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
