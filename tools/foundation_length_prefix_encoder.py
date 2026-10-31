#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 length-prefix-encoder evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: it writes a length-prefixed header plus one
payload byte and returns the total length. The header constants' meaning is
not claimed anywhere. The payload is a single byte in every path; in the
third path it lands at offset 3 and overwrites the dword header's top byte,
so the observable output there is 4 bytes, not 5.
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
START, END = 0x55716a0, 0x557170a
PAD_END = 0x5571710
BODY = bytes.fromhex(
    'f30f1efa4883f91f771e8d0ccd01000000be01000000b802000000880f0fb612881437c3'
    '0f1f40004881f9ff0f0000761fc1e104be03000000b80400000083c10d890f0fb612881437'
    'c3660f1f440000c1e104be02000000b80300000083c10566890f0fb612881437c3')
PAD = b'\xcc' * 6
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000c8142d00bcec5b046a00000000000000')
CALLER_FDE = bytes.fromhex(
    'a000000088172d004c0d5c049905000000420e108f02450e188e03450e208d04480e288c05'
    '410e308606410e388307470e90010350010a0e38410e30410e28420e20420e18420e10420'
    'e08490b02df0e9801480ea001420ea801440eb001470eb801410ec0015e0e90010351010a'
    '0e38410e30410e28420e20420e18420e10420e08420b02bc0e98014c0ea001420ea801440eb'
    '001470eb801410ec0015e0e9001000000')
NEXT_FDE_HEAD = bytes.fromhex('68000000dc142d0018ed5b046f05000000460e108f')
CALLER_START, CALLER_END = 0x55739f0, 0x5573f89
CALL_SITE = 0x5573e2b


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encode(length, payload):
    """Decoded formula of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The first path's header uses
    8-bit cl, the second 16-bit cx, the third 32-bit ecx — so the third
    path truncates lengths above 2^32, while the first two paths take the
    full 64-bit length (their thresholds keep the products small).
    """
    if length <= 0x1f:
        return bytes([(length * 8 + 1) & 0xff, payload]), 2
    if length <= 0xfff:
        header = (length * 16 + 5) & 0xffff
        return header.to_bytes(2, 'little') + bytes([payload]), 3
    header = ((((length & 0xffffffff) << 4) + 13) & 0xffffffff)
    # The payload store at offset 3 overwrites the dword header's top byte,
    # so the observable output is 4 bytes: header bytes 0-2 plus payload.
    return header.to_bytes(4, 'little')[:3] + bytes([payload]), 4


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
    require(body == BODY, 'Length-prefix-encoder instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x2d14c4, FDE, START, END),
                                    (0x2d1784, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # The next FDE starts exactly at the stride end; its head bytes are
    # locked here (its full record is retained in frames.txt, not re-decoded).
    require(read(eh['address'] + 0x2d14d8, len(NEXT_FDE_HEAD)) == NEXT_FDE_HEAD,
            'Next FDE record changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x55716a0.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'endbr64 changed')
    require(body[4:8] == bytes.fromhex('4883f91f'), 'Length-0x1f compare changed')
    require(body[8:10] == bytes.fromhex('771e'), 'Length-0x1f branch changed')
    require(body[10:17] == bytes.fromhex('8d0ccd01000000'), 'Path-1 header lea changed')
    require(body[17:22] == bytes.fromhex('be01000000'), 'Path-1 index changed')
    require(body[22:27] == bytes.fromhex('b802000000'), 'Path-1 return changed')
    require(body[27:29] == bytes.fromhex('880f'), 'Path-1 header store changed')
    require(body[29:32] == bytes.fromhex('0fb612'), 'Payload load changed')
    require(body[32:35] == bytes.fromhex('881437'), 'Payload store changed')
    require(body[35:36] == bytes.fromhex('c3'), 'Path-1 ret changed')
    require(body[36:40] == bytes.fromhex('0f1f4000'), 'Path-1 gap nop changed')
    require(body[40:47] == bytes.fromhex('4881f9ff0f0000'), 'Length-0xfff compare changed')
    require(body[47:49] == bytes.fromhex('761f'), 'Length-0xfff branch changed')
    require(body[49:52] == bytes.fromhex('c1e104'), 'Path-3 shift changed')
    require(body[52:57] == bytes.fromhex('be03000000'), 'Path-3 index changed')
    require(body[57:62] == bytes.fromhex('b804000000'), 'Path-3 return changed')
    require(body[62:65] == bytes.fromhex('83c10d'), 'Path-3 header add changed')
    require(body[65:67] == bytes.fromhex('890f'), 'Path-3 header store changed')
    require(body[73:74] == bytes.fromhex('c3'), 'Path-3 ret changed')
    require(body[74:80] == bytes.fromhex('660f1f440000'), 'Path-3 gap nop changed')
    require(body[80:83] == bytes.fromhex('c1e104'), 'Path-2 shift changed')
    require(body[83:88] == bytes.fromhex('be02000000'), 'Path-2 index changed')
    require(body[88:93] == bytes.fromhex('b803000000'), 'Path-2 return changed')
    require(body[93:96] == bytes.fromhex('83c105'), 'Path-2 header add changed')
    require(body[96:99] == bytes.fromhex('66890f'), 'Path-2 header store changed')
    require(body[105:106] == bytes.fromhex('c3'), 'Path-2 ret changed')
    # Caller call bytes and argument setup come before the incoming scan, so
    # a mutated call site reports its own check rather than the scan's.
    call = read(CALL_SITE, 5)
    require(call == bytes.fromhex('e870d8ffff'), 'Caller call bytes changed')
    require(CALL_SITE + 5 + struct.unpack_from('<i', call, 1)[0] == START,
            'Caller call target changed')
    require(read(0x5573e20, 5) == bytes.fromhex('488b742408'),
            'Caller payload-pointer setup changed')
    require(read(0x5573e25, 3) == bytes.fromhex('4c89d2'),
            'Caller length setup changed')
    require(read(0x5573e28, 3) == bytes.fromhex('4c89e7'),
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
    require(encode(0, 0x41) == (b'\x01A', 2), 'Zero-length edge changed')
    require(encode(0x1f, 0x00) == (b'\xf9\x00', 2), 'Path-1 top edge changed')
    require(encode(0x20, 0x00) == (b'\x05\x02\x00', 3), 'Path-2 bottom edge changed')
    require(encode(0xfff, 0x00) == (b'\xf5\xff\x00', 3), 'Path-2 top edge changed')
    require(encode(0x1000, 0x00) == (b'\x0d\x00\x01\x00', 4), 'Path-3 bottom edge changed')
    require(encode(0x100000001, 0x00) == (b'\x1d\x00\x00\x00', 4),
            'Path-3 truncation edge changed')
    require(encode(0xffffffff, 0x00) == (b'\xfd\xff\xff\x00', 4),
            'Path-3 wrap edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_site': CALL_SITE,
        'path_edges': {'path1_top': 0x1f, 'path2_top': 0xfff},
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 length-prefix-'
                    'encoder evidence packet.')
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
        print('Foundation length-prefix-encoder evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
