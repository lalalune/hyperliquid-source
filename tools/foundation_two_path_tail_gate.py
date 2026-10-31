#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 two-path tail-gate evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window reads two bytes from the struct at rdi: byte+0x15 selects the path
and byte+0xd40 confirms the first path. Tag 3 with confirmation tail-jumps with
rdi+0x60; tag 4 tail-jumps with rdi+0x20; anything else returns without a jump.
The tail targets are named, not decoded, and what the fields mean is not
claimed anywhere.
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
START, END = 0x1fc7780, 0x1fc77aa
PAD_END = 0x1fc77b0
BODY = bytes.fromhex(
    '0fb6471583f803740e83f804751b4883c720e9f922feff80bf400d000003'
    '75094883c760e97744feffc3')
PAD = b'\xcc' * 6
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000024a1040040c129012a00000000000000')
FDE_OFFSET = 0x4a120
NEXT_FDE_OFFSET = 0x389b38
NEXT_START, NEXT_END = 0x1fc77b0, 0x1fc7859
# Tail targets, named and locked as FDE starts, explicitly not decoded.
TAIL20 = 0x1fa9a90
TAIL20_FDE_OFFSET = 0x383390
TAIL20_END = 0x1fa9b3a
TAIL60 = 0x1fabc20
TAIL60_FDE_OFFSET = 0x383cb4
TAIL60_END = 0x1fabcbc
# (FDE offset, FDE start, FDE end, call site, call bytes, setup bytes)
CALLERS = [
    (0x395958, 0x2033080, 0x2034eae, 0x2034d5a, bytes.fromhex('e8212af9ff')),
    (0x3959fc, 0x2035170, 0x2036453, 0x203636b, bytes.fromhex('e81014f9ff')),
    (0x395aa0, 0x20367d0, 0x2037936, 0x203784e, bytes.fromhex('e82dfff8ff')),
    (0x395bec, 0x203a190, 0x203c0bb, 0x203bf67, bytes.fromhex('e814b8f8ff')),
]
SETUP = bytes.fromhex('4c89ef')  # mov %r13,%rdi, immediately before each call


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gate(tag, confirm):
    """Decoded gate of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. Tag 4 tail-jumps with rdi+0x20
    regardless of the confirmation byte; tag 3 tail-jumps with rdi+0x60 only
    when the confirmation byte is also 3; anything else returns.
    """
    if tag == 4:
        return ('tail20', TAIL20)
    if tag == 3 and confirm == 3:
        return ('tail60', TAIL60)
    return ('ret', None)


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
    require(body == BODY, 'Two-path tail-gate instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    record = read(eh['address'] + FDE_OFFSET, len(FDE))
    require(record == FDE, 'FDE record changed')
    pc = eh['address'] + FDE_OFFSET + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require((pc, pc + extent) == (START, END), 'FDE PC/range changed')
    # The next FDE starts exactly at the stride end; decode and lock its
    # PC/range (its full record is retained in frames.txt, not re-decoded).
    nrec = read(eh['address'] + NEXT_FDE_OFFSET, 20)
    npc = eh['address'] + NEXT_FDE_OFFSET + 8 + struct.unpack_from('<i', nrec, 8)[0]
    nextent = struct.unpack_from('<I', nrec, 12)[0]
    require((npc, npc + nextent) == (NEXT_START, NEXT_END),
            'Next FDE PC/range changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x1fc7780.
    require(body[0:4] == bytes.fromhex('0fb64715'), 'Tag load changed')
    require(body[4:7] == bytes.fromhex('83f803'), 'Tag-three compare changed')
    require(body[7:9] == bytes.fromhex('740e'), 'Jump-to-confirm changed')
    require(body[9:12] == bytes.fromhex('83f804'), 'Tag-four compare changed')
    require(body[12:14] == bytes.fromhex('751b'), 'Jump-to-return changed')
    require(body[14:18] == bytes.fromhex('4883c720'), 'Tag-four add changed')
    require(body[18:23] == bytes.fromhex('e9f922feff'), 'Tag-four tail jump changed')
    jmp20 = START + 18 + 5 + struct.unpack_from('<i', body, 19)[0]
    require(jmp20 == TAIL20, 'Tag-four tail target changed')
    require(body[23:30] == bytes.fromhex('80bf400d000003'),
            'Confirmation compare changed')
    require(body[30:32] == bytes.fromhex('7509'), 'Jump-to-return changed')
    require(body[32:36] == bytes.fromhex('4883c760'), 'Tag-three add changed')
    require(body[36:41] == bytes.fromhex('e97744feff'), 'Tag-three tail jump changed')
    jmp60 = START + 36 + 5 + struct.unpack_from('<i', body, 37)[0]
    require(jmp60 == TAIL60, 'Tag-three tail target changed')
    require(body[41:42] == bytes.fromhex('c3'), 'Return changed')
    # Tail targets are FDE starts, locked but not decoded.
    for off, start, end in ((TAIL20_FDE_OFFSET, TAIL20, TAIL20_END),
                            (TAIL60_FDE_OFFSET, TAIL60, TAIL60_END)):
        trec = read(eh['address'] + off, 20)
        tpc = eh['address'] + off + 8 + struct.unpack_from('<i', trec, 8)[0]
        textent = struct.unpack_from('<I', trec, 12)[0]
        require((tpc, tpc + textent) == (start, end), 'Tail FDE PC/range changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend (full-section scan: 80,022 .rela.dyn +
    # 278 .rela.plt entries).
    naming = []
    for relname in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[relname]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        for off in range(0, len(raw), 24):
            address, info, addend = struct.unpack_from('<QQq', raw, off)
            if addend == START:
                naming.append(address)
    require(naming == [], 'Naming relocation appeared')
    # Incoming calls: exactly four direct e8 calls (byte-pattern scan over
    # .text), each locked with its caller FDE record, call bytes, and the
    # mov %r13,%rdi setup immediately before the call.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [c[3] for c in CALLERS], 'Incoming direct calls changed')
    for off, cstart, cend, site, callbytes in CALLERS:
        crec = read(eh['address'] + off, 20)
        cpc = eh['address'] + off + 8 + struct.unpack_from('<i', crec, 8)[0]
        cent = struct.unpack_from('<I', crec, 12)[0]
        require((cpc, cpc + cent) == (cstart, cend), 'Caller FDE PC/range changed')
        require(read(site, 5) == callbytes, 'Caller call bytes changed')
        require(read(site - 3, 3) == SETUP, 'Caller argument setup changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(gate(3, 3) == ('tail60', TAIL60), 'Tag-3-confirmed edge changed')
    require(gate(3, 0) == ('ret', None), 'Tag-3-unconfirmed edge changed')
    require(gate(3, 4) == ('ret', None), 'Tag-3-wrong-confirm edge changed')
    require(gate(4, 0) == ('tail20', TAIL20), 'Tag-4 edge changed')
    require(gate(4, 3) == ('tail20', TAIL20), 'Tag-4-confirmed edge changed')
    require(gate(0, 0) == ('ret', None), 'Tag-0 edge changed')
    require(gate(5, 3) == ('ret', None), 'Tag-5 edge changed')
    require(gate(0xff, 0xff) == ('ret', None), 'Tag-max edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'callers': [c[3] for c in CALLERS],
        'tails': (TAIL20, TAIL60),
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 two-path tail-gate '
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
        require(retained['function']['sha256'] ==
                'd96fc09e8fe55fa0cc7a97a07c60a533b445104ef29a19aa98f98672bd2a82a1',
                'Retained body hash mismatch')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c[3]) for c in CALLERS], 'Retained callers changed')
        require(retained['data_edge']['relative_slots_naming_window'] == [],
                'Retained slots changed')
        print('Foundation two-path-tail-gate evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
