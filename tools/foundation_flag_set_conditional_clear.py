#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 flag-set plus conditional clear packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window is a flag-set plus conditional clear: rdi = base pointer. It loads
the pointer field [rdi+0x1a0] into rax, stores 1 into the dword field
[rdi+0x108], and when the loaded pointer is non-null writes 0 into the byte
it points at. No return value is claimed: rax holds the pointer or 0 on exit.
What the fields mean, and what reads the flag or the cleared byte, is not
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
START, END = 0x53cf560, 0x53cf57e
PAD_END = 0x53cf580
BRANCH_TARGET = 0x53cf57d
BODY = bytes.fromhex('f30f1efa488b87a0010000c78708010000010000004885c07403c60000c3')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE0 = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
CALLER_CIE = bytes.fromhex('1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000')
FDE = bytes.fromhex('1000000044672b00007943041e00000000000000')
NEXT = bytes.fromhex('2400000058672b000c7943046e00000000450e108602440e188303470e20025b0e18410e10410e08')
CALLER_FDES = [
    (0x637a80,
     '58000000b4740100a06ae8031d0a00000432108cff450e108602430d06448f038e044b8d058c064483070350012e1002d32e0002f72e1002e32e0002660a0c0708420b0346012e500343012e000354012e1002932e00682e10482e00',
     0x519fa40, 0x51a045d),
    (0x637d54,
     '5c00000088770100dc96e8038913000004e20e8cff450e108602460d06508f038e048d058c0683070367042e100375022e000398012e1002d12e000332010a0c0708460b024c2e1002d82e00031a012e105b2e000350032e500353012e000000',
     0x51a2950, 0x51a3cd9),
    (0x6396f8,
     '540000002c9101007881eb03191000000409088cff450e108602430d06488f038e048d058c0644830703da022e800102bc2e00037e012e30782e000356020a0c07084a0b03d8032e1002672e000378012e30027e2e000000',
     0x51d2d90, 0x51d3da9),
    (0x639e8c,
     '54000000c0980100a439ec03690e0000046f048cff460e108f02420e188e03420e208d04420e288c05410e308606410e388307470eb8204c0ec0210365060a0e38410e30410e28420e20420e18420e10420e08480b000000',
     0x51ded50, 0x51dfbb9),
    (0x653b20,
     '4800000054350300904a0304d81f0000049d418bff450e108602460d06498f038e048d058c068307037a012e10752e00026a0a0c0708410b0361052e3002402e0003ae052e60029e2e000000',
     0x5369ad0, 0x536baa8),
    (0x654344,
     '58000000783d03004c460404b13e0000046a408bff450e108602430d06748f038e048d058c06830703d3010a0c0708410b0397012e1002772e0003290a2e10782e0002f12e1002442e0003a9122e3002582e0003b80d2e1002cd2e00',
     0x5379eb0, 0x537dd61),
    (0x657fc4,
     '30000000f8790300ac6e0904bd0000000495278bff450e1083024d0e30570e38450e40550e38410e30024e0a0e10430e084b0b00',
     0x53d0390, 0x53d044d),
]
CALLERS = [
    (0x51a018c, 'e8cff32200', 0x519fa40, 0x51a045d),
    (0x51a3bd0, 'e88bb92200', 0x51a2950, 0x51a3cd9),
    (0x51d3c4e, 'e80db91f00', 0x51d2d90, 0x51d3da9),
    (0x51df28d, 'e8ce021f00', 0x51ded50, 0x51dfbb9),
    (0x536b50c, 'e84f400600', 0x5369ad0, 0x536baa8),
    (0x537d1a0, 'e8bb230500', 0x5379eb0, 0x537dd61),
    (0x53d0433, 'e828f1ffff', 0x53d0390, 0x53d044d),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(ptr_is_null):
    """Decoded rule, for edge checks only.

    A Python restatement of the retained instruction sequence, not a run or
    emulation of the captured binary. Returns (flag_set, byte_cleared): the
    flag dword is always set to 1, and the pointed-to byte is cleared
    exactly when the loaded pointer is non-null.
    """
    return (True, not ptr_is_null)


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    require(len(data) == 91774280, 'Target size changed')
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
    require(body == BODY, 'Flag-set-conditional-clear instruction window changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x0, len(CIE0)) == CIE0, 'CIE at offset 0 changed')
    require(read(eh['address'] + 0x6205d0, len(CALLER_CIE)) == CALLER_CIE,
            'Caller CIE changed')
    for offset, raw, start, end in [
            (0x2b6740, FDE, START, END),
            (0x2b6754, NEXT, PAD_END, 0x53cf5ee)] + [
            (off, bytes.fromhex(raw), s, e) for off, raw, s, e in CALLER_FDES]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
    # Padding: two int3 bytes between the FDE end and the next FDE start.
    require(read(END, PAD_END - END) == b'\xcc' * 2, 'Padding changed')
    require(PAD_END == 0x53cf580, 'FDE stride end changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x53cf560.
    fixed = [
        (0, 'f30f1efa', 'Entry endbr64 changed'),
        (4, '488b87a0010000', 'Pointer field load changed'),
        (11, 'c7870801000001000000', 'Flag store changed'),
        (21, '4885c0', 'Pointer test changed'),
        (24, '7403', 'Null branch changed'),
        (26, 'c60000', 'Conditional byte clear changed'),
        (29, 'c3', 'Return changed'),
    ]
    for off, raw, message in fixed:
        require(body[off:off + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                message)
    # The branch lands exactly on the ret: je at START+24 is 2 bytes, so
    # target = START+24+2+disp.
    disp_null = struct.unpack_from('<b', body, 25)[0]
    require(START + 24 + 2 + disp_null == BRANCH_TARGET, 'Null branch target changed')
    # No call opcode inside the window.
    require(b'\xe8' not in body, 'Unexpected call opcode in window')
    # Relocations: no record of any type names this window as addend.
    naming = []
    for sec in secs:
        if sec['name'].startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((sec['name'], address))
    require(naming == [], 'Unexpected relocation naming this window')
    # Incoming calls: direct e8 call sites anywhere in .text, each with its
    # locked call bytes and caller FDE range.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [site for site, _, _, _ in CALLERS],
            'Incoming direct calls changed')
    for site, raw, fde_start, fde_end in CALLERS:
        require(read(site, 5) == bytes.fromhex(raw), 'Caller call bytes changed')
        require(fde_start <= site < fde_end, 'Caller site outside its FDE')
    # Decoded-rule edges, hand-computed from the retained bytes (not execution).
    require(parse(True) == (True, False), 'Null-pointer edge changed')
    require(parse(False) == (True, True), 'Non-null-pointer edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'relocation_slots': [[name, hex(addr)] for name, addr in naming],
        'direct_callers': direct,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'flag-set plus conditional clear evidence packet.')
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
        require(retained['function']['padding_bytes'] == 2, 'Retained padding changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(c) for c in result['direct_callers']],
                'Retained callers changed')
        require(retained['incoming_pattern_scan']['relocation_slots'] ==
                result['relocation_slots'], 'Retained relocation slots changed')
        print('Foundation flag-set-conditional-clear evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
