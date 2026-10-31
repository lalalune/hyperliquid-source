#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 two-table lookup evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
Table contents are deliberately not claimed: only the gate, the index
arithmetic, and the table base addresses are locked.
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
START, END = 0x5560660, 0x55606a8
NEXT_START, NEXT_END = 0x55606b0, 0x55606cb
CALLER_START, CALLER_END = 0x55c84f0, 0x55c8bc3
CALL_SITE = 0x55c8554
TABLE1, TABLE2 = 0x576d9e0, 0x576db20
BODY = bytes.fromhex(
    'f30f1efa8d47fd83f802770583fe01741f4863d24863ff488d0492488d1447488d055ad32000'
    '488b04d0c30f1f4400004863d24898488d14524801d0488d157dd42000488b04c2c3')
PAD = b'\xcc' * 8
# Raw FDE records at .eh_frame offsets, decoded below (zR pcrel sdata4).
FDE = bytes.fromhex('100000000c012d0038f05a044800000000000000')
NEXT_FDE = bytes.fromhex('1000000020012d0074f05a041b00000000000000')
CALLER_FDE = bytes.fromhex(
    '7c000000f83b2d00dc336104d306000000460e108f02450e188e03420e208d04480e288c0549'
    '0e308606440e388307470e6003cd020a0e38470e30440e28450e20420e18420e10420e08440b0'
    '389030a0e38410e30410e28420e20420e18420e10420e08410b580a0e38410e30410e28420e20'
    '420e18420e10420e08410b0000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def s32(value):
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def lookup(edi, esi, edx):
    """Return (table, index) for the window's rule, indices sign-extended.

    edi/esi are compared as low 32 bits; edx is sign-extended for the index.
    Table contents are unknown, so only the table choice and index are given.
    """
    gate = (edi - 3) & 0xFFFFFFFF
    if gate <= 2 and (esi & 0xFFFFFFFF) == 1:
        return ('table2', s32(gate) + 3 * s32(edx))
    return ('table1', s32(edi) + 10 * s32(edx))


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
    require(body == BODY, 'Two-table lookup window changed')
    require(read(END, 8) == PAD, 'Window padding changed')
    eh = by_name['.eh_frame']
    for offset, raw, start, end in [(0x2d0108, FDE, START, END),
                                    (0x2d011c, NEXT_FDE, NEXT_START, NEXT_END),
                                    (0x2d3bf4, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # CIE pointer field points back to the CIE at section offset 0.
        require(struct.unpack_from('<I', record, 4)[0] == offset + 4,
                'FDE CIE pointer changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    # Instruction-level locks at fixed body offsets.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'endbr64 changed')
    require(body[4:7] == bytes.fromhex('8d47fd'), 'lea -3(%rdi) changed')
    require(body[7:10] == bytes.fromhex('83f802'), 'cmp $2 changed')
    require(body[10:12] == bytes.fromhex('7705'), 'ja target changed')
    require(body[12:15] == bytes.fromhex('83fe01'), 'cmp $1,%esi changed')
    require(body[15:17] == bytes.fromhex('741f'), 'je target changed')
    require(body[17:20] == bytes.fromhex('4863d2'), 'table1 movslq edx changed')
    require(body[20:23] == bytes.fromhex('4863ff'), 'table1 movslq edi changed')
    require(body[23:27] == bytes.fromhex('488d0492'), 'table1 lea 5*edx changed')
    require(body[27:31] == bytes.fromhex('488d1447'), 'table1 lea edi+10*edx changed')
    require(struct.unpack_from('<i', body, 34)[0] == 0x20d35a,
            'table1 lea displacement changed')
    require(0x5560686 + 0x20d35a == TABLE1, 'table1 base arithmetic changed')
    require(body[38:42] == bytes.fromhex('488b04d0'), 'table1 mov load changed')
    require(body[42:43] == b'\xc3', 'table1 ret changed')
    require(body[43:48] == bytes.fromhex('0f1f440000'), 'in-body nopl changed')
    require(body[48:51] == bytes.fromhex('4863d2'), 'table2 movslq edx changed')
    require(body[51:53] == bytes.fromhex('4898'), 'table2 cltq changed')
    require(body[53:57] == bytes.fromhex('488d1452'), 'table2 lea 3*edx changed')
    require(body[57:60] == bytes.fromhex('4801d0'), 'table2 add changed')
    require(struct.unpack_from('<i', body, 63)[0] == 0x20d47d,
            'table2 lea displacement changed')
    require(0x55606a3 + 0x20d47d == TABLE2, 'table2 base arithmetic changed')
    require(body[71:72] == b'\xc3', 'table2 ret changed')
    # Both table bases live in .data.rel.ro; contents are not claimed.
    relro = by_name['.data.rel.ro']
    for table in (TABLE1, TABLE2):
        require(relro['address'] <= table < relro['address'] + relro['size'],
                'Table base outside .data.rel.ro')

    # No relocation record of any type names this window as addend.
    for secname in ('.rela.dyn', '.rela.plt'):
        sec = by_name[secname]
        require(sec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(sec['address'], sec['size'])
        for off in range(0, len(raw), 24):
            _address, _info, addend = struct.unpack_from('<QQq', raw, off)
            require(addend != START, 'Unexpected naming relocation')

    # This byte-pattern scan is explicitly NOT a complete xref census. Linear
    # disassembly from the caller FDE start validates the one retained site.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    hits = []
    for i in range(len(code) - 5):
        if code[i] == 0xe8:
            rel = struct.unpack_from('<i', code, i + 1)[0]
            if text['address'] + i + 5 + rel == START:
                hits.append(text['address'] + i)
    require(hits == [CALL_SITE], 'Direct caller set changed')
    require(read(CALL_SITE, 5) == bytes.fromhex('e80781f9ff'), 'Call bytes changed')
    caller_txt = (ROOT / 'research/work-items/foundation-two-table-lookup-94'
                  / 'caller.objdump.txt').read_text()
    require('55c8554:\te8 07 81 f9 ff' in caller_txt, 'Retained caller line changed')

    return dict(window=hex(START), fde_end=hex(END), next_fde=hex(NEXT_START),
                caller=hex(CALL_SITE), table1=hex(TABLE1), table2=hex(TABLE2),
                body_sha256=hashlib.sha256(body).hexdigest())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', metavar='EVIDENCE')
    parser.add_argument('--binary', default=str(TARGET))
    args = parser.parse_args()
    data = Path(args.binary).read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    found = analyze(data)
    if args.check:
        retained = json.loads(Path(args.check).read_text())
        for key, value in retained.items():
            if key in found:
                require(found[key] == value, 'Retained evidence mismatch: ' + key)
    print('Foundation two-table lookup evidence reproduces exactly.')


if __name__ == '__main__':
    main()
