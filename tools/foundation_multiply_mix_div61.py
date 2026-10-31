#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 multiply-mix divide-by-61 packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window unconditionally updates a 64-bit state word with a multiply-add
mix, indexes a 64-byte .rodata table by the mix's top 6 bits, multiplies the
table byte by a sign-extended 32-bit field, divides that product by 61 with a
mulhi idiom, stores the quotient's low 32 bits, and returns 1.

The divide-by-61 claim is not taken from the scout note on trust: the builder
re-verified the mulhi tail numerically, with 0 mismatches on 55,003 values
(including the full 64-bit range) for the full quotient, and 0 mismatches on
20,000 realistic table-byte times sign-extended-field combinations for the
stored low 32 bits. The product is treated as u64 by the unsigned mul, so a
negative sign-extended field still divides as a large u64 value; the store is
32-bit, so only the quotient's low 32 bits are written.

This window is bound ALONE. No census of similar windows is claimed.
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
START, END = 0x5553fe0, 0x5554037
BODY = bytes.fromhex(
    '48b82d7f954c2df45158480faf06488d0d8bd12afb48ba4f8167f77e7b05144c63'
    '47044801d048890648c1e83a0fb6340148b811aca3cdfb14970c490faff048f7e6'
    'b8010000004829d648d1ee4801f248c1ea058917c3')
STRIDE_END = 0x5554040
PADDING = bytes.fromhex('cccccccccccccccccc')
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# The window CIE and FDE encodings are zR: initial_location is a 4-byte
# signed PC-relative value under the CIE's zR encoding; range is a 4-byte
# unsigned value. The next FDE belongs to the same zR CIE; its raw bytes are
# locked and its range is the GNU-decoded value, not a hand re-derivation.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000e8ef2c00dc3a5a045700000000000000')
NEXT_FDE = bytes.fromhex(
    '48000000fcef2c00283b5a04d102000000420e108f024a0e188e03450e208d04450'
    'e288c05440e308606410e388307440e7003a2020a0e38410e30410e28420e20420'
    'e18420e10420e08410b')
TABLE_BASE = 0x801180
TABLE = bytes.fromhex(
    'fed3bba99c90877f78716b66615d5955514d4a4744413e3c39373532302e2c2a28'
    '27252321201e1d1b1a181715141312100f0e0d0c0a09080706050403020100')
C_MULT = 0x5851f42d4c957f2d
C_ADD = 0x14057b7ef767814f
DIV_MAGIC = 0xc9714fbcda3ac11
CALLERS = [
    # (site, call bytes, caller FDE range)
    (0x555585d, bytes.fromhex('e87ee7ffff'), (0x5554b50, 0x5555bcc)),
    (0x5556412, bytes.fromhex('e8c9dbffff'), (0x5555bd0, 0x555661f)),
    (0x5556f7e, bytes.fromhex('e85dd0ffff'), (0x55566f0, 0x5557058)),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def apply_window(old_state, field_i32):
    """Decoded rule of the window, for edge checks only.

    This is a Python restatement of the retained instructions, not a run or
    emulation of the captured binary. field_i32 is the signed 32-bit value at
    rdi+0x4, sign-extended by movslq before the multiply. Returns
    (new_state, table_index, stored_u32, return_value).
    """
    mixed = (C_MULT * (old_state % (1 << 64)) + C_ADD) % (1 << 64)
    idx = mixed >> 58
    table_byte = TABLE[idx]
    product = (table_byte * (field_i32 % (1 << 64))) % (1 << 64)
    quotient = product // 61
    return mixed, idx, quotient % (1 << 32), 1


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
    require(body == BODY, 'Multiply-mix instruction window changed')
    require(read(END, STRIDE_END - END) == PADDING,
            'Stride padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2cefe4, FDE, START, END)
    check_fde(0x2ceff8, NEXT_FDE, STRIDE_END, STRIDE_END + 721)
    # Table base and contents in .rodata.
    require(read(TABLE_BASE, len(TABLE)) == TABLE, 'Lookup table changed')
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x5553fe0. The window has no
    # endbr64: it starts directly with movabs.
    require(body[0:10] == bytes.fromhex('48b82d7f954c2df45158'),
            'Mix multiplier movabs changed')
    require(struct.unpack_from('<Q', body, 2)[0] == C_MULT,
            'Mix multiplier value changed')
    require(body[10:14] == bytes.fromhex('480faf06'), 'State imul changed')
    require(body[14:21] == bytes.fromhex('488d0d8bd12afb'),
            'Table base lea changed')
    require(struct.unpack_from('<i', body, 17)[0] == -0x4d52e75,
            'Table base displacement changed')
    require(0x5553ff5 + struct.unpack_from('<i', body, 17)[0] == TABLE_BASE,
            'Table base target changed')
    require(body[21:31] == bytes.fromhex('48ba4f8167f77e7b0514'),
            'Mix addend movabs changed')
    require(struct.unpack_from('<Q', body, 23)[0] == C_ADD,
            'Mix addend value changed')
    require(body[31:35] == bytes.fromhex('4c634704'), 'Field movslq changed')
    require(body[34] == 0x04, 'Field offset changed')
    require(body[35:38] == bytes.fromhex('4801d0'), 'Mix add changed')
    require(body[38:41] == bytes.fromhex('488906'), 'State store changed')
    require(body[41:45] == bytes.fromhex('48c1e83a'), 'Index shift changed')
    require(body[44] == 0x3a, 'Index shift amount changed')
    require(body[45:49] == bytes.fromhex('0fb63401'), 'Table byte load changed')
    require(body[49:59] == bytes.fromhex('48b811aca3cdfb14970c'),
            'Division magic movabs changed')
    require(struct.unpack_from('<Q', body, 51)[0] == DIV_MAGIC,
            'Division magic value changed')
    require(body[59:63] == bytes.fromhex('490faff0'), 'Product imul changed')
    require(body[63:66] == bytes.fromhex('48f7e6'), 'Division mul changed')
    require(body[66:71] == bytes.fromhex('b801000000'), 'Return 1 changed')
    require(body[71:74] == bytes.fromhex('4829d6'), 'Div tail sub changed')
    require(body[74:77] == bytes.fromhex('48d1ee'), 'Div tail shr 1 changed')
    require(body[77:80] == bytes.fromhex('4801f2'), 'Div tail add changed')
    require(body[80:84] == bytes.fromhex('48c1ea05'), 'Div tail shr 5 changed')
    require(body[84:86] == bytes.fromhex('8917'), 'Quotient store changed')
    require(body[86:87] == bytes.fromhex('c3'), 'Window ret changed')
    # Data edge: no relocation record of any type in any .rela.* section
    # names this window as addend (full-section scan).
    naming = []
    for name, sec in by_name.items():
        if name.startswith('.rela.') and sec['size'] % 24 == 0:
            raw = read(sec['address'], sec['size'])
            for off in range(0, len(raw), 24):
                address, info, addend = struct.unpack_from('<QQq', raw, off)
                if addend == START:
                    naming.append((address, info & 0xffffffff))
    require(naming == [], 'Naming relocation changed')
    # Incoming calls: exactly three direct e8 calls in .text. This is a
    # byte-pattern scan, explicitly not a complete xref census. The sites
    # were confirmed as instruction starts by linear disassembly from their
    # caller FDE starts with GNU objdump; the checker pins the call bytes,
    # the rel32 targets, and caller-FDE containment.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [c[0] for c in CALLERS], 'Incoming direct calls changed')
    for site, call_bytes, (fde_start, fde_end) in CALLERS:
        require(read(site, 5) == call_bytes, 'Caller call bytes changed')
        rel = struct.unpack_from('<i', call_bytes, 1)[0]
        require(site + 5 + rel == START, 'Caller call target changed')
        require(fde_start <= site < fde_end, 'Caller FDE containment changed')
    # Decoded-rule edges (restatement of the retained bytes, not execution).
    require(apply_window(0, 0) == (C_ADD, 5, 0, 1), 'Zero-field edge changed')
    require(apply_window(0, 61) == (C_ADD, 5, 144, 1),
            'Field-61 edge changed')
    require(apply_window(0, -1)[2] == 4013330093,
            'Negative-field edge changed')
    require(apply_window(0, 1)[2] == 2, 'Field-1 edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': direct,
        'naming': naming,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 '
                    'multiply-mix divide-by-61 evidence packet.')
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
        require(retained['incoming_pattern_scan']['e8_candidates']
                == [hex(v) for v in result['call_sites']], 'Retained callers changed')
        require(retained['naming_relocation']['slot'] is None,
                'Retained naming slot changed')
        require(retained['naming_relocation']['type'] is None,
                'Retained naming type changed')
        print('Foundation multiply-mix-div61 evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
