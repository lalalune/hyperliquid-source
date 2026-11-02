#!/usr/bin/env python3
"""Qualify the #94 order-wire decimal output preparation from ELF bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
MASK = (1 << 64) - 1
# FDE extents and exact body hashes qualify the manually decoded instruction path.
FUNCTIONS = {
    0x332ee40: (0x332f151, '0185415df3a32b56d7e0c60f48e8901cb28795b6c94f670f628a1a836d36e2cc'),
    0x332f160: (0x332f1e6, '42c41b01c53c7838e1eccb0a22ed7542d6e85c7e87bebde2b6dbb439f7954f50'),
    0x3330570: (0x3330900, 'f6b4a1c10d7c42c1a8fefc076610f510d1d26cc13eadb8d85f4a4e3ae2919ad8'),
    0x4eabb90: (0x4eac0d0, '5d39b8d57418bb0cae1589dbf036992a9a7163727060566dcd59577d4567fc6a'),
    0x4ead4f0: (0x4ead671, 'd4bdb6a49a23d453b788d83a1773c4cef5a35ae80dd2746e14db941c07d0a9a1'),
}
# These instruction starts are reviewed; the bytes and operands are read from the ELF.
BRANCHES = (0x33305fd, 0x333063e, 0x3330687, 0x33306cd,
            0x3330719, 0x3330766, 0x33307b2, 0x33307f8)
# (immediate VA, width, right shift, input pre-shift), corresponding to 10^1..10^8.
RECIPROCALS = ((0x33305ae, 4, 35, 0), (0x3330653, 4, 37, 0),
               (0x3330696, 4, 38, 0), (0x33306e1, 4, 45, 0),
               (0x333072c, 4, 39, 5), (0x333077b, 4, 50, 0),
               (0x33307be, 4, 54, 0), (0x333080a, 4, 57, 0))
ANCHORS = {
    0x333057b: '4885f60f8835030000',
    0x3330599: '31ff84c1740a4531c031f6e969020000',
    0x33305cf: '49ba9a999999999999194889c849f7e249bbcdcccccccccccccc490fafcb48d1c949be99999999999999194c39f1760d',
    0x3330812: '897c2420c74424240000000089742428448944242c',
    0x333086b: 'ff15ff50440284c0751d',
    0x332ee57: '488b77104c8b7f18',
    0x332ee90: '488dbc2480000000e8d3160000488dbc24980000004c89fee8c3160000',
    0x332f167: '488b7710488b5f18',
    0x332eeb7: '0f108424800000000f29442420488b842490000000',
    0x332eed1: '0f108424980000000f11442438488b8424a80000004889442448',
    0x332f011: '488d3526be25fd488d7c2408488d4c2420ba01000000e8d41d9500',
    0x332f03f: '488d4c2438488d35b1b825fd488d7c2408ba01000000e8a61d9500',
    0x3330842: '48c744244020000060',
    0x4ead507: '8b4e10440fb74616c1e91c83e101488d7c24184c89f631d2e86ce6ff',
    0x4eabbab: '8b3ec78424c400000000000000448b7604448b6e088b760c4489e809f04409f0',
    0x4eabc38: 'f7d8428d0c2883c13083fb200f83ec030000894c9c4448ffc3',
    0x4eabc8c: '31db89f8c1e810440fb6c04139d87628',
    0x4eabd49: '4489d1c6040c304c8d71014489742420c6440c012e4183ca02',
    0x4eabf50: '4183fa200f870f0100000f84390100004589d742c6043c2e',
    0x4eabe46: '4539d1751d4183fa200f87140200000f846c02000042c6040c3041ffc2',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require_target(data):
    if digest(data) != TARGET:
        raise ValueError('node #94 SHA-256 mismatch')


def read_va(data, rows, va, size, executable=False):
    if size < 0:
        raise ValueError('negative size')
    matches = [s for s in rows if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']
               and (not executable or s['flags'] & 4)]
    if len(matches) != 1:
        raise ValueError('address has no unique file-backed mapping')
    s = matches[0]
    off = s['offset'] + va - s['address']
    return data[off:off + size]


def decoded_call(data, rows, va):
    raw = read_va(data, rows, va, 5, True)
    if raw[0] != 0xe8:
        raise ValueError('expected direct call')
    return va + 5 + struct.unpack('<i', raw[1:])[0]


def qualify(data):
    require_target(data)
    rows = sections(data)
    _, extents, _ = fde_extents(data)
    fdes = {r['start']: r for r in extents}
    records = []
    for start, (end, expected) in sorted(FUNCTIONS.items()):
        f = fdes.get(start)
        if f is None or f['end'] != end:
            raise ValueError('unexpected FDE extent')
        body = read_va(data, rows, start, end - start, True)
        if digest(body) != expected:
            raise ValueError('unexpected function bytes')
        section = next(s for s in rows if s['type'] != 8 and s['flags'] & 4
                       and s['address'] <= start and end <= s['address'] + s['size'])
        file_offset = section['offset'] + start - section['address']
        records.append({'start_va': hex(start), 'file_offset': hex(file_offset), 'end_va_exclusive': hex(end),
                        'fde_va': hex(f['fde']), 'body_bytes': len(body),
                        'body_sha256': digest(body)})
    anchors = []
    for va, expected in sorted(ANCHORS.items()):
        raw = bytes.fromhex(expected)
        observed = read_va(data, rows, va, len(raw), True)
        if observed != raw:
            raise ValueError('instruction anchor mismatch')
        anchors.append({'va': hex(va), 'bytes': observed.hex()})
    branch_rows = []
    scale_sites = (0x3330602, 0x3330640, 0x3330689, 0x33306cf,
                   0x333071b, 0x3330768, 0x33307b4, 0x33307fa)
    for i, va in enumerate(BRANCHES):
        raw = read_va(data, rows, va, 2, True)
        if raw[0] != 0x76:
            raise ValueError('expected unsigned below-or-equal branch')
        move = read_va(data, rows, scale_sites[i], 5, True)
        if move[0] != 0xbf or int.from_bytes(move[1:], 'little') != (8-i) << 16:
            raise ValueError('unexpected scale immediate')
        branch_rows.append({'site_va': hex(va), 'bytes': raw.hex(),
                            'scale_move_va': hex(scale_sites[i]),
                            'taken_va': hex(va + 2 + struct.unpack('b', raw[1:])[0]),
                            'not_taken_scale': 8-i})
    route_specs = (
        (0x333057e, 0x33308b9, 'negative input panic'),
        (0x3330873, 0x3330892, 'formatter error panic'),
        (0x332ef74, 0x332efc3, 'first field writer error'),
        (0x332ef7b, 0x332efa0, 'serializer state clear'),
        (0x332efc1, 0x332f006, 'second field writer success'),
        (0x332f00b, 0x332ef7d, 'serializer state error'),
        (0x332f032, 0x332efc3, 'price writer error'),
        (0x332f039, 0x332ef7d, 'serializer state error'),
        (0x332f060, 0x332efc3, 'size writer error'),
        (0x332f06b, 0x332ef7d, 'serializer state error'),
        (0x332f092, 0x332efc3, 'next field writer error'),
        (0x332f0ad, 0x332efc3, 'order type writer error'),
        (0x332f0b6, 0x332f0d3, 'optional field absent'),
        (0x332f0cd, 0x332efc3, 'optional field writer error'),
    )
    routes = []
    for va, target, description in route_specs:
        head = read_va(data, rows, va, 2, True)
        if head[0] in (0x74, 0x75):
            raw = head
            delta = struct.unpack('b', raw[1:])[0]
        elif head[0] == 0x0f and head[1] in (0x84, 0x85, 0x88):
            raw = read_va(data, rows, va, 6, True)
            delta = struct.unpack('<i', raw[2:])[0]
        else:
            raise ValueError('unexpected route branch opcode')
        dest = va + len(raw) + delta
        if dest != target:
            raise ValueError('route branch target changed')
        routes.append({'site_va': hex(va), 'bytes': raw.hex(),
                       'taken_va': hex(dest), 'meaning': description})
    constants = []
    for k, (va, width, shift, pre) in enumerate(RECIPROCALS, 1):
        value = int.from_bytes(read_va(data, rows, va, width, True), 'little')
        d = 10**k >> pre
        error = d * value - (1 << shift)
        maximum = ((1 << 31) - 1) >> pre
        if not (0 <= error and error * maximum < 1 << shift):
            raise ValueError('reciprocal bound failed')
        constants.append({'k': k, 'immediate_va': hex(va), 'multiplier': value,
                          'divisor_after_pre_shift': d, 'pre_shift': pre,
                          'post_shift': shift, 'excess': error,
                          'max_input_after_pre_shift': maximum})
    magic = int.from_bytes(read_va(data, rows, 0x33305d1, 8, True), 'little')
    inverse = int.from_bytes(read_va(data, rows, 0x33305e1, 8, True), 'little')
    threshold = int.from_bytes(read_va(data, rows, 0x33305f2, 8, True), 'little')
    limb_bound = (10 * (1 << 32)) - 1
    if magic != ((1 << 64) + 9)//10 or (10*magic - (1 << 64))*limb_bound >= 1 << 64 or (inverse * 5) & MASK != 1 or threshold != MASK//10:
        raise ValueError('limb arithmetic constants mismatch')
    # Location uses a RELATIVE relocation: retain only the non-sensitive path suffix.
    location = 0x56e9a80
    relocations = []
    slot_relocations = []
    for sec in rows:
        if sec['type'] == 4:
            if sec['size'] % 24:
                raise ValueError('invalid RELA size')
            for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
                offset, info, addend = struct.unpack_from('<QQq', data, pos)
                if offset == location:
                    relocations.append((info, addend))
                if offset == 0x5775970:
                    slot_relocations.append((info, addend))
    if slot_relocations != [(8, 0x4ead4f0)] or decoded_call(data, rows, 0x4ead51f) != 0x4eabb90:
        raise ValueError('formatter call path changed')
    if len(relocations) != 1 or relocations[0][0] != 8:
        raise ValueError('unexpected Location path relocation')
    path_va = relocations[0][1]
    raw_loc = read_va(data, rows, location, 24)
    _, length, line, column = struct.unpack('<QQII', raw_loc)
    path = read_va(data, rows, path_va, length)
    if not path.endswith(b'l1/src/order_wire.rs') or (line, column) != (326, 35):
        raise ValueError('unexpected Location')
    location_record = {'record_va': hex(location), 'path_va': hex(path_va),
                       'path_suffix': 'l1/src/order_wire.rs', 'line': line, 'column': column}
    calls = []
    for va in (0x332ee98, 0x332eea8, 0x332f174, 0x332f181):
        target = decoded_call(data, rows, va)
        if target != 0x3330570:
            raise ValueError('unexpected converter call')
        calls.append({'site_va': hex(va), 'target_va': hex(target)})
    keys = []
    for site, target in ((0x332f011, 0x58ae3e), (0x332f044, 0x58a8fc)):
        raw = read_va(data, rows, site, 7, True)
        if raw[:3] != b'\x48\x8d\x35' or site + 7 + struct.unpack('<i', raw[3:])[0] != target:
            raise ValueError('unexpected key reference')
        keys.append({'lea_va': hex(site), 'key_va': hex(target),
                     'ascii': read_va(data, rows, target, 1).decode('ascii')})
    if [x['ascii'] for x in keys] != ['p', 's']:
        raise ValueError('unexpected field keys')
    return {'target_sha256': digest(data), 'functions': records, 'anchors': anchors, 'branches': branch_rows, 'route_branches': routes,
            'reciprocals': constants, 'low_limb_magic': magic,
            'divisibility_inverse': inverse, 'divisibility_threshold': threshold,
            'combined_limb_max': limb_bound,
            'calls': calls, 'keys': keys, 'negative_input_location': location_record,
            'formatter': {'slot_va': hex(0x5775970), 'target_va': hex(slot_relocations[0][1]),
                          'digit_builder_call_va': hex(0x4ead51f),
                          'digit_builder_target_va': hex(decoded_call(data, rows, 0x4ead51f))}}


def prepare(x, qualified):
    """Hand-transcribed arithmetic path, qualified by exact function bytes.

    Returns a Decimal carrier (flags, high, low), or None for the signed guard.
    Formatting after the carrier is outside this numeric model.
    """
    if not 0 <= x <= MASK:
        raise ValueError('expected an unsigned 64-bit input')
    if x >> 63:
        return None
    if x == 0:
        return (0, 0, 0)
    original_hi = x >> 32
    hi, low = original_hi, x & 0xffffffff
    inverse = qualified['divisibility_inverse']
    threshold = qualified['divisibility_threshold']
    magic = qualified['low_limb_magic']
    for k, r in enumerate(qualified['reciprocals'], 1):
        qhi = ((original_hi >> r['pre_shift']) * r['multiplier']) >> r['post_shift']
        combined = ((hi - qhi * 10) << 32) | low
        v = (combined * inverse) & MASK
        rotated = (v >> 1) | ((v & 1) << 63)
        if rotated > threshold:
            return ((9-k) << 16, hi, low)
        low = (combined * magic) >> 64
        hi = qhi
    return (0, hi, low)

def interpret(data, rows, x, coverage=None):
    """Interpret the closed, register-only arithmetic span from its actual bytes.

    Unsupported opcode, memory operand, escape or excessive steps fails closed.
    This is a static interpreter; it never invokes the captured executable.
    """
    if not 0 <= x <= MASK:
        raise ValueError('expected an unsigned 64-bit input')
    start, end = 0x333057b, 0x3330827
    code = read_va(data, rows, start, end-start, True)
    regs = [0] * 16
    regs[6] = x  # rsi
    flags = {'z': False, 'c': False, 's': False, 'o': False}
    pc = start

    def mark(va, condition):
        if coverage is not None:
            row = coverage.setdefault(va, {'taken': 0, 'not_taken': 0})
            row['taken' if condition else 'not_taken'] += 1

    def read(r, bits):
        return regs[r] & ((1 << bits)-1)

    def write(r, bits, value):
        value &= (1 << bits)-1
        if bits == 64 or bits == 32:
            regs[r] = value
        else:
            regs[r] = (regs[r] & ~((1 << bits)-1)) | value

    def set_logic(value, bits):
        value &= (1 << bits)-1
        flags.update(z=value == 0, s=bool(value & (1 << (bits-1))), c=False, o=False)

    def invalidate_flags():
        flags.update(z=None, c=None, s=None, o=None)

    def flag(name):
        if flags[name] is None:
            raise ValueError('branch uses unmodelled flags')
        return flags[name]

    def set_sub(a, b, bits):
        mask = (1 << bits)-1
        result = (a-b) & mask
        flags.update(z=result == 0, s=bool(result & (1 << (bits-1))),
                     c=a < b, o=bool(((a ^ b) & (a ^ result)) & (1 << (bits-1))))

    for _ in range(512):
        if pc == 0x33308b9:
            return None
        if pc == 0x3330812:
            return (read(7, 32), read(8, 32), read(6, 32))
        if not start <= pc < end:
            raise ValueError('control flow escaped arithmetic span')
        pos = pc-start

        def take(n):
            nonlocal pos
            if pos+n > len(code):
                raise ValueError('truncated instruction')
            value = code[pos:pos+n]
            pos += n
            return value

        def imm(n, signed=False):
            return int.from_bytes(take(n), 'little', signed=signed)

        rex = 0
        op = imm(1)
        if 0x40 <= op <= 0x4f:
            rex = op
            op = imm(1)
        w = 64 if rex & 8 else 32

        def modrm(allow_lea=False):
            m = imm(1)
            mod, reg, rm = m >> 6, ((m >> 3) & 7) | ((rex & 4) << 1), (m & 7) | ((rex & 1) << 3)
            if mod == 3:
                return reg, rm, None
            if not allow_lea:
                raise ValueError('unexpected memory operand')
            base_low = m & 7
            if base_low == 4:
                sib = imm(1)
                scale = 1 << (sib >> 6)
                index_low = (sib >> 3) & 7
                index = index_low | ((rex & 2) << 2)
                base_low = sib & 7
                base = base_low | ((rex & 1) << 3)
                index_value = 0 if index_low == 4 and not rex & 2 else regs[index]*scale
            else:
                base = rm
                index_value = 0
            if mod == 0 and base_low == 5:
                raise ValueError('unsupported displacement-only address')
            displacement = imm(1, True) if mod == 1 else imm(4, True) if mod == 2 else 0
            return reg, rm, (regs[base] + index_value + displacement) & MASK

        if 0xb8 <= op <= 0xbf:
            reg = (op-0xb8) | ((rex & 1) << 3)
            write(reg, w, imm(8 if w == 64 else 4))
        elif op in (0x89, 0x8b, 0x31, 0x09, 0x29, 0x01, 0x39, 0x85, 0x84, 0x28):
            reg, rm, _ = modrm()
            bits = 8 if op in (0x84, 0x28) else w
            a, b = read(rm, bits), read(reg, bits)
            if op == 0x89:
                write(rm, bits, b)
            elif op == 0x8b:
                write(reg, bits, a)
            elif op in (0x85, 0x84):
                set_logic(a & b, bits)
            elif op == 0x39:
                set_sub(a, b, bits)
            elif op in (0x29, 0x28):
                set_sub(a, b, bits)
                write(rm, bits, a-b)
            elif op == 0x31:
                write(rm, bits, a ^ b)
                set_logic(a ^ b, bits)
            elif op == 0x09:
                write(rm, bits, a | b)
                set_logic(a | b, bits)
            else:
                write(rm, bits, a+b)
                invalidate_flags()
        elif op == 0x8d:
            reg, _, address = modrm(allow_lea=True)
            if address is None:
                raise ValueError('register LEA')
            write(reg, w, address)
        elif op == 0x0f:
            op2 = imm(1)
            if op2 in (0x84, 0x85, 0x88):
                delta = imm(4, True)
                condition = flag('z') if op2 == 0x84 else not flag('z') if op2 == 0x85 else flag('s')
                mark(pc, condition)
                if condition:
                    pc = start + pos + delta
                    continue
            elif op2 in (0x94, 0xb6, 0xb7, 0xaf):
                reg, rm, _ = modrm()
                if op2 == 0x94:
                    if reg != 0:
                        raise ValueError('invalid setcc')
                    write(rm, 8, int(flag('z')))
                elif op2 in (0xb6, 0xb7):
                    write(reg, w, read(rm, 8 if op2 == 0xb6 else 16))
                else:
                    write(reg, w, read(reg, w) * read(rm, w))
                    invalidate_flags()
            else:
                raise ValueError('unsupported 0f opcode')
        elif op in (0x69, 0x6b):
            reg, rm, _ = modrm()
            multiplier = imm(1 if op == 0x6b else 4, True)
            write(reg, w, read(rm, w) * multiplier)
            invalidate_flags()
        elif op == 0xf7:
            subop, rm, _ = modrm()
            if subop != 4 or w != 64:
                raise ValueError('unsupported f7 operation')
            value = read(0, 64)*read(rm, 64)
            write(0, 64, value)
            write(2, 64, value >> 64)
            invalidate_flags()
        elif op in (0xc1, 0xd1):
            subop, rm, _ = modrm()
            count = (imm(1) if op == 0xc1 else 1) & (63 if w == 64 else 31)
            value = read(rm, w)
            if subop == 4:
                result = value << count
            elif subop == 5:
                result = value >> count
            elif subop == 1:
                result = ((value >> count) | (value << (w-count))) if count else value
            else:
                raise ValueError('unsupported shift')
            write(rm, w, result)
            invalidate_flags()
        elif op == 0x83:
            subop, rm, _ = modrm()
            value = imm(1, True)
            if subop != 4:
                raise ValueError('unsupported immediate operation')
            result = read(rm, w) & value
            write(rm, w, result)
            set_logic(result, w)
        elif op in (0x74, 0x75, 0x76, 0xeb, 0xe9):
            delta = imm(4 if op == 0xe9 else 1, True)
            condition = (flag('z') if op == 0x74 else not flag('z') if op == 0x75
                         else flag('c') or flag('z') if op == 0x76 else True)
            if op in (0x74, 0x75, 0x76):
                mark(pc, condition)
            if condition:
                pc = start + pos + delta
                continue
        else:
            raise ValueError(f'unsupported arithmetic opcode {op:#x} at {pc:#x}')
        pc = start + pos
    raise ValueError('instruction budget exceeded')


def expected(x):
    if x >> 63:
        return None
    if x == 0:
        return (0, 0, 0)
    scale = 8
    while scale and x % 10 == 0:
        x //= 10
        scale -= 1
    return (scale << 16, x >> 32, x & 0xffffffff)


def render_carrier(carrier):
    """Model the normal default-precision digit path, excluding writer effects."""
    if carrier is None:
        return None
    flags, high, low = carrier
    value = (high << 32) | low
    scale = (flags >> 16) & 0xff
    digits = str(value)
    if scale == 0:
        return digits
    digits = digits.rjust(scale + 1, '0')
    return digits[:-scale] + '.' + digits[-scale:]


def samples():
    values = {0, 1, 123400000, (1 << 63)-1, 1 << 63, MASK}
    for power in range(0, 20):
        for delta in (-1, 0, 1):
            n = 10**power + delta
            if 0 <= n <= MASK:
                values.add(n)
    for n in (1 << 32, 1 << 63):
        values.update(n + d for d in (-2, -1, 0, 1, 2) if 0 <= n+d <= MASK)
    state = 0x7baf017d5023d98e
    for _ in range(8192):
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK
        values.add(state)
        values.add((state % ((1 << 63) // 100000000)) * 100000000)
    return sorted(values)


def generate(out, data):
    report = qualify(data)
    samples_out = []
    rows = sections(data)
    coverage = {}
    for x in samples():
        actual = interpret(data, rows, x, coverage)
        if actual != prepare(x, report) or actual != expected(x):
            raise ValueError('arithmetic model disagrees with integer reference')
        if x < 102 or x == 123400000 or x in {10**k + d for k in range(1, 19) for d in (-1, 0, 1)} or x in (10**8, 10**8-1, 10**8+1, (1<<32)-1,
                             1<<32, (1<<63)-1, 1<<63, MASK):
            samples_out.append({'input': x, 'carrier': actual, 'modeled_text': render_carrier(actual)})
    report['model_checks'] = {'inputs': len(samples()), 'mismatches': 0,
                              'note': 'static byte interpreter and independent integer model; no target execution'}
    report['arithmetic_branch_coverage'] = [dict(site_va=hex(va), **coverage[va]) for va in sorted(coverage)]
    if any(not row['taken'] or not row['not_taken'] for row in coverage.values()):
        raise ValueError('vector set missed a branch outcome')
    report['examples'] = samples_out
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(args.out, BINARY.read_bytes())


if __name__ == '__main__':
    main()
