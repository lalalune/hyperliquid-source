#!/usr/bin/env python3
"""Authenticated node94 chrono datetime-shift helper binding (0x15206e0 / 0x151f870).

Binds the two chrono-0.4.38 datetime-shift callees referenced by the ema
window-guard packet to the node #94 digest: their FDE-bounded bodies, the
nanosecond normalization constants, the four magic divisions (86400, 146097,
400, 365) proved as exact trunc/unsigned division over grids, the eleven
panic Locations across naive/time/mod.rs, naive/date/mod.rs and internals.rs,
both shared MDL table lookups (400-entry table anchored to the datediff
packet), the packed-date field masks, and the GOT-mediated call census.
Static byte/record checks only; the captured binary is never executed.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

C1_START, C1_END = 0x15206e0, 0x1520842
C1_FDE_VA = 0xcf67f0
C2_START, C2_END = 0x151f870, 0x151fa9c
C2_FDE_VA = 0xcf65ac

CHRONO_ROOT = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
               b'chrono-0.4.38/src/')
TIME_PATH = CHRONO_ROOT + b'naive/time/mod.rs'
DATE_PATH = CHRONO_ROOT + b'naive/date/mod.rs'
INTERNALS_PATH = CHRONO_ROOT + b'naive/internals.rs'

# Panic Locations: (lea site, Location struct VA, expected path, line, column).
C1_LOCATIONS = [
    (0x15207f4, 0x5672368, TIME_PATH, 627, 24),
    (0x1520801, 0x5672380, TIME_PATH, 628, 9),
    (0x152080e, 0x56723c8, TIME_PATH, 639, 25),
    (0x152081b, 0x56723b0, TIME_PATH, 632, 13),
    (0x1520828, 0x5672398, TIME_PATH, 635, 13),
    (0x1520835, 0x5672350, TIME_PATH, 623, 60),
]
C2_LOCATIONS = [
    (0x151fa4e, 0x5672188, DATE_PATH, 2334, 5),
    (0x151fa5b, 0x5672140, DATE_PATH, 2325, 9),
    (0x151fa68, 0x56721a0, INTERNALS_PATH, 80, 9),
    (0x151fa7a, 0x5672158, DATE_PATH, 2326, 27),
    (0x151fa8f, 0x5672170, DATE_PATH, 2326, 9),
]

# GOT slots -> relocated targets for every indirect call in both bodies.
GOT_C1, GOT_C2 = 0x576e8a8, 0x576e8b0
PANIC_TARGETS = {0x576e118: 0x157b480, 0x576e150: 0x157b520, 0x576dfc8: 0x157b64f}

NANOS_PER_SEC = 0x3b9aca00       # 1e9
NANOS_BOUND = 0x3b9ac9ff         # 1e9 - 1
NANOS_PAIR_LIMIT = 0x77359400    # 2e9
NEG_NANOS_ADD = 0xc4653600       # -1e9 as u32

DAY_MAGIC = 0x1845c8a0ce512957   # trunc division by 86400, shifts 13 + sign
SECS_PER_DAY = 86400
CYCLE_DAYS = 0x23ab1             # 146097 days per 400-year cycle
CYCLE_MAGIC = 0x396b06bd         # trunc division by 146097, shifts 47 + sign
YEAR_MAGIC = 0x51eb851f          # trunc division by 400, shifts 39 + sign
YEAR_LIMIT = 0x190               # 400
MONTH_MAGIC = 0x6719f361         # unsigned division by 365, variant sequence
DAYS_NORMAL = 0x16d              # 365
DAYS_LEAP = 0x16e                # 366
PACKED_BOUND = 0x16e1            # ordinal-field validation bound (366 << 4 + 1)

MDL_TABLE = 0x250354             # 400-entry table shared with the datediff packet
MDL_TABLE_SPAN = 400
MDL_TABLE2 = 0x2504e5            # second lookup base, MDL_TABLE + 401
MDL_TABLE_SHA256 = '299e3736aeadd129cbda9e5a769e28b6c336935a9d0e2d405d1b5dad8eb92b6c'

# GOT-mediated call census over the complete .text (ff 15 encoding; the
# denominator and lea control are recomputed on every run).
C1_GOT_SITES = 133
C2_GOT_SITES = 150

C1_BODY = bytes.fromhex(
    '50448b068b76044885d20f98c085c9410f9fc14120c1450fb6c94c01ca8d8100'
    '3665c44584c90f44c181fe00ca9a3b7c414885d27f3685c00f9ec141b9009435'
    '774129c14439ce410f9cc14108c94180f90175184885d20f88a500000001c60f'
    '80f000000031c0e98700000081c6003665c44901d00f809900000001c60f809e'
    '000000781981feffc99a3b762049ffc00f80b200000081c6003665c4eb0f49ff'
    'c80f809400000081c600ca9a3b48b9572951cea0c845184c89c048f7e94889d0'
    '48c1e83f48c1fa0d4801c24869c2805101004c89c24829c24889d148c1f93f81'
    'e1805101004801d14929c870414c89c04189c8448907897704488947084889f8'
    '59c381c6003665c449ffc04901d00f8167ffffff488d3d6d1b1504ff1517d924'
    '04488d3d781b1504ff150ad92404488d3db31b1504ff1535d92404488d3d8e1b'
    '1504ff1528d92404488d3d691b1504ff15e3d82404488d3d141b1504ff15d6d8'
    '2404'
)
C1_FDE = bytes.fromhex(
    '18000000dc520100e89e82006201000000410e100300010e08410e10')

C2_BODY = bytes.fromhex(
    '55535089f9c1e90481e1ff01000089c801f00f90c285c0410f9ec04108d07516'
    '89fac1e21cc1fa1f81c26e01000039d00f8696010000c1ff0d4863c74869d01f'
    '85eb514889d748c1ef3f48c1fa2701fa69fa9001000029f84189c041c1f81f45'
    '89c14181e1900100004101c14169f96d0100004c8d1d6a0ad3fe430fb6041901'
    'cf01c70f8455010000ffcf31c001f70f80b60000004863ff4869f7bd066b3948'
    '89f148c1e93f48c1ee20c1fe0f01ce69ceb13a020029cf4189f941c1f91f4489'
    'c981e1b13a020001f94c69d161f3196749c1ea2089cf4429d7d1ef4401d7c1ef'
    '0869df6d0100004189ca4129da420fb62c1f4489d329eb735981f96d0100000f'
    '82e6000000ffcf89f981ff910100000f83f5000000460fb61c194489dbf7db44'
    '01d381c36d0100004439d30f82ee0000004529da4181c26e010000458d9a91fe'
    'ffff4181fb92feffff732b4883c4085b5dc381f94f3a02000f879a000000ffc3'
    '4889f94189da458d9a91feffff4181fb92feffff72d54101d04101f04501c841'
    '69d0900100008d341781c60100fcff81fe0200f8ff72b401d7488d05d50ad3fe'
    '0fb60401c1e70d09c741c1e2044109fa4489d181e1f81f000031c081f9e11600'
    '00410f42c24883c4085b5dc381e70fe0ffffc1e00409f84883c4085b5dc3488d'
    '3d33271504ff15f5e62404488d3dde261504ff15e8e62404488d1531271504be'
    '90010000ff154ee52404488d15d7261504be910100004889cfff1539e5240448'
    '8d3dda261504ff157ce62404'
)
C2_FDE = bytes.fromhex(
    '4400000098500100bc9282002c02000000410e10410e18410e2083038602034c'
    '010e18410e10410e08410e2002770e18410e10410e08410e204f0e18410e1041'
    '0e08410e20000000')

# Verified conditional branches and the tail jumps (offset, pattern,
# rel position, instruction length, destination).
C1_BRANCHES = [
    (0x2f, '7c41', 1, 2, 0x1520752),
    (0x34, '7f36', 1, 2, 0x152074c),
    (0x52, '7518', 1, 2, 0x152074c),
    (0x57, '0f88a5000000', 2, 6, 0x15207e2),
    (0x5f, '0f80f0000000', 2, 6, 0x1520835),
    (0x67, 'e987000000', 1, 5, 0x15207d3),
    (0x75, '0f8099000000', 2, 6, 0x15207f4),
    (0x7d, '0f809e000000', 2, 6, 0x1520801),
    (0x83, '7819', 1, 2, 0x152077e),
    (0x8b, '7620', 1, 2, 0x152078d),
    (0x90, '0f80b2000000', 2, 6, 0x1520828),
    (0x9c, 'eb0f', 1, 2, 0x152078d),
    (0xa1, '0f8094000000', 2, 6, 0x152081b),
    (0xeb, '7041', 1, 2, 0x152080e),
    (0x10e, '0f8167ffffff', 2, 6, 0x152075b),
]
C2_BRANCHES = [
    (0x1e, '7516', 1, 2, 0x151f8a6),
    (0x30, '0f8696010000', 2, 6, 0x151fa3c),
    (0x83, '0f8455010000', 2, 6, 0x151fa4e),
    (0x8f, '0f80b6000000', 2, 6, 0x151f9bb),
    (0xf7, '7359', 1, 2, 0x151f9c2),
    (0xff, '0f82e6000000', 2, 6, 0x151fa5b),
    (0x10f, '0f83f5000000', 2, 6, 0x151fa7a),
    (0x12b, '0f82ee000000', 2, 6, 0x151fa8f),
    (0x149, '732b', 1, 2, 0x151f9e6),
    (0x158, '0f879a000000', 2, 6, 0x151fa68),
    (0x174, '72d5', 1, 2, 0x151f9bb),
    (0x195, '72b4', 1, 2, 0x151f9bb),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def trunc_div(dividend, divisor):
    quotient = abs(dividend) // abs(divisor)
    return quotient if dividend >= 0 else -quotient


def day_quotient(n):
    high = (n * DAY_MAGIC) >> 64
    return (high >> 13) + (1 if high < 0 else 0)


def cycle_quotient(n):
    product = (n * CYCLE_MAGIC) & ((1 << 64) - 1)
    if product >= 1 << 63:
        product -= 1 << 64
    return (product >> 47) + (1 if product < 0 else 0)


def year_quotient(n):
    product = (n * YEAR_MAGIC) & ((1 << 64) - 1)
    if product >= 1 << 63:
        product -= 1 << 64
    return (product >> 39) + (1 if product < 0 else 0)


def month_quotient(n):
    high = (n * MONTH_MAGIC) >> 32
    return (high + ((n - high) >> 1)) >> 8


class Reader:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.by_name = {s['name']: s for s in self.sections}

    def read(self, va, size):
        matches = [s for s in self.sections if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'Ambiguous or unmapped VA {va:#x}')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return self.data[off:off + size]


def relocations(reader):
    raw = reader.read(reader.by_name['.rela.dyn']['address'],
                      reader.by_name['.rela.dyn']['size'])
    rels = {}
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        if info == 8:
            require(address not in rels, 'Duplicate relative relocation')
            rels[address] = addend
    return rels


def check_body_and_fde(reader, start, end, body, fde, fde_va, branches, label):
    require(reader.read(start, end - start) == body, f'{label} body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= fde_va < eh['address'] + eh['size'],
            f'{label} FDE outside .eh_frame')
    record = reader.read(fde_va, len(fde))
    require(record == fde, f'{label} FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = fde_va + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(fde) - 4, f'{label} FDE length changed')
    require((pc, pc + extent) == (start, end), f'{label} FDE PC range changed')

    for offset, pattern, rel_pos, insn_len, destination in branches:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'{label} branch instruction changed at +{offset:#x}')
        fmt = '<b' if insn_len == 2 else '<i'
        rel = struct.unpack_from(fmt, body, offset + rel_pos)[0]
        require(start + offset + insn_len + rel == destination,
                f'{label} branch destination changed at +{offset:#x}')
        require(start <= destination < end, f'{label} branch escapes body')


def check_locations(reader, rels, locations, label):
    seen = []
    for site, loc_va, path, line, column in locations:
        off = site - (C1_START if label == 'callee1' else C2_START)
        body = C1_BODY if label == 'callee1' else C2_BODY
        require(body[off:off + 3] in (b'\x48\x8d\x3d', b'\x48\x8d\x15'),
                f'{label} Location lea changed at {site:#x}')
        require(site + 7 + struct.unpack_from('<i', body, off + 3)[0] == loc_va,
                f'{label} Location address changed at {site:#x}')
        path_va = rels.get(loc_va)
        require(path_va is not None, f'{label} Location relocation missing at {loc_va:#x}')
        length_, line_, column_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((length_, line_, column_) == (len(path), line, column),
                f'{label} Location layout changed at {loc_va:#x}')
        require(reader.read(path_va, length_) == path,
                f'{label} chrono path changed at {loc_va:#x}')
        seen.append(dict(location_va=hex(loc_va), line=line, column=column,
                         path=path.decode().split('chrono-0.4.38/src/')[-1]))
    return seen


def analyze(data):
    reader = Reader(data)
    rels = relocations(reader)

    check_body_and_fde(reader, C1_START, C1_END, C1_BODY, C1_FDE, C1_FDE_VA,
                       C1_BRANCHES, 'callee1')
    check_body_and_fde(reader, C2_START, C2_END, C2_BODY, C2_FDE, C2_FDE_VA,
                       C2_BRANCHES, 'callee2')

    # Nanosecond normalization constants in callee1 (pattern occurrence counts).
    for pattern, count, note in [
            ('8d81003665c4', 1, 'lea secs-1e9'),
            ('81fe00ca9a3b', 1, 'cmp frac, 1e9'),
            ('41b900943577', 1, 'mov 2e9 pair limit'),
            ('81feffc99a3b', 1, 'cmp frac, 1e9-1'),
            ('81c6003665c4', 3, 'add -1e9 renormalization'),
            ('81c600ca9a3b', 1, 'add +1e9 renormalization')]:
        require(C1_BODY.count(bytes.fromhex(pattern)) == count,
                f'nanosecond constant changed: {note}')

    # Callee1 day division: magic, sign shift, 13-bit shift, 86400 multiplier.
    require(C1_BODY[0xad:0xaf] == b'\x48\xb9'
            and struct.unpack_from('<Q', C1_BODY, 0xaf)[0] == DAY_MAGIC,
            'day-division magic changed')
    require(C1_BODY[0xc4:0xc8] == bytes.fromhex('48c1fa0d'),
            'day-division shift changed')
    require(C1_BODY.count(bytes.fromhex('4869c280510100')) == 1,
            '86400 multiplier changed')

    # Callee2 magic divisions and packed-date field constants.
    for pattern, count, note in [
            ('c1e904', 1, 'ordinal extract shift 4'),
            ('81e1ff010000', 1, 'ordinal extract mask 0x1ff'),
            ('81c26e010000', 2, '366 constants (one rex-prefixed)'),
            ('4869d01f85eb51', 1, '400-year magic'),
            ('48c1fa27', 1, '400-year shift 39'),
            ('69fa90010000', 1, '400 multiplier'),
            ('4869f7bd066b39', 1, '146097 magic'),
            ('69ceb13a0200', 1, '146097 multiplier'),
            ('81e1b13a0200', 1, '146097 sign mask'),
            ('4c69d161f31967', 1, '365 magic'),
            ('49c1ea20', 1, '365 magic shift 32'),
            ('69df6d010000', 1, '365 multiplier'),
            ('81f96d010000', 1, '365 compare'),
            ('81f9e1160000', 1, 'packed-date validation bound 0x16e1'),
            ('81e1f81f0000', 1, 'packed-date validation mask 0x1ff8'),
            ('81e70fe0ffff', 1, 'ordinal clear mask 0xffffe00f'),
            ('c1e00409f8', 1, 'ordinal insert shift 4'),
            ('c1e70d', 1, 'ordinal repack shift 13'),
            ('41c1e204', 1, 'year frob shift 4'),
            ('81c60100fcff', 1, 'year range bias add'),
            ('81fe0200f8ff', 1, 'year range compare'),
            ('be90010000', 1, 'panic operand 400'),
            ('be91010000', 1, 'panic operand 401')]:
        require(C2_BODY.count(bytes.fromhex(pattern)) == count,
                f'callee2 constant changed: {note}')

    # Shared MDL table lookups: 400-entry table anchored to the datediff
    # packet (0x151d1b0) and the second base at +401.
    require(C2_BODY[0x73:0x7a] == bytes.fromhex('4c8d1d6a0ad3fe'),
            'MDL table lea changed')
    require(0x151f8ea + struct.unpack_from('<i', C2_BODY, 0x76)[0] == MDL_TABLE,
            'MDL table address changed')
    table = reader.read(MDL_TABLE, MDL_TABLE_SPAN)
    require(hashlib.sha256(table).hexdigest() == MDL_TABLE_SHA256,
            'MDL 400-entry table bytes changed')
    require(C2_BODY[0x199:0x1a0] == bytes.fromhex('488d05d50ad3fe'),
            'MDL second-table lea changed')
    require(0x151fa10 + struct.unpack_from('<i', C2_BODY, 0x19c)[0] == MDL_TABLE2,
            'MDL second-table address changed')
    require(MDL_TABLE2 == MDL_TABLE + 401, 'MDL table bases drifted')

    # GOT-mediated panic and helper calls resolve through relocations.
    require(rels.get(GOT_C1) == C1_START, 'callee1 GOT slot changed')
    require(rels.get(GOT_C2) == C2_START, 'callee2 GOT slot changed')
    for slot, target in PANIC_TARGETS.items():
        require(rels.get(slot) == target, f'panic GOT slot {slot:#x} changed')
    indirect = []
    pos = 0
    while (pos := C1_BODY.find(b'\xff\x15', pos)) >= 0:
        indirect.append((C1_START + pos, struct.unpack_from('<i', C1_BODY, pos + 2)[0]))
        pos += 2
    for site, disp in indirect:
        require(PANIC_TARGETS.get(site + 6 + disp) is not None,
                f'callee1 indirect call at {site:#x} left the panic GOT set')
    indirect2 = []
    pos = 0
    while (pos := C2_BODY.find(b'\xff\x15', pos)) >= 0:
        indirect2.append((C2_START + pos, struct.unpack_from('<i', C2_BODY, pos + 2)[0]))
        pos += 2
    for site, disp in indirect2:
        require(PANIC_TARGETS.get(site + 6 + disp) is not None,
                f'callee2 indirect call at {site:#x} left the panic GOT set')
    require(len(indirect) == 6 and len(indirect2) == 5,
            'indirect panic-call counts changed')

    c1_seen = check_locations(reader, rels, C1_LOCATIONS, 'callee1')
    c2_seen = check_locations(reader, rels, C2_LOCATIONS, 'callee2')

    # Magic-division identities over grids (exact trunc or unsigned division).
    for n in range(-3_000_000, 3_000_001, 7_919):
        require(day_quotient(n) == trunc_div(n, SECS_PER_DAY),
                f'86400 identity failed for {n}')
    for n in range(-800_000_000, 800_000_001, 97):
        require(cycle_quotient(n) == trunc_div(n, CYCLE_DAYS),
                f'146097 identity failed for {n}')
    for n in range(-50_000_000, 50_000_001, 397):
        require(year_quotient(n) == trunc_div(n, YEAR_LIMIT),
                f'400 identity failed for {n}')
    for n in range(0, 800_000_000, 367):
        require(month_quotient(n) == n // DAYS_NORMAL,
                f'365 identity failed for {n}')

    # Census over the complete .text: no direct e8 calls, no lea references,
    # GOT-mediated sites only.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct_c1 = direct_c2 = lea_c1 = lea_c2 = 0
    got_c1 = got_c2 = 0
    pos = 0
    while pos < len(code) - 6:
        byte = code[pos]
        va = text['address'] + pos
        if byte == 0xe8 and pos + 5 <= len(code):
            destination = va + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == C1_START:
                direct_c1 += 1
            elif destination == C2_START:
                direct_c2 += 1
            pos += 1
        elif byte == 0xff and code[pos + 1] == 0x15:
            slot = va + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if slot == GOT_C1:
                got_c1 += 1
            elif slot == GOT_C2:
                got_c2 += 1
            pos += 2
        elif byte == 0x48 and code[pos + 1] == 0x8d and (code[pos + 2] & 0xC7) == 0x05:
            destination = va + 7 + struct.unpack_from('<i', code, pos + 3)[0]
            if destination == C1_START:
                lea_c1 += 1
            elif destination == C2_START:
                lea_c2 += 1
            pos += 3
        else:
            pos += 1
    require(direct_c1 == 0 and direct_c2 == 0, 'direct caller census changed')
    require(lea_c1 == 0 and lea_c2 == 0, 'lea reference census changed')
    require(got_c1 == C1_GOT_SITES, f'callee1 GOT census changed: {got_c1}')
    require(got_c2 == C2_GOT_SITES, f'callee2 GOT census changed: {got_c2}')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        helpers=dict(
            callee1=dict(start_va=hex(C1_START), end_va_exclusive=hex(C1_END),
                         bytes=C1_END - C1_START,
                         sha256=hashlib.sha256(C1_BODY).hexdigest(),
                         fde_va=hex(C1_FDE_VA), got=hex(GOT_C1),
                         inferred_label='NaiveTime shift with nanosecond '
                                        'normalization and day carry'),
            callee2=dict(start_va=hex(C2_START), end_va_exclusive=hex(C2_END),
                         bytes=C2_END - C2_START,
                         sha256=hashlib.sha256(C2_BODY).hexdigest(),
                         fde_va=hex(C2_FDE_VA), got=hex(GOT_C2),
                         inferred_label='NaiveDate day shift over the 400-year '
                                        'cycle with packed-date validation')),
        chrono_anchors=dict(
            callee1_locations=c1_seen,
            callee2_locations=c2_seen,
            shared_with_prior_packets=dict(
                mdl_table=dict(va=hex(MDL_TABLE), entries=MDL_TABLE_SPAN,
                               sha256=MDL_TABLE_SHA256,
                               note='same 400-entry table as the datediff core 0x151d1b0'),
                date_mod_rs_2334_5='date/mod.rs:2334:5 Location shared with the datediff core'),
            magic_divisions=dict(
                day=dict(magic=hex(DAY_MAGIC), divisor=SECS_PER_DAY,
                         identity='trunc division, shift 13 + sign, grid step 7919'),
                cycle=dict(magic=hex(CYCLE_MAGIC), divisor=CYCLE_DAYS,
                           identity='trunc division, shift 47 + sign, grid step 97'),
                year=dict(magic=hex(YEAR_MAGIC), divisor=YEAR_LIMIT,
                          identity='trunc division, shift 39 + sign, grid step 397'),
                month=dict(magic=hex(MONTH_MAGIC), divisor=DAYS_NORMAL,
                           identity='unsigned variant sequence, grid step 367')),
            nanosecond_constants=dict(base=NANOS_PER_SEC, bound=NANOS_BOUND,
                                      pair_limit=NANOS_PAIR_LIMIT),
            packed_date=dict(validation_mask=0x1ff8, validation_bound=PACKED_BOUND,
                             ordinal_clear_mask=0xffffe00f,
                             ordinal_extract_mask=0x1ff)),
        panic_got=dict({hex(slot): hex(target)
                        for slot, target in sorted(PANIC_TARGETS.items())}),
        call_census=dict(
            direct_e8=0, lea_references=0,
            got_mediated=dict(callee1=got_c1, callee2=got_c2),
            denominator='complete .text scan for e8, ff 15 and 48 8d encodings'),
        captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256,
            'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    parser.add_argument('--output', type=Path, help='Write the record JSON to this path')
    args = parser.parse_args()
    result = inspect(args.binary)
    text = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.check is not None:
        expected = args.check.read_text()
        require(text == expected, 'Retained evidence record drifted')
        print('Record matches retained evidence.')
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    else:
        print(text)


if __name__ == '__main__':
    main()
