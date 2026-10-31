#!/usr/bin/env python3
"""Authenticated node94 day-count date constructor binding (0x151f6f0).

Binds the lookup behind the lock-guard cell accessor (RE-001-lock-descriptor-94)
to the node #94 digest: the 378-byte body 0x151f6f0..0x151f86a takes a raw day
count, adds the immediate 365, and runs the shared chrono day machinery — the
146097 magic 0x396b06bd, the year-estimate magic 0x6719f361, both tables at
0x250354 (401 bytes with sentinel) and 0x2504e5, the borrow correction, the
year gate, and four panic Locations shared with the NaiveDate day-shift
packet — returning a packed date or 0. The packet proves the epoch identity:
the accessor's constant index 0xaf93b plus 365 equals 719528, the day count of
1970-01-01 from 0000-01-01 in the proleptic Gregorian calendar, and the decoded
machinery maps it to (year 1970, ordinal 1, flag 10). Static byte/record checks
only; the captured binary is never executed.
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

START, END = 0x151f6f0, 0x151f86a
FDE_VA = 0xcf6588
GOT_SELF = 0x576e890
EPOCH_INDEX = 0xaf93b
DAY_OFFSET_IMM = 0x16d

TABLE1_VA, TABLE2_VA, TABLE_LEN = 0x250354, 0x2504e5, 400
DATE_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
             b'chrono-0.4.38/src/naive/date/mod.rs')
INTERNALS_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
                  b'chrono-0.4.38/src/naive/internals.rs')
LOCATIONS = [(0x5672140, DATE_PATH, 2325, 9), (0x5672158, DATE_PATH, 2326, 27),
             (0x5672170, DATE_PATH, 2326, 9), (0x56721a0, INTERNALS_PATH, 80, 9)]
GOT_PANIC_A, PANIC_A = 0x576e118, 0x157b480
GOT_PANIC_B, PANIC_B = 0x576e150, 0x157b520
GOT_PANIC_C, PANIC_C = 0x576dfc8, 0x157b64f

ACCESSOR_SITE = 0x3790ff0               # the lock-cell accessor calls through GOT_SELF

BODY = bytes.fromhex(
'5031c081c76d0100000f80be0000004863ff4869d7bd066b394889d148c1e93f'
'48c1ea20c1fa0f01ca69cab13a020029cf89fec1fe1f89f181e1b13a020001f9'
'4c69c161f3196749c1e82089cf4429c7d1ef4401c7c1ef084469cf6d01000041'
'89c84529c84c8d0df80bd3fe460fb61c0f4589c24529da735681f96d0100000f'
'82b4000000ffcf89f981ff910100000f83c3000000460fb60c094589ca41f7da'
'4501c24181c26d0100004539c20f82ba0000004529c84181c06e010000458d88'
'91feffff4181f992feffff732359c381f94f3a0200776f41ffc24889f94589d0'
'458d8891feffff4181f992feffff72dd01d669d6900100008d341781c60100fc'
'ff81fe0200f8ff72c401d7488d05e30cd3fe0fb60401c1e70d09c741c1e00441'
'09f84489c181e1f81f000031c081f9e1160000410f42c059c3488d3d10291504'
'ff151ae92404488d1563291504be90010000ff1580e72404488d1509291504be'
'910100004889cfff156be72404488d3d0c291504ff15aee82404')

FDE = bytes.fromhex(
'2000000074500100609182007a01000000410e1002cd0e08410e1002690e0841'
'0e100000')

# (offset, bytes, label) anchors.
ANCHORS = [
    (0x0, '5031c0', 'push slot and zero default'),
    (0x3, '81c76d010000', 'add edi, 365 day offset'),
    (0x12, '4869d7bd066b39', 'div-146097 magic'),
    (0x29, '69cab13a0200', '146097 days per cycle'),
    (0x40, '4c69c161f31967', 'year-estimate magic'),
    (0x89, '81ff91010000', 'table bound 401'),
    (0xcf, '81f94f3a0200', 'day-in-cycle defensive bound 146127'),
    (0xfb, '81c60100fcff', 'year gate low -262143'),
    (0x101, '81fe0200f8ff', 'year gate span'),
    (0x116, 'c1e70d', 'year shift 13'),
    (0x11b, '41c1e004', 'ordinal shift 4'),
    (0x125, '81e1f81f0000', 'ordinal field mask 0x1ff8'),
    (0x12d, '81f9e1160000', 'ordinal limit 0x16e1'),
]

# (lea offset, Location VA, call offset, GOT slot, esi length or None).
PANIC_SITES = [(0x139, 0x5672140, 0x140, GOT_PANIC_B, None),
               (0x146, 0x56721a0, 0x152, GOT_PANIC_C, 400),
               (0x158, 0x5672158, 0x167, GOT_PANIC_C, 401),
               (0x16d, 0x5672170, 0x174, GOT_PANIC_A, None)]

CALLERS = [
    0x13c8e97, 0x14001a5, 0x144c9c6, 0x151c490, 0x151cc42, 0x1719721, 0x171a6a6, 0x1775123,
    0x17a4da8, 0x1830451, 0x18bea13, 0x193757b, 0x195bad1, 0x195d5c8, 0x197d464, 0x1a46d7d,
    0x1a51f10, 0x1c00bc5, 0x1c00c8c, 0x1c1b446, 0x1c1b49d, 0x1c1bb58, 0x1c1bb75, 0x1c39697,
    0x1c5fc19, 0x1c5fd4e, 0x1c76e66, 0x1c7cd1e, 0x1caaed2, 0x1caaee9, 0x1cae489, 0x1cae532,
    0x1cd9dd7, 0x1d04b3b, 0x1d04bd3, 0x1d078a0, 0x1d078ff, 0x1d1ccd1, 0x1dd2b10, 0x1dd2c0a,
    0x1dd8680, 0x1dd877a, 0x1dd8b75, 0x1de2520, 0x1de261a, 0x1df1430, 0x1df152a, 0x1dfb8b0,
    0x1dfb8c3, 0x1dfb9ba, 0x1dfb9cd, 0x1e0794e, 0x1e52767, 0x1e5287e, 0x1e58029, 0x1e58172,
    0x1f84684, 0x1f84699, 0x1f849f0, 0x22ce1a5, 0x263401e, 0x26c7d87, 0x26c7e38, 0x26c8060,
    0x26c8408, 0x26c8614, 0x26c8856, 0x26c8a61, 0x26d67fe, 0x26d68d7, 0x26d6e27, 0x26d6e8b,
    0x26d728e, 0x26d736f, 0x26e624f, 0x26e75bf, 0x2721490, 0x275c36a, 0x275c54e, 0x275c7cd,
    0x275ca20, 0x275ce8d, 0x275d0a0, 0x275d41e, 0x275d56d, 0x275d857, 0x275d9db, 0x275db87,
    0x275dd57, 0x282fccb, 0x282fce0, 0x287837f, 0x28d3ace, 0x28d3b75, 0x28d3d4e, 0x28d3df1,
    0x28e5e8f, 0x28e5eb3, 0x28e6261, 0x28e62ef, 0x28e6620, 0x28e666a, 0x28e6ab9, 0x28e6b67,
    0x28e705f, 0x28e7083, 0x28e73e4, 0x28e7464, 0x294ba58, 0x294bab4, 0x2b1ac93, 0x2b21511,
    0x2b3dfd7, 0x2bec15b, 0x2c867d4, 0x2c93b88, 0x2d8baa3, 0x2d96990, 0x2dab621, 0x2dac5a6,
    0x2e2172a, 0x2e34688, 0x309c406, 0x30cd1b0, 0x312bf0b, 0x312bfa3, 0x312f7d9, 0x312f882,
    0x3150785, 0x315084c, 0x3153290, 0x31532ef, 0x3157847, 0x3163eb6, 0x3163f0d, 0x316caf9,
    0x316cc2e, 0x319ec72, 0x319ec89, 0x31a0768, 0x31a0785, 0x31a9fd1, 0x31adb77, 0x31c2640,
    0x31c273a, 0x31c3d60, 0x31c3d73, 0x31c3e6a, 0x31c3e7d, 0x31c5bb0, 0x31c5caa, 0x31c60a5,
    0x31cc0b0, 0x31cc1aa, 0x31e9080, 0x31e917a, 0x31fb0fe, 0x323c777, 0x323c88e, 0x323ea39,
    0x323eb82, 0x325cf78, 0x325dc09, 0x32606ac, 0x326072b, 0x32608bc, 0x3260933, 0x3260bb9,
    0x3260c18, 0x32610b4, 0x3261b81, 0x32636a6, 0x3266473, 0x327034d, 0x327046d, 0x33bc37f,
    0x34d71a9, 0x35969a2, 0x3597060, 0x359c66b, 0x359c680, 0x370a8fa, 0x370a9a5, 0x370aada,
    0x373269e, 0x3732741, 0x373286e, 0x3732915, 0x3732ae9, 0x3732b4b, 0x3735f96, 0x37367b5,
    0x373ac16, 0x373c10a, 0x373cb14, 0x373e39e, 0x373e477, 0x373e9c7, 0x373ea2b, 0x373ef2e,
    0x373f00f, 0x375401d, 0x3754230, 0x375453a, 0x37547a5, 0x3754add, 0x3754d30, 0x3755227,
    0x37553f7, 0x3755627, 0x37557ab, 0x375595e, 0x3755aad, 0x3790919, 0x3790ee9, 0x3790ff0,
    0x37d5ff1, 0x37d62c6, 0x37d675a, 0x37d69dd, 0x37d6ddc, 0x37d7046, 0x37d7285, 0x37da4ef,
    0x37da5c3, 0x37da75f, 0x37da830, 0x37da92c, 0x37daa02, 0x39310b7, 0x3931f66, 0x394b95c,
    0x394b9db, 0x394bafc, 0x394bb77, 0x394bc59, 0x394bcfd, 0x3952d39, 0x39598ba, 0x398accf,
    0x398acf3, 0x398b054, 0x398b0d4, 0x398b2bf, 0x398b309, 0x398b68a, 0x398b738, 0x398ba2f,
    0x398ba53, 0x398be01, 0x398be8f, 0x39957fb, 0x3c0c7eb, 0x3d22053, 0x3e63c73, 0x3e9d517,
    0x3ea54d3, 0x3eb79b1, 0x3ec0011, 0x3ec0f96, 0x3f4d888, 0x3f50894, 0x3f5391d, 0x3f78da0,
    0x4021358, 0x40ec17b, 0x43ba4a0, 0x43ba59a, 0x43c03f0, 0x43c04ea, 0x43c2a70, 0x43c2a83,
    0x43c2b7a, 0x43c2b8d, 0x43c8235, 0x43ccac0, 0x43ccbba, 0x43d37f0, 0x43d38ea, 0x43edb7e,
    0x44372b7, 0x44373ce, 0x443d719, 0x443d862, 0x461037a, 0x47d765c, 0x47d7671, 0x47d7d9c,
    0x48c9089, 0x48c90eb, 0x48c93be, 0x48c9461, 0x48c958e, 0x48c9635, 0x48d0767, 0x48d07cb,
    0x48d0bce, 0x48d0ca7, 0x48d11fe, 0x48d12df, 0x48d5d0c, 0x48d5d8b, 0x48d5eac, 0x48d5f27,
    0x48d6009, 0x48d60ad, 0x4955cff, 0x4b2a165, 0x4c00aa5, 0x4c00b15, 0x4d262f0, 0x4d268f0,
    0x4d8897d, 0x4d88bd0, 0x4d8905a, 0x4d8923e, 0x4d8952d, 0x4d89740, 0x4d89ab7, 0x4d89c87,
    0x4d89eb7, 0x4d8a03b, 0x4d8a1ee, 0x4d8a33d,
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def leap_table_model():
    table = []
    total = 0
    for year in range(TABLE_LEN):
        table.append(total)
        if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
            total += 1
    return table


def year_flag_model():
    flags = []
    for year in range(TABLE_LEN):
        jan1 = days_from_civil(year, 1, 1)
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        flags.append((0 if leap else 8) | ((jan1 + 1) % 7 + 1))
    return flags


def days_from_civil(year, month, day):
    """Days from 1970-01-01, proleptic Gregorian, astronomical year numbering."""
    year -= 1 if month <= 2 else 0
    era = (year if year >= 0 else year - 399) // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def year_in_cycle_estimate(day_in_cycle):
    """Decoded 0x151f730..0x151f745 round-division estimate."""
    product = day_in_cycle * 0x6719f361
    hi = (product >> 32) & 0xffffffff
    t = ((day_in_cycle - hi) & 0xffffffff) >> 1
    return ((t + hi) & 0xffffffff) >> 8


def year_and_ordinal(day_in_cycle, leap_table):
    """Decoded 0x151f748..0x151f7de: estimate plus borrow correction."""
    estimate = year_in_cycle_estimate(day_in_cycle)
    raw_ordinal = day_in_cycle - 365 * estimate - leap_table[estimate]
    if raw_ordinal >= 0:
        return estimate, raw_ordinal + 1
    require(day_in_cycle >= 365, 'borrow path panic site reached (2325:9)')
    prior = estimate - 1
    require(0 <= prior < 401, 'borrow path table bound panic reached (2326:27)')
    return prior, day_in_cycle - 365 * (prior + 1) - leap_table[prior] + 366


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


def analyze(data):
    reader = Reader(data)
    rels = relocations(reader)

    body = reader.read(START, END - START)
    require(body == BODY, 'Constructor body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    fde = reader.read(FDE_VA, len(FDE))
    require(fde == FDE, 'Constructor FDE record changed')
    length = struct.unpack_from('<I', fde, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, hexstr, label in ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, f'Anchor changed: {label}')

    # Table lea displacements.
    disp = struct.unpack_from('<i', body, 0x65 + 3)[0]
    require(START + 0x65 + 7 + disp == TABLE1_VA, 'leap table address changed')
    disp = struct.unpack_from('<i', body, 0x10b + 3)[0]
    require(START + 0x10b + 7 + disp == TABLE2_VA, 'year flag table address changed')

    # Panic Locations and callees.
    for lea_off, loc_va, call_off, got, esi_len in PANIC_SITES:
        require(body[lea_off:lea_off + 3] == bytes.fromhex('488d3d')
                or body[lea_off:lea_off + 3] == bytes.fromhex('488d15'),
                'panic lea opcode changed')
        disp = struct.unpack_from('<i', body, lea_off + 3)[0]
        require(START + lea_off + 7 + disp == loc_va, 'panic Location address changed')
        require(body[call_off:call_off + 2] == bytes.fromhex('ff15'), 'panic call opcode changed')
        disp = struct.unpack_from('<i', body, call_off + 2)[0]
        require(START + call_off + 6 + disp == got, 'panic call GOT changed')
        for candidate_va, path, line, column in LOCATIONS:
            if candidate_va == loc_va:
                path_va = rels.get(loc_va)
                require(path_va is not None, 'panic Location relocation missing')
                str_len, line_, column_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
                require((str_len, line_, column_) == (len(path), line, column),
                        'panic Location layout changed')
                require(reader.read(path_va, str_len) == path, 'chrono path changed')
        if esi_len is not None:
            operand = b'\xbe' + struct.pack('<I', esi_len)
            require(any(body[call_off - k - 5:call_off - k] == operand
                        for k in (0, 3, 5, 8)),
                    'index panic length operand changed')
    require(rels.get(GOT_PANIC_A) == PANIC_A, 'panic GOT slot A target changed')
    require(rels.get(GOT_PANIC_B) == PANIC_B, 'panic GOT slot B target changed')
    require(rels.get(GOT_PANIC_C) == PANIC_C, 'panic GOT slot C target changed')

    # Tables: full models plus the sentinel.
    table1 = list(reader.read(TABLE1_VA, TABLE_LEN))
    require(table1 == leap_table_model(), 'Leap table no longer matches the Gregorian model')
    require(reader.read(TABLE1_VA + TABLE_LEN, 1)[0] == 97, 'Leap table sentinel changed')
    table2 = list(reader.read(TABLE2_VA, TABLE_LEN))
    require(table2 == year_flag_model(), 'Year flag table no longer matches the model')

    # Exhaustive day-cycle identity.
    table1_ext = table1 + [reader.read(TABLE1_VA + TABLE_LEN, 1)[0]]
    for day in range(146097):
        year, ordinal = year_and_ordinal(day, table1_ext)
        require(365 * year + table1[year] + ordinal - 1 == day,
                f'Day-to-(year, ordinal) identity failed for day {day}')
        require(1 <= ordinal <= 366, f'Ordinal out of range for day {day}')

    # Epoch identity: the accessor constant plus the immediate equals the day
    # count of 1970-01-01 from 0000-01-01; the machinery maps it exactly.
    total = EPOCH_INDEX + DAY_OFFSET_IMM
    require(total == -days_from_civil(0, 1, 1), 'Epoch day count identity failed')
    cycles, day_in_cycle = divmod(total, 146097)
    year_in_cycle, ordinal = year_and_ordinal(day_in_cycle, table1_ext)
    year = 400 * cycles + year_in_cycle
    flag = table2[year_in_cycle]
    require((year, ordinal, flag) == (1970, 1, table2[370]),
            'Epoch date resolution failed')
    require(flag == 8 | ((days_from_civil(1970, 1, 1) + 1) % 7 + 1),
            '1970 flag mismatch against the model')
    import datetime
    oracle = datetime.date(1970, 1, 1)
    require((oracle.year, oracle.timetuple().tm_yday) == (1970, 1),
            'Python calendar oracle mismatch')

    # Census over the whole .text.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct, indirect, lea = [], [], []
    pos = 0
    while (pos := code.find(b'\xff\x15', pos)) >= 0:
        if pos + 6 <= len(code):
            slot = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if rels.get(slot) == START:
                indirect.append(text['address'] + pos)
        pos += 2
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    for m in range(len(code) - 7):
        if code[m] == 0x48 and code[m + 1] == 0x8d and (code[m + 2] & 0xC7) == 0x05:
            d = struct.unpack_from('<i', code, m + 3)[0]
            if text['address'] + m + 7 + d == START:
                lea.append(text['address'] + m)
    require(direct == [], 'Unexpected direct callers')
    require(lea == [], 'Unexpected lea references')
    require(indirect == CALLERS,
            f'GOT-indirect caller census changed: {len(indirect)} sites')
    require(rels.get(GOT_SELF) == START, 'self GOT slot changed')
    require(ACCESSOR_SITE in indirect, 'lock-cell accessor call site missing')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        constructor=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                         sha256=hashlib.sha256(body).hexdigest(), fde_va=hex(FDE_VA),
                         got_slot=hex(GOT_SELF),
                         inferred_label='chrono NaiveDate-style day-count constructor '
                                        'returning a packed date or 0'),
        epoch_identity=dict(
            accessor_index=hex(EPOCH_INDEX), immediate=DAY_OFFSET_IMM,
            day_total=total,
            day_total_equals='-days_from_civil(0, 1, 1)',
            resolved=dict(year=1970, ordinal=1, flag=10, packed='0xf6401a',
                          label='1970-01-01, the Unix epoch date'),
            oracle='Python datetime.date(1970, 1, 1) agrees on year and ordinal'),
        shared_machinery=dict(
            leap_table=dict(va=hex(TABLE1_VA), entries=TABLE_LEN, sentinel_400=97,
                            shared_with='RE-001-datediff-chrono-94, RE-001-chrono-callees-94'),
            year_flags=dict(va=hex(TABLE2_VA), entries=TABLE_LEN,
                            shared_with='RE-001-chrono-callees-94'),
            magics=dict(div146097='0x396b06bd', year_estimate='0x6719f361'),
            panic_locations=['date/mod.rs:2325:9', 'date/mod.rs:2326:27',
                             'date/mod.rs:2326:9', 'internals.rs:80:9'],
            year_gate='[-262143, 262142]'),
        identities=dict(day_cycle_exhaustive='146097/146097 pass',
                        epoch_resolution='1970-01-01 verified against the Python calendar'),
        call_census=dict(got_slot=hex(GOT_SELF), got_indirect_sites=len(CALLERS),
                         direct_e8=0, lea_refs=0,
                         accessor_site='0x3790ff0 (RE-001-lock-descriptor-94)',
                         note='byte-pattern census over the complete .text for '
                              'e8/ff15/lea encodings'),
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
