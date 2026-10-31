#!/usr/bin/env python3
"""Authenticated node94 chrono NaiveTime/NaiveDate callee-pair binding.

Binds the two chrono-0.4.38 callees left out of the ema window guard packet
(RE-001-ema-window-guard-94) to the node #94 digest: the NaiveTime
TimeDelta-addition body 0x15206e0 (nanosecond normalization constants, the
shared 86400-second day division with euclidean remainder fixup, six
arithmetic-overflow panics routed to naive/time/mod.rs Locations) and the
NaiveDate day-shift body 0x151f870 (packed year<<13|ordinal<<4|flags layout,
the 400-entry cumulative leap table with its 97 sentinel, the 400-entry year
flag table validated against the proleptic Gregorian model, the 400/146097/
365.2425 division chain with an exhaustive day-cycle identity, the year-range
gate, and five panic Locations across naive/date/mod.rs and internals.rs).
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

# Callee 1: NaiveTime + TimeDelta overflowing addition (naive/time/mod.rs).
C1_START, C1_END = 0x15206e0, 0x1520842
C1_FDE_VA = 0xcf67f0
C1_GOT = 0x576e8a8
TIME_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
             b'chrono-0.4.38/src/naive/time/mod.rs')
# (Location VA, line, column) in naive/time/mod.rs order of appearance.
C1_LOCATIONS = [(0x5672350, 623, 60), (0x5672368, 627, 24), (0x5672380, 628, 9),
                (0x5672398, 635, 13), (0x56723b0, 632, 13), (0x56723c8, 639, 25)]
# (lea site, Location VA, call site, GOT slot) for the six overflow panics.
C1_PANIC_SITES = [(0x15207f4, 0x5672368, 0x15207fb, 0x576e118),
                  (0x1520801, 0x5672380, 0x1520808, 0x576e118),
                  (0x152080e, 0x56723c8, 0x1520815, 0x576e150),
                  (0x152081b, 0x56723b0, 0x1520822, 0x576e150),
                  (0x1520828, 0x5672398, 0x152082f, 0x576e118),
                  (0x1520835, 0x5672350, 0x152083c, 0x576e118)]

# Callee 2: NaiveDate + days (naive/date/mod.rs and internals.rs).
C2_START, C2_END = 0x151f870, 0x151fa9c
C2_FDE_VA = 0xcf65ac
C2_GOT = 0x576e8b0
DATE_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
             b'chrono-0.4.38/src/naive/date/mod.rs')
INTERNALS_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
                  b'chrono-0.4.38/src/naive/internals.rs')
C2_LOCATIONS = [(0x5672140, DATE_PATH, 2325, 9), (0x5672158, DATE_PATH, 2326, 27),
                (0x5672170, DATE_PATH, 2326, 9), (0x5672188, DATE_PATH, 2334, 5),
                (0x56721a0, INTERNALS_PATH, 80, 9)]

TABLE1_VA, TABLE2_VA, TABLE_LEN = 0x250354, 0x2504e5, 400

GOT_PANIC_A, PANIC_A = 0x576e118, 0x157b480   # shared chrono panic callee
GOT_PANIC_B, PANIC_B = 0x576e150, 0x157b520   # panic callee also used by the datediff core
GOT_PANIC_C, PANIC_C = 0x576dfc8, 0x157b64f   # table index panic (length in esi)

GUARD_START, GUARD_END = 0x474fb90, 0x474fce5  # ema window guard, separate packet

DAY_MAGIC = 0x1845c8a0ce512957
DIV400_MAGIC = 0x51eb851f
DIV146097_MAGIC = 0x396b06bd
YEAR_MAGIC = 0x6719f361

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
    '2404')

C1_FDE = bytes.fromhex('18000000dc520100e89e82006201000000410e100300010e08410e10')

# (offset, little-endian bytes, label) immediates inside callee 1.
C1_IMMEDIATES = [
    (0x29, '81fe00ca9a3b', 'nanos-per-second 1e9 compare'),
    (0x3b, '41b900943577', '2e9 carry threshold'),
    (0x6c, '81c6003665c4', '-1e9 normalization (first)'),
    (0x85, '81feffc99a3b', '0x3b9ac9ff day-second ceiling'),
    (0x96, '81c6003665c4', '-1e9 normalization (second)'),
    (0xa7, '81c600ca9a3b', '1e9 normalization'),
    (0xad, '48b9572951cea0c84518', 'day-division magic'),
    (0xcb, '4869c280510100', 'q * 86400'),
    (0xdf, '81e180510100', 'euclidean remainder mask 86400'),
]

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
    '8d3dda261504ff157ce62404')

C2_FDE = bytes.fromhex(
    '4400000098500100bc9282002c02000000410e10410e18410e2083038602034c'
    '010e18410e10410e08410e2002770e18410e10410e08410e204f0e18410e1041'
    '0e08410e20000000')

# (offset, bytes, label) immediates inside callee 2.
C2_IMMEDIATES = [
    (0x8, '81e1ff010000', 'ordinal mask 0x1ff'),
    (0x28, '81c26e010000', '366 days in leap year'),
    (0x3c, '4869d01f85eb51', 'signed div-400 magic'),
    (0x50, '69fa90010000', '400 (cycle years)'),
    (0x6c, '4169f96d010000', '365 (common year)'),
    (0x73, '4c8d1d6a0ad3fe', 'leap table lea'),
    (0x98, '4869f7bd066b39', 'div-146097 magic'),
    (0xaf, '69ceb13a0200', '146097 days per 400-year cycle'),
    (0xc9, '4c69d161f31967', 'year-in-cycle estimate magic'),
    (0xe1, '69df6d010000', '365 (ordinal base)'),
    (0x109, '81ff91010000', 'table bound 401'),
    (0x152, '81f94f3a0200', 'day-in-cycle defensive bound 146127'),
    (0x17f, '4169d090010000', '400 (year rejoin)'),
    (0x189, '81c60100fcff', 'year gate low -262143'),
    (0x18f, '81fe0200f8ff', 'year gate span'),
    (0x199, '488d05d50ad3fe', 'year flag table lea'),
    (0x1a4, 'c1e70d', 'year shift 13'),
    (0x1a9, '41c1e204', 'ordinal shift 4'),
    (0x1b3, '81e1f81f0000', 'ordinal field mask 0x1ff8'),
    (0x1bb, '81f9e1160000', 'ordinal limit 0x16e1'),
]

C1_CALLERS = [
    0x13c8fa6, 0x1459d70, 0x151d0d0, 0x1e5f7e9, 0x1e5f85f, 0x1f681f0, 0x201823e,
    0x2044920, 0x21b4b56, 0x21b5068, 0x22283eb, 0x2228b73, 0x2229d39, 0x2271dad,
    0x22bf870, 0x26dc147, 0x26dca05, 0x26fb787, 0x26fb835, 0x2701dd2, 0x2701e7d,
    0x270260a, 0x270269d, 0x2707962, 0x2709329, 0x27214f5, 0x272367a, 0x2736333,
    0x2745222, 0x276726a, 0x276732b, 0x27e5654, 0x28c2a31, 0x325edff, 0x32661e2,
    0x3342d2a, 0x33700fc, 0x3372560, 0x342209b, 0x3422656, 0x3422a1b, 0x342365b,
    0x342819b, 0x3714f36, 0x3756e18, 0x392bade, 0x3949b9a, 0x3986e10, 0x3986f7c,
    0x398700e, 0x3987b00, 0x3987b9a, 0x3994a12, 0x3bc333a, 0x3bc3463, 0x42ef205,
    0x42efc07, 0x42f04b7, 0x42f0d75, 0x42f5c42, 0x42f64a2, 0x43210b5, 0x4321a65,
    0x435ea25, 0x4391fef, 0x44766ed, 0x44aa7f3, 0x470da2b, 0x470ef19, 0x47101d3,
    0x47114b3, 0x47168e1, 0x471839b, 0x474d6c1, 0x474ed1c, 0x474fbf3, 0x47b7334,
    0x47b950d, 0x47ba11d, 0x47ed806, 0x47edaa1, 0x47eddc7, 0x47ee0d6, 0x47ee3e2,
    0x47f0f1b, 0x485619f, 0x48569d5, 0x4857526, 0x485779f, 0x48579ae, 0x4857bd0,
    0x4857dcf, 0x4857ff0, 0x48581d4, 0x48583c4, 0x48585b4, 0x48988ff, 0x489a617,
    0x489b707, 0x4957b90, 0x49c27e1, 0x4bfee29, 0x4bfee9f, 0x4bff129, 0x4bff19f,
    0x4c64c56, 0x4c65168, 0x4c654d6, 0x4c659e8, 0x4ce1337, 0x4ce13e5, 0x4ce1697,
    0x4ce1745, 0x4cedd03, 0x4ceddb0, 0x4cee023, 0x4cee0d0, 0x4ceefea, 0x4cef07d,
    0x4cef19a, 0x4cef22d, 0x4cf38b7, 0x4cf955f, 0x4d26355, 0x4d26955, 0x4d42273,
    0x4d461b3, 0x4d5e642, 0x4d5eb32, 0x4d9a12a, 0x4d9a1eb, 0x4d9ad6a, 0x4d9ae2b,
]

C2_CALLERS = [
    0x13c8ff7, 0x13ce13b, 0x1450836, 0x1459dc0, 0x151d143, 0x1e5f82d, 0x1e5f896,
    0x201829b, 0x204497d, 0x21b4ba9, 0x21b50c7, 0x220c040, 0x2228450, 0x2228bc9,
    0x2229d85, 0x2271e03, 0x227975f, 0x22bf8cd, 0x26dc1a2, 0x26dca63, 0x26fb7e1,
    0x26fb86e, 0x26ff36b, 0x26ff621, 0x26ff7f1, 0x2701e2b, 0x2701eb5, 0x2702648,
    0x27026e2, 0x27079c4, 0x2709387, 0x2721546, 0x27236d8, 0x2736391, 0x274527b,
    0x2763e86, 0x27672c1, 0x2767376, 0x27d8638, 0x27e56aa, 0x28c2a82, 0x28f0c55,
    0x325ee4c, 0x3266237, 0x3342d7d, 0x337015b, 0x33725be, 0x3422102, 0x34226ae,
    0x34236b2, 0x3425abd, 0x34281ed, 0x3714f88, 0x3756e71, 0x37e3fe6, 0x392bb33,
    0x3949c02, 0x3986e4f, 0x3986fd3, 0x398705e, 0x3987b60, 0x3987bd5, 0x3994a6e,
    0x3bc338c, 0x3bc34b5, 0x42e7538, 0x42e7ae8, 0x42ef263, 0x42efc62, 0x42f0512,
    0x42f0dd3, 0x42f5c9f, 0x42f64ff, 0x432110b, 0x4321abb, 0x432f360, 0x435ea7c,
    0x439204f, 0x4470a4a, 0x4476746, 0x44aa850, 0x470da90, 0x470ef65, 0x4710229,
    0x4711509, 0x471692d, 0x4718400, 0x474d71d, 0x474ed7c, 0x474fc46, 0x47b7391,
    0x47ed855, 0x47edaf0, 0x47ede16, 0x47ee124, 0x47ee430, 0x47f0f73, 0x48561f7,
    0x4856a25, 0x4857574, 0x48577ee, 0x48579fd, 0x4857c1f, 0x4857e1e, 0x485803f,
    0x4858223, 0x4858413, 0x4858603, 0x489a66d, 0x489b75d, 0x4957be7, 0x49c2832,
    0x4bfee6d, 0x4bfeed6, 0x4bff16d, 0x4bff1d6, 0x4c64ca9, 0x4c651c7, 0x4c65529,
    0x4c65a47, 0x4ce1391, 0x4ce141e, 0x4ce16f1, 0x4ce177e, 0x4ce893b, 0x4ce8a4b,
    0x4ce8db1, 0x4ce98e1, 0x4cedd5d, 0x4cedde9, 0x4cee07d, 0x4cee109, 0x4cef028,
    0x4cef0c2, 0x4cef1d8, 0x4cef272, 0x4cf3919, 0x4cf95c1, 0x4d263a6, 0x4d269a6,
    0x4d422d1, 0x4d46211, 0x4d5e697, 0x4d5eb87, 0x4d91eda, 0x4d94c0a, 0x4d9a181,
    0x4d9a236, 0x4d9adc1, 0x4d9ae76,
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def leap_table_model():
    """Cumulative leap days before cycle year i, proleptic Gregorian."""
    table = []
    total = 0
    for year in range(TABLE_LEN):
        table.append(total)
        if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
            total += 1
    return table


def days_from_civil(year, month, day):
    """Days from 1970-01-01 to the given proleptic Gregorian date (Howard Hinnant)."""
    year -= 1 if month <= 2 else 0
    era = (year if year >= 0 else year - 399) // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def year_flag_model():
    """(0b1000 if common else 0) | ((dow(jan1) + 1) % 7 + 1), astronomical years.

    Cycle year y is astronomical year y (year 0 = 1 BC); days_from_civil uses
    the 1970-01-01 epoch and handles astronomical year numbering natively.
    """
    flags = []
    for year in range(TABLE_LEN):
        jan1 = days_from_civil(year, 1, 1)
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        flags.append((0 if leap else 8) | ((jan1 + 1) % 7 + 1))
    return flags


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


def euclid_div(a, b):
    q = a // b
    if a % b < 0:
        q += 1
    return q


def euclid_mod(a, b):
    return a - euclid_div(a, b) * b


def day_division_sequence(x):
    """Decoded callee-1 tail: magic quotient plus explicit remainder fixup."""
    full = x * DAY_MAGIC
    hi = full >> 64
    quotient = (hi >> 13) + ((hi >> 63) & 1)
    raw_remainder = x - quotient * 86400
    secs_of_day = raw_remainder + (86400 if raw_remainder < 0 else 0)
    return secs_of_day, x - secs_of_day


def div400_sequence(year):
    """Decoded 0x151f8a9..0x151f8dc: signed magic then euclidean remainder."""
    product = year * DIV400_MAGIC          # imul rdx, rax, imm32 (64-bit)
    quotient = (product >> 39) + ((product >> 63) & 1)
    raw = year - quotient * 400
    return quotient, raw + (400 if raw < 0 else 0)


def div146097_sequence(day_index):
    """Decoded 0x151f905..0x151f937: high-dword magic quotient, euclidean remainder."""
    product = day_index * DIV146097_MAGIC
    hi = (product >> 32) & 0xffffffff      # shr rsi, 0x20 view (bits 63..32)
    hi_signed = hi - 0x100000000 if hi >= 0x80000000 else hi
    quotient = (hi_signed >> 15)           # sar esi, 0x15 (Python >> is arithmetic)
    quotient += 1 if product < 0 else 0    # shr rcx, 0x3f / add
    raw = day_index - quotient * 146097
    return quotient, raw + (146097 if raw < 0 else 0)


def year_in_cycle_estimate(day_in_cycle):
    """Decoded 0x151f939..0x151f94e round-division estimate."""
    product = day_in_cycle * YEAR_MAGIC
    hi = (product >> 32) & 0xffffffff
    t = ((day_in_cycle - hi) & 0xffffffff) >> 1
    return ((t + hi) & 0xffffffff) >> 8


def year_and_ordinal_from_day(day_in_cycle, leap_table):
    """Decoded 0x151f951..0x151f9b2: estimate plus borrow correction."""
    estimate = year_in_cycle_estimate(day_in_cycle)
    raw_ordinal = day_in_cycle - 365 * estimate - leap_table[estimate]
    if raw_ordinal >= 0:                   # jae 0x151f9c2 path
        return estimate, raw_ordinal + 1
    require(day_in_cycle >= 365, 'borrow path panic site reached (2325:9)')
    prior = estimate - 1
    require(0 <= prior < 401, 'borrow path table bound panic reached (2326:27)')
    ordinal = day_in_cycle - 365 * (prior + 1) - leap_table[prior] + 366
    return prior, ordinal


def analyze(data):
    reader = Reader(data)
    rels = relocations(reader)

    # ---- Callee 1: body, FDE, immediates. ----
    body1 = reader.read(C1_START, C1_END - C1_START)
    require(body1 == C1_BODY, 'NaiveTime callee body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= C1_FDE_VA < eh['address'] + eh['size'], 'callee1 FDE outside .eh_frame')
    fde1 = reader.read(C1_FDE_VA, len(C1_FDE))
    require(fde1 == C1_FDE, 'NaiveTime callee FDE record changed')
    length1 = struct.unpack_from('<I', fde1, 0)[0]
    pc1 = C1_FDE_VA + 8 + struct.unpack_from('<i', fde1, 8)[0]
    extent1 = struct.unpack_from('<I', fde1, 12)[0]
    require(length1 == len(C1_FDE) - 4, 'callee1 FDE length changed')
    require((pc1, pc1 + extent1) == (C1_START, C1_END), 'callee1 FDE PC range changed')

    for offset, hexstr, label in C1_IMMEDIATES:
        raw = bytes.fromhex(hexstr)
        require(body1[offset:offset + len(raw)] == raw, f'callee1 immediate changed: {label}')

    # Six overflow panics: lea -> Location struct -> chrono path; call -> GOT -> callee.
    for lea_site, loc_va, call_site, got in C1_PANIC_SITES:
        off = lea_site - C1_START
        require(body1[off:off + 3] == b'\x48\x8d\x3d', 'callee1 panic lea opcode changed')
        disp = struct.unpack_from('<i', body1, off + 3)[0]
        require(lea_site + 7 + disp == loc_va, 'callee1 panic Location address changed')
        require(body1[call_site - C1_START:call_site - C1_START + 2] == b'\xff\x15',
                'callee1 panic call opcode changed')
        call_disp = struct.unpack_from('<i', body1, call_site - C1_START + 2)[0]
        require(call_site + 6 + call_disp == got, 'callee1 panic GOT displacement changed')
        line, column = None, None
        for candidate_va, l, c in C1_LOCATIONS:
            if candidate_va == loc_va:
                line, column = l, c
        require(line is not None, 'callee1 Location not in the recorded set')
        path_va = rels.get(loc_va)
        require(path_va is not None, 'callee1 Location relocation missing')
        str_len, line_, column_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((str_len, line_, column_) == (len(TIME_PATH), line, column),
                'callee1 chrono time Location changed')
        require(reader.read(path_va, str_len) == TIME_PATH, 'callee1 chrono time path changed')

    require(rels.get(GOT_PANIC_A) == PANIC_A, 'callee1 panic GOT slot A target changed')
    require(rels.get(GOT_PANIC_B) == PANIC_B, 'callee1 panic GOT slot B target changed')

    # ---- Callee 2: body, FDE, immediates. ----
    body2 = reader.read(C2_START, C2_END - C2_START)
    require(body2 == C2_BODY, 'NaiveDate callee body bytes changed')
    require(eh['address'] <= C2_FDE_VA < eh['address'] + eh['size'], 'callee2 FDE outside .eh_frame')
    fde2 = reader.read(C2_FDE_VA, len(C2_FDE))
    require(fde2 == C2_FDE, 'NaiveDate callee FDE record changed')
    length2 = struct.unpack_from('<I', fde2, 0)[0]
    pc2 = C2_FDE_VA + 8 + struct.unpack_from('<i', fde2, 8)[0]
    extent2 = struct.unpack_from('<I', fde2, 12)[0]
    require(length2 == len(C2_FDE) - 4, 'callee2 FDE length changed')
    require((pc2, pc2 + extent2) == (C2_START, C2_END), 'callee2 FDE PC range changed')

    for offset, hexstr, label in C2_IMMEDIATES:
        raw = bytes.fromhex(hexstr)
        require(body2[offset:offset + len(raw)] == raw, f'callee2 immediate changed: {label}')

    # Table lea displacements resolve to the recorded table VAs.
    off = 0x151f8e3 - C2_START
    require(body2[off:off + 3] == b'\x4c\x8d\x1d', 'leap table lea opcode changed')
    require(0x151f8ea + struct.unpack_from('<i', body2, off + 3)[0] == TABLE1_VA,
            'leap table address changed')
    off = 0x151fa09 - C2_START
    require(body2[off:off + 3] == b'\x48\x8d\x05', 'year flag table lea opcode changed')
    require(0x151fa10 + struct.unpack_from('<i', body2, off + 3)[0] == TABLE2_VA,
            'year flag table address changed')

    # Callee 2 panic Locations (two also carry table lengths in esi).
    for loc_va, path, line, column in C2_LOCATIONS:
        path_va = rels.get(loc_va)
        require(path_va is not None, 'callee2 Location relocation missing')
        str_len, line_, column_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((str_len, line_, column_) == (len(path), line, column),
                'callee2 Location layout changed')
        require(reader.read(path_va, str_len) == path, 'callee2 chrono path changed')
    require(rels.get(GOT_PANIC_C) == PANIC_C, 'index panic GOT slot target changed')
    # The two index-panic sites carry the table lengths 400 and 401 in esi.
    require(body2[0x151fa6f - C2_START:0x151fa74 - C2_START] == b'\xbe\x90\x01\x00\x00',
            'index panic length operand 400 changed')
    require(body2[0x151fa81 - C2_START:0x151fa86 - C2_START] == b'\xbe\x91\x01\x00\x00',
            'index panic length operand 401 changed')

    # ---- Tables. ----
    table1 = list(reader.read(TABLE1_VA, TABLE_LEN))
    require(table1 == leap_table_model(), 'Leap table no longer matches the Gregorian model')
    require(reader.read(TABLE1_VA + TABLE_LEN, 1)[0] == 97,
            'Leap table sentinel byte (entry 400) changed')
    table2 = list(reader.read(TABLE2_VA, TABLE_LEN))
    require(table2 == year_flag_model(), 'Year flag table no longer matches the model')
    require(all(1 <= (flag & 7) <= 7 for flag in table2), 'Year flag class out of range')
    require(sum(1 for flag in table2 if flag < 8) == 97, 'Year flag leap count changed')

    # ---- Identities. ----
    # Day division: euclidean decomposition on a grid including negatives.
    for x in [0, 1, -1, 30, 86399, 86400, -86400, 86401, 172800, 10**9, -10**9,
              262144 * 366 * 86400, -262144 * 366 * 86400, 2**47, -2**47]:
        secs, whole = day_division_sequence(x)
        require(secs == euclid_mod(x, 86400) and whole == euclid_div(x, 86400) * 86400,
                f'Day-division identity failed for {x}')
    for i in range(-200, 200):
        x = i * 86400 + (i * 7919) % 86400
        secs, whole = day_division_sequence(x)
        require(secs == euclid_mod(x, 86400) and whole == euclid_div(x, 86400) * 86400,
                f'Day-division identity failed for {x}')

    # Div-400: euclidean remainder with a self-consistent decomposition on the
    # year domain (and beyond); the magic quotient itself is trunc-style and is
    # recombined with sign terms downstream.
    for year in list(range(-803, 804, 7)) + [-262150, -262144, -262143, 0, 400,
                                             262142, 262143, 262150]:
        q, r = div400_sequence(year)
        require(r == euclid_mod(year, 400) and year - r == euclid_div(year, 400) * 400
                and abs(year - q * 400) < 400,
                f'Div-400 decomposition failed for {year}')

    # Div-146097: euclidean remainder with a self-consistent decomposition on
    # the day-index domain.
    for day in list(range(-4 * 146097, 4 * 146097 + 1, 1013)) + [-146097, -1, 0, 1,
                                                                146096, 146097]:
        q, r = div146097_sequence(day)
        require(r == euclid_mod(day, 146097) and day - r == euclid_div(day, 146097) * 146097
                and abs(day - q * 146097) < 146097,
                f'Div-146097 decomposition failed for {day}')

    # Year-in-cycle + ordinal: exhaustive over the whole 400-year day cycle.
    # The estimate may reach 400 on the last cycle days; the code then reads the
    # sentinel entry (97) and the borrow path resolves to year 399.
    table1_ext = table1 + [reader.read(TABLE1_VA + TABLE_LEN, 1)[0]]
    for day in range(146097):
        year, ordinal = year_and_ordinal_from_day(day, table1_ext)
        require(365 * year + table1[year] + ordinal - 1 == day,
                f'Day-to-(year, ordinal) identity failed for day {day}')
        require(1 <= ordinal <= 366, f'Ordinal out of range for day {day}')

    # Fast-path day count: flag bit 3 marks common years; leap years keep 366.
    for year in range(TABLE_LEN):
        flag = table2[year]
        ndays = 366 - (1 if flag & 8 else 0)
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        require(ndays == (366 if leap else 365), f'Fast-path day count wrong for {year}')

    # Year gate: u32(year - 262143) >= 0xfff80002 admits [-262143, 262142].
    for year in [-262144, -262143, -262142, 0, 262141, 262142, 262143, 262144]:
        admitted = ((year - 262143) & 0xffffffff) >= 0xfff80002
        require(admitted == (-262143 <= year <= 262142),
                f'Year gate decode failed for {year}')

    # ---- Census over the whole .text. ----
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    for fn, got, expected in [(C1_START, C1_GOT, C1_CALLERS), (C2_START, C2_GOT, C2_CALLERS)]:
        pos, direct, indirect = 0, [], []
        while (pos := code.find(b'\xff\x15', pos)) >= 0:
            if pos + 6 <= len(code):
                slot = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
                if rels.get(slot) == fn:
                    indirect.append(text['address'] + pos)
            pos += 2
        pos = 0
        while (pos := code.find(b'\xe8', pos)) >= 0:
            if pos + 5 <= len(code):
                destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
                if destination == fn:
                    direct.append(text['address'] + pos)
            pos += 1
        require(direct == [], f'Unexpected direct callers of {fn:#x}')
        require(indirect == expected,
                f'GOT-indirect caller census changed for {fn:#x}: {len(indirect)} sites')
    require(rels.get(C1_GOT) == C1_START, 'callee1 self GOT slot changed')
    require(rels.get(C2_GOT) == C2_START, 'callee2 self GOT slot changed')

    # Cross-link: both callees are called from inside the ema window guard body.
    for site, callers in [(0x474fbf3, C1_CALLERS), (0x474fc46, C2_CALLERS)]:
        require(site in callers, 'Window guard call site missing from census')
        require(GUARD_START <= site < GUARD_END, 'Window guard call site outside the guard body')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        callee_time=dict(
            start_va=hex(C1_START), end_va_exclusive=hex(C1_END), bytes=len(body1),
            sha256=hashlib.sha256(body1).hexdigest(), fde_va=hex(C1_FDE_VA),
            got_slot=hex(C1_GOT),
            inferred_label='chrono NaiveTime overflowing TimeDelta addition '
                           '(seconds-of-day, fraction, day-carry seconds result)'),
        normalization=dict(nanos_per_second=1000000000, carry_threshold=2000000000,
                           negative_step=-1000000000,
                           observed='input fraction compared against 1e9/2e9; '
                                    'six arithmetic-overflow panics guard the adds'),
        day_division=dict(magic=hex(DAY_MAGIC), divisor=86400,
                          identity='euclidean decomposition (magic quotient plus '
                                   'explicit remainder fixup) validated on a signed grid',
                          shared_with='RE-001-ema-window-guard-94 day division'),
        callee_date=dict(
            start_va=hex(C2_START), end_va_exclusive=hex(C2_END), bytes=len(body2),
            sha256=hashlib.sha256(body2).hexdigest(), fde_va=hex(C2_FDE_VA),
            got_slot=hex(C2_GOT),
            inferred_label='chrono NaiveDate day shift returning packed date or 0 '
                           '(observed None marker)'),
        packed_layout=dict(year='dword >>a 13', ordinal='(dword >> 4) & 0x1ff',
                           flags='dword & 0xf; bit 3 (8) marks a common year; '
                                 'bits 0-2 are the Jan-1 weekday class',
                           result='year << 13 | ordinal << 4 | flags, or 0 when the '
                                  'ordinal or year-range check fails'),
        tables=dict(
            leap_cumulative=dict(va=hex(TABLE1_VA), entries=TABLE_LEN,
                                 sentinel_entry_400=97,
                                 model='cumulative proleptic-Gregorian leap days per '
                                       '400-year cycle',
                                 shared_with='RE-001-datediff-chrono-94 leap table'),
            year_flags=dict(va=hex(TABLE2_VA), entries=TABLE_LEN,
                            model='(8 if common else 0) | ((dow(Jan 1) + 1) % 7 + 1) over '
                                  'the astronomical 400-year cycle; 97 leap entries',
                            validated_entries=TABLE_LEN)),
        era_constants=dict(cycle_days=146097, cycle_years=400, days_per_year=365,
                           leap_year_days=366, div400_magic='0x51eb851f',
                           div146097_magic='0x396b06bd',
                           year_estimate_magic='0x6719f361'),
        identities=dict(
            day_division_grid='pass', div400_grid='pass', div146097_grid='pass',
            day_cycle_exhaustive='146097/146097 pass',
            flag_table_400='pass', leap_table_400='pass', fast_path_day_count='pass',
            year_gate='[-262143, 262142]'),
        panic_anchors=dict(
            time_mod=[
                dict(location_va=hex(va), line=line, column=column)
                for va, line, column in C1_LOCATIONS],
            date_mod=[
                dict(location_va=hex(va), line=line, column=column)
                for va, path, line, column in C2_LOCATIONS if path is DATE_PATH],
            internals=[dict(location_va='0x56721a0', line=80, column=9,
                            table_length_operands=[400, 401])],
            callees=dict(panic_a=hex(PANIC_A), got_a=hex(GOT_PANIC_A),
                         panic_b=hex(PANIC_B), got_b=hex(GOT_PANIC_B),
                         panic_index=hex(PANIC_C), got_index=hex(GOT_PANIC_C))),
        call_census=dict(
            callee_time=dict(got_slot=hex(C1_GOT), got_indirect_sites=len(C1_CALLERS),
                             direct_e8=0),
            callee_date=dict(got_slot=hex(C2_GOT), got_indirect_sites=len(C2_CALLERS),
                             direct_e8=0),
            window_guard_sites=dict(callee_time='0x474fbf3', callee_date='0x474fc46'),
            note='byte-pattern census over the complete .text for e8/ff15 encodings'),
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
