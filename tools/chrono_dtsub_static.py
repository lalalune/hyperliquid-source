#!/usr/bin/env python3
"""Authenticated node94 chrono NaiveDateTime-Sub wrapper binding (0x151d080).

Binds the datetime-level wrapper that consumes both chrono shift helpers of
the chrono-shift packet to the node #94 digest: its FDE-bounded body, the
TimeDelta negation complement (1e9-nanos, -1-secs), the i64::MIN sentinel
check, both day-carry range gates (the second pair identical to the ema
window-guard packet), the unsigned 86400 magic variant, both helper GOT
slots, three panic Locations across time_delta.rs and naive/time/mod.rs,
and the four-site GOT-mediated call census. Static byte/record checks only;
the captured binary is never executed.
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

START, END = 0x151d080, 0x151d1a4
FDE_VA = 0xcf62d8

CHRONO_ROOT = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
               b'chrono-0.4.38/src/')
DELTA_PATH = CHRONO_ROOT + b'time_delta.rs'
TIME_PATH = CHRONO_ROOT + b'naive/time/mod.rs'

# (lea site, Location struct VA, expected path, line, column).
LOCATIONS = [
    (0x151d17d, 0x5671eb0, DELTA_PATH, 475, 27),
    (0x151d18a, 0x5671ec8, TIME_PATH, 670, 16),
    (0x151d197, 0x5671e98, DELTA_PATH, 473, 26),
]

# GOT slots -> relocated targets for the five indirect calls.
GOT_C1, GOT_C2 = 0x576e8a8, 0x576e8b0          # both helpers, as in the shift packet
GOT_PANIC_NEW, GOT_PANIC_SHARED = 0x576eb38, 0x576e150
PANIC_NEW, PANIC_SHARED = 0x157b4c0, 0x157b520
CALLEE1, CALLEE2 = 0x15206e0, 0x151f870
GOT_SELF = 0x576f748

NANOS_PER_SEC = 0x3b9aca00      # 1e9, negation complement base
I64_MIN = 0x8000000000000000    # day-carry sentinel
DAY_MAGIC = 0x1845c8a0ce512957  # unsigned 86400 division variant here (shr, not sar)
SECS_PER_DAY = 86400
DATE_RANGE_LO, DATE_RANGE_HI = 0xffdf3b645a1cac08, 0xffbe76c8b4395811
DT_RANGE_LO, DT_RANGE_HI = 0xffff574000000000, 0xfffeae7ffffeae81  # as in the guard packet

CALL_SITES = [0x151c698, 0x2229fd4, 0x470f1b4, 0x4717007]

BODY = bytes.fromhex(
    '41574156534883ec204989f64889fb85c90f84d600000089c8b900ca9a3b29c1'
    '0f80f100000048c7c0ffffffff4889d648f7de0f80c4000000498d760449bf00'
    '000000000000804829d04889e74889c2ff15d2172504488b4424084c39f80f84'
    'a600000048b908ac1c5a643bdfff4801c148ba115839b4c876beff4839d1725a'
    '48b9000000004057ffff4801c148ba81aefeff7faefeff4839d1723ef20f1004'
    '240f29442410418b3e48b9572951cea0c8451848f7e94889d648c1ee3f48c1ea'
    '0d01d6ff156717250485c0740d89030f284424100f134304eb06c70300000000'
    '4889d84883c4205b415e415fc331c031c94889d648f7de0f813cffffff488d3d'
    '2c4d1504ff15ae192504488d3d374d1504ff15a1192504488d3dfa4c1504ff15'
    'ac0f2504'
)
FDE = bytes.fromhex(
    '30000000c44d0100a06d82002401000000420e10420e18410e20440e4083048e'
    '038f0202de0e20410e18420e10420e08410e4000')

# Verified conditional branches and the tail jump (offset, pattern,
# rel32 position, instruction length, destination).
BRANCHES = [
    (0x11, '0f84d6000000', 2, 6, 0x151d16d),
    (0x20, '0f80f1000000', 2, 6, 0x151d197),
    (0x33, '0f80c4000000', 2, 6, 0x151d17d),
    (0x5e, '0f84a6000000', 2, 6, 0x151d18a),
    (0x7e, '725a', 1, 2, 0x151d15a),
    (0x9a, '723e', 1, 2, 0x151d15a),
    (0xcb, '740d', 1, 2, 0x151d15a),
    (0xd8, 'eb06', 1, 2, 0x151d160),
    (0xf7, '0f813cffffff', 2, 6, 0x151d0b9),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


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


def unsigned_day_quotient(n):
    high = (n * DAY_MAGIC) >> 64
    return (high >> 13) + (high >> 63)


def analyze(data):
    reader = Reader(data)
    body = reader.read(START, END - START)
    require(body == BODY, 'Wrapper body bytes changed')
    require(len(body) == 292, 'FDE extent length changed')

    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'],
            'FDE outside .eh_frame')
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'Wrapper FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, pattern, rel_pos, insn_len, destination in BRANCHES:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'Branch instruction changed at +{offset:#x}')
        fmt = '<b' if insn_len == 2 else '<i'
        rel = struct.unpack_from(fmt, body, offset + rel_pos)[0]
        require(START + offset + insn_len + rel == destination,
                f'Branch destination changed at +{offset:#x}')
        require(START <= destination < END, 'Branch escapes body')

    # TimeDelta negation: 1e9 complement, -1 borrow, i64::MIN sentinel.
    require(body[0x19:0x1e] == bytes.fromhex('b900ca9a3b'),
            'negation 1e9 complement changed')
    require(body[0x26:0x2d] == bytes.fromhex('48c7c0ffffffff'),
            'negation -1 borrow changed')
    require(body[0x3d:0x47] == bytes.fromhex('49bf0000000000000080'),
            'i64::MIN sentinel changed')

    # Day-carry range gates; the second pair is the guard packet's gate.
    require(struct.unpack_from('<Q', body, 0x66)[0] == DATE_RANGE_LO,
            'date range low changed')
    require(struct.unpack_from('<Q', body, 0x73)[0] == DATE_RANGE_HI,
            'date range high changed')
    require(struct.unpack_from('<Q', body, 0x82)[0] == DT_RANGE_LO,
            'datetime range low changed')
    require(struct.unpack_from('<Q', body, 0x8f)[0] == DT_RANGE_HI,
            'datetime range high changed')

    # Unsigned 86400 magic variant: shr 63 / shr 13 (logical, not sar).
    require(struct.unpack_from('<Q', body, 0xab)[0] == DAY_MAGIC,
            'day-division magic changed')
    require(body[0xb9:0xc1] == bytes.fromhex('48c1ee3f48c1ea0d'),
            'unsigned day-division shifts changed')

    rels = relocations(reader)
    require(rels.get(GOT_C1) == CALLEE1, 'callee1 GOT slot changed')
    require(rels.get(GOT_C2) == CALLEE2, 'callee2 GOT slot changed')
    require(rels.get(GOT_PANIC_NEW) == PANIC_NEW, 'new panic GOT slot changed')
    require(rels.get(GOT_PANIC_SHARED) == PANIC_SHARED, 'shared panic GOT slot changed')
    require(rels.get(GOT_SELF) == START, 'wrapper GOT slot changed')
    for insn_va, got in [(0x151d0d0, GOT_C1), (0x151d143, GOT_C2),
                         (0x151d184, GOT_PANIC_NEW), (0x151d191, GOT_PANIC_NEW),
                         (0x151d19e, GOT_PANIC_SHARED)]:
        off = insn_va - START
        require(body[off:off + 2] == b'\xff\x15',
                f'Indirect call opcode changed at {insn_va:#x}')
        disp = struct.unpack_from('<i', body, off + 2)[0]
        require(insn_va + 6 + disp == got,
                f'Indirect call target changed at {insn_va:#x}')

    seen = []
    for site, loc_va, path, line, column in LOCATIONS:
        off = site - START
        require(body[off:off + 3] == b'\x48\x8d\x3d',
                f'Location lea changed at {site:#x}')
        require(site + 7 + struct.unpack_from('<i', body, off + 3)[0] == loc_va,
                f'Location address changed at {site:#x}')
        path_va = rels.get(loc_va)
        require(path_va is not None, f'Location relocation missing at {loc_va:#x}')
        length_, line_, column_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((length_, line_, column_) == (len(path), line, column),
                f'Location layout changed at {loc_va:#x}')
        require(reader.read(path_va, length_) == path,
                f'chrono path changed at {loc_va:#x}')
        seen.append(dict(location_va=hex(loc_va), line=line, column=column,
                         path=path.decode().split('chrono-0.4.38/src/')[-1]))

    # The unsigned variant computes n // 86400 exactly for non-negative n
    # (the day carry is range-gated before the division).
    for n in list(range(0, 4_000_000, 7919)) + [10**9, 10**12]:
        require(unsigned_day_quotient(n) == n // SECS_PER_DAY,
                f'unsigned 86400 identity failed for {n}')

    # Census over the complete .text.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct, lea_refs, got_sites = [], [], []
    pos = 0
    while pos < len(code) - 6:
        byte = code[pos]
        va = text['address'] + pos
        if byte == 0xe8 and pos + 5 <= len(code):
            destination = va + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(va)
            pos += 1
        elif byte == 0xff and code[pos + 1] == 0x15:
            slot = va + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if slot == GOT_SELF:
                got_sites.append(va)
            pos += 2
        elif byte == 0x48 and code[pos + 1] == 0x8d and (code[pos + 2] & 0xC7) == 0x05:
            destination = va + 7 + struct.unpack_from('<i', code, pos + 3)[0]
            if destination == START:
                lea_refs.append(va)
            pos += 3
        else:
            pos += 1
    require(direct == [], f'Direct caller census changed: {[hex(x) for x in direct]}')
    require(lea_refs == [], f'lea reference census changed: {[hex(x) for x in lea_refs]}')
    require(got_sites == CALL_SITES,
            f'GOT census changed: {[hex(x) for x in got_sites]}')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        wrapper=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                     sha256=hashlib.sha256(body).hexdigest(), fde_va=hex(FDE_VA),
                     got=hex(GOT_SELF),
                     inferred_label='NaiveDateTime Sub wrapper: negate TimeDelta, '
                                    'shift NaiveTime, gate day carry, shift NaiveDate'),
        chrono_anchors=dict(
            locations=seen,
            negation=dict(nanos_complement=NANOS_PER_SEC, secs_borrow=-1,
                          observed='(-1 - secs, 1e9 - nanos) when nanos nonzero; '
                                   '(0 - secs, 0) otherwise',
                          delta_paths='time_delta.rs:473 and :475 (impl Neg sites)'),
            sentinel=dict(value=hex(I64_MIN),
                          observed='day carry equal to i64::MIN routes to a panic'),
            range_gates=dict(
                date=dict(low=hex(DATE_RANGE_LO), high=hex(DATE_RANGE_HI),
                          observed='first gate over the day carry'),
                datetime=dict(low=hex(DT_RANGE_LO), high=hex(DT_RANGE_HI),
                              observed='second gate, identical constants to the ema '
                                       'window-guard packet')),
            day_division=dict(magic=hex(DAY_MAGIC), divisor=SECS_PER_DAY,
                              variant='unsigned (shr 63 / shr 13), unlike the '
                                      'signed variant inside callee1',
                              identity='exact n // 86400 for non-negative n')),
        helper_got=dict(callee1=dict(slot=hex(GOT_C1), target=hex(CALLEE1),
                                     site='0x151d0d0'),
                        callee2=dict(slot=hex(GOT_C2), target=hex(CALLEE2),
                                     site='0x151d143')),
        panic_got={hex(GOT_PANIC_NEW): hex(PANIC_NEW),
                   hex(GOT_PANIC_SHARED): hex(PANIC_SHARED)},
        call_census=dict(direct_e8=0, lea_references=0,
                         got_mediated=[hex(x) for x in CALL_SITES],
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
