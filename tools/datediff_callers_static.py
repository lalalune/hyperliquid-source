#!/usr/bin/env python3
"""Authenticated node94 chrono date-difference caller binding (0x1450a60, 0x13cec80).

Binds the two callers of the chrono date-difference core left outside the
datediff and Time Sub packets to the node #94 digest: the 115-byte
microseconds wrapper 0x1450a60 (euclidean borrow adjustment, the 1e6 and 1e9
immediates, the 0x10624dd3 divide-by-1000 magic with shift 38, the shared
1e6 double at 0x20ae60, the absolute-value mask at 0x202ed0, and its single
GOT-mediated caller) and the datediff call site at +0x1141 of the 7186-byte
body 0x13cec80..0x13d0892 (FDE-bound, single GOT-mediated caller, body itself
out of scope). Static byte/record checks only; the captured binary is never
executed.
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

# Wrapper 0x1450a60.
WRAP_START, WRAP_END = 0x1450a60, 0x1450ad3
WRAP_FDE_VA = 0xcec23c
GOT_DIFF, DIFF_FN = 0x576eaa0, 0x151d1b0       # datediff core, PR#66 packet
GOT_WRAP, WRAP_CALLER = 0x576f6c8, 0x44ab1b2
MICROS_IMM = 0xf4240                             # 1e6
NANOS_IMM = 0x3b9aca00                           # 1e9
DIV1000_MAGIC = 0x10624dd3
ONE_E6_VA = 0x20ae60                             # shared 1e6 double anchor
ABS_MASK_VA = 0x202ed0
ABS_MASK = 'ffffffffffffff7fffffffffffffff7f'
CALLER_FN = (0x44aa5a0, 0x44ab55b)               # FDE bounds of the wrapper caller

# Giant 0x13cec80 (datediff call site only).
GIANT_START, GIANT_END = 0x13cec80, 0x13d0892
GIANT_FDE_VA = 0xfc624c
GIANT_CALL_OFFSET = 0x1141
GOT_GIANT, GIANT_CALLER = 0x576ea80, 0x1400e4f
GIANT_CALLER_FN = (0x1400d80, 0x1400e8d)         # FDE bounds of the giant caller

WRAP_BODY = bytes.fromhex(
'50ff1539e031044885c0400f98c685d20f9fc14020f10fb6f14801c64869c640'
'420f00660f57c070408db2003665c484c90f44f24863ce4869c9d34d62104889'
'ca48c1ea3f48c1f92601d14863c94801c80f90c1f6c10175100f57c0f2480f2a'
'c0f20f5e0597a3dbfe660f5405ff23dbfe58c3')

WRAP_FDE = bytes.fromhex(
'1400000028ad00001c4876007300000000410e1002710e08')

GIANT_FDE = bytes.fromhex(
'34000000248600002c8a4000121c000004f79195ff410e10420e18420e20420e'
'28420e30410e38470ec00283078c068d058e048f03860200')

# (offset, bytes, label) anchors inside the wrapper body.
WRAP_ANCHORS = [
    (0x0, '50', 'push rax return slot'),
    (0x1, 'ff1539e03104', 'datediff core call'),
    (0x1c, '4869c640420f00', 'seconds * 1e6 immediate'),
    (0x29, '8db2003665c4', 'nanos - 1e9 borrow adjust'),
    (0x37, '4869c9d34d6210', 'divide-by-1000 magic'),
    (0x45, '48c1f926', 'magic shift 38'),
    (0x61, 'f20f5e0597a3dbfe', 'divide by the shared 1e6 double'),
    (0x69, '660f5405ff23dbfe', 'absolute-value mask'),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def div1000_quotient(x):
    """Decoded 0x1450a94..0x1450ab1: truncating magic division by 1000."""
    product = x * DIV1000_MAGIC
    quotient = (product >> 38) + ((product >> 63) & 1)
    return quotient


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

    # ---- Wrapper: body, FDE, anchors. ----
    body = reader.read(WRAP_START, WRAP_END - WRAP_START)
    require(body == WRAP_BODY, 'Wrapper body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= WRAP_FDE_VA < eh['address'] + eh['size'], 'wrapper FDE outside .eh_frame')
    fde = reader.read(WRAP_FDE_VA, len(WRAP_FDE))
    require(fde == WRAP_FDE, 'Wrapper FDE record changed')
    length = struct.unpack_from('<I', fde, 0)[0]
    pc = WRAP_FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require(length == len(WRAP_FDE) - 4, 'wrapper FDE length changed')
    require((pc, pc + extent) == (WRAP_START, WRAP_END), 'wrapper FDE PC range changed')

    for offset, hexstr, label in WRAP_ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, f'Wrapper anchor changed: {label}')

    # The datediff call resolves through the core's GOT slot.
    disp = struct.unpack_from('<i', body, 3)[0]
    require(WRAP_START + 1 + 6 + disp == GOT_DIFF, 'datediff GOT displacement changed')
    require(rels.get(GOT_DIFF) == DIFF_FN, 'datediff GOT slot target changed')

    # The two rip-relative double loads hit the shared 1e6 anchor and the
    # absolute-value mask.
    disp = struct.unpack_from('<i', body, 0x65)[0]
    require(WRAP_START + 0x61 + 8 + disp == ONE_E6_VA, '1e6 anchor address changed')
    require(struct.unpack('<d', reader.read(ONE_E6_VA, 8))[0] == 1e6,
            '1e6 anchor value changed')
    disp = struct.unpack_from('<i', body, 0x6d)[0]
    require(WRAP_START + 0x69 + 8 + disp == ABS_MASK_VA, 'abs mask address changed')
    require(reader.read(ABS_MASK_VA, 16) == bytes.fromhex(ABS_MASK),
            'abs mask pattern changed')

    # Divide-by-1000 identity: truncating for the signed nanosecond domain.
    for x in list(range(-1000, 1001, 37)) + [-999999999, -1, 0, 1, 999999999]:
        q = div1000_quotient(x)
        expected = (-(-x // 1000)) if x < 0 else x // 1000
        require(q == expected,
                f'Divide-by-1000 identity failed for {x}')

    # ---- Giant: FDE and the datediff call site only. ----
    gfde = reader.read(GIANT_FDE_VA, len(GIANT_FDE))
    require(gfde == GIANT_FDE, 'Giant FDE record changed')
    pc = GIANT_FDE_VA + 8 + struct.unpack_from('<i', gfde, 8)[0]
    extent = struct.unpack_from('<I', gfde, 12)[0]
    require((pc, pc + extent) == (GIANT_START, GIANT_END), 'giant FDE PC range changed')
    site = reader.read(GIANT_START + GIANT_CALL_OFFSET, 6)
    require(site[:2] == bytes.fromhex('ff15'), 'giant datediff call opcode changed')
    disp = struct.unpack_from('<i', site, 2)[0]
    require(GIANT_START + GIANT_CALL_OFFSET + 6 + disp == GOT_DIFF,
            'giant datediff call GOT changed')

    # ---- Census over the whole .text. ----
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    for fn, got, expected, name in [(WRAP_START, GOT_WRAP, [WRAP_CALLER], 'wrapper'),
                                    (GIANT_START, GOT_GIANT, [GIANT_CALLER], 'giant')]:
        direct, indirect, lea = [], [], []
        pos = 0
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
        for m in range(len(code) - 7):
            if code[m] == 0x48 and code[m + 1] == 0x8d and (code[m + 2] & 0xC7) == 0x05:
                d = struct.unpack_from('<i', code, m + 3)[0]
                if text['address'] + m + 7 + d == fn:
                    lea.append(text['address'] + m)
        require(direct == [], f'Unexpected direct callers of the {name}')
        require(indirect == expected, f'{name} caller census changed')
        require(lea == [], f'{name} gained lea references')
        require(rels.get(got) == fn, f'{name} GOT slot changed')

    require(CALLER_FN[0] <= WRAP_CALLER < CALLER_FN[1], 'wrapper caller outside its FDE')
    require(GIANT_CALLER_FN[0] <= GIANT_CALLER < GIANT_CALLER_FN[1],
            'giant caller outside its FDE')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        wrapper=dict(start_va=hex(WRAP_START), end_va_exclusive=hex(WRAP_END),
                     bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                     fde_va=hex(WRAP_FDE_VA), got_slot=hex(GOT_WRAP),
                     inferred_label='date-difference to float-seconds wrapper'),
        structure=dict(
            observed='datediff returns (i64 seconds, i32 nanos); a borrow flag '
                     '(seconds < 0 and nanos > 0) adjusts both parts; the seconds '
                     'scale by 1e6, the nanos divide by 1000 through the '
                     '0x10624dd3 magic with shift 38, the sums convert to double '
                     'and divide by the shared 1e6 double; the result is masked '
                     'with the absolute-value constant pair',
            overflow_guards='two seto/jne pairs skip the conversion on overflow',
            immediates=dict(micros_per_second=1000000, nanos_per_second=1000000000,
                            div1000_magic='0x10624dd3', div1000_shift=38)),
        shared_anchors=dict(one_e6_double='0x20ae60', abs_mask='0x202ed0',
                            datediff_got='0x576eaa0', datediff_core='0x151d1b0',
                            note='datediff core and 1e6 double shared with '
                                 'RE-001-datediff-chrono-94'),
        giant=dict(start_va=hex(GIANT_START), end_va_exclusive=hex(GIANT_END),
                   bytes=GIANT_END - GIANT_START, fde_va=hex(GIANT_FDE_VA),
                   got_slot=hex(GOT_GIANT),
                   datediff_call_offset=hex(GIANT_CALL_OFFSET),
                   scope='FDE record and the datediff call site only; the body '
                         'itself stays unbound'),
        identities=dict(div1000_trunc_grid='pass over [-1e9, 1e9] samples'),
        call_census=dict(wrapper=dict(got_slot=hex(GOT_WRAP), got_indirect=['0x44ab1b2'],
                                      direct_e8=0, lea_refs=0),
                         giant=dict(got_slot=hex(GOT_GIANT), got_indirect=['0x1400e4f'],
                                    direct_e8=0, lea_refs=0),
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
