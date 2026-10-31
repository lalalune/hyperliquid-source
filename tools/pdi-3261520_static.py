#!/usr/bin/env python3
"""Authenticated node94 pdi-3261520 binding (0x3261520).

Machine-derived static binding: FDE record, body bytes, every branch
destination, every direct and GOT-mediated call site, every panic
Location, and the whole-.text caller census, all checked byte-exactly
against the authenticated node #94 digest. Static checks only; the
captured binary is never executed.
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

START, END = 0x3261520, 0x3261b23
FDE_VA = 0x115b784
FDE = bytes.fromhex(
    '500000005cdb1900945d1002030600000433e191ff410e10420e18420e20420e'
    '28420e30410e38470ec00283078c068d058e048f0386020302050e38410e3042'
    '0e28420e20420e18420e10410e08410ec0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec080100004889bc249000000048c74424400000'
    '000048c74424500000000048c74424580000000048c74424680000000048c784'
    '24d00000000000000048c78424e000000000000000488b421048894424304885'
    'c00f84500400004889d1488b7a30ba102700004889f848f7e20f802605000049'
    '89c04c8b6108488b44243048c1e004488d04404889842498000000488b461048'
    '894424284869c7005307004883c82a48898424a80000004889bc24b800000048'
    '69c700a60e004803460848898424b00000004531ed48b94b598638d6c56d344d'
    '89c64c898424a00000004c89642438904c89f048f7e14d39c60f826a04000048'
    '89d548c1ed0b4c69e5f0d8ffff4d01f44c89f048f7e14c3b6424280f83200400'
    '004889d3488b4424384a8b7428084a8b7c28104885ff48893c244c89b424c000'
    '00004c89ac24c800000074244889742408ff1561c950024885c00f84d0030000'
    '4989c7488b742408eb0c660f1f44000041bf010000004c69f5005af1ff4c03b4'
    '24b000000048c1eb0b4c89ff4c8b2c244c89eaff1527c950024c896c24104c89'
    '7c24184c896c24204c8bac24c8000000438b446e38488d8c2480000000894108'
    '4b8b446e30488901483b9c24b80000000f85480300004c3b6424300f833d0300'
    '004869c500530700488bac24a80000004829c54c8b6424384b8d042c48894424'
    '080fb64405004883f8070f8368030000f3430f6f446e20b90600000029c1c1e1'
    '03660f6fc8660fdb0dd378fafc660feb0d8b5ffafc660f73d020660feb05be34'
    'fafc660f5c05c634fafc660f58c1488d05933332fdf20f100c01660f14c9660f'
    '5ec1660f29442470488dbc24e8000000488d742440488d542410488d4c2470e8'
    'fc8614004b8b5c2c084b8b7c2c104885ff48893c247419ff151bc850024885c0'
    '0f848a0200004989c7eb0b0f1f44000041bf010000004c89ff4889de488b1c24'
    '4889daff15f7c7500248895c24104c897c241848895c24204b8b046e4b8b4c6e'
    '10438b546e18488db4248000000089560848890e488b4c24080fb60c294883f9'
    '070f8380020000ba0600000029cac1e203f3430f7e446e0866480f6ec8660f6c'
    'c8660f6fc1660fdb05d377fafc660feb058b5efafc660f73d120660feb0dbe33'
    'fafc660f5c0dc633fafc660f58c8488d05933232fdf20f100402660f14c0660f'
    '5ec8660f294c2470488dbc24e8000000488d742458488d542410488d4c2470e8'
    'fc8514004b8b5c2c084b8b7c2c104885ff48893c247419ff151bc750024885c0'
    '0f848a0100004989c7eb0b0f1f44000041bf010000004c89ff4889de488b1c24'
    '4889daff15f7c6500248895c24104c897c241848895c24204b8b446e404b8b4c'
    '6e50438b546e58488db4248000000089560848890e488b4c24080fb60c294883'
    'f9070f838e010000ba0600000029cac1e203f3430f7e446e4866480f6ec8660f'
    '6cc8660f6fc1660fdb05d276fafc660feb058a5dfafc660f73d120660feb0dbd'
    '32fafc660f5c0dc532fafc660f58c8488d05923132fdf20f100402660f14c066'
    '0f5ec8660f294c2470488dbc24e8000000488db424d0000000488d542410488d'
    '4c2470e8f88414004983c5304c8bb424c000000049ffc64c39ac24980000004c'
    '8b8424a000000048b94b598638d6c56d340f8539fcffff488b4c2450488b8424'
    '9000000048894810488b4c2440488908488b4c244848894808488b4c24584889'
    '4818488b4c246048894820488b4c2468488948280f108424d00000000f114030'
    '488b8c24e0000000488948404881c4080100005b415c415d415e415f5dc3488d'
    '3d7b074902ff1525ca5002e982000000bf01000000488b3424ff1559c55002eb'
    '714c89f048f7e148c1ea0b4869faf0d8ffff4c01f7488d1564dd4702488b7424'
    '28ff1541c55002eb49488d3d38dd4702ff1582c65002eb3a488d3db1184902ff'
    '15abc65002eb2b488d3da2184902ff159cc65002eb1c488d3d93184902ff158d'
    'c65002eb0d488d3dfcdc4702ff15dec650020f0beb02eb004889c3eb174889c3'
    '488b34244885f6740b4c89ff31d2ff151cc55002488dbc24d0000000e89ff319'
    '00488d7c2458e895f31900488d7c2440e88bf319004889dfe8f3e53f02ff1505'
    'c65002'
)
BODY_SHA256 = '11f5a83c6fbcc45c8a68f14eaf2235efbbd83eb27733be2b441c281d55768f9a'
BRANCHES = [
    (0x61, '0f8450040000', 2, 6, 0x32619d7),
    (0x79, '0f8026050000', 2, 6, 0x3261ac5),
    (0xf9, '0f826a040000', 2, 6, 0x3261a89),
    (0x11b, '0f8320040000', 2, 6, 0x3261a61),
    (0x14a, '7424', 1, 2, 0x3261690),
    (0x15a, '0f84d0030000', 2, 6, 0x3261a50),
    (0x168, 'eb0c', 1, 2, 0x3261696),
    (0x1d0, '0f8548030000', 2, 6, 0x3261a3e),
    (0x1db, '0f833d030000', 2, 6, 0x3261a3e),
    (0x20a, '0f8368030000', 2, 6, 0x3261a98),
    (0x295, '7419', 1, 2, 0x32617d0),
    (0x2a0, '0f848a020000', 2, 6, 0x3261a50),
    (0x2a9, 'eb0b', 1, 2, 0x32617d6),
    (0x301, '0f8380020000', 2, 6, 0x3261aa7),
    (0x395, '7419', 1, 2, 0x32618d0),
    (0x3a0, '0f848a010000', 2, 6, 0x3261a50),
    (0x3a9, 'eb0b', 1, 2, 0x32618d6),
    (0x402, '0f838e010000', 2, 6, 0x3261ab6),
    (0x4b1, '0f8539fcffff', 2, 6, 0x3261610),
    (0x52b, 'e982000000', 1, 5, 0x3261ad2),
    (0x53f, 'eb71', 1, 2, 0x3261ad2),
    (0x567, 'eb49', 1, 2, 0x3261ad2),
    (0x576, 'eb3a', 1, 2, 0x3261ad2),
    (0x585, 'eb2b', 1, 2, 0x3261ad2),
    (0x594, 'eb1c', 1, 2, 0x3261ad2),
    (0x5a3, 'eb0d', 1, 2, 0x3261ad2),
    (0x5b4, 'eb02', 1, 2, 0x3261ad8),
    (0x5b6, 'eb00', 1, 2, 0x3261ad8),
    (0x5bb, 'eb17', 1, 2, 0x3261af4),
    (0x5c7, '740b', 1, 2, 0x3261af4),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x326179f, 0x33a9ea0),
    (0x326189f, 0x33a9ea0),
    (0x32619a3, 0x33a9ea0),
    (0x3261afc, 0x3400ea0),
    (0x3261b06, 0x3400ea0),
    (0x3261b10, 0x3400ea0),
    (0x3261b18, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3261671, 0x576dfd8),
    (0x32616b3, 0x576dfe0),
    (0x32617b7, 0x576dfd8),
    (0x32617e3, 0x576dfe0),
    (0x32618b7, 0x576dfd8),
    (0x32618e3, 0x576dfe0),
    (0x3261a45, 0x576e470),
    (0x3261a59, 0x576dfb8),
    (0x3261a81, 0x576dfc8),
    (0x3261a90, 0x576e118),
    (0x3261a9f, 0x576e150),
    (0x3261aae, 0x576e150),
    (0x3261abd, 0x576e150),
    (0x3261acc, 0x576e1b0),
    (0x3261aee, 0x576e010),
    (0x3261b1d, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3261a3e, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x3261a75, 0x56df7e0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
    (0x3261a89, 0x56df7c8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f61737365742f7064692e7273'), 30, 14),
    (0x3261a98, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
    (0x3261aa7, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
    (0x3261ab6, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5775528']
GOT_SITES = {'0x5775528': ['0x4855fc6']}


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


def analyze(data):
    reader = Reader(data)
    body = reader.read(START, END - START)
    require(body == BODY, 'Body bytes changed')
    require(hashlib.sha256(body).hexdigest() == BODY_SHA256, 'Body hash changed')

    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'],
            'FDE outside .eh_frame')
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'FDE record changed')
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

    for offset, pattern, rel_pos, insn_len, destination in TAIL_CALLS:
        raw = bytes.fromhex(pattern)
        require(body[offset:offset + len(raw)] == raw,
                f'Tail-jump instruction changed at +{offset:#x}')
        fmt = '<b' if insn_len == 2 else '<i'
        rel = struct.unpack_from(fmt, body, offset + rel_pos)[0]
        require(START + offset + insn_len + rel == destination,
                f'Tail-jump destination changed at +{offset:#x}')
        require(not (START <= destination < END), 'Tail jump stayed inside the body')

    for site, target in DIRECT_CALLS:
        off = site - START
        require(body[off] == 0xe8, f'Direct call opcode changed at {site:#x}')
        rel = struct.unpack_from('<i', body, off + 1)[0]
        require(site + 5 + rel == target,
                f'Direct call destination changed at {site:#x}')

    rels = relocations(reader)
    for site, slot in INDIRECT_CALLS:
        off = site - START
        require(body[off:off + 2] == b'\xff\x15',
                f'Indirect call opcode changed at {site:#x}')
        disp = struct.unpack_from('<i', body, off + 2)[0]
        require(site + 6 + disp == slot,
                f'Indirect call slot changed at {site:#x}')

    seen = []
    for site, loc_va, path, line, column in LOCATIONS:
        off = site - START
        require(body[off:off + 3] in (b'\x48\x8d\x3d', b'\x48\x8d\x15',
                                      b'\x4c\x8d\x1d'),
                f'Location lea changed at {site:#x}')
        require(site + 7 + struct.unpack_from('<i', body, off + 3)[0] == loc_va,
                f'Location address changed at {site:#x}')
        path_va = rels.get(loc_va)
        require(path_va is not None, f'Location relocation missing at {loc_va:#x}')
        length_, line_, column_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((length_, line_, column_) == (len(path), line, column),
                f'Location layout changed at {loc_va:#x}')
        require(reader.read(path_va, length_) == path,
                f'panic path changed at {loc_va:#x}')
        seen.append(dict(location_va=hex(loc_va), line=line, column=column,
                         path=path.decode().rsplit('src/', 1)[-1]))

    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = (text['address'] + pos + 5
                           + struct.unpack_from('<i', code, pos + 1)[0])
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    require(direct == CALLERS, f'Direct caller census changed: {[hex(x) for x in direct]}')

    lea_refs = 0
    pos = 0
    while (pos := code.find(b'\x48\x8d', pos)) >= 0:
        if pos + 7 <= len(code) and (code[pos + 2] & 0xC7) == 0x05:
            destination = (text['address'] + pos + 7
                           + struct.unpack_from('<i', code, pos + 3)[0])
            if destination == START:
                lea_refs += 1
        pos += 1
    require(lea_refs == LEA_REFS, f'lea census changed: {lea_refs}')

    from collections import Counter
    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        body=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                  sha256=BODY_SHA256, fde_va=hex(FDE_VA)),
        locations=seen,
        direct_calls={hex(t): n for t, n in Counter(t for _, t in DIRECT_CALLS).items()},
        tail_calls={hex(t): n for t, n in Counter(t for _, _, _, _, t in TAIL_CALLS).items()},
        indirect_got={hex(slot): n for slot, n in
                      Counter(slot for _, slot in INDIRECT_CALLS).items()},
        call_census=dict(direct_e8=[hex(x) for x in CALLERS], lea_references=LEA_REFS,
                         caller_functions=CALLER_FUNCTIONS,
                         own_got_slots=OWN_GOT_SLOTS, got_sites=GOT_SITES,
                         denominator='complete .text scan for e8 and lea encodings'),
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

