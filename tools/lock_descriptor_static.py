#!/usr/bin/env python3
"""Authenticated node94 lock-guard cell descriptor binding (0x5786278 family).

Binds the .data cell the shared read-lock helper consults (bound separately in
RE-001-readlock-helper-94) to the node #94 digest: the 0x40-byte cell at
0x5786278 with its two relocation-bound code pointers, the 18-byte zeroing
glue 0x35ab620 reachable only through the cell's first slot, the 180-byte
accessor 0x3790fc0 that builds a 48-byte value through the chrono-adjacent
callee 0x151f6f0 with the constant index 0xaf93b, and the 353-byte sibling
guard 0x358db60 (GOT slot 0x5773e18, three call sites) whose six descriptor
lea references, lock cmpxchg sequences and 1e9-nanosecond timeout mirror the
952-site helper. Static byte/record checks only; the captured binary is never
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

# Cell (.data) and its two relocation-bound targets.
DESC_VA = 0x5786278
DROP_START, DROP_END = 0x35ab620, 0x35ab632
DROP_FDE_VA = 0xe3586c
ACC_START, ACC_END = 0x3790fc0, 0x3791074
ACC_FDE_VA = 0x11a7fd0
ACC_INDEX = 0xaf93b
GOT_LOOKUP, LOOKUP_FN = 0x576e890, 0x151f6f0
GOT_DISPLAY, DISPLAY_FN = 0x576e470, 0x157a9f0
GOT_PANIC_A, PANIC_A = 0x576e118, 0x157b480
GOT_PANIC_B, PANIC_B = 0x576e128, 0x157b63b

# Sibling guard (rare variant of the 952-site helper).
SIB_START, SIB_END = 0x358db60, 0x358dcc1
SIB_FDE_VA = 0x1187d78
SIB_GOT = 0x5773e18
SIB_CALLERS = [0x2359937, 0x4cae247, 0x4cb6bd7]
CALLER_FN = [(0x2355f40, 0x235e836), (0x4caa870, 0x4cb31f6), (0x4cb3200, 0x4cbbb86)]
GOT_ONCE, ONCE_FN = 0x576e8b8, 0x4ee3b20
GOT_UNPARK_A, UNPARK_A = 0x576f600, 0x4e0c150
GOT_UNPARK_B, UNPARK_B = 0x576f608, 0x4e0d2c0

# The 952-site helper (separate packet) and its own six cell references.
HELPER_START, HELPER_END = 0x358dcd0, 0x358de41
HELPER_LEA_SITES = [0x358dcf7, 0x358dd55, 0x358ddb3, 0x358ddd2, 0x358ddf6, 0x358de2a]

# (offset, bytes, label) anchors inside the sibling body.
SIB_ANCHORS = [
    (0x13, 'b908000000', 'mov ecx, 8 (cell state claim)'),
    (0xe9, 'ba00ca9a3b', '1e9-nanosecond park timeout'),
    (0xc1, 'be01000000', 'mov esi, 1 (once force flag)'),
]

SIB_LEA_OFFSETS = [0x29, 0x94, 0xe2, 0xf4, 0x118, 0x14a]

ACC_ANCHORS = [
    (0x2b, 'bf3bf90a00', 'constant index 0xaf93b'),
]

DESC = bytes.fromhex(
'0000000000000000000000000000000000000000000000000000000000000000'
'0300000000000000000000000000000000000000000000000000000000000000')

DROP_BODY = bytes.fromhex(
'4889f848c74718000000000f57c00f1107c3')

DROP_FDE = bytes.fromhex(
'1000000058431500ac5d77021200000000000000')

ACC_BODY = bytes.fromhex(
'534883ec404889fb48c7442420000000000f57c00f1144243048c74424080000'
'000048c744241800000000bf3bf90a00ff159ad8fd0185c0744648c703000000'
'000f104424200f104c24300f1143080f114b180f104424080f114328488b4c24'
'1848894b3889435048c74354000000000f57c00f1143404889d84883c4405bc3'
'488d3db19aed01ff1523d4fd010f0b4889c3488d7c2408e8941dc6ff488d7c24'
'20e8eac9c6ff4889dfe8a2f0ec01ff15b4d0fd01')

ACC_FDE = bytes.fromhex(
'24000000a8a31e00e88f5e02b400000004af6d90ff410e10440e50830202790e'
'10410e08410e5000')

SIB_BODY = bytes.fromhex(
'534883ec208b052d871f0285c00f8581000000b90800000031c0f0480fb10df5'
'861f020f85b9000000488d05e8861f02488d0de2861f024839c10f82cb000000'
'488b05d9861f0248c705ce861f020000000048894424080f1005ca861f0248c7'
'05c7861f02000000000f11442410488d7c2408e8d888e6ff31c9b808000000f0'
'480fb10d90861f020f858a0000004883c4205bc3488d057d861f024889042448'
'89e04889442408488d3d8a861f02488d0d730b16024c8d05940b1602488d5424'
'08be01000000ff158c0c1e02b90800000031c0f0480fb10d3c861f020f8447ff'
'ffff488d3d2f861f02ba00ca9a3bff15ac191e02488d051d861f02488d0d1786'
'1f024839c10f8335ffffff488d3d863a1602ff15a0041e02488d3df9851f0231'
'f6ff1581191e024883c4205bc34889c331c9b808000000f0480fb10dd8851f02'
'75084889dfe866240d02488d3dc7851f0231f6ff154f191e02ebe7ff1567041e'
'02')

SIB_FDE = bytes.fromhex(
'3000000050a11c00e05d40026101000004071b91ff410e10440e308302028d0e'
'10410e08410e3002970e10410e08410e30000000')


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
    rels = relocations(reader)

    # ---- The cell: two relocation-bound pointers, one state word. ----
    cell = reader.read(DESC_VA, len(DESC))
    require(cell == DESC, 'Cell bytes changed')
    require(rels.get(DESC_VA) == DROP_START, 'Cell slot 0 relocation changed')
    require(rels.get(DESC_VA + 0x28) == ACC_START, 'Cell slot 0x28 relocation changed')
    require(struct.unpack_from('<Q', cell, 0x20)[0] == 3, 'Cell state word changed')
    for off in (0x8, 0x10, 0x18, 0x30, 0x38):
        require(struct.unpack_from('<Q', cell, off)[0] == 0,
                f'Cell padding word at +0x{off:x} changed')

    # ---- Zeroing glue 0x35ab620: body, FDE, structure. ----
    drop = reader.read(DROP_START, DROP_END - DROP_START)
    require(drop == DROP_BODY, 'Zeroing glue body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= DROP_FDE_VA < eh['address'] + eh['size'], 'glue FDE outside .eh_frame')
    fde = reader.read(DROP_FDE_VA, len(DROP_FDE))
    require(fde == DROP_FDE, 'Zeroing glue FDE record changed')
    length = struct.unpack_from('<I', fde, 0)[0]
    pc = DROP_FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require(length == len(DROP_FDE) - 4, 'glue FDE length changed')
    require((pc, pc + extent) == (DROP_START, DROP_END), 'glue FDE PC range changed')
    require(drop[:3] == bytes.fromhex('4889f8'), 'glue must return its argument')
    require(drop[3:11] == bytes.fromhex('48c7471800000000'),
            'glue must zero the third qword')
    require(drop[11:] == bytes.fromhex('0f57c00f1107c3'),
            'glue must zero the first 16 bytes and return')

    # ---- Accessor 0x3790fc0: body, FDE, index, calls. ----
    acc = reader.read(ACC_START, ACC_END - ACC_START)
    require(acc == ACC_BODY, 'Accessor body bytes changed')
    require(eh['address'] <= ACC_FDE_VA < eh['address'] + eh['size'], 'accessor FDE outside .eh_frame')
    afde = reader.read(ACC_FDE_VA, len(ACC_FDE))
    require(afde == ACC_FDE, 'Accessor FDE record changed')
    pc = ACC_FDE_VA + 8 + struct.unpack_from('<i', afde, 8)[0]
    extent = struct.unpack_from('<I', afde, 12)[0]
    require((pc, pc + extent) == (ACC_START, ACC_END), 'accessor FDE PC range changed')
    for offset, hexstr, label in ACC_ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(acc[offset:offset + len(raw)] == raw, f'Accessor anchor changed: {label}')
    for offset, got, target in [(0x30, GOT_LOOKUP, LOOKUP_FN),
                                (0x87, GOT_DISPLAY, DISPLAY_FN),
                                (0xae, GOT_PANIC_B, PANIC_B)]:
        require(acc[offset:offset + 2] == bytes.fromhex('ff15'),
                f'accessor call opcode at +0x{offset:x} changed')
        disp = struct.unpack_from('<i', acc, offset + 2)[0]
        require(ACC_START + offset + 6 + disp == got, f'accessor call GOT at +0x{offset:x} changed')
        require(rels.get(got) == target, f'accessor call target for GOT {got:#x} changed')
    require(bytes.fromhex('ff1523d4fd010f0b') in acc,
            'accessor error path must reach ud2 right after the display panic')

    # ---- Sibling guard 0x358db60: body, FDE, anchors, cell references. ----
    sib = reader.read(SIB_START, SIB_END - SIB_START)
    require(sib == SIB_BODY, 'Sibling guard body bytes changed')
    require(eh['address'] <= SIB_FDE_VA < eh['address'] + eh['size'], 'sibling FDE outside .eh_frame')
    sfde = reader.read(SIB_FDE_VA, len(SIB_FDE))
    require(sfde == SIB_FDE, 'Sibling FDE record changed')
    pc = SIB_FDE_VA + 8 + struct.unpack_from('<i', sfde, 8)[0]
    extent = struct.unpack_from('<I', sfde, 12)[0]
    require((pc, pc + extent) == (SIB_START, SIB_END), 'sibling FDE PC range changed')
    for offset, hexstr, label in SIB_ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(sib[offset:offset + len(raw)] == raw, f'Sibling anchor changed: {label}')
    require(sib.count(bytes.fromhex('f0480fb1')) == 4,
            'sibling lock cmpxchg count changed')
    for offset in SIB_LEA_OFFSETS:
        require(sib[offset:offset + 2] == bytes.fromhex('488d')
                and (sib[offset + 2] & 0xC7) == 0x05,
                f'sibling lea opcode at +0x{offset:x} changed')
        disp = struct.unpack_from('<i', sib, offset + 3)[0]
        require(SIB_START + offset + 7 + disp == DESC_VA,
                f'sibling lea at +0x{offset:x} no longer targets the cell')
    for offset, got, target in [(0xc6, GOT_ONCE, ONCE_FN),
                                (0xee, GOT_UNPARK_A, UNPARK_A),
                                (0x112, GOT_PANIC_A, PANIC_A),
                                (0x121, GOT_UNPARK_B, UNPARK_B),
                                (0x153, GOT_UNPARK_B, UNPARK_B),
                                (0x15b, GOT_PANIC_B, PANIC_B)]:
        require(sib[offset:offset + 2] == bytes.fromhex('ff15'),
                f'sibling call opcode at +0x{offset:x} changed')
        disp = struct.unpack_from('<i', sib, offset + 2)[0]
        require(SIB_START + offset + 6 + disp == got, f'sibling call GOT at +0x{offset:x} changed')
        require(rels.get(got) == target, f'sibling call target for GOT {got:#x} changed')

    # ---- Census over the whole .text. ----
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])

    def census(fn):
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
                disp = struct.unpack_from('<i', code, m + 3)[0]
                if text['address'] + m + 7 + disp == fn:
                    lea.append(text['address'] + m)
        return direct, indirect, lea

    for fn, name in [(DROP_START, 'zeroing glue'), (ACC_START, 'accessor')]:
        direct, indirect, lea = census(fn)
        require(direct == [] and indirect == [] and lea == [],
                f'{name} gained code references')

    direct, indirect, _ = census(SIB_START)
    require(direct == [], 'Unexpected direct callers of the sibling')
    require(indirect == SIB_CALLERS,
            f'Sibling caller census changed: {[hex(x) for x in indirect]}')
    for (lo, hi), site in zip(CALLER_FN, SIB_CALLERS):
        require(lo <= site < hi, f'Sibling call site {site:#x} left its caller FDE')
    require(rels.get(SIB_GOT) == SIB_START, 'sibling GOT slot changed')

    # The helper's own six cell references (bound separately) still hold.
    helper = reader.read(HELPER_START, HELPER_END - HELPER_START)
    for site in HELPER_LEA_SITES:
        offset = site - HELPER_START
        require(helper[offset:offset + 2] == bytes.fromhex('488d')
                and (helper[offset + 2] & 0xC7) == 0x05, 'helper lea opcode changed')
        disp = struct.unpack_from('<i', helper, offset + 3)[0]
        require(HELPER_START + offset + 7 + disp == DESC_VA,
                'helper lea no longer targets the cell')

    # Exactly twelve lea references to the cell across .text: six in the
    # sibling, six in the helper.
    _, _, cell_leas = census(DESC_VA)
    expected = sorted([SIB_START + o for o in SIB_LEA_OFFSETS] + HELPER_LEA_SITES)
    require(cell_leas == expected,
            f'Cell lea census changed: {len(cell_leas)} references')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        cell=dict(va=hex(DESC_VA), section='.data', bytes=len(DESC),
                  slot_0x00=hex(DROP_START), slot_0x28=hex(ACC_START),
                  state_word_0x20=3,
                  inferred_label='once-style guarded cell consulted by both read-lock guards'),
        zeroing_glue=dict(start_va=hex(DROP_START), end_va_exclusive=hex(DROP_END),
                          bytes=len(drop), sha256=hashlib.sha256(drop).hexdigest(),
                          fde_va=hex(DROP_FDE_VA),
                          observed='returns rdi after zeroing 24 bytes at [rdi]',
                          reachability='cell slot +0x00 only; zero code references'),
        accessor=dict(start_va=hex(ACC_START), end_va_exclusive=hex(ACC_END),
                      bytes=len(acc), sha256=hashlib.sha256(acc).hexdigest(),
                      fde_va=hex(ACC_FDE_VA),
                      constant_index=hex(ACC_INDEX),
                      lookup=dict(got=hex(GOT_LOOKUP), target=hex(LOOKUP_FN)),
                      observed='zeroes a 48-byte result, calls the lookup with the '
                               'constant index, copies the result on success; the '
                               'error path reaches ud2 through the display panic',
                      reachability='cell slot +0x28 only; zero code references'),
        sibling_guard=dict(start_va=hex(SIB_START), end_va_exclusive=hex(SIB_END),
                           bytes=len(sib), sha256=hashlib.sha256(sib).hexdigest(),
                           fde_va=hex(SIB_FDE_VA), got_slot=hex(SIB_GOT),
                           cell_lea_offsets=[hex(o) for o in SIB_LEA_OFFSETS],
                           lock_cmpxchg=4, park_timeout_ns=1000000000,
                           callees=dict(once=hex(ONCE_FN), unpark_a=hex(UNPARK_A),
                                        unpark_b=hex(UNPARK_B), panic_a=hex(PANIC_A),
                                        panic_b=hex(PANIC_B)),
                           inferred_label='rare sibling of the 952-site read-lock helper'),
        call_census=dict(sibling=dict(got_slot=hex(SIB_GOT), got_indirect_sites=3,
                                      direct_e8=0,
                                      caller_fdes=[hex(lo) for lo, _ in CALLER_FN]),
                          glue_code_references=0, accessor_code_references=0,
                          cell_lea_references=dict(sibling=6, helper=6),
                          note='byte-pattern census over the complete .text for '
                               'e8/ff15/lea encodings'),
        cross_links=dict(readlock_helper=dict(body='0x358dcd0..0x358de41',
                                              packet='readlock-helper-94',
                                              got_slot_sites=952),
                         shared_parking_wrapper=hex(UNPARK_B)),
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
