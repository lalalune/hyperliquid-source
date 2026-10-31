#!/usr/bin/env python3
"""Authenticated node94 spot-meta-4ce4d00 binding (0x4ce4d00).

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

START, END = 0x4ce4d00, 0x4ce5470
FDE_VA = 0x12df760
FDE = bytes.fromhex(
    '50000000381b32009855a0037007000004ab248dff410e10420e18420e20420e'
    '28420e30410e38470ea00283078c068d058e048f03860203b3060e38410e3042'
    '0e28420e20420e18420e10410e08410ea0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ece80000004989fe83bf80000000017513498bb6'
    '88000000498dbe68020000e89094c5ff498b86e0020000498b8ee802000031d2'
    '4889c64885c00f95c27407498bb6f0020000488954242848c744243000000000'
    '488944243848894c2440488954244848c744245000000000488944245848894c'
    '24604889742468488dbc24b8000000488d742428e84779ecfe4c8bac24c00000'
    '00488b9c24c80000004983be78020000007423498bb6680200004885f60f842f'
    '060000498b9670020000488d7c2428e86c00cbffeb1248c74424280000000048'
    'c744243800000000498d868000000048898424a8000000498d86900000004889'
    '442418488d04dd000000004c01e848898424b0000000488b5c243848899c2480'
    '000000488b4424284889442470488b44243048894424784c8b7c2470488b6c24'
    '784d85ff48899c2490000000490f44df0f95442407498d868033000048898424'
    'a00000004c89742410498d865002000048894424204531f64c896c24084c89bc'
    '24980000004889ac2488000000eb1690b801000000488b7c24204c89e64889c2'
    'e81ba6c4ff4d85ed74264c3bac24b0000000741c498d45084d8b65004989c54d'
    '85e40f8584010000ebc6660f1f4400004885db0f84cd020000f6442407010f84'
    '1d0500004d85f67416410fb746624839c50f83990000004c89f0e9ae00000048'
    '85ed74364889e84d89fe4883e007742f31c966666666662e0f1f840000000000'
    '4d8b766848ffc14839c875f44889e84829c84883fd087318eb3c4d89feeb3748'
    '89e84883fd08722e0f1f840000000000498b4e68488b4968488b4968488b4968'
    '488b4968488b4968488b49684c8b71684883c0f875da4531ff31ed410fb74662'
    '4839c50f826effffff0f1f8000000000498b064885c00f844704000049ffc741'
    '0fb76e604989c6663b686273e34d85ff746b488d0ce84883c1704c89fa4883e2'
    '070f84cd01000031f60f1f80000000004c8b31498d4e6848ffc64839f275f14c'
    '89fa4829f24983ff08722e0f1f440000488b09488b4968488b4968488b496848'
    '8b4968488b4968488b49684c8b7168498d4e684883c2f875d731c9eb07488d4d'
    '014989c648ffcb4c8d2ce84983c508c64424070131c04531ff4889cd4d8b6500'
    '4989c54d85e40f8444feffff488bbc24a80000004c89e6488b9424a0000000ff'
    '15abf8a8004885c00f8437feffff488b4c2410488b89180200004885c90f844c'
    '0300004939cc0f8343030000488b7c2410488b97100200000fb64a494969f4e8'
    '0000002a4c32480f825d03000080bff2080000030f85dbfdffff66480f6ec066'
    '0f6205b9ed51fb660f5c05d1dd51fb660f28c8660f15c8f20f58c80fb6c9488d'
    '1523fa89fbf20f5e0ccaf20f580d865152fb660f540dd6dd51fb660f2e0dbe53'
    '52fb0f868dfdffff488b542410488b8ae00200004885c90f8478fdffff488b92'
    'e80200000fb779624189f841c1e00348c7c6ffffffff662e0f1f840000000000'
    '4d85c0743b4c3b64f110410f97c14180d90048ffc64983c0f84180f90174e141'
    '0fb6f985ff0f842afdffff4883ea01731ce91ffdffff662e0f1f840000000000'
    '4889fe4883ea010f8208fdffff488b4cf170eb904c89fa4983ff080f834ffeff'
    'ffe973feffff488b8424980000004885c0744248c74424300000000048894424'
    '38488b8c248800000048894c244048c744245000000000488944245848894c24'
    '60b801000000488b6c2410488b8c2490000000eb0931c031c9488b6c24104889'
    '442428488944244848894c24684c8da424d00000004c8d6c2428660f1f440000'
    '4c89e74c89eee8053dc6ff4883bc24d00000000075ea488bb424b80000004885'
    'f6741148c1e603488b7c240831d2ff15bc8da800488b85c80500004885c00f84'
    '59010000488b9dc00500004c69f0f00200004901de49bd5c8fc2f5285c8f02eb'
    '276666666666662e0f1f840000000000f20f1183a00200004881c3f00200004c'
    '39f30f84150100004c8b6350488b442420488b004885c00f8483000000488b8d'
    '580200000fb7b0ba00000089f7c1e70348c7c2ffffffff660f1f840000000000'
    '4885ff742b4c3b64d010410f97c04180d80048ffc24883c7f84180f80174e141'
    '0fb6f085f674294883e901730ceb31904889f24883e9017227488b84d0c00000'
    '00eba1666666662e0f1f840000000000488b54d0604c8b7c2418eb180f1f4000'
    '4c8b7c24184c89ff4c89e6ff15f7f1a8004889c2bf00ca9a3b4c89e64c89f9e8'
    '5cc159fe66480f6eca660f620d0feb51fb660f5c0d27db51fb660f28c1660f15'
    'c1f20f58c1f20f5e05934e52fb4c39ea730ea8010f85f6feffffeb140f1f4000'
    'f20f1005885352fba8010f85e0fefffff20f1005785352fbe9d3feffff4881c4'
    'e80000005b415c415d415e415f5dc3488d3d1acea0004c8b6c2408ff158f90a8'
    '00eb39488d3d66eba400ff158090a800eb2a488d3dbf03a500ff157190a800eb'
    '1b488d3d78dba400ebcc488d3d47cea0004c8b6c2408ff15348da8000f0b4889'
    'c34c8b6c2408eb1e4889c34c8b6c2408eb0a4889c3eb0f0f0b4889c3488d7c24'
    '70e85ae0ccff488bb424b80000004885f6740f48c1e6034c89ef31d2ff15ae8b'
    'a8004889dfe8a6ac9700ff15b88ca800'
)
BODY_SHA256 = '4c06362c608199a5f904e58cdb31318df854eeb0c05a30900500f13559249c60'
BRANCHES = [
    (0x1b, '7513', 1, 2, 0x4ce4d30),
    (0x49, '7407', 1, 2, 0x4ce4d52),
    (0xb1, '7423', 1, 2, 0x4ce4dd6),
    (0xbd, '0f842f060000', 2, 6, 0x4ce53f2),
    (0xd4, 'eb12', 1, 2, 0x4ce4de8),
    (0x18d, 'eb16', 1, 2, 0x4ce4ea5),
    (0x1a8, '7426', 1, 2, 0x4ce4ed0),
    (0x1b2, '741c', 1, 2, 0x4ce4ed0),
    (0x1c2, '0f8584010000', 2, 6, 0x4ce504c),
    (0x1c8, 'ebc6', 1, 2, 0x4ce4e90),
    (0x1d3, '0f84cd020000', 2, 6, 0x4ce51a6),
    (0x1de, '0f841d050000', 2, 6, 0x4ce5401),
    (0x1e7, '7416', 1, 2, 0x4ce4eff),
    (0x1f1, '0f8399000000', 2, 6, 0x4ce4f90),
    (0x1fa, 'e9ae000000', 1, 5, 0x4ce4fad),
    (0x202, '7436', 1, 2, 0x4ce4f3a),
    (0x20e, '742f', 1, 2, 0x4ce4f3f),
    (0x22a, '75f4', 1, 2, 0x4ce4f20),
    (0x236, '7318', 1, 2, 0x4ce4f50),
    (0x238, 'eb3c', 1, 2, 0x4ce4f76),
    (0x23d, 'eb37', 1, 2, 0x4ce4f76),
    (0x246, '722e', 1, 2, 0x4ce4f76),
    (0x274, '75da', 1, 2, 0x4ce4f50),
    (0x283, '0f826effffff', 2, 6, 0x4ce4ef7),
    (0x296, '0f8447040000', 2, 6, 0x4ce53e3),
    (0x2ab, '73e3', 1, 2, 0x4ce4f90),
    (0x2b0, '746b', 1, 2, 0x4ce501d),
    (0x2c1, '0f84cd010000', 2, 6, 0x4ce5194),
    (0x2dd, '75f1', 1, 2, 0x4ce4fd0),
    (0x2e9, '722e', 1, 2, 0x4ce5019),
    (0x317, '75d7', 1, 2, 0x4ce4ff0),
    (0x31b, 'eb07', 1, 2, 0x4ce5024),
    (0x346, '0f8444feffff', 2, 6, 0x4ce4e90),
    (0x368, '0f8437feffff', 2, 6, 0x4ce4ea5),
    (0x37d, '0f844c030000', 2, 6, 0x4ce53cf),
    (0x386, '0f8343030000', 2, 6, 0x4ce53cf),
    (0x3a7, '0f825d030000', 2, 6, 0x4ce540a),
    (0x3b4, '0f85dbfdffff', 2, 6, 0x4ce4e95),
    (0x402, '0f868dfdffff', 2, 6, 0x4ce4e95),
    (0x417, '0f8478fdffff', 2, 6, 0x4ce4e95),
    (0x443, '743b', 1, 2, 0x4ce5180),
    (0x45d, '74e1', 1, 2, 0x4ce5140),
    (0x465, '0f842afdffff', 2, 6, 0x4ce4e95),
    (0x46f, '731c', 1, 2, 0x4ce518d),
    (0x471, 'e91ffdffff', 1, 5, 0x4ce4e95),
    (0x487, '0f8208fdffff', 2, 6, 0x4ce4e95),
    (0x492, 'eb90', 1, 2, 0x4ce5124),
    (0x49b, '0f834ffeffff', 2, 6, 0x4ce4ff0),
    (0x4a1, 'e973feffff', 1, 5, 0x4ce5019),
    (0x4b1, '7442', 1, 2, 0x4ce51f5),
    (0x4f3, 'eb09', 1, 2, 0x4ce51fe),
    (0x534, '75ea', 1, 2, 0x4ce5220),
    (0x541, '7411', 1, 2, 0x4ce5254),
    (0x55e, '0f8459010000', 2, 6, 0x4ce53bd),
    (0x57f, 'eb27', 1, 2, 0x4ce52a8),
    (0x5a2, '0f8415010000', 2, 6, 0x4ce53bd),
    (0x5b7, '0f8483000000', 2, 6, 0x4ce5340),
    (0x5e3, '742b', 1, 2, 0x4ce5310),
    (0x5fd, '74e1', 1, 2, 0x4ce52e0),
    (0x605, '7429', 1, 2, 0x4ce5330),
    (0x60b, '730c', 1, 2, 0x4ce5319),
    (0x60d, 'eb31', 1, 2, 0x4ce5340),
    (0x617, '7227', 1, 2, 0x4ce5340),
    (0x621, 'eba1', 1, 2, 0x4ce52c4),
    (0x63a, 'eb18', 1, 2, 0x4ce5354),
    (0x690, '730e', 1, 2, 0x4ce53a0),
    (0x694, '0f85f6feffff', 2, 6, 0x4ce5290),
    (0x69a, 'eb14', 1, 2, 0x4ce53b0),
    (0x6aa, '0f85e0feffff', 2, 6, 0x4ce5290),
    (0x6b8, 'e9d3feffff', 1, 5, 0x4ce5290),
    (0x6e1, 'eb39', 1, 2, 0x4ce541c),
    (0x6f0, 'eb2a', 1, 2, 0x4ce541c),
    (0x6ff, 'eb1b', 1, 2, 0x4ce541c),
    (0x708, 'ebcc', 1, 2, 0x4ce53d6),
    (0x726, 'eb1e', 1, 2, 0x4ce5446),
    (0x730, 'eb0a', 1, 2, 0x4ce543c),
    (0x735, 'eb0f', 1, 2, 0x4ce5446),
    (0x751, '740f', 1, 2, 0x4ce5462),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x4ce4d2b, 0x493e1c0),
    (0x4ce4d94, 0x3bac6e0),
    (0x4ce4dcf, 0x4994e40),
    (0x4ce4ea0, 0x492f4c0),
    (0x4ce5226, 0x4948f30),
    (0x4ce535f, 0x32814c0),
    (0x4ce5441, 0x49b34a0),
    (0x4ce5465, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4ce505f, 0x5774910),
    (0x4ce524e, 0x576e010),
    (0x4ce534b, 0x5774548),
    (0x4ce53db, 0x576e470),
    (0x4ce53ea, 0x576e470),
    (0x4ce53f9, 0x576e470),
    (0x4ce5416, 0x576e150),
    (0x4ce545c, 0x576e010),
    (0x4ce546a, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4ce53cf, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4ce53e3, 0x5733f50, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x4ce53f2, 0x57357b8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6d61702e7273'), 306, 46),
    (0x4ce540a, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x470f7ad, 0x4cea3fb]
CALLER_FUNCTIONS = {'0x470f7ad': ('0x470e9a0', '0x4710066'), '0x4cea3fb': ('0x4cea1a0', '0x4cea47c')}
LEA_REFS = 0
OWN_GOT_SLOTS = []
GOT_SITES = {}


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

