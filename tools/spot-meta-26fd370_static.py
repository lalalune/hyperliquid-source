#!/usr/bin/env python3
"""Authenticated node94 spot-meta-26fd370 binding (0x26fd370).

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

START, END = 0x26fd370, 0x26fdae8
FDE_VA = 0x10ed440
FDE = bytes.fromhex(
    '5000000018f8120028ff6001780700000447fc92ff410e10420e18420e20420e'
    '28420e30410e38470ea00283078c068d058e048f03860203bb060e38410e3042'
    '0e28420e20420e18420e10410e08410ea0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ece80000004989fe83bf80000000017513498bb6'
    '88000000498dbe68020000e8f0071600498b86e0020000498b8ee802000031d2'
    '4889c64885c00f95c27407498bb6f0020000488954242848c744243000000000'
    '488944243848894c2440488954244848c744245000000000488944245848894c'
    '24604889742468488dbc24b8000000488d742428e8d7f24a014c8bac24c00000'
    '00488b9c24c80000004983be78020000007423498bb6680200004885f60f8437'
    '060000498b9670020000488d7c2428e85c141a00eb1248c74424280000000048'
    'c744243800000000498d868000000048898424a8000000498d86900000004889'
    '442418488d04dd000000004c01e848898424b0000000488b5c243848899c2480'
    '000000488b4424284889442470488b44243048894424784c8b7c2470488b6c24'
    '784d85ff48899c2490000000490f44df0f95442407498d868033000048898424'
    'a00000004c89742410498d865002000048894424204531f64c896c24084c89bc'
    '24980000004889ac2488000000eb1690b801000000488b7c24204c89e64889c2'
    'e8fb1116004d85ed74264c3bac24b0000000741c498d45084d8b65004989c54d'
    '85e40f8584010000ebc6660f1f4400004885db0f84cd020000f6442407010f84'
    '250500004d85f67416410fb746624839c50f83990000004c89f0e9ae00000048'
    '85ed74364889e84d89fe4883e007742f31c966666666662e0f1f840000000000'
    '4d8b766848ffc14839c875f44889e84829c84883fd087318eb3c4d89feeb3748'
    '89e84883fd08722e0f1f840000000000498b4e68488b4968488b4968488b4968'
    '488b4968488b4968488b49684c8b71684883c0f875da4531ff31ed410fb74662'
    '4839c50f826effffff0f1f8000000000498b064885c00f844f04000049ffc741'
    '0fb76e604989c6663b686273e34d85ff746b488d0ce84883c1704c89fa4883e2'
    '070f84cd01000031f60f1f80000000004c8b31498d4e6848ffc64839f275f14c'
    '89fa4829f24983ff08722e0f1f440000488b09488b4968488b4968488b496848'
    '8b4968488b4968488b49684c8b7168498d4e684883c2f875d731c9eb07488d4d'
    '014989c648ffcb4c8d2ce84983c508c64424070131c04531ff4889cd4d8b6500'
    '4989c54d85e40f8444feffff488bbc24a80000004c89e6488b9424a0000000ff'
    '153b7207034885c00f8437feffff488b4c2410488b89180200004885c90f8454'
    '0300004939cc0f834b030000488b7c2410488b97100200000fb64a494969f4e8'
    '0000002a4c32480f826503000080bff2080000030f85dbfdffff66480f6ec066'
    '0f62054967b0fd660f5c056157b0fd660f28c8660f15c8f20f58c80fb6c9488d'
    '15b373e8fdf20f5e0ccaf20f580d16cbb0fd660f540d6657b0fd660f2e0d4ecd'
    'b0fd0f868dfdffff488b542410488b8ae00200004885c90f8478fdffff488b92'
    'e80200000fb779624189f841c1e00348c7c6ffffffff662e0f1f840000000000'
    '4d85c0743b4c3b64f110410f97c14180d90048ffc64983c0f84180f90174e141'
    '0fb6f985ff0f842afdffff4883ea01731ce91ffdffff662e0f1f840000000000'
    '4889fe4883ea010f8208fdffff488b4cf170eb904c89fa4983ff080f8278feff'
    'ffe94afeffff488b8424980000004885c0744248c74424300000000048894424'
    '38488b8c248800000048894c244048c744245000000000488944245848894c24'
    '60b801000000488b6c2410488b8c2490000000eb0931c031c9488b6c24104889'
    '442428488944244848894c24684c8da424d00000004c8d6c2428660f1f440000'
    '4c89e74c89eee885dc16004883bc24d00000000075ea488bb424b80000004885'
    'f6741148c1e603488b7c240831d2ff154c070703488b85c80500004885c00f84'
    '61010000488b9dc00500004c69f0f00200004901de49bd5c8fc2f5285c8f02eb'
    '276666666666662e0f1f840000000000f20f1183a00200004881c3f00200004c'
    '39f30f841d0100004c8b6350488b442420488b004885c00f8483000000488b8d'
    '580200000fb7b0ba00000089f7c1e70348c7c2ffffffff660f1f840000000000'
    '4885ff742b4c3b64d010410f97c04180d80048ffc24883c7f84180f80174e141'
    '0fb6f085f674294883e901730ceb31904889f24883e9017227488b84d0c00000'
    '00eba1666666662e0f1f840000000000488b54d0604c8b7c2418eb180f1f4000'
    '4c8b7c24184c89ff4c89e6ff15876b07034889c2bf00ca9a3b4c89e64c89f9e8'
    'ec3ab80066480f6eca660f620d9f64b0fd660f5c0db754b0fd660f28c1660f15'
    'c1f20f58c1f20f5e0523c8b0fd4c39ea721ef20f100526cdb0fda8010f85eefe'
    'ffffeb146666662e0f1f840000000000a8010f85d8fefffff20f100500cdb0fd'
    'e9cbfeffff4881c4e80000005b415c415d415e415f5dc3488d3da247ff024c8b'
    '6c2408ff15170a0703eb39488d3dde7afc02ff15080a0703eb2a488d3dc78ffc'
    '02ff15f9090703eb1b488d3d705dfc02ebcc488d3dcf47ff024c8b6c2408ff15'
    'bc0607030f0b4889c34c8b6c2408eb1e4889c34c8b6c2408eb0a4889c3eb0f0f'
    '0b4889c3488d7c2470e852f71a00488bb424b80000004885f6740f48c1e6034c'
    '89ef31d2ff15360507034889dfe82e26f602ff1540060703'
)
BODY_SHA256 = '02ff9687a636d305f139097689a61414854f49166a02984ba63b58e6503d345f'
BRANCHES = [
    (0x1b, '7513', 1, 2, 0x26fd3a0),
    (0x49, '7407', 1, 2, 0x26fd3c2),
    (0xb1, '7423', 1, 2, 0x26fd446),
    (0xbd, '0f8437060000', 2, 6, 0x26fda6a),
    (0xd4, 'eb12', 1, 2, 0x26fd458),
    (0x18d, 'eb16', 1, 2, 0x26fd515),
    (0x1a8, '7426', 1, 2, 0x26fd540),
    (0x1b2, '741c', 1, 2, 0x26fd540),
    (0x1c2, '0f8584010000', 2, 6, 0x26fd6bc),
    (0x1c8, 'ebc6', 1, 2, 0x26fd500),
    (0x1d3, '0f84cd020000', 2, 6, 0x26fd816),
    (0x1de, '0f8425050000', 2, 6, 0x26fda79),
    (0x1e7, '7416', 1, 2, 0x26fd56f),
    (0x1f1, '0f8399000000', 2, 6, 0x26fd600),
    (0x1fa, 'e9ae000000', 1, 5, 0x26fd61d),
    (0x202, '7436', 1, 2, 0x26fd5aa),
    (0x20e, '742f', 1, 2, 0x26fd5af),
    (0x22a, '75f4', 1, 2, 0x26fd590),
    (0x236, '7318', 1, 2, 0x26fd5c0),
    (0x238, 'eb3c', 1, 2, 0x26fd5e6),
    (0x23d, 'eb37', 1, 2, 0x26fd5e6),
    (0x246, '722e', 1, 2, 0x26fd5e6),
    (0x274, '75da', 1, 2, 0x26fd5c0),
    (0x283, '0f826effffff', 2, 6, 0x26fd567),
    (0x296, '0f844f040000', 2, 6, 0x26fda5b),
    (0x2ab, '73e3', 1, 2, 0x26fd600),
    (0x2b0, '746b', 1, 2, 0x26fd68d),
    (0x2c1, '0f84cd010000', 2, 6, 0x26fd804),
    (0x2dd, '75f1', 1, 2, 0x26fd640),
    (0x2e9, '722e', 1, 2, 0x26fd689),
    (0x317, '75d7', 1, 2, 0x26fd660),
    (0x31b, 'eb07', 1, 2, 0x26fd694),
    (0x346, '0f8444feffff', 2, 6, 0x26fd500),
    (0x368, '0f8437feffff', 2, 6, 0x26fd515),
    (0x37d, '0f8454030000', 2, 6, 0x26fda47),
    (0x386, '0f834b030000', 2, 6, 0x26fda47),
    (0x3a7, '0f8265030000', 2, 6, 0x26fda82),
    (0x3b4, '0f85dbfdffff', 2, 6, 0x26fd505),
    (0x402, '0f868dfdffff', 2, 6, 0x26fd505),
    (0x417, '0f8478fdffff', 2, 6, 0x26fd505),
    (0x443, '743b', 1, 2, 0x26fd7f0),
    (0x45d, '74e1', 1, 2, 0x26fd7b0),
    (0x465, '0f842afdffff', 2, 6, 0x26fd505),
    (0x46f, '731c', 1, 2, 0x26fd7fd),
    (0x471, 'e91ffdffff', 1, 5, 0x26fd505),
    (0x487, '0f8208fdffff', 2, 6, 0x26fd505),
    (0x492, 'eb90', 1, 2, 0x26fd794),
    (0x49b, '0f8278feffff', 2, 6, 0x26fd689),
    (0x4a1, 'e94afeffff', 1, 5, 0x26fd660),
    (0x4b1, '7442', 1, 2, 0x26fd865),
    (0x4f3, 'eb09', 1, 2, 0x26fd86e),
    (0x534, '75ea', 1, 2, 0x26fd890),
    (0x541, '7411', 1, 2, 0x26fd8c4),
    (0x55e, '0f8461010000', 2, 6, 0x26fda35),
    (0x57f, 'eb27', 1, 2, 0x26fd918),
    (0x5a2, '0f841d010000', 2, 6, 0x26fda35),
    (0x5b7, '0f8483000000', 2, 6, 0x26fd9b0),
    (0x5e3, '742b', 1, 2, 0x26fd980),
    (0x5fd, '74e1', 1, 2, 0x26fd950),
    (0x605, '7429', 1, 2, 0x26fd9a0),
    (0x60b, '730c', 1, 2, 0x26fd989),
    (0x60d, 'eb31', 1, 2, 0x26fd9b0),
    (0x617, '7227', 1, 2, 0x26fd9b0),
    (0x621, 'eba1', 1, 2, 0x26fd934),
    (0x63a, 'eb18', 1, 2, 0x26fd9c4),
    (0x690, '721e', 1, 2, 0x26fda20),
    (0x69c, '0f85eefeffff', 2, 6, 0x26fd900),
    (0x6a2, 'eb14', 1, 2, 0x26fda28),
    (0x6b2, '0f85d8feffff', 2, 6, 0x26fd900),
    (0x6c0, 'e9cbfeffff', 1, 5, 0x26fd900),
    (0x6e9, 'eb39', 1, 2, 0x26fda94),
    (0x6f8, 'eb2a', 1, 2, 0x26fda94),
    (0x707, 'eb1b', 1, 2, 0x26fda94),
    (0x710, 'ebcc', 1, 2, 0x26fda4e),
    (0x72e, 'eb1e', 1, 2, 0x26fdabe),
    (0x738, 'eb0a', 1, 2, 0x26fdab4),
    (0x73d, 'eb0f', 1, 2, 0x26fdabe),
    (0x759, '740f', 1, 2, 0x26fdada),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x26fd39b, 0x285db90),
    (0x26fd404, 0x3bac6e0),
    (0x26fd43f, 0x289e8a0),
    (0x26fd510, 0x285e710),
    (0x26fd896, 0x286b520),
    (0x26fd9cf, 0x32814c0),
    (0x26fdab9, 0x28ad210),
    (0x26fdadd, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x26fd6cf, 0x5774910),
    (0x26fd8be, 0x576e010),
    (0x26fd9bb, 0x5774548),
    (0x26fda53, 0x576e470),
    (0x26fda62, 0x576e470),
    (0x26fda71, 0x576e470),
    (0x26fda8e, 0x576e150),
    (0x26fdad4, 0x576e010),
    (0x26fdae2, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x26fda47, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x26fda5b, 0x56c5540, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x26fda6a, 0x56c6a38, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6d61702e7273'), 306, 46),
    (0x26fda82, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x222a61d, 0x270030b]
CALLER_FUNCTIONS = {'0x222a61d': ('0x22297c0', '0x222af3e'), '0x270030b': ('0x27000b0', '0x2700383')}
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

