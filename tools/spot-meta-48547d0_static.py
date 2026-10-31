#!/usr/bin/env python3
"""Authenticated node94 spot-meta-48547d0 binding (0x48547d0).

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

START, END = 0x48547d0, 0x48551d5
FDE_VA = 0x129d408
FDE = bytes.fromhex(
    '9c000000e0f72d00c0735b03050a000004373c8eff410e10420e18420e20420e'
    '28420e30410e38470ef00e83078c068d058e048f038602740e38410e30420e28'
    '420e20420e18420e10410e08450ef00e510e38410e30420e28420e20420e1842'
    '0e10410e08460ef00e030b020e38410e30420e28420e20420e18420e10410e08'
    '460ef00e037b060e38410e30420e28420e20420e18420e10410e08410ef00e00'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec380700004989f6488b06488d70fe4883f802b8'
    '06000000480f43c64889fb488d353a8beafb486304864801f0ffe04c89f74881'
    'c4380700005b415c415d415e415f5de9fcb7f8ff4983c6084889df4c89f64881'
    'c4380700005b415c415d415e415f5dff25b322f2004989cf4989d449bd000000'
    '0000000080488dbc2440040000ba680200004c89f6ff157597f10031c0483b83'
    'e80400000f81e6010000488d83200400004c39280f844a0800000fb68c248206'
    '00004c8bac2430060000488bac24380600004c896c24403a8c24640600000f85'
    '20080000884c24304889442438488b842440060000488904240fb68424830600'
    '00884424080fb6842480060000884424280fb684248106000088442420488dbc'
    '24f00100004c89ee4c89e2ff152f0ef200488dbc24a8060000488d5424404c89'
    'f64c89e1e8a7241b004c8bbc24f0010000488b8424f801000048894424104885'
    'ed0f84350600004889ef4c89ee4c89e2e89bfdd4fff20f11442418e925060000'
    '31c0483b83b00500000f8075070000498b46084889442410498b461048894424'
    '20498b46184889442428498b462048894424184d8b7e28498b46304889442430'
    '410fb6464c884424380fb683780a000088442408488dbc24f00100004889d5ff'
    '15eb9ef100488b85700100004939c70f833c0700004889ee4c8ba5680100004d'
    '89fd49c1e5054b8b142c488dbc24b0000000ff15e0eef1000fb68c24b8000000'
    '4883f9020f8373020000b80a00000048f7a424b00000000f80e80600004801c8'
    '48c7c1ffffffff4989c74c0f42f94c0f43f84981ff001f0afa0f827a02000049'
    '81c700e1f5054c0f42f9e9710200004983c6084889df4c89f64881c438070000'
    '5b415c415d415e415f5dff25a020f20080bc248206000000488d842450050000'
    '488d8c2458040000480f45c8488b29488d842458050000488d8c246004000048'
    '0f45c84c8b29488dbc24b0000000488db424400400004c89e24c89f9e88fc13a'
    '008b8424c0000000894424500f108424b00000000f29442440488db424c80000'
    '004c8db424f0010000ba200100004c89f7ff15f994f100f20f108424c8020000'
    'f20f1104244c8bbc2400020000f20f10842408020000f20f11442408488dbc24'
    '100300004c89f6ff154308f200488b8424f002000048898424300400000f1084'
    '24e30200000f118424230400004889ac24100300004c89ac2418030000f20f10'
    '0424f20f118424080400004c89bc2420030000f20f10442408f20f1184242803'
    '00000fb6ab780a0000488dbc24a4000000ff15199df1004c8db3e8040000488d'
    'bc24c8000000488db42410030000ba28010000ff153794f1000f284424400f29'
    '8424b00000008b442450898424c0000000488b83700a000048894424700f1083'
    '600a00000f29442460400fb6f5488d9424a4000000488d8c24b00000004c8d44'
    '24604c89f7e8e693f9ff488bb424100200004885f648bb000000000000008074'
    '10488bbc241802000031d2ff15ef93f100488bb424280200004885f67410488b'
    'bc243002000031d2ff15d293f100488bb424400200004839de0f848504000048'
    '85f60f847c040000488bbc244802000031d2ff15a893f100e9670400004c897c'
    '24404d85ff0f84fb0100004981ff00e1f5057331488d0575549bfb48898424b0'
    '000000488b05e69af10048898424b8000000488d442440eb3b4981c700e1f505'
    '4c897c24404981c7001f0afa4c897c2460488d0584539bfb48898424b0000000'
    '488b05a99af10048898424b8000000488d44246048898424c0000000488b059d'
    '93f10048898424c8000000488d35d0c298fb488dbc2410030000488d9424b000'
    '0000ff152893f100488b842410030000488904244c8bbc24180300004c8b9424'
    '200300004d01ec498b442408488b8d880100004839c80f839a030000498b1424'
    '4839ca0f838d030000488bb5800100004869c0e80000000fb64c06494869c2e8'
    '0000000fb644064838c10f82940300004983c638488dbbb005000028c1f20f10'
    '4c24180f140de6f09afb660f5c0dfee09afb660f28c1660f15c1f20f58c10fb6'
    'd1488d0db826eafbf20f5e04d1488b7424104885f64c8b4424284c8b4c242074'
    '734883fe010fb65424080f85da000000660f57d2660f57c94d85c9742666490f'
    '6ed9660f621d86f09afb660f5c1d9ee09afb660f28cb660f15cbf20f58cbf20f'
    '5e0cc14d85c00f849e00000066490f6ed8660f621d57f09afb660f5c1d6fe09a'
    'fb660f28d3660f15d3f20f58d3f20f5e14c1eb764d85c90fb654240874686649'
    '0f6ed1660f621525f09afb660f5c153de09afb660f28ca660f15caf20f58caf2'
    '0f5e0cc1eb44bf09000000ff155791f1004885c00f84990200004989c70fb605'
    '0449d6fb41884708488b05f148d6fb498907b8090000004889042441ba090000'
    '00e97efeffff660f57c9418b461089842400010000410f101e0f119c24f00000'
    '00488b44243048898424e0000000488b042448898424c80000004c89bc24d000'
    '00004c899424d80000000fb644243888842404010000f20f118424e800000048'
    '89b424b0000000f20f118c24b8000000f20f119424c0000000488b83700a0000'
    '48898424200300000f1083600a00000f298424100300000fb6f2488d9424f001'
    '0000488d8c24b00000004c8d842410030000e84993f9ffe9680100000f57c0f2'
    '0f11442418488b3c244c89ee4c89e2e85cfbd4fff20f110424f644240801741d'
    '4d89fd410f108644020000410f108e540200000f298c2490000000eb0e4d89fd'
    '0f57c00f298424900000000f298424800000004c8bbc24000200000fb6ab780a'
    '0000488d7c2460ff15c398f1004c8da424b0000000488db424a8060000ba9000'
    '00004c89e7ff15e58ff1004c89ac2440010000488b4424104889842448010000'
    '4c89bc2450010000f20f10442418f20f11842458010000f20f100424f20f1184'
    '24600100000f28842480000000660f288c24900000000f11842468010000660f'
    '118c2478010000498b86180200004889842488010000418b8620020000898424'
    '900100000fb6442428888424940100000fb6442420888424950100000fb64424'
    '3088842496010000488b83700a000048898424200300000f1083600a00000f29'
    '842410030000400fb6f5488d5424604c8d842410030000488b7c24384c89e1e8'
    '5c8bf9ff4881c4380700005b415c415d415e415f5dc3488d3d03d1e900ff157d'
    '93f100eb2c48c7c0ffffffffe90cf9ffff488d1568fbeb004c89ff4889c6ff15'
    'b48ef100488d3d3dd1e900ff152f90f1000f0bbf01000000be09000000ff1585'
    '8ef1004889c34d85ed0f848e000000488b7c24104c89eeeb7c4889c3488bb424'
    'f00100004885f67474488bbc24f8010000eb624889c34d85ff74624c89fe488b'
    '7c2410eb50eb254889c3488dbc2410030000e84922f9ff488dbc24f0010000e8'
    '7c27f9ff4889dfe874afe0004889c3488dbc24f0010000e86427f9ff4889dfe8'
    '5cafe0004889c348833c2400740f4c89ff488b342431d2ff15438ef1004889df'
    'e83bafe000'
)
BODY_SHA256 = 'dd307f53eabaaf8b3f04045bbaf23c2af4ef4d49169229b4395b7cd01a4b3ea6'
BRANCHES = [
    (0x39, 'ffe0', 1, 2, 0x48547eb),
    (0x6f, 'ff25b322f200', 1, 2, 0x4854866),
    (0xa4, '0f81e6010000', 2, 6, 0x4854a60),
    (0xb4, '0f844a080000', 2, 6, 0x48550d4),
    (0xde, '0f8520080000', 2, 6, 0x48550d4),
    (0x161, '0f8435060000', 2, 6, 0x4854f6c),
    (0x17b, 'e925060000', 1, 5, 0x4854f75),
    (0x189, '0f8075070000', 2, 6, 0x48550d4),
    (0x1ef, '0f833c070000', 2, 6, 0x4855101),
    (0x224, '0f8373020000', 2, 6, 0x4854c6d),
    (0x237, '0f80e8060000', 2, 6, 0x48550f5),
    (0x259, '0f827a020000', 2, 6, 0x4854ca9),
    (0x26a, 'e971020000', 1, 5, 0x4854cb0),
    (0x28a, 'ff25a020f200', 1, 2, 0x4854a81),
    (0x43f, '7410', 1, 2, 0x4854c21),
    (0x45c, '7410', 1, 2, 0x4854c3e),
    (0x479, '0f8485040000', 2, 6, 0x48550d4),
    (0x482, '0f847c040000', 2, 6, 0x48550d4),
    (0x498, 'e967040000', 1, 5, 0x48550d4),
    (0x4a5, '0f84fb010000', 2, 6, 0x4854e76),
    (0x4b2, '7331', 1, 2, 0x4854cb5),
    (0x4d7, 'eb3b', 1, 2, 0x4854ce4),
    (0x576, '0f839a030000', 2, 6, 0x48550e6),
    (0x583, '0f838d030000', 2, 6, 0x48550e6),
    (0x5aa, '0f8294030000', 2, 6, 0x4855114),
    (0x5ff, '7473', 1, 2, 0x4854e44),
    (0x60a, '0f85da000000', 2, 6, 0x4854eba),
    (0x61b, '7426', 1, 2, 0x4854e13),
    (0x646, '0f849e000000', 2, 6, 0x4854eba),
    (0x672, 'eb76', 1, 2, 0x4854eba),
    (0x67c, '7468', 1, 2, 0x4854eb6),
    (0x6a4, 'eb44', 1, 2, 0x4854eba),
    (0x6b4, '0f8499020000', 2, 6, 0x4855123),
    (0x6e1, 'e97efeffff', 1, 5, 0x4854d34),
    (0x797, 'e968010000', 1, 5, 0x48550d4),
    (0x7be, '741d', 1, 2, 0x4854fad),
    (0x7db, 'eb0e', 1, 2, 0x4854fbb),
    (0x923, 'eb2c', 1, 2, 0x4855121),
    (0x92c, 'e90cf9ffff', 1, 5, 0x4854a0d),
    (0x969, '0f848e000000', 2, 6, 0x48551cd),
    (0x977, 'eb7c', 1, 2, 0x48551c5),
    (0x987, '7474', 1, 2, 0x48551cd),
    (0x991, 'eb62', 1, 2, 0x48551c5),
    (0x999, '7462', 1, 2, 0x48551cd),
    (0x9a3, 'eb50', 1, 2, 0x48551c5),
    (0x9a5, 'eb25', 1, 2, 0x485519c),
    (0x9ec, '740f', 1, 2, 0x48551cd),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
    (0x4f, 'e9fcb7f8ff', 1, 5, 0x47e0020),
]
DIRECT_CALLS = [
    (0x4854914, 0x4a06dc0),
    (0x4854940, 0x45a46e0),
    (0x4854aac, 0x4c00c40),
    (0x4854bf5, 0x47edfe0),
    (0x4854f62, 0x47ee2b0),
    (0x4854f7f, 0x45a4ae0),
    (0x48550cf, 0x47edc30),
    (0x4855182, 0x47e73d0),
    (0x485518f, 0x47e7910),
    (0x4855197, 0x5660110),
    (0x48551a7, 0x47e7910),
    (0x48551af, 0x5660110),
    (0x48551d0, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4854865, 0x576dfe0),
    (0x48548fb, 0x5775730),
    (0x48549af, 0x576e8a0),
    (0x48549e2, 0x57738c8),
    (0x4854ae1, 0x576dfe0),
    (0x4854b17, 0x5775360),
    (0x4854b81, 0x576e8a0),
    (0x4854ba3, 0x576dfe0),
    (0x4854c1b, 0x576e010),
    (0x4854c38, 0x576e010),
    (0x4854c62, 0x576e010),
    (0x4854d12, 0x576e040),
    (0x4854e7b, 0x576dfd8),
    (0x4854fd7, 0x576e8a0),
    (0x4854ff5, 0x576dfe0),
    (0x48550ed, 0x576e470),
    (0x485510e, 0x576dfc8),
    (0x485511b, 0x576e150),
    (0x485512d, 0x576dfb8),
    (0x48551c7, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x48550e6, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4855101, 0x5714c70, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x4855114, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x432b2da, 0x4d925e8]
CALLER_FUNCTIONS = {'0x432b2da': ('0x432a990', '0x432b43f'), '0x4d925e8': ('0x4d8fce0', '0x4d92a0e')}
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

