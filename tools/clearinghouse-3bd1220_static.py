#!/usr/bin/env python3
"""Authenticated node94 clearinghouse-3bd1220 binding (0x3bd1220).

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

START, END = 0x3bd1220, 0x3bd199e
FDE_VA = 0x11e5188
FDE = bytes.fromhex(
    '500000006075220090c09e027e070000041be78fff410e10420e18420e20420e'
    '28420e30410e38470ef00183078c068d058e048f03860203e1060e38410e3042'
    '0e28420e20420e18420e10410e08410ef0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecb80000004989f74889fb488d46484889442478'
    '488984248000000048898424880000004889f7e808d973ff4885c00f846f0600'
    '004889d14c8db424800000004c8d642410eb21666666662e0f1f840000000000'
    '4c89ffe8d8d873ff4889d14885c00f843c060000488379100074e583390075e0'
    '488b104c89e74c89f6e81203b9ff807c24100074cb48895c24600f104424180f'
    '104c24280f298c24a00000000f29842490000000bf80000000ff15f9ccb90148'
    '85c00f8471060000660f28842490000000660f288c24a0000000660f11481066'
    '0f110048c7442410040000004889442448488944241848c74424200100000049'
    '8b6f404885ed0f84bd050000498b47504889442468498b47604889442458498b'
    '47684889442440410fb60f498b474848894424704d8b6718498b47104d8b7f08'
    'ba010000004889542408f6c1010f84f60500004d85ff7419410fb78f22030000'
    '4939cc0f83b70000004c89f9e9d70000004d85e474314c89e14989c74883e107'
    '742a31d26666662e0f1f8400000000004d8bbf2803000048ffc24839d175f14c'
    '89e04829d0eb084989c7eb524c89e04983fc08724966662e0f1f840000000000'
    '498b8f28030000488b8928030000488b8928030000488b8928030000488b8928'
    '030000488b8928030000488b89280300004c8bb9280300004883c0f875c24531'
    'e431c0410fb78f220300004939cc0f8255ffffff6666662e0f1f840000000000'
    '498b8fc00200004885c90f84eb04000048ffc0450fb7a7200300004989cf6644'
    '3ba12203000073d84885c00f84840000004a8d14e14881c2300300004889c648'
    '83e6070f84cb02000031ff0f1f4400004c8b3a498d972803000048ffc74839fe'
    '75ee4889c64829fe4883f80872436690488b02488b8028030000488b80280300'
    '00488b8028030000488b8028030000488b8028030000488b80280300004c8bb8'
    '28030000498d97280300004883c6f875bf31c0eb08498d4424014989cf4a8d14'
    'e14881c2c802000049c1e4064c89e64801ce4989c4eb29660f1f840000000000'
    '4c89f8498d4c24014a8d14e04881c2c802000049c1e4064c89e64801c64989cc'
    '48ffcd4c8b76104d85f67470833e00756b4c8b2a4c89e848b94b598638d6c56d'
    '3448f7e148c1ea0b4869c2102700004c89ef4829c7488b442470488b70104839'
    'f70f83c3030000488b4008488d0c7f48c1e105488b5c08204885db0f887c0300'
    '00490fafde0f8072030000488b442468488b004885c00f85f40000004885ed0f'
    '8424030000410fb787220300004939c40f824affffffb20131c9660f1f440000'
    '498b87c00200004885c00f843c03000089d748ffc1450fb7a7200300008d5701'
    '4989c766443ba02203000073d34889ce4883ee01730a4989c7e905ffffff6690'
    '4a8d14e04881c230030000f6c1077478400fb6ff83e7074531c0660f1f440000'
    '4c8b3a498d972803000049ffc04c39c775ee4c29c14883fe0772460f1f440000'
    '488b12488b9228030000488b9228030000488b9228030000488b922803000048'
    '8b9228030000488b92280300004c8bba28030000498d97280300004883c1f875'
    'bf31c9e980feffff4883fe0773b2ebf14889d948f7d9480f48cb66480f6ec1f3'
    '0f7e15b92763fc660f62c2660f281dcd1763fc660f5cc3660f28c8660f15c8f2'
    '0f58c866480f6ec0660f62c2660f5cc3660f28d0660f15d0f20f58d0f20f5eca'
    '488b4424580f57c0f2480f2a00f20f59c166480f7ec048b9ffffffffffffff7f'
    '4821c8660f57c948b9ffffffffffffef7f4839c87f48f20f100d7a9563fc660f'
    '2ec87722660f2e05a49063fc7718660f28c8eb2a4889c64883f8080f834ffdff'
    'ffe98bfdfffff20f10154a9563fcf20f5fd0f20f100d769063fcf20f5dcaf248'
    '0f2cc1660f2e0d3d8b63fc48b9ffffffffffffff7f480f47c1660f2ec9b90000'
    '0000480f4bc848890c244889c84829d80f809d0000004889442438488b442440'
    '488b084889c8482b04240f80bf000000488b4c2440488901488b742408483b74'
    '24107529ba01000000b90800000041b820000000488d7c2410e8025270ff488b'
    '4424184889442448488b7424084889f048c1e005488b4c24484c892c014c8974'
    '0108488b542438488954011048895c011848ffc648897424084889742420b101'
    'b8000000004885ed0f851cfbffffe99600000031ff488d359c04b201ff152e19'
    'ba0131c0488b14244839da0f99c048b9ffffffffffffff7f4801c84889d14829'
    'd9480f40c848894c2438e92cffffff48894c245031ff488d355b04b201ff15ed'
    '18ba0131c0488b1424488b7424504839d60f99c048b9ffffffffffffff7f4801'
    'c84829d6480f40f04889f0e900ffffff48c7030000000048c743080800000048'
    'c7431000000000eb1f488b442420488b5c246048894310488b44241048890348'
    '8b442418488943084889d84881c4b80000005b415c415d415e415f5dc3488d3d'
    '2405b201ff1546cbb901eb2b488d3db586b101ff1537cbb901eb1c488d3da686'
    'b101ff1528cbb901eb0d488d155f03b201ff1571c6b9010f0bbf08000000be80'
    '000000ff154fc6b901488d3db071b101ebb2eb040f0b0f0b4889c3488b742410'
    '4885f67411488b7c241848c1e60531d2ff157ac6b9014889dfe872e7a801'
)
BODY_SHA256 = '518a80a7d1a8348dc9962abf7d8bc64235e9a61ccb971e1c2cbaa8b140d2a62f'
BRANCHES = [
    (0x3b, '0f846f060000', 2, 6, 0x3bd18d0),
    (0x51, 'eb21', 1, 2, 0x3bd1294),
    (0x6e, '0f843c060000', 2, 6, 0x3bd18d0),
    (0x79, '74e5', 1, 2, 0x3bd1280),
    (0x7e, '75e0', 1, 2, 0x3bd1280),
    (0x93, '74cb', 1, 2, 0x3bd1280),
    (0xc2, '0f8471060000', 2, 6, 0x3bd1959),
    (0x106, '0f84bd050000', 2, 6, 0x3bd18e9),
    (0x14d, '0f84f6050000', 2, 6, 0x3bd1969),
    (0x156, '7419', 1, 2, 0x3bd1391),
    (0x163, '0f83b7000000', 2, 6, 0x3bd1440),
    (0x16c, 'e9d7000000', 1, 5, 0x3bd1468),
    (0x174, '7431', 1, 2, 0x3bd13c7),
    (0x180, '742a', 1, 2, 0x3bd13cc),
    (0x19d, '75f1', 1, 2, 0x3bd13b0),
    (0x1a5, 'eb08', 1, 2, 0x3bd13cf),
    (0x1aa, 'eb52', 1, 2, 0x3bd141e),
    (0x1b3, '7249', 1, 2, 0x3bd141e),
    (0x1fc, '75c2', 1, 2, 0x3bd13e0),
    (0x20e, '0f8255ffffff', 2, 6, 0x3bd1389),
    (0x22a, '0f84eb040000', 2, 6, 0x3bd193b),
    (0x246, '73d8', 1, 2, 0x3bd1440),
    (0x24b, '0f8484000000', 2, 6, 0x3bd14f5),
    (0x263, '0f84cb020000', 2, 6, 0x3bd1754),
    (0x280, '75ee', 1, 2, 0x3bd1490),
    (0x28c, '7243', 1, 2, 0x3bd14f1),
    (0x2cf, '75bf', 1, 2, 0x3bd14b0),
    (0x2d3, 'eb08', 1, 2, 0x3bd14fd),
    (0x2f5, 'eb29', 1, 2, 0x3bd1540),
    (0x32a, '7470', 1, 2, 0x3bd15bc),
    (0x32f, '756b', 1, 2, 0x3bd15bc),
    (0x361, '0f83c3030000', 2, 6, 0x3bd194a),
    (0x37b, '0f887c030000', 2, 6, 0x3bd191d),
    (0x385, '0f8072030000', 2, 6, 0x3bd191d),
    (0x396, '0f85f4000000', 2, 6, 0x3bd16b0),
    (0x39f, '0f8424030000', 2, 6, 0x3bd18e9),
    (0x3b0, '0f824affffff', 2, 6, 0x3bd1520),
    (0x3ca, '0f843c030000', 2, 6, 0x3bd192c),
    (0x3eb, '73d3', 1, 2, 0x3bd15e0),
    (0x3f4, '730a', 1, 2, 0x3bd1620),
    (0x3f9, 'e905ffffff', 1, 5, 0x3bd1523),
    (0x40e, '7478', 1, 2, 0x3bd16a8),
    (0x430, '75ee', 1, 2, 0x3bd1640),
    (0x439, '7246', 1, 2, 0x3bd16a1),
    (0x47f, '75bf', 1, 2, 0x3bd1660),
    (0x483, 'e980feffff', 1, 5, 0x3bd1528),
    (0x48c, '73b2', 1, 2, 0x3bd1660),
    (0x48e, 'ebf1', 1, 2, 0x3bd16a1),
    (0x514, '7f48', 1, 2, 0x3bd177e),
    (0x522, '7722', 1, 2, 0x3bd1766),
    (0x52c, '7718', 1, 2, 0x3bd1766),
    (0x532, 'eb2a', 1, 2, 0x3bd177e),
    (0x53b, '0f834ffdffff', 2, 6, 0x3bd14b0),
    (0x541, 'e98bfdffff', 1, 5, 0x3bd14f1),
    (0x590, '0f809d000000', 2, 6, 0x3bd1853),
    (0x5aa, '0f80bf000000', 2, 6, 0x3bd188f),
    (0x5c2, '7529', 1, 2, 0x3bd180d),
    (0x628, '0f851cfbffff', 2, 6, 0x3bd136a),
    (0x62e, 'e996000000', 1, 5, 0x3bd18e9),
    (0x66a, 'e92cffffff', 1, 5, 0x3bd17bb),
    (0x6ab, 'e900ffffff', 1, 5, 0x3bd17d0),
    (0x6c7, 'eb1f', 1, 2, 0x3bd1908),
    (0x70a, 'eb2b', 1, 2, 0x3bd1957),
    (0x719, 'eb1c', 1, 2, 0x3bd1957),
    (0x728, 'eb0d', 1, 2, 0x3bd1957),
    (0x750, 'ebb2', 1, 2, 0x3bd1924),
    (0x752, 'eb04', 1, 2, 0x3bd1978),
    (0x763, '7411', 1, 2, 0x3bd1996),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x3bd1253, 0x330eb60),
    (0x3bd1283, 0x330eb60),
    (0x3bd12a9, 0x37615c0),
    (0x3bd17f9, 0x32d6a00),
    (0x3bd1999, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3bd12d9, 0x576dfd8),
    (0x3bd185c, 0x5773190),
    (0x3bd189d, 0x5773190),
    (0x3bd1924, 0x576e470),
    (0x3bd1933, 0x576e470),
    (0x3bd1942, 0x576e470),
    (0x3bd1951, 0x576dfc8),
    (0x3bd1963, 0x576dfb8),
    (0x3bd1990, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x3bd191d, 0x56f1e48, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f636c656172696e67686f7573652e7273'), 172, 98),
    (0x3bd192c, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x3bd193b, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x3bd194a, 0x56f1cb0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = [0x3316dbf]
CALLER_FUNCTIONS = {'0x3316dbf': ('0x3316d60', '0x3316fb0')}
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

