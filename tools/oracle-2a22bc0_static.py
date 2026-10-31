#!/usr/bin/env python3
"""Authenticated node94 oracle-2a22bc0 binding (0x2a22bc0).

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

START, END = 0x2a22bc0, 0x2a2344f
FDE_VA = 0x1121440
FDE = bytes.fromhex(
    '5000000018381600781790018f08000004c3e591ff410e10420e18420e20420e'
    '28420e30410e38470eb00283078c068d058e048f0386020384070e38410e3042'
    '0e28420e20420e18420e10410e08410eb0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecf80000004989cc4989d54989f74889fb488954'
    '24184c898424d80000004c898c24e0000000660fefc0660f7f442420c7442430'
    '00000000f30f6f09660f6e5110660f74d0660f74c8660fdbca660fd7c13dffff'
    '00007437f3410f6f0424f30f6f0dee94b7fd660f74c866410f6e442410660f6e'
    '15eb94b7fd660f74d0660fdbd1660fd7c24d89e63dffff000075158b056737d6'
    '024c8d354837d60285c00f850f070000418b461089842480000000410f10060f'
    '29442470894424300f294424204d8db7f8000000488d7424204c89f7e84f2bcd'
    '00488b480849ba4b598638d6c56d344885c94c897424580f841f020000488b40'
    '100fb7b1220300004189f041c1e00648c7c2ffffffff31ff0f1f840000000000'
    '4939f8742b4c3bacd1d0020000410f97c14180d9004883c74048ffc24180f901'
    '74de410fb6f185f6741deb070f1f40004889f24883e8010f82bf010000488b8c'
    'd128030000eb9a8b4439c0894424108b4439c489442414488b4439c848898424'
    'a80000004c8b7439d04c89e849f7e248c1ea0b4869c2102700004929c54c89a4'
    '24c8000000498b77704939f50f83e1010000498b47684a8d0c6d000000004c01'
    'e948c1e105488b44082048894424684d8daf280100008b842480000000894424'
    '300f284424700f29442420488b5424184c8b259125d502488d7424204c89ef31'
    'c941ffd44889c58b84248000000089442430660f28442470660f29442420488b'
    '542418488d7424204c89efb90100000041ffd44889ac24e800000048898424f0'
    '0000004c89b424b00000004c897c2420488d4424184889442428488d44247048'
    '89442430488d44246848894424384c8db424d80000004c89742440488d8424b0'
    '0000004889442448488d6c24204889ef31f6e889bbffff4989c44989d54889ef'
    'be01000000e876bbffff4989c24883bc24b0000000000f84e70000004889d148'
    '8b7424684889f049f7e50f90c231ff49b8feffffffffffff7f4c39c0480f47c7'
    '84d2480f45c78b7c2414660f57ed660f57f64839f849b94b598638d6c56d340f'
    '82a50100004889c248c1ea200f848401000031d248f7f7e97e010000488d7c24'
    '204c89ee4c89fae8e4d01d014c89e848b94b598638d6c56d3448f7e148c1ea0b'
    '493b57300f85680400004869c2102700004929c54d3b6f100f83540400008b44'
    '2420894424108b44242489442414488b44242848898424a80000004531f64c89'
    'a424c8000000498b77704939f50f821ffeffff488d15861ecb024c89efff1565'
    'b0d4024d89e54c895424604531e4837c241000410f95c4410fb6afed0200008b'
    '842480000000898424a0000000660f28442470660f29842490000000488db424'
    '90000000488b7c2458e84228cd004d8d4f604c893c24438d0c64ffc1488d7c24'
    '204889c631d24189e8ff15a901d502488b4424284885c00f88210400004c8b64'
    '24204c89e14829c10f80d00300004d89ec31c04885c9480f4fc148898424d000'
    '0000488d8424d000000048894424204c89742428488d8424e800000048894424'
    '30488dbc2490000000488d742420e8adbbfffff20f10b42490000000f20f10ac'
    '249800000049b94b598638d6c56d344c8b542460eb5531d2f7f70f57f6f2480f'
    '2af0f20f5e35f67d7efd4889f048f7e10f90c131d24c39c0480f47c284c9480f'
    '45c24839f872244889c148c1e920740731d248f7f7eb0431d2f7f70f57edf248'
    '0f2ae8f20f5e2db57d7efd488b4c24184889c849f7e148c1ea0b4d8b773031ed'
    '41bd010000004c39f20f859d0000004869d2102700004889c84829d0493b4710'
    '0f8386000000f20f11b424b80000004c89a424c0000000f20f116c24584c8954'
    '2460498b4f08488d044048c1e0044c8b640108488b6c01104885ed74154889ef'
    'ff15b2aed4024885c00f84f40200004989c54c89ef4c89e64889eaff159faed4'
    '02488b4c241849b94b598638d6c56d344c8b542460f20f106c24584c8ba424c0'
    '000000f20f10b424b80000004d85e474744889c849f7e148c1ea0b4c39f20f85'
    'dc0100004889c849f7e148c1ea0b4869d2102700004889c84829d0493b47100f'
    '83bb010000498b5708488d044048c1e0040fb644022a66490f6ecc660f620dbd'
    '0c7efd660f5c0dd5fc7dfd660f28c1660f15c1f20f58c1488d150aea9ffdf20f'
    '5e04c2eb04660f57c04889c849f7e14889d648c1ee0b4d85d274724c39f60f85'
    '5c0100004889c849f7e148c1ea0b4869d2102700004889c84829d0493b47100f'
    '833b010000498b5708488d044048c1e0040fb644022a66490f6ed2660f62153d'
    '0c7efd660f5c1555fc7dfd660f28ca660f15caf20f58ca488d158ae99ffdf20f'
    '5e0cc24c39f67412e9f3000000660f57c94c39f60f85e60000004889c849f7e1'
    '48c1ea0b4869c2102700004829c1493b4f100f83c8000000498b4708488d0c49'
    '48c1e1040fb644082a4883f8070f833c010000b906000000f20f105424680f14'
    '15bb0b7efd660f5c15d3fb7dfd29c1660f28da660f15daf20f58dac1e103488d'
    '05d3e09ffdf20f5e1c010f57d2f2480f2a9424a8000000f20f5e15617b7efd48'
    '8b8c24c80000008b41108943600f10210f11635048892b4c896b0848896b108b'
    '4424108943188b44241489431cf20f115320f20f114328f20f114b30f20f1173'
    '38f20f116b40f20f115b484889d84881c4f80000005b415c415d415e415f5dc3'
    '488d3d59eecc02ff1503b1d402e98a000000488d3d47eecc02ff15f1b0d4024c'
    '89b42490000000488d8424900000004889442420488d3d2d30d602488d0d2608'
    'cd024c8d054708cd02488d542420be01000000ff15ffb4d402e9b2f8ffff0f99'
    'c10fb6c948baffffffffffffff7f4801ca4929c4488d359d06cd024c0f40e231'
    'ffff15a9fdd4024c89e1e9fffbffff488d3d5affcc02ff1554add4020f0b488d'
    '3ded8db7fd488d0dfc08cd024c8d054d06cd02488d542420be2b000000ff1525'
    'acd402bf010000004889eeff1587abd4024889c34885ed740e4c89ef4889ee31'
    'd2ff15c9abd4024889dfe8c1ccc302'
)
BODY_SHA256 = 'd3aea604bd8d336ae32c6ec05c38c52bd25a0a1e4fefbf3207ade962f15f91a9'
BRANCHES = [
    (0x62, '7437', 1, 2, 0x2a22c5b),
    (0x99, '7515', 1, 2, 0x2a22c70),
    (0xaa, '0f850f070000', 2, 6, 0x2a2337f),
    (0xf7, '0f841f020000', 2, 6, 0x2a22edc),
    (0x123, '742b', 1, 2, 0x2a22d10),
    (0x140, '74de', 1, 2, 0x2a22ce0),
    (0x148, '741d', 1, 2, 0x2a22d27),
    (0x14a, 'eb07', 1, 2, 0x2a22d13),
    (0x157, '0f82bf010000', 2, 6, 0x2a22edc),
    (0x165, 'eb9a', 1, 2, 0x2a22cc1),
    (0x1ac, '0f83e1010000', 2, 6, 0x2a22f53),
    (0x2b6, '0f84e7000000', 2, 6, 0x2a22f63),
    (0x2ff, '0f82a5010000', 2, 6, 0x2a2306a),
    (0x30c, '0f8484010000', 2, 6, 0x2a23056),
    (0x317, 'e97e010000', 1, 5, 0x2a2305a),
    (0x344, '0f8568040000', 2, 6, 0x2a23372),
    (0x358, '0f8354040000', 2, 6, 0x2a23372),
    (0x38d, '0f821ffeffff', 2, 6, 0x2a22d72),
    (0x417, '0f8821040000', 2, 6, 0x2a233fe),
    (0x428, '0f80d0030000', 2, 6, 0x2a233be),
    (0x494, 'eb55', 1, 2, 0x2a230ab),
    (0x4c5, '7224', 1, 2, 0x2a230ab),
    (0x4ce, '7407', 1, 2, 0x2a23097),
    (0x4d5, 'eb04', 1, 2, 0x2a2309b),
    (0x509, '0f859d000000', 2, 6, 0x2a2316c),
    (0x520, '0f8386000000', 2, 6, 0x2a2316c),
    (0x55b, '7415', 1, 2, 0x2a23132),
    (0x569, '0f84f4020000', 2, 6, 0x2a23423),
    (0x5af, '7474', 1, 2, 0x2a231e5),
    (0x5be, '0f85dc010000', 2, 6, 0x2a23360),
    (0x5df, '0f83bb010000', 2, 6, 0x2a23360),
    (0x623, 'eb04', 1, 2, 0x2a231e9),
    (0x639, '7472', 1, 2, 0x2a2326d),
    (0x63e, '0f855c010000', 2, 6, 0x2a23360),
    (0x65f, '0f833b010000', 2, 6, 0x2a23360),
    (0x6a6, '7412', 1, 2, 0x2a2327a),
    (0x6a8, 'e9f3000000', 1, 5, 0x2a23360),
    (0x6b4, '0f85e6000000', 2, 6, 0x2a23360),
    (0x6d2, '0f83c8000000', 2, 6, 0x2a23360),
    (0x6ed, '0f833c010000', 2, 6, 0x2a233ef),
    (0x7ad, 'e98a000000', 1, 5, 0x2a233fc),
    (0x7f9, 'e9b2f8ffff', 1, 5, 0x2a22c70),
    (0x82a, 'e9fffbffff', 1, 5, 0x2a22fee),
    (0x877, '740e', 1, 2, 0x2a23447),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x2a22c9c, 0x36f57f0),
    (0x2a22e52, 0x2a1e9e0),
    (0x2a22e65, 0x2a1e9e0),
    (0x2a22ee7, 0x3bfffd0),
    (0x2a22fa9, 0x36f57f0),
    (0x2a2302e, 0x2a1ebe0),
    (0x2a2344a, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x2a22f5d, 0x576dfc8),
    (0x2a22fc9, 0x5773178),
    (0x2a23120, 0x576dfd8),
    (0x2a2313b, 0x576dfe0),
    (0x2a23367, 0x576e470),
    (0x2a23379, 0x576e470),
    (0x2a233b3, 0x576e8b8),
    (0x2a233e1, 0x5773190),
    (0x2a233f6, 0x576e150),
    (0x2a2341d, 0x576e048),
    (0x2a2342b, 0x576dfb8),
    (0x2a23441, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2a22f53, 0x56d4de0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
    (0x2a23360, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x2a23372, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x2a233ef, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774ee8']
GOT_SITES = {'0x5774ee8': ['0x27d72d8']}


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

