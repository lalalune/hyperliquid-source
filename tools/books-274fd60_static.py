#!/usr/bin/env python3
"""Authenticated node94 books-274fd60 binding (0x274fd60).

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

START, END = 0x274fd60, 0x27506b8
FDE_VA = 0x10f07e4
FDE = bytes.fromhex(
    'cc000000bc2b130074f565015809000004c7fa92ff410e10420e18420e20420e'
    '28420e30410e38470eb00483078c068d058e048f0386027b2e007d2e007a2e00'
    '02702e0002522e00692e0002872e0002b02e004b2e00024f2e105d0eb804420e'
    'c0044a0eb004652e006d2e0002742e0002e10e38410e30420e28420e20420e18'
    '420e10410e08410eb00402ca2e0002fd2e00025a2e00702e004d2e004d2e0002'
    '5e2e00027e2e006a2e00502e00502e005a2e006d2e00502e004b2e004f2e0049'
    '2e004f2e00492e004d2e00482e000000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecf80100004989cf48895424084989f6488bb600'
    '0200004839f10f836f0800004d89cd4889fb498b86f80100004d89fc49c1e405'
    '4a8b2c20498b7008498b5010488dbc2490000000ff151e3402030fb784249000'
    '00003d860100000f85db030000498db6900000000f108424940000000f114424'
    '120f298424d0010000488d7c2430488d8c24d00100004c89fae8e2b3bbff0fb7'
    '4424303d860100000f8509040000488b4424384889842440010000498b750849'
    '8b5510488dbc2490000000ff15a73302030fb78424900000003d860100000f85'
    '360400000f108424940000000f114424320f298424e0010000498bb600020000'
    '4939f70f83a2070000498b86f80100004a8b0420493b86180200000f834a0600'
    '00498b8e100200004869c0e80000008b4c0148488dbc2458010000488db424e0'
    '010000ba01000000ff159a3902036681bc245801000086010f85260400004983'
    'bec8050000000f844f0700004c8ba424600100004d8baec005000066c7842490'
    '0000004101488dbc2490000000e89e95c200488b4c24088b4110898424a00000'
    '00660f1001660f29842490000000488db424900000004c89efff154147020348'
    'b9cb10c7bab88d06004839c80f8789040000488b8c2438020000488b94243002'
    '0000486bc0644c897c2438488bb4244001000048897424304c89642440488954'
    '244848894c245048894424584d3bbe903300000f835f050000498d8e80000000'
    '498db6d03800004d69c7d80000004d038688330000488dbc2490000000488d54'
    '2430ff15284d02030fb78424900000003d860100000f851d040000488b8c2498'
    '0000004889c848c1e80248bac3f5285c8fc2f52848f7e248b8295c8fc2f5285c'
    '8f480fafc148c1c80248b95c8fc2f5285c8f024531e44839c80f97c0493bae18'
    '0200000f83dc04000048c1ea024188c44901d4498b86100200004869cde80000'
    '00803c0800750e4801c848c700010000004c8960084d85e40f8483040000498d'
    'beb805000031f6ff15333d02034989c5488d1599d9f6024889c74c89e6ff1575'
    '4c02034d8d96403800004d8d9ed0050000488b5424088b4a10894c2420f30f6f'
    '02660f7f442410660f76c0660f7f842490000000c78424a0000000ffffffff48'
    '8d7c2430488d542410488d8c24900000004c89ee4989c04531c941534152ff15'
    '244902034883c41066817c243086010f851d040000660f76c0660f7f84249000'
    '0000c78424a0000000ffffffff488d7c2430488d8c249000000041b801000000'
    '4c89f631d24d89e1e8e3f5fbff66817c243086010f8556040000bf14000000ff'
    '15b3de01034885c00f84bd0400004989c5488b4c24088b4110418945100f1001'
    '410f11450048c78424b8010000010000004c89ac24c001000048c78424c80100'
    '0001000000418b466889842450010000498b4660488984244801000041833e01'
    '0f85ae020000498b4e08498b5628410fb6b6f2080000488d7c24304531c0e80d'
    '7b2301e9990200000fb78c24a200000066894c24200f108424920000000f2944'
    '24100f108424e00000000f1143500f108424d40000000f1143440f108424c400'
    '00000f1143340f108424b40000000f1143240f108424a40000000f1143140fb7'
    '4c242066894b12660f28442410660f114302668903eb4e0fb74c243666894b06'
    '8b4c2432894b02488b4c24380f104424500f1143200f104424600f1143300f10'
    '4424700f1143400f108424800000000f114350660f10442440660f1143106689'
    '0348894b084889d84881c4f80100005b415c415d415e415f5dc30fb78c24a200'
    '000066894c24400f108424920000000f294424300f108424e00000000f114350'
    '0f108424d40000000f1143440f108424c40000000f1143340f108424b4000000'
    '0f1143240f108424a40000000f1143140fb74c244066894b12660f28442430e9'
    '29ffffff0f108424a80100000f298424e00000000f108424980100000f298424'
    'd00000000f108424580100000f108c24680100000f109424780100000f109c24'
    '880100000f299c24c00000000f299424b00000000f298c24a00000000f298424'
    '90000000488dbc2490000000e84fe802000fb784245e010000668943068b8424'
    '5a010000894302488b8424600100000f108424780100000f1143200f10842488'
    '0100000f1143300f108424980100000f1143400f108424a80100000f11435066'
    '0f10842468010000660f11431066c703aa0048894308e9aafeffff66c703df00'
    '488d05b7fbc9fd4889430848c7431023000000e98dfeffff0fb78c2496000000'
    '66894b068b8c2492000000894b02488b8c24980000000f108424b00000000f11'
    '43200f108424c00000000f1143300f108424d00000000f1143400f108424e000'
    '00000f114350660f108424a0000000e925feffff0f57c00f294424400f294424'
    '30488d7c2410ff159448020349f7dc0f57c0f2490f2ac4f20f5e0501aaabfd49'
    '81c6f3080000488b44242048898424a80000000f104c24100f118c2498000000'
    'f20f118424b000000048b810000000000000804889842490000000488db424b8'
    '010000488d942448010000488d4c24304c8d8424900000004c89f7ff15774202'
    '0366c7038601e99afdffff488d3d1e1dfa02ff1598df0103488d3d99aff602ff'
    '158bdf0103488d3d1c1dfa02ff157edf01030f108424800000000f298424e000'
    '00000f104424700f298424d00000000f104424300f104c24400f105424500f10'
    '5c24600f299c24c00000000f299424b00000000f298c24a00000000f29842490'
    '000000488d3d58fdc9fd488d0d0fdcf6024c8d05b0d4f602488d942490000000'
    'be2b000000ff15ddda0103e9dd0000000f108424800000000f298424e0000000'
    '0f104424700f298424d00000000f104424300f104c24400f105424500f105c24'
    '600f299c24c00000000f299424b00000000f298c24a00000000f298424900000'
    '00488d3ddafcc9fd488d0d91dbf6024c8d054ad4f602488d942490000000be2b'
    '000000ff155fda0103eb62bf01000000be14000000ff1525da0103488d1506cc'
    'f6024c89ffff15bdd90103488d15c619fa024c89ffff15add9010366c7842490'
    '0000004101488d3d4dbae3fd488d0ddd98f9024c8d05a694f902488d94249000'
    '0000be2b000000ff15fbd901030f0b4889c3be140000004c89ef31d2ff15aed9'
    '01034889dfe8a6faf0024889c3488dbc2490000000e8168ec200eb2eff15a6da'
    '01034889c3488dbc2490000000e80ee50200eb16ff158eda01034889c3488dbc'
    '2490000000e8f6e402004889dfe85efaf002ff1570da0103'
)
BODY_SHA256 = 'db2168fadbb64c9a7bdcff273bf8be0ef877a7ba2d0fa492825a84693c47cd56'
BRANCHES = [
    (0x26, '0f836f080000', 2, 6, 0x27505fb),
    (0x67, '0f85db030000', 2, 6, 0x27501a8),
    (0xa8, '0f8509040000', 2, 6, 0x2750217),
    (0xde, '0f8536040000', 2, 6, 0x275027a),
    (0x103, '0f83a2070000', 2, 6, 0x275060b),
    (0x11b, '0f834a060000', 2, 6, 0x27504cb),
    (0x158, '0f8526040000', 2, 6, 0x27502e4),
    (0x166, '0f844f070000', 2, 6, 0x275061b),
    (0x1cc, '0f8789040000', 2, 6, 0x27503bb),
    (0x213, '0f835f050000', 2, 6, 0x27504d8),
    (0x255, '0f851d040000', 2, 6, 0x27503d8),
    (0x2a3, '0f83dc040000', 2, 6, 0x27504e5),
    (0x2c5, '750e', 1, 2, 0x2750035),
    (0x2d8, '0f8483040000', 2, 6, 0x27504c1),
    (0x36f, '0f851d040000', 2, 6, 0x27504f2),
    (0x3b4, '0f8556040000', 2, 6, 0x2750570),
    (0x3c8, '0f84bd040000', 2, 6, 0x27505eb),
    (0x420, '0f85ae020000', 2, 6, 0x2750434),
    (0x443, 'e999020000', 1, 5, 0x2750441),
    (0x4b5, 'eb4e', 1, 2, 0x2750265),
    (0x57f, 'e929ffffff', 1, 5, 0x275020d),
    (0x656, 'e9aafeffff', 1, 5, 0x2750265),
    (0x673, 'e98dfeffff', 1, 5, 0x2750265),
    (0x6cf, 'e925feffff', 1, 5, 0x2750259),
    (0x766, 'e99afdffff', 1, 5, 0x2750265),
    (0x80b, 'e9dd000000', 1, 5, 0x275064d),
    (0x889, 'eb62', 1, 2, 0x275064d),
    (0x91a, 'eb2e', 1, 2, 0x27506aa),
    (0x932, 'eb16', 1, 2, 0x27506aa),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x274fdf9, 0x230b1e0),
    (0x274feed, 0x3379490),
    (0x2750108, 0x270f6f0),
    (0x275019e, 0x3987cb0),
    (0x275034c, 0x277eba0),
    (0x2750665, 0x5660110),
    (0x2750675, 0x3379490),
    (0x275068d, 0x277eba0),
    (0x27506a5, 0x277eba0),
    (0x27506ad, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x274fdb4, 0x57731d8),
    (0x274fe2b, 0x57731d8),
    (0x274fea8, 0x5773848),
    (0x274ff19, 0x5774660),
    (0x274ffa2, 0x5774cd0),
    (0x2750047, 0x5773d80),
    (0x275005d, 0x5774cd8),
    (0x27500be, 0x57749e8),
    (0x275011f, 0x576dfd8),
    (0x2750446, 0x5774ce0),
    (0x27504bb, 0x5774738),
    (0x27504d2, 0x576e470),
    (0x27504df, 0x576e470),
    (0x27504ec, 0x576e470),
    (0x2750565, 0x576e048),
    (0x27505e3, 0x576e048),
    (0x27505f5, 0x576e020),
    (0x2750605, 0x576dfc8),
    (0x2750615, 0x576dfc8),
    (0x2750647, 0x576e048),
    (0x275065c, 0x576e010),
    (0x275067c, 0x576e128),
    (0x2750694, 0x576e128),
    (0x27506b2, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x27504cb, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x27504d8, 0x56bb478, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 19, 47),
    (0x27504e5, 0x56f2208, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 119, 37),
    (0x27505fb, 0x56bd208, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x275060b, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = [0x23e85d2, 0x274d4ab, 0x274d6a5]
CALLER_FUNCTIONS = {'0x23e85d2': ('0x23e7d10', '0x23e863d'), '0x274d4ab': ('0x274c9f0', '0x274daf5'), '0x274d6a5': ('0x274c9f0', '0x274daf5')}
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

