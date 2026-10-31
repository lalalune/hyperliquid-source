#!/usr/bin/env python3
"""Authenticated node94 books-4d72a80 binding (0x4d72a80).

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

START, END = 0x4d72a80, 0x4d73542
FDE_VA = 0x12e5000
FDE = bytes.fromhex(
    'dc000000d873320078daa803c20a0000042b238dff410e10420e18420e20420e'
    '28420e30410e38470ea00583078c068d058e048f03860202432e0002952e0002'
    '452e00552e00024e2e00025a2e00692e0002872e0002b82e004b2e0002552e10'
    '600ea805420eb0054a0ea005652e006d2e0002742e0002e62e0002c80e38410e'
    '30420e28420e20420e18420e10410e08410ea00502ca2e000309012e0002632e'
    '00702e004d2e004d2e004d2e004d2e00025b2e00027b2e006a2e00502e00502e'
    '00572e006d2e00502e004b2e004f2e00492e004f2e00492e004d2e00482e0000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec680200004989cc48895424784889f5488bb600'
    '0200004839f10f83dc0900004d89cd4889fb4c8bbdf80100004d89e649c1e605'
    '4b8b04374889842460010000498b7008498b5010488dbc2480000000ff15f606'
    'a0000fb78424800000003d860100000f854a0400004d01f70f10842484000000'
    '0f118424320100000f29842440020000498b47084889ac2450010000488bad18'
    '0200004839e80f8318080000498b0f4839e90f8319080000488b942450010000'
    '4c8bb2100200004869c0e8000000410fb64406494869c9e8000000412a440e48'
    '0f82320900000fb6c8488d7c2410488db42440020000ba02000000ff15c70ca0'
    '0066817c241086010f852f040000488b4424184885c00f84d604000048898424'
    '5801000066c7842480000000a900488dbc2480000000e8e5c80300498b750849'
    '8b5510488dbc2480000000ff150706a0000fb78424800000003d860100000f85'
    'fa0400000f108424840000000f114424120f29842450020000498b074839e80f'
    '83590700004869c0e8000000418b4c0648488dbc2478010000488db424500200'
    '00ba01000000ff151c0ca0006681bc247801000086014c8bbc24500100000f85'
    '040500004983bf48100000000f84530800004c8bb424800100004d8baf401000'
    '0066c78424800000004101488dbc2480000000e8186860fe488b4c24788b4110'
    '89842490000000660f1001660f29842480000000488db424800000004c89efff'
    '15bb19a00048b9cb10c7bab88d06004839c80f8767050000488b8c24a8020000'
    '488b9424a0020000486bc0644c89642418488bb4245801000048897424104c89'
    '742420488954242848894c243048894424384d3ba7103e00000f836c06000049'
    '8d8f80000000498db7504300004d69c4d80000004d0387083e0000488dbc2480'
    '000000488d542410ff15a21fa0000fb78424800000003d860100000f85fb0400'
    '00488b8c24880000004889c848c1e80248bac3f5285c8fc2f52848f7e248b829'
    '5c8fc2f5285c8f480fafc148c1c80248b95c8fc2f5285c8f024531e44839c80f'
    '97c0488b8c2460010000493b8f180200000f83e105000048c1ea024188c44901'
    'd4498b87100200004869c9e8000000803c0800750e4801c848c700010000004c'
    '8960084d85e40f846e050000498dbf3810000031f6ff15a50fa0004989c5488d'
    '15bb189d004889c74c89e6ff15e71ea0004d8d97c04200004d8d9f5010000048'
    '8b5424788b4a10898c2440010000f30f6f02660f7f842430010000660f76c066'
    '0f7f842480000000c7842490000000ffffffff488d7c2410488d942430010000'
    '488d8c24800000004c89ee4989c04531c941534152ff158d1ba0004883c41066'
    '817c241086010f8519050000660f76c0660f7f842480000000c7842490000000'
    'ffffffff488d7c2410488d8c248000000041b8010000004c89fe31d24d89e1e8'
    'ec5397ff66817c241086010f854f050000bf14000000ff151cb19f004885c00f'
    '84b30500004989c5488b4c24788b4110418945100f1001410f11450048c78424'
    'd8010000010000004c89ac24e001000048c78424e801000001000000418b4768'
    '89842470010000498b4760488984246801000041833f010f8587030000498b4f'
    '08498b5728410fb6b772130000488d7c24104531c0e8764dc1fee9720300000f'
    'b78c249200000066898c24400100000f108424820000000f298424300100000f'
    '108424d00000000f1143500f108424c40000000f1143440f108424b40000000f'
    '1143340f108424a40000000f1143240f108424940000000f1143140fb78c2440'
    '01000066894b12660f28842430010000660f114302668903e90c0100000f1044'
    '24600f298424d00000000f104424500f298424c00000000f104424100f104c24'
    '200f105424300f105c24400f299c24b00000000f299424a00000000f298c2490'
    '0000000f29842480000000488dbc2480000000e888c403008b44241289442408'
    '0fb7442416668944240c488b4424180f104424200f298424f00100000f104424'
    '300f298424000200000f104424400f298424100200000f104424500f29842420'
    '0200000f104424600f29842430020000eb0066c703a9008b4c2408894b020fb7'
    '4c240c66894b06488943080f288424f00100000f288c24000200000f28942410'
    '0200000f289c24200200000f1143100f114b200f1153300f115b40660f288424'
    '30020000660f1143504889d84881c4680200005b415c415d415e415f5dc30fb7'
    '8c249200000066894c24200f108424820000000f294424100f108424d0000000'
    '0f1143500f108424c40000000f1143440f108424b40000000f1143340f108424'
    'a40000000f1143240f108424940000000f1143140fb74c242066894b12660f28'
    '442410e968feffff0f108424c80100000f298424d00000000f108424b8010000'
    '0f298424c00000000f108424780100000f108c24880100000f10942498010000'
    '0f109c24a80100000f299c24b00000000f299424a00000000f298c2490000000'
    '0f29842480000000488dbc2480000000e8ebc203000fb784247e010000668943'
    '068b84247a010000894302488b8424800100000f108424980100000f1143200f'
    '108424a80100000f1143300f108424b80100000f1143400f108424c80100000f'
    '114350660f10842488010000660f11431066c703aa0048894308e9aafeffff66'
    'c703df00488d0554219afb4889430848c7431023000000e98dfeffff0fb78c24'
    '8600000066894b068b8c2482000000894b02488b8c24880000000f108424a000'
    '00000f1143200f108424b00000000f1143300f108424c00000000f1143400f10'
    '8424d00000000f114350660f10842490000000660f11431066890348894b08e9'
    '25feffff0f57c00f294424200f29442410488dbc2430010000ff15211aa00049'
    'f7dc0f57c0f2490f2ac4f20f5e058e7b49fb4981c7b8050000488b8424400100'
    '0048898424980000000f108c24300100000f118c2488000000f20f118424a000'
    '000048b810000000000000804889842480000000488db424d8010000488d9424'
    '68010000488d4c24104c8d8424800000004c89ffff159637a00066c7038601e9'
    '85fdffff488d3da5ee9700ff151fb19f00488d3d98ee9700ff1512b19f00488d'
    '3d8bee9700ff1505b19f00488d3dc6ef9c00ff15f8b09f00488d3d89ee9700ff'
    '15ebb09f000f104424600f298424d00000000f104424500f298424c00000000f'
    '104424100f104c24200f105424300f105c24400f299c24b00000000f299424a0'
    '0000000f298c24900000000f29842480000000488d3d96229afb488d0d0f199d'
    '004c8d05d0129d00488d942480000000be2b000000ff154dac9f00e9d7000000'
    '0f104424600f298424d00000000f104424500f298424c00000000f104424100f'
    '104c24200f105424300f105c24400f299c24b00000000f299424a00000000f29'
    '8c24900000000f29842480000000488d3d1b229afb488d0d94189d004c8d056d'
    '129d00488d942480000000be2b000000ff15d2ab9f00eb5fbf01000000be1400'
    '0000ff1598ab9f00488d15b1119d004c89e7ff1530ab9f00488d3db9ed9700ff'
    '15abac9f0066c78424800000004101488d3dc38b81fb488d0d536a97004c8d05'
    '1c669700488d942480000000be2b000000ff1571ab9f000f0b4889c3be140000'
    '004c89ef31d2ff1524ab9f004889dfe81ccc8e004889c3488dbc2480000000e8'
    '8c5f60feeb2eff151cac9f004889c3488dbc2480000000e884bf0300eb16ff15'
    '04ac9f004889c3488dbc2480000000e86cbf03004889dfe8d4cb8e00ff15e6ab'
    '9f00'
)
BODY_SHA256 = '5db962cb2d963c221ac416abec4c08c59a11e1bcaf97a9067bb9a0e434af19aa'
BRANCHES = [
    (0x26, '0f83dc090000', 2, 6, 0x4d73488),
    (0x6f, '0f854a040000', 2, 6, 0x4d72f3f),
    (0xa6, '0f8318080000', 2, 6, 0x4d73344),
    (0xb2, '0f8319080000', 2, 6, 0x4d73351),
    (0xe0, '0f8232090000', 2, 6, 0x4d73498),
    (0x108, '0f852f040000', 2, 6, 0x4d72fbd),
    (0x116, '0f84d6040000', 2, 6, 0x4d73072),
    (0x15e, '0f85fa040000', 2, 6, 0x4d730de),
    (0x17f, '0f8359070000', 2, 6, 0x4d7335e),
    (0x1be, '0f8504050000', 2, 6, 0x4d73148),
    (0x1cc, '0f8453080000', 2, 6, 0x4d734a5),
    (0x232, '0f8767050000', 2, 6, 0x4d7321f),
    (0x279, '0f836c060000', 2, 6, 0x4d7336b),
    (0x2bb, '0f85fb040000', 2, 6, 0x4d7323c),
    (0x311, '0f83e1050000', 2, 6, 0x4d73378),
    (0x333, '750e', 1, 2, 0x4d72dc3),
    (0x346, '0f846e050000', 2, 6, 0x4d7333a),
    (0x3e6, '0f8519050000', 2, 6, 0x4d73385),
    (0x42b, '0f854f050000', 2, 6, 0x4d73400),
    (0x43f, '0f84b3050000', 2, 6, 0x4d73478),
    (0x497, '0f8587030000', 2, 6, 0x4d732a4),
    (0x4ba, 'e972030000', 1, 5, 0x4d732b1),
    (0x538, 'e90c010000', 1, 5, 0x4d730c9),
    (0x5f0, 'eb00', 1, 2, 0x4d73072),
    (0x6c3, 'e968feffff', 1, 5, 0x4d72fb0),
    (0x79a, 'e9aafeffff', 1, 5, 0x4d730c9),
    (0x7b7, 'e98dfeffff', 1, 5, 0x4d730c9),
    (0x81f, 'e925feffff', 1, 5, 0x4d730c9),
    (0x8bf, 'e985fdffff', 1, 5, 0x4d730c9),
    (0x97b, 'e9d7000000', 1, 5, 0x4d734d7),
    (0x9f6, 'eb5f', 1, 2, 0x4d734d7),
    (0xa84, 'eb2e', 1, 2, 0x4d73534),
    (0xa9c, 'eb16', 1, 2, 0x4d73534),
]
DIRECT_CALLS = [
    (0x4d72bb6, 0x4daf4a0),
    (0x4d72c73, 0x3379490),
    (0x4d72e9f, 0x46e8290),
    (0x4d72f35, 0x3987cb0),
    (0x4d73013, 0x4daf4a0),
    (0x4d731b0, 0x4daf4a0),
    (0x4d734ef, 0x5660110),
    (0x4d734ff, 0x3379490),
    (0x4d73517, 0x4daf4a0),
    (0x4d7352f, 0x4daf4a0),
    (0x4d73537, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4d72adc, 0x57731d8),
    (0x4d72b7b, 0x5773848),
    (0x4d72bcb, 0x57731d8),
    (0x4d72c26, 0x5773848),
    (0x4d72c9f, 0x5774660),
    (0x4d72d28, 0x5774cd0),
    (0x4d72dd5, 0x5773d80),
    (0x4d72deb, 0x5774cd8),
    (0x4d72e55, 0x57749e8),
    (0x4d72eb6, 0x576dfd8),
    (0x4d732b9, 0x5774ce0),
    (0x4d73334, 0x5776ad0),
    (0x4d7334b, 0x576e470),
    (0x4d73358, 0x576e470),
    (0x4d73365, 0x576e470),
    (0x4d73372, 0x576e470),
    (0x4d7337f, 0x576e470),
    (0x4d733f5, 0x576e048),
    (0x4d73470, 0x576e048),
    (0x4d73482, 0x576e020),
    (0x4d73492, 0x576dfc8),
    (0x4d7349f, 0x576e150),
    (0x4d734d1, 0x576e048),
    (0x4d734e6, 0x576e010),
    (0x4d73506, 0x576e128),
    (0x4d7351e, 0x576e128),
    (0x4d7353c, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4d73344, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d73351, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d7335e, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d7336b, 0x5742338, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 19, 47),
    (0x4d73378, 0x56f2208, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 119, 37),
    (0x4d73488, 0x5744640, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x4d73498, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x4ad8aa2, 0x4d6dddb, 0x4d6dfb3]
CALLER_FUNCTIONS = {'0x4ad8aa2': ('0x4ad81e0', '0x4ad8b0d'), '0x4d6dddb': ('0x4d6d570', '0x4d6e373'), '0x4d6dfb3': ('0x4d6d570', '0x4d6e373')}
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

