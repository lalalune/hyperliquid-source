#!/usr/bin/env python3
"""Authenticated node94 duration-26dc780 binding (0x26dc780).

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

START, END = 0x26dc780, 0x26dd18e
FDE_VA = 0x10ec5d4
FDE = bytes.fromhex(
    '50000000ace91200a4015f010e0a00000437fa92ff410e10420e18420e20420e'
    '28420e30410e38470e900883078c068d058e048f038602036f090e38410e3042'
    '0e28420e20420e18420e10410e08410e90080000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecd80300004c8984249000000048894c24604889'
    '5424684889742418488d471848894424384c8b6f184d85ed48897c24200f84c9'
    '000000488b472048894424304c8b35b51c0903410fb785ee0100004889442428'
    '8d048500000000488d2c8048f7dd41bf1000000049c7c4ffffffffbb10010000'
    '488d042b483d1001000074444a8d342bba14000000488b7c241841ffd6489848'
    '85c00f98c10f9fc028c84983c7e849ffc44883c3143c0174c70fb6c085c07432'
    'eb1366666666662e0f1f8400000000004c8b642428488b4424304883e801722f'
    '48894424304f8bace5f0010000e961ffffff4d29fd498b5d004885db4c8b7c24'
    '680f85d1000000e96d0800004531ed488b542418488b02488b4a088b52108954'
    '244848894c2440488b4c243848898c24600100004c89ac246801000048c78424'
    '70010000000000004c89a424780100004889842480010000488b442440488984'
    '24880100008b442448898424900100008b44244c8984249401000048c7442470'
    '0000000048c784248000000000000000488dbc24a0000000488db42460010000'
    '488d542470e8c6e61900488b8424a0000000488b8c24b0000000488d0c494c8d'
    '2cc84983c508498b5d004885db4c8b7c24680f84a1070000498b45080fb79382'
    '04000089d1c1e105488d344948c7c1ffffffff4531ed662e0f1f840000000000'
    '4c39ee742b4c3bbccb30040000400f97c74080df004983c56048ffc14080ff01'
    '74de400fb6d785d2741deb070f1f40004889d14883e8010f823c070000488b9c'
    'cb88040000eb954e8b642ba0428b442be8894424784a8b4c2be048894c247089'
    '8424a800000048898c24a0000000488db424a4000000488dbc2460010000ba1e'
    '00000031c9ff159d1e0903488b84246801000048b9000000004057ffff4801c1'
    '48ba81aefeff7faefeff4839d10f82d8060000448bb424600100008bac246401'
    '00008bbc24a000000048b9572951cea0c8451848f7e94889d648c1ee3f48c1ea'
    '0d01d6ff15471e090385c00f849a06000089442408448974240c896c2410488b'
    '4c2460488d516048895424583b41600f9cc07513443b71640f92c0750a3b6968'
    '720de9da00000084c00f84d2000000488b4c24588b4108898424a8000000488b'
    '0148898424a00000008b44241089842468010000488b44240848898424600100'
    '0048b801000000540000004889842470010000488d056bccedfd488984247801'
    '000048c78424800100002b000000488dbc24a0000000488db42460010000ff15'
    '9c1d0903660f57c9660f2ec10f8232050000f20f5e0566d6b2fdff15887c0903'
    '660f57c9660f2ec10f822f050000f20f59054ad6b2fd488dbc2460010000488d'
    '742408ff154f2409038b84246801000089442410488b84246001000048894424'
    '084a8d042b4883c0e08b4c2410894808488b4c24084889084a8b4c2bd848ffc1'
    '48c7c0ffffffff480f45c14a8b4c2bc84a89442bd84a3b4c2ba80f83c8000000'
    'f2420f104c2bb0660f57c0660f2ec80f828f040000f20f5e0d1be0b2fd66480f'
    '7ec948baffffffffffffff7f4821ca48b9ffffffffffffef7f4839ca7f2a660f'
    '57d2660f2ed17710660f2e0d00d9b2fd7706660f28c1eb10f20f5fd1f20f1005'
    'ecd8b2fdf20f5dc2f2480f2cc84889ca48c1fa3f660f28c8f20f5c0db0dbb2fd'
    'f2480f2cf14821d64809ce31c9660f57c9660f2ec1480f43ce660f2e05b7d5b2'
    'fd48c7c2ffffffff480f47ca4885c90f88210400004801c948ffc1480f44ca48'
    '39c80f86250400004c89a42488000000488b4c24188b4110894424500f10010f'
    '294424404c89bc2498000000488b442438488b084885c90f84dc000000488b44'
    '2420488b40204889442428488d6c24404c8b35b1170903488db1100100000fb7'
    '81ee01000048894c2430488d59f048894424208d0485000000004c8d3c8049c7'
    'c4ffffffff66662e0f1f8400000000004d85ff743b4c8d6e14ba140000004889'
    'ef41ffd648984885c00f98c10f9fc028c84883c31849ffc44983c7ec4c89ee3c'
    '0174cd0fb6c085c0742deb090f1f40004c8b642420488b4424284883e801488b'
    '4c2430723448894424284a8b8ce1f0010000e960ffffff488dbc246001000048'
    '8d9424980000004889dee841ae180080bc248201000002751c66c78424600100'
    '00ce00488dbc2460010000e8f01d0a00e9440300000fb7ac24600100000f1084'
    '24620100000f298424000100000f108424720100000f298424100100000f1084'
    '24820100000f298424200100000f108424920100000f298424300100000f1084'
    '24a20100000f298424400100000f108424b00100000f1184244e01000048837b'
    '10004c8bb424900000004c8b7c24684c8ba424880000000f85c6000000488dbc'
    '24a0000000488d542440488b742438e8cca918004883bc24a0000000000f84a0'
    '000000488b8c24a80000004885c9744f488b9424b0000000488b8424b8000000'
    '48c78424680100000000000048898c2470010000488994247801000048c78424'
    '880100000000000048898c24900100004889942498010000b901000000eb0431'
    'c931c048898c246001000048898c248001000048898424a0010000488d5c2470'
    '4c8dac24600100000f1f8400000000004889df4c89eee84512190048837c2470'
    '0075ed6689ac24a00000000f288424000100000f288c24100100000f28942420'
    '0100000f289c24300100000f118424a20000000f118c24b20000000f119424c2'
    '0000000f119c24d20000000f288424400100000f118424e20000000f1084244e'
    '0100000f118424f000000048b94b598638d6c56d344c89e048f7e148c1ea0b48'
    '8b442460483b90c80500000f83930100004869daf0020000480398c005000066'
    'c78424600100004101488dbc2460010000e8dac4c900488dbc2468010000488d'
    'b424a00000004889dae8e248c3ff488b4c24188b4110898424fc0100000f1001'
    '0f118424ec01000048b8020000000000008048898424c00100004c89bc24d801'
    '0000488b4c2458488b0148898424e00100008b4108898424e801000048c78424'
    '6001000004000000498b5e10493b1e75094c89f7ff151e6d09034869fb780200'
    '0049037e08488db42460010000ba78020000ff15880f090348ffc349895e10e9'
    '95000000488d3deeceb3fd488d1586ddf802be1e000000ff158b100903488d3d'
    'edccb3fd488d15cddaf802be1c000000ff157210090348c7c1ffffffff48ffc1'
    '480f44ca4839c80f87dbfbffff8b44241089842470010000488b442408488984'
    '2468010000488b4424180f10000f118424740100008b4010898424840100004c'
    '89bc2460010000488db42460010000488b7c2420e8e72e0c004881c4d8030000'
    '5b415c415d415e415f5dc3488d3d0dcfb3fd488d15ffddf802be26000000ff15'
    '4413090366c78424600100004101488d3d44efeafd488d0dd4cd00034c8d059d'
    'c90003488d942460010000be2b000000ff15f20e09030f0b4889c3488dbc2460'
    '010000e828cd0900eb16ff15b80f09034889c3488dbc2460010000e810c3c900'
    '4889dfe8882ff802ff159a0f0903'
)
BODY_SHA256 = 'a5d4f516d2f200d81a7791078867fd3233ee6ce59b11544a53b7fbc7fca542ba'
BRANCHES = [
    (0x3d, '0f84c9000000', 2, 6, 0x26dc88c),
    (0x8a, '7444', 1, 2, 0x26dc850),
    (0xb7, '74c7', 1, 2, 0x26dc800),
    (0xbe, '7432', 1, 2, 0x26dc872),
    (0xc0, 'eb13', 1, 2, 0x26dc855),
    (0xde, '722f', 1, 2, 0x26dc88f),
    (0xed, 'e961ffffff', 1, 5, 0x26dc7d3),
    (0x101, '0f85d1000000', 2, 6, 0x26dc958),
    (0x107, 'e96d080000', 1, 5, 0x26dd0f9),
    (0x1d2, '0f84a1070000', 2, 6, 0x26dd0f9),
    (0x203, '742b', 1, 2, 0x26dc9b0),
    (0x220, '74de', 1, 2, 0x26dc980),
    (0x228, '741d', 1, 2, 0x26dc9c7),
    (0x22a, 'eb07', 1, 2, 0x26dc9b3),
    (0x237, '0f823c070000', 2, 6, 0x26dd0f9),
    (0x245, 'eb95', 1, 2, 0x26dc95c),
    (0x2ad, '0f82d8060000', 2, 6, 0x26dd10b),
    (0x2eb, '0f849a060000', 2, 6, 0x26dd10b),
    (0x312, '7513', 1, 2, 0x26dcaa7),
    (0x31b, '750a', 1, 2, 0x26dcaa7),
    (0x320, '720d', 1, 2, 0x26dcaaf),
    (0x322, 'e9da000000', 1, 5, 0x26dcb81),
    (0x329, '0f84d2000000', 2, 6, 0x26dcb81),
    (0x3ac, '0f8232050000', 2, 6, 0x26dd064),
    (0x3c8, '0f822f050000', 2, 6, 0x26dd07d),
    (0x43a, '0f83c8000000', 2, 6, 0x26dcc88),
    (0x44f, '0f828f040000', 2, 6, 0x26dd064),
    (0x47c, '7f2a', 1, 2, 0x26dcc28),
    (0x486, '7710', 1, 2, 0x26dcc18),
    (0x490, '7706', 1, 2, 0x26dcc18),
    (0x496, 'eb10', 1, 2, 0x26dcc28),
    (0x4ef, '0f8821040000', 2, 6, 0x26dd096),
    (0x502, '0f8625040000', 2, 6, 0x26dd0ad),
    (0x537, '0f84dc000000', 2, 6, 0x26dcd99),
    (0x593, '743b', 1, 2, 0x26dcd50),
    (0x5c1, '74cd', 1, 2, 0x26dcd10),
    (0x5c8, '742d', 1, 2, 0x26dcd77),
    (0x5ca, 'eb09', 1, 2, 0x26dcd55),
    (0x5e3, '7234', 1, 2, 0x26dcd99),
    (0x5f2, 'e960ffffff', 1, 5, 0x26dccd7),
    (0x617, '751c', 1, 2, 0x26dcdb5),
    (0x630, 'e944030000', 1, 5, 0x26dd0f9),
    (0x6b7, '0f85c6000000', 2, 6, 0x26dcf03),
    (0x6dd, '0f84a0000000', 2, 6, 0x26dcf03),
    (0x6ee, '744f', 1, 2, 0x26dcebf),
    (0x73d, 'eb04', 1, 2, 0x26dcec3),
    (0x781, '75ed', 1, 2, 0x26dcef0),
    (0x80b, '0f8393010000', 2, 6, 0x26dd124),
    (0x8af, '7509', 1, 2, 0x26dd03a),
    (0x8df, 'e995000000', 1, 5, 0x26dd0f9),
    (0x927, '0f87dbfbffff', 2, 6, 0x26dcc88),
    (0x9e8, 'eb16', 1, 2, 0x26dd180),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x26dc925, 0x287aff0),
    (0x26dcd8a, 0x2867bd0),
    (0x26dcdab, 0x277eba0),
    (0x26dce4f, 0x2867820),
    (0x26dcef6, 0x286e140),
    (0x26dcfb1, 0x3379490),
    (0x26dcfc9, 0x23118b0),
    (0x26dd0f4, 0x279ffe0),
    (0x26dd163, 0x2779e90),
    (0x26dd17b, 0x3379490),
    (0x26dd183, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x26dca05, 0x576e8a8),
    (0x26dca63, 0x576e8b0),
    (0x26dcb1e, 0x576e8c0),
    (0x26dcb3a, 0x57747c8),
    (0x26dcb63, 0x576efb8),
    (0x26dd034, 0x5773d58),
    (0x26dd052, 0x576dfe0),
    (0x26dd077, 0x576e108),
    (0x26dd090, 0x576e108),
    (0x26dd11e, 0x576e468),
    (0x26dd150, 0x576e048),
    (0x26dd16a, 0x576e128),
    (0x26dd188, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x26dd06b, 0x566adf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6475726174696f6e2e7273'), 89, 13),
    (0x26dd084, 0x566ab58, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6475726174696f6e2e7273'), 112, 13),
    (0x26dd112, 0x566af18, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f6461746574696d652f6d6f642e7273'), 1631, 38),
]
CALLERS = [0x26fa6b9, 0x27763ab]
CALLER_FUNCTIONS = {'0x26fa6b9': ('0x26f9b70', '0x26fb746'), '0x27763ab': ('0x27758c0', '0x277643c')}
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

