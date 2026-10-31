#!/usr/bin/env python3
"""Authenticated node94 node-20432b0 binding (0x20432b0).

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

START, END = 0x20432b0, 0x2043ad7
FDE_VA = 0x1077830
FDE = bytes.fromhex(
    '50000000089c0b0078bafc002708000004df1e94ff410e10420e18420e20420e'
    '28420e30410e38470ea00783078c068d058e048f038602030f070e38410e3042'
    '0e28420e20420e18420e10410e08410ea0070000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec680300004889fb4c8b26bf01000000e82f05ea'
    '024989c689d54c8b3b498b47384889442408418b47408944240480bb28020000'
    '004c89f80f858e000000c68328020000014c89b4242002000089ac2428020000'
    '488b44240848898424e00000008b442404898424e8000000488d7c2420488db4'
    '2420020000488d9424e0000000e8ee03ea02b800ca9a3b48f76424288b4c2430'
    '4801c84883d20031c948f7daba000000004819d24809c2807c242000480f45d1'
    '498b4730f048015058488b03488b4030f048ff4018488b0331c9488748104839'
    '8b200200007324498b4730f048ff40204889c8482b83200200000f827d060000'
    '498b5730f048014260eb094885c90f8415010000498b4730f048ff40284889c8'
    '48c1e80949bd535a9ba02fb8440049f7e548c1ea0b488b4424084801d00f80e8'
    '0500004869d200ca9a3b4829d1034c240481f900ca9a3b720f48ffc00f80c905'
    '000081c1003665c44c89b4242002000089ac242802000048898424e000000089'
    '8c24e8000000488d7c2420488db42420020000488d9424e0000000e8e002ea02'
    'b800ca9a3b48f76424288b4c24304801c84883d20031f648f7dab90000000048'
    '19c94809c1807c242000480f45ce4889c848c1e80949f7e548c1ea0b498b4730'
    '483b90a000000075214869d200ca9a3b4889ce4829d639b0a8000000760eba80'
    '000000be48000000eb0c72f2ba88000000be40000000f048ff0430f048010c10'
    '498b4730f0480148684c8b2bb90100000031c0f0490fb14d284883f802743748'
    '85c00f8592000000498b4d18498b04244885c9742f498b7c24084839c1752a49'
    '397d20752431c9b801000000f0490fb14d287544eb64498b0424498b7c2408ff'
    '5010eb56498b7c2408ff104989c44989d6498b45184885c07407498b7d20ff50'
    '184d8965184d89752031c9b801000000f0490fb14d287422498b4518498b7d20'
    '49c74518000000004885c00f849f04000031c949874d28ff5008488d6b08488b'
    '034883c010488d0dece0640348898c24d000000048898424d8000000488d8424'
    'd00000004889842400020000488984240802000048c784241002000000000000'
    'bf01000000e82602ea024989c40fb68318020000488d0d850638fe4863048148'
    '01c84c8964241889542414ffe0c6831902000001488db3a80000004889b42420'
    '020000488dbc24e0000000e8d0b2960083bc24e0000000020f8426040000488b'
    '84245001000048898424900000000f108424400100000f298424800000000f10'
    '8424300100000f294424700f108424200100000f294424600f108424e0000000'
    '0f108c24f00000000f109424000100000f109c24100100000f295c24500f2954'
    '24400f294c24300f2944242048c784249800000000000000c78424b000000000'
    'ca9a3b48c78424b800000000000000c78424c80000000001000066c78424cc00'
    '00000002c68319020000004c8db424e0000000baa00000004c89f74889eeff15'
    'eca87203488dbc24200200004c89f6e8fc171e000f284424200f284c24300f28'
    '5424400f285c24500f298424800100000f298c24900100000f299424a0010000'
    '0f299c24b00100000f284424600f298424c00100000f284424700f298424d001'
    '00000f288424800000000f298424e0010000488b84249000000048898424f001'
    '0000488dbc24c8020000488db424200200004c8b3557a87203baa000000041ff'
    'd6488b8424f0010000488983380100000f288424e00100000f1183280100000f'
    '288424d00100000f1183180100000f288424c00100000f1183080100000f2884'
    '24800100000f288c24900100000f289424a00100000f289c24b00100000f119b'
    'f80000000f1193e80000000f118bd80000000f1183c800000048c78340010000'
    '00000000c7835801000000ca9a3b48c7836001000000000000c7837001000000'
    '01000066c783740100000002488dbb76010000488db424c6020000baa2000000'
    '41ffd64c8dabc8000000488db424000200004c89efe8c60128004989c4b00341'
    'f6c40175164989d64c89efe8c050f6ffb0014d85f60f85690100008883180200'
    '00bf01000000e865ffe9024989c64189d5488984242002000089942428020000'
    '488b44240848898424e00000008b442404898424e8000000488d7c2420488db4'
    '2420020000488d9424e0000000e84efee902b800ca9a3b48f76424288b4c2430'
    '4801c84883d20031ed48f7dab9000000004819c94809c1807c242000480f45cd'
    '48898b200200004c89b424200200004489ac2428020000488b44241848898424'
    'e00000008b442414898424e8000000488d7c2420488db42420020000488d9424'
    'e0000000e8d7fde902807c242000b80000000075098b6c2430488b442428498b'
    '4f30483b819000000075143ba998000000730ebe70000000bf30000000eb0c72'
    'f2be78000000bf38000000ba00ca9a3b48f7e24189e84901c04883d20031c048'
    'f7da4819c0f048ff04394c09c0f0480104314180e4014489e04881c468030000'
    '5b415c415d415e415f5dc3488d3d78aa78fe488d1537f77003be28000000ff15'
    '74aa72034c89742420488d3d180938fe488d0de9ef64034c8d0502f36403488d'
    '542420be2b000000ff152aa67203eb49488d3dd1706303ff1543aa7203488d3d'
    'd4dc6403ff1516a77203488d3db7f26403ff15f1b57203488d3daaf26403ff15'
    'ecb57203488bb424e8000000488dbc2420020000e867dc96000f0b4d8965184d'
    '8975204889c7e895c66103eb1c4989c7488d7c2420e87693f8ffeb1f4989c74c'
    '89efe8a94ef6ffeb124989c7eb0d4989c7488d7c2420e8c5e7f6ff80bb190200'
    '000074084889efe854fcf6ffc68318020000024c89ffe845c66103ff1557a672'
    '03ff1551a67203'
)
BODY_SHA256 = '4f5e7d05c3180741e1ced8c4e02a92185610695fee9365d69a76054379ecb072'
BRANCHES = [
    (0x44, '0f858e000000', 2, 6, 0x2043388),
    (0xe5, '7324', 1, 2, 0x20433bb),
    (0xfa, '0f827d060000', 2, 6, 0x2043a2d),
    (0x109, 'eb09', 1, 2, 0x20433c4),
    (0x10e, '0f8415010000', 2, 6, 0x20434d9),
    (0x13d, '0f80e8050000', 2, 6, 0x20439db),
    (0x157, '720f', 1, 2, 0x2043418),
    (0x15c, '0f80c9050000', 2, 6, 0x20439db),
    (0x1e7, '7521', 1, 2, 0x20434ba),
    (0x1fc, '760e', 1, 2, 0x20434bc),
    (0x208, 'eb0c', 1, 2, 0x20434c6),
    (0x20a, '72f2', 1, 2, 0x20434ae),
    (0x23d, '7437', 1, 2, 0x2043526),
    (0x242, '0f8592000000', 2, 6, 0x204358a),
    (0x253, '742f', 1, 2, 0x2043534),
    (0x25d, '752a', 1, 2, 0x2043539),
    (0x263, '7524', 1, 2, 0x2043539),
    (0x272, '7544', 1, 2, 0x2043568),
    (0x274, 'eb64', 1, 2, 0x204358a),
    (0x282, 'eb56', 1, 2, 0x204358a),
    (0x298, '7407', 1, 2, 0x2043551),
    (0x2b6, '7422', 1, 2, 0x204358a),
    (0x2cb, '0f849f040000', 2, 6, 0x2043a20),
    (0x34b, 'ffe0', 1, 2, 0x20435dd),
    (0x378, '0f8426040000', 2, 6, 0x2043a54),
    (0x5c3, '7516', 1, 2, 0x204388b),
    (0x5d5, '0f8569010000', 2, 6, 0x20439f4),
    (0x6b3, '7509', 1, 2, 0x204396e),
    (0x6c9, '7514', 1, 2, 0x204398f),
    (0x6d1, '730e', 1, 2, 0x2043991),
    (0x6dd, 'eb0c', 1, 2, 0x204399b),
    (0x6df, '72f2', 1, 2, 0x2043983),
    (0x76e, 'eb49', 1, 2, 0x2043a69),
    (0x7cb, 'eb1c', 1, 2, 0x2043a99),
    (0x7da, 'eb1f', 1, 2, 0x2043aab),
    (0x7e7, 'eb12', 1, 2, 0x2043aab),
    (0x7ec, 'eb0d', 1, 2, 0x2043aab),
    (0x802, '7408', 1, 2, 0x2043abc),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x20432cc, 0x4ee3800),
    (0x204333d, 0x4ee3730),
    (0x204344b, 0x4ee3730),
    (0x20435d5, 0x4ee3800),
    (0x204361b, 0x29ae8f0),
    (0x20436ff, 0x2224f00),
    (0x2043865, 0x22c3a30),
    (0x204387b, 0x1fa8940),
    (0x2043896, 0x4ee3800),
    (0x20438dd, 0x4ee3730),
    (0x2043954, 0x4ee3730),
    (0x2043a64, 0x29b16d0),
    (0x2043a76, 0x5660110),
    (0x2043a85, 0x1fcce00),
    (0x2043a92, 0x1fa8940),
    (0x2043aa6, 0x1fb2270),
    (0x2043ab7, 0x1fb3710),
    (0x2043ac6, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x20436ee, 0x576dfe0),
    (0x20439ee, 0x576e468),
    (0x2043a18, 0x576e048),
    (0x2043a27, 0x576e470),
    (0x2043a34, 0x576e150),
    (0x2043a41, 0x576f038),
    (0x2043a4e, 0x576f040),
    (0x2043acb, 0x576e128),
    (0x2043ad1, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x20439e2, 0x5753120, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f7374642f7372632f74696d652e7273'), 429, 33),
    (0x2043a20, 0x567aaf8, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f667574757265732d636f72652d302e332e33312f7372632f7461736b2f5f5f696e7465726e616c2f61746f6d69635f77616b65722e7273'), 311, 68),
    (0x2043a2d, 0x5691708, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f746f6b696f2d6d6574726963732d302e332e312f7372632f7461736b2e7273'), 2483, 23),
]
CALLERS = [0x2014d04]
CALLER_FUNCTIONS = {'0x2014d04': ('0x2014c70', '0x2014df6')}
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

