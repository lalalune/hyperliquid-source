#!/usr/bin/env python3
"""Authenticated node94 ema-tracker-48797c0 binding (0x48797c0).

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

START, END = 0x48797c0, 0x4879e20
FDE_VA = 0x12a04c4
FDE = bytes.fromhex(
    '500000009c282e00f4925d036006000004db288eff410e10420e18420e20420e'
    '28420e30410e38470ed00183078c068d058e048f03860203b8050e38410e3042'
    '0e28420e20420e18420e10410e08410ed0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec980000004889f348897c24384889f7e86fb801'
    '004885c00f84cf0000004989c648895c2410488b4348488b184885db0f849e00'
    '0000488b400848890424488db3800400000fb7835e0500004c8d6bb848894424'
    '188d048500000000488d2c8049c7c7ffffffff666666662e0f1f840000000000'
    '4885ed743b4c8d6614ba140000004c89f7ff15314cef0048984885c00f98c10f'
    '9fc028c84983c56849ffc74883c5ec4c89e63c0174ca0fb6c085c07508eb5b90'
    '4c8b7c2418488b04244883e8017211488904244a8b9cfb60050000e96affffff'
    '488b5c24104889dfe8a3b701004989c64885c00f8539ffffff488b44243848c7'
    '000000000048c740080800000048c7401000000000e9a8040000f2410f104500'
    '660f57c9660f2ec14c8b7c241075027b14660f2ec10f86c3040000f2410f104d'
    'f8f20f5ec8f20f110c24418b461089442470410f10060f29442460bf80000000'
    'ff15b246ef004885c00f84b7040000488b4c2470488948100f284424600f1100'
    'f20f100424f20f11401848c7442420040000004889442440488944242848c744'
    '2430010000004d8b77404d85f60f84f0030000498b0f498b5f08498b47104d8b'
    '6718498b5748488954244841bf01000000eb55666666662e0f1f840000000000'
    '4c89f848c1e005488b8c2490000000488b54244048894c02100f288424800000'
    '000f110402f20f100424f20f1144021849ffc74c897c2430b101b8000000004d'
    '85f60f847b0300004c897c2458f6c1010f84e10300004885db74250fb78be600'
    '00004939cc0f83c50000004889d94c89e2e9dc000000662e0f1f840000000000'
    '4d85e474384c89e14889c34883e107743131d2666666662e0f1f840000000000'
    '488b9be800000048ffc24839d175f14c89e04829d04983fc087315eb514889c3'
    'eb4c4c89e04983fc0872430f1f440000488b8be8000000488b89e8000000488b'
    '89e8000000488b89e8000000488b89e8000000488b89e8000000488b89e80000'
    '00488b99e80000004883c0f875c24531e431c00fb78be60000004939cc0f8248'
    'ffffff666666662e0f1f840000000000488b0b4885c90f84d302000048ffc00f'
    'b793e40000004889cb663b91e600000073de4885c00f8495000000488d34d148'
    '81c6f00000004889c74883e7070f849d0100004531c0662e0f1f840000000000'
    '488b1e488db3e800000049ffc04c39c775ee4889c74c29c74883f80872436690'
    '488b06488b80e8000000488b80e8000000488b80e8000000488b80e800000048'
    '8b80e8000000488b80e8000000488b98e8000000488db3e80000004883c7f875'
    'bf48c744240800000000eb100f1f4000488d420148894424084889cb49ffce4c'
    '89742450488b442448488b384885ff0f84db000000488d04924c8d2c814983c5'
    '08488b442448488b40084889442418488db7800400000fb7875e05000048893c'
    '244c8d7fb848894424108d0485000000004c8d348048c7c5ffffffff0f1f4000'
    '4d85f6745b4c8d6614ba140000004c89efff157148ef0048984885c00f98c10f'
    '9fc028c84983c76848ffc54983c6ec4c89e63c0174ca0fb6c085c00f848f0000'
    '00488b4424184883e801488b3c247324eb3e66666666662e0f1f840000000000'
    '488b6c2410488b4424184883e801488b3c24721c4889442418488bbcef600500'
    '00e949ffffff662e0f1f840000000000b101b8000000004c8b7424504d85f64c'
    '8b6424080f8543fdffffe9b4000000904889c74883f8080f82c4feffffe97efe'
    'ffff66666666662e0f1f840000000000f2410f1007660f57d2660f57c9f20f11'
    '0c24660f2ec275027b19660f2ec10f86a0000000f2410f104ff8f20f5ec8f20f'
    '110c2466410f104500418b451089842490000000660f298424800000004c8b7c'
    '24584c3b7c24204c8b7424504c8b6424080f8569fcffffba01000000b9080000'
    '0041b820000000488d7c24204c89fee87c58cdff488b4424284889442440e93d'
    'fcffff488b4c2430488b44243848894810488b4c2420488908488b4c24284889'
    '48084881c4980000005b415c415d415e415f5dc3488d3da80a9afb488d151e28'
    'df00be21000000ff155b43ef00eb35488d3d9aa1eb00ff15b446ef00eb26488d'
    '3d7e0a9afb488d15f427df00be21000000ff153143ef00488d3da291eb00ff15'
    '8c46ef000f0bbf08000000be80000000ff15c241ef00eb020f0b4889c3488b74'
    '24204885f67411488b7c242848c1e60531d2ff15f841ef004889dfe8f062de00'
)
BODY_SHA256 = '83f195238f845cbbeb527e2c3a3d034ad76c311ac7709e2fe47bffe569ab88ef'
BRANCHES = [
    (0x24, '0f84cf000000', 2, 6, 0x48798b9),
    (0x3c, '0f849e000000', 2, 6, 0x48798a0),
    (0x83, '743b', 1, 2, 0x4879880),
    (0xb4, '74ca', 1, 2, 0x4879840),
    (0xbb, '7508', 1, 2, 0x4879885),
    (0xbd, 'eb5b', 1, 2, 0x48798da),
    (0xcd, '7211', 1, 2, 0x48798a0),
    (0xdb, 'e96affffff', 1, 5, 0x487980a),
    (0xf3, '0f8539ffffff', 2, 6, 0x48797f2),
    (0x115, 'e9a8040000', 1, 5, 0x4879d82),
    (0x12d, '7502', 1, 2, 0x48798f1),
    (0x12f, '7b14', 1, 2, 0x4879905),
    (0x135, '0f86c3040000', 2, 6, 0x4879dbe),
    (0x169, '0f84b7040000', 2, 6, 0x4879de6),
    (0x1ad, '0f84f0030000', 2, 6, 0x4879d63),
    (0x1d1, 'eb55', 1, 2, 0x48799e8),
    (0x222, '0f847b030000', 2, 6, 0x4879d63),
    (0x230, '0f84e1030000', 2, 6, 0x4879dd7),
    (0x239, '7425', 1, 2, 0x4879a20),
    (0x245, '0f83c5000000', 2, 6, 0x4879ad0),
    (0x251, 'e9dc000000', 1, 5, 0x4879af2),
    (0x263, '7438', 1, 2, 0x4879a5d),
    (0x26f, '7431', 1, 2, 0x4879a62),
    (0x28d, '75f1', 1, 2, 0x4879a40),
    (0x299, '7315', 1, 2, 0x4879a70),
    (0x29b, 'eb51', 1, 2, 0x4879aae),
    (0x2a0, 'eb4c', 1, 2, 0x4879aae),
    (0x2a9, '7243', 1, 2, 0x4879aae),
    (0x2ec, '75c2', 1, 2, 0x4879a70),
    (0x2fd, '0f8248ffffff', 2, 6, 0x4879a0b),
    (0x316, '0f84d3020000', 2, 6, 0x4879daf),
    (0x330, '73de', 1, 2, 0x4879ad0),
    (0x335, '0f8495000000', 2, 6, 0x4879b90),
    (0x34d, '0f849d010000', 2, 6, 0x4879cb0),
    (0x370, '75ee', 1, 2, 0x4879b20),
    (0x37c, '7243', 1, 2, 0x4879b81),
    (0x3bf, '75bf', 1, 2, 0x4879b40),
    (0x3ca, 'eb10', 1, 2, 0x4879b9c),
    (0x3ef, '0f84db000000', 2, 6, 0x4879c90),
    (0x443, '745b', 1, 2, 0x4879c60),
    (0x474, '74ca', 1, 2, 0x4879c00),
    (0x47b, '0f848f000000', 2, 6, 0x4879cd0),
    (0x48e, '7324', 1, 2, 0x4879c74),
    (0x490, 'eb3e', 1, 2, 0x4879c90),
    (0x4b2, '721c', 1, 2, 0x4879c90),
    (0x4c1, 'e949ffffff', 1, 5, 0x4879bcf),
    (0x4e4, '0f8543fdffff', 2, 6, 0x48799ed),
    (0x4ea, 'e9b4000000', 1, 5, 0x4879d63),
    (0x4f7, '0f82c4feffff', 2, 6, 0x4879b81),
    (0x4fd, 'e97efeffff', 1, 5, 0x4879b40),
    (0x526, '7502', 1, 2, 0x4879cea),
    (0x528, '7b19', 1, 2, 0x4879d03),
    (0x52e, '0f86a0000000', 2, 6, 0x4879d94),
    (0x571, '0f8569fcffff', 2, 6, 0x48799a0),
    (0x59e, 'e93dfcffff', 1, 5, 0x48799a0),
    (0x5ed, 'eb35', 1, 2, 0x4879de4),
    (0x5fc, 'eb26', 1, 2, 0x4879de4),
    (0x636, 'eb02', 1, 2, 0x4879dfa),
    (0x645, '7411', 1, 2, 0x4879e18),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x48797dc, 0x4895050),
    (0x48798a8, 0x4895050),
    (0x4879d4f, 0x454f5d0),
    (0x4879e1b, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4879851, 0x576e488),
    (0x4879920, 0x576dfd8),
    (0x4879c11, 0x576e488),
    (0x4879da7, 0x576e108),
    (0x4879db6, 0x576e470),
    (0x4879dd1, 0x576e108),
    (0x4879dde, 0x576e470),
    (0x4879df0, 0x576dfb8),
    (0x4879e12, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4879d9b, 0x566c5c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f656d615f747261636b65722e7273'), 59, 13),
    (0x4879daf, 0x5733f50, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x4879dc5, 0x566c5c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f656d615f747261636b65722e7273'), 59, 13),
    (0x4879dd7, 0x5732f80, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
]
CALLERS = [0x489c6a7]
CALLER_FUNCTIONS = {'0x489c6a7': ('0x489c660', '0x489c800')}
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

