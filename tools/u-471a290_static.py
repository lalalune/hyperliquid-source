#!/usr/bin/env python3
"""Authenticated node94 u-471a290 binding (0x471a290).

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

START, END = 0x471a290, 0x471a8cf
FDE_VA = 0x12817fc
FDE = bytes.fromhex(
    '50000000d43b2c008c8a49033f06000004abb98eff410e10420e18420e20420e'
    '28420e30410e38470ee00183078c068d058e048f0386020347020e38410e3042'
    '0e28420e20420e18420e10410e08410ee0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881eca80000004889fb85d20f848f0000004c8b3e4c'
    '8b6e084c8b6610c644240d00c644240e00488d1598450101488d7c240d488d74'
    '240ee86970c6ff4885c00f8599020000807c240d000f842e0100000fb66c240e'
    '48c7c1d8eeffff644c8b3425000000004901ce640fb6414883f8010f84c60200'
    '0083f8020f85a102000040886c240a4c8d64240bc644240b00488d3db8440101'
    'ff15e2450501e9de040000488b064c8b7608488b4e10488b0948898424900000'
    '004c89b4249800000048c78424800000000100000048898c248800000048c784'
    '24a000000000000000488d7c2410488db42480000000e85513c7ff0f10442418'
    '0f29442460488b4424284889442470488b442430807c2410000f85d200000048'
    '8b4c247048894c24500f284424600f2944244048894424584c2bb42498000000'
    '0f8209040000488b442440488b4c244848894c2410488b4c245048894c241848'
    '8b4c245848894c24204883f8040f85a5000000b901000000ba20000000bf0800'
    '000031f6e9a4000000498b04244c89bc24900000004c89ac249800000048c784'
    '248000000001000000488984248800000048c78424a000000000000000488d7c'
    '2410488db42480000000e88112c7ff8b4c24100f104424180f29442460488b44'
    '24284889442470488b44243083f9017572488b4c247048894c24200f28442460'
    '0f29442410b901000000ba20000000bf0800000031f6eb1848894308be010000'
    '00ba30000000bf1000000031c94c89f04c8b4424204c89443b100f284424100f'
    '11043b4889041348890b488973284889d84881c4a80000005b415c415d415e41'
    '5f5dc3488b4c247048894c24500f284424600f2944244048894424584c2bac24'
    '980000000f82d4020000488b442440488b4c244848894c2410488b4c24504889'
    '4c2418488b4c245848894c24204883f8047519b901000000ba20000000bf0800'
    '000031f64c89e8e964ffffff48894308be01000000ba30000000bf1000000031'
    'c94c89e8e947ffffff48898424800000004889942488000000488d8424800000'
    '004889442410488d05d3f554004889442418488d3da4feacfb488d15b0420101'
    '488d742410ff15dd3a0501488d356ec585004c89f7ff15154c050148c7c1d8ee'
    'ffff64c6414801640fb7414464c641440040886c240a668944240b640fb66946'
    '4080fd020f84b001000064c641460240886c240f498b04244c89bc2490000000'
    '4c89ac249800000048c784248000000001000000488984248800000048c78424'
    'a000000000000000488d7c2410488db42480000000e89610c7ff8b4c24100f10'
    '4424180f29442460488b4424284889442470488b44243083f9017527488b4c24'
    '7048894c24200f284424600f29442410b901000000ba20000000bf0800000031'
    'f6eb7b488b4c247048894c24500f284424600f2944244048894424584c2bac24'
    '980000000f8252010000488b442440488b4c244848894c2410488b4c24504889'
    '4c2418488b4c245848894c24204883f8047513b901000000ba20000000bf0800'
    '000031f6eb1548894308be01000000ba30000000bf1000000031c94c89e84c8b'
    '4424204c89443b100f284424100f11043b4889041348890b4889732831ff4c8d'
    '64240be8d87d85004885c00f84bc00000080784602757d4088684648c7c1d8ee'
    'ffff640fb6414883f801742a83f8020f8479fdffff488d35c4c385004c89f7ff'
    '156b4a050148c7c1d8eeffff64c64148014c8d64240b64807946020f844dfdff'
    'ff4983c628488d74240a4c89f74c89e2e8eb568500e934fdffff488d152f4f01'
    '01be3d000000488d3d6417fefb4c8d64240beb13488d151daf0301be45000000'
    '488d3d5a690bfcff15bb380501eb3a488d3d2a380201ff1564390501eb2b488d'
    '3d1b380201ff1555390501eb1c488d3d64ac0301ff150e410501eb0d488d3dfd'
    '370201ff15373905010f0b4889c3488d7c2440e8c81d4000eb09ff15f8380501'
    '4889c3488d7c240fff152aa805014c8d64240beb33ff15dd3805014889c3488d'
    '7c2440e8981d4000eb67ff15c83805014889c3488d7c2440e8831d4000eb52ff'
    '15b33805014889c349c7c7d8eeffff64410fb6474883f801741b83f802743248'
    '8d359ac285004c89f7ff15414905016441c64748016441807f460274144983c6'
    '28488d74240a4c89f74c89e2e8cf5585004889dfe84758f400ff1559380501'
)
BODY_SHA256 = 'b1858bb27b652fed37670f273076962d886b48ae6b24746bf2a5be1397aa5a06'
BRANCHES = [
    (0x16, '0f848f000000', 2, 6, 0x471a33b),
    (0x4a, '0f8599020000', 2, 6, 0x471a579),
    (0x55, '0f842e010000', 2, 6, 0x471a419),
    (0x7b, '0f84c6020000', 2, 6, 0x471a5d7),
    (0x84, '0f85a1020000', 2, 6, 0x471a5bb),
    (0xa6, 'e9de040000', 1, 5, 0x471a819),
    (0x119, '0f85d2000000', 2, 6, 0x471a481),
    (0x140, '0f8209040000', 2, 6, 0x471a7df),
    (0x16d, '0f85a5000000', 2, 6, 0x471a4a8),
    (0x184, 'e9a4000000', 1, 5, 0x471a4bd),
    (0x1ef, '7572', 1, 2, 0x471a4f3),
    (0x216, 'eb18', 1, 2, 0x471a4c0),
    (0x284, '0f82d4020000', 2, 6, 0x471a7ee),
    (0x2b1, '7519', 1, 2, 0x471a55c),
    (0x2c7, 'e964ffffff', 1, 5, 0x471a4c0),
    (0x2e4, 'e947ffffff', 1, 5, 0x471a4c0),
    (0x364, '0f84b0010000', 2, 6, 0x471a7aa),
    (0x3da, '7527', 1, 2, 0x471a693),
    (0x401, 'eb7b', 1, 2, 0x471a70e),
    (0x424, '0f8252010000', 2, 6, 0x471a80c),
    (0x451, '7513', 1, 2, 0x471a6f6),
    (0x464, 'eb15', 1, 2, 0x471a70b),
    (0x4ab, '0f84bc000000', 2, 6, 0x471a7fd),
    (0x4b5, '757d', 1, 2, 0x471a7c4),
    (0x4ca, '742a', 1, 2, 0x471a786),
    (0x4cf, '0f8479fdffff', 2, 6, 0x471a4de),
    (0x4fb, '0f844dfdffff', 2, 6, 0x471a4de),
    (0x515, 'e934fdffff', 1, 5, 0x471a4de),
    (0x532, 'eb13', 1, 2, 0x471a7d7),
    (0x54d, 'eb3a', 1, 2, 0x471a819),
    (0x55c, 'eb2b', 1, 2, 0x471a819),
    (0x56b, 'eb1c', 1, 2, 0x471a819),
    (0x57a, 'eb0d', 1, 2, 0x471a819),
    (0x598, 'eb09', 1, 2, 0x471a833),
    (0x5b3, 'eb33', 1, 2, 0x471a878),
    (0x5c8, 'eb67', 1, 2, 0x471a8c1),
    (0x5dd, 'eb52', 1, 2, 0x471a8c1),
    (0x5f8, '741b', 1, 2, 0x471a8a5),
    (0x5fd, '7432', 1, 2, 0x471a8c1),
    (0x61b, '7414', 1, 2, 0x471a8c1),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x471a2d2, 0x4381340),
    (0x471a386, 0x438b6e0),
    (0x471a45a, 0x438b6e0),
    (0x471a645, 0x438b6e0),
    (0x471a733, 0x4f72510),
    (0x471a7a0, 0x4f6fe90),
    (0x471a823, 0x4b1c5f0),
    (0x471a853, 0x4b1c5f0),
    (0x471a868, 0x4b1c5f0),
    (0x471a8bc, 0x4f6fe90),
    (0x471a8c4, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x471a330, 0x576e918),
    (0x471a5b5, 0x576e098),
    (0x471a5c5, 0x576f1e0),
    (0x471a76f, 0x576f1e0),
    (0x471a7d7, 0x576e098),
    (0x471a7e6, 0x576e150),
    (0x471a7f5, 0x576e150),
    (0x471a804, 0x576e918),
    (0x471a813, 0x576e150),
    (0x471a82a, 0x576e128),
    (0x471a838, 0x5775068),
    (0x471a845, 0x576e128),
    (0x471a85a, 0x576e128),
    (0x471a86f, 0x576e128),
    (0x471a899, 0x576f1e0),
    (0x471a8c9, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x471a7df, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
    (0x471a7ee, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
    (0x471a80c, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
]
CALLERS = [0x4b73f9f]
CALLER_FUNCTIONS = {'0x4b73f9f': ('0x4b73f50', '0x4b74083')}
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

