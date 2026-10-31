#!/usr/bin/env python3
"""Authenticated node94 spot-meta-257d2f0 binding (0x257d2f0).

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

START, END = 0x257d2f0, 0x257d8d5
FDE_VA = 0x10cd230
FDE = bytes.fromhex(
    '5000000008f61000b8004b01e50500000437a093ff410e10420e18420e20420e'
    '28420e30410e38440eb00183078c068d058e048f038602034e050e38410e3042'
    '0e28420e20420e18420e10410e08410eb0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534883ec784989f64889fb4889f7e8d43626004885c00f'
    '84fe0400004d8b7e484d8d66504c8d6c2401eb1d6666662e0f1f840000000000'
    '4c89f7e8a83626004885c00f84d2040000488b28493baf880100000f83060500'
    '00498b87800100004869cde8000000488b9408df000000488954242d0f108408'
    'd20000000f29442420418b44241041894510f3410f6f0424f3410f7f4500f644'
    '242001749bf30f6f442421f30f6f4c2401660f74c8660f6e442431660f6e5424'
    '11660f74d0660fdbd1660fd7c23dffff00000f8568ffffffbf20000000ff1505'
    '0c1f034885c00f84b504000048892848c7042404000000488944240848c74424'
    '1001000000498b16498b6e08498b4e104d8b7e184d8b6e404d8b5648418b7424'
    '1089742470f3410f6f0424660f7f4424604d85ed0f8402040000be0100000048'
    '897424184c8d6424214c89542438f6c2010f845a0400004885ed741b0fb79572'
    '0200004939d70f83b40000004889ea4c89fee9cf0000004d85ff742b4c89fa48'
    '89cd4883e207742431f6660f1f440000488bad7802000048ffc64839f275f14c'
    '89f94829f1eb084889cdeb524c89f94983ff08724966662e0f1f840000000000'
    '488b9578020000488b9278020000488b9278020000488b9278020000488b9278'
    '020000488b9278020000488b9278020000488baa780200004883c1f875c24531'
    'ff31c90fb795720200004939d70f8259ffffff666666662e0f1f840000000000'
    '488b95100200004885d20f846203000048ffc10fb7b5700200004889d5663bb2'
    '7202000073da4885c90f849e000000488d3cf24881c7800200004989c84983e0'
    '070f84aa0200004531c9660f1f440000488b2f488dbd7802000049ffc14d39c8'
    '75ee4989c84d29c84883f90872436690488b0f488b8978020000488b89780200'
    '00488b8978020000488b8978020000488b8978020000488b8978020000488ba9'
    '78020000488dbd780200004983c0f875bf4531ff498b8a880100004c8bb4f218'
    '0200004939ce7224e9870200004c8d7e014889d5498b8a880100004c8bb4f218'
    '0200004939ce0f8368020000498b9280010000eb2666662e0f1f840000000000'
    '4889ee498d7f014e8bb4fe180200004989ff4939ce0f833902000049ffcd4969'
    'f6e8000000488bbc32df00000048897c244d0f108432d20000000f294424408b'
    '7424704189742410660f6f442460f3410f7f0424f6442440017434f30f6f4424'
    '41f30f6f4c2421660f74c8660f6e442451660f6e542431660f74d0660fdbd166'
    '0fd7f281feffff00000f840d0100004d85ed0f84840100000fb7b57202000049'
    '39f70f8258ffffff41b10131ff0f1f00488bb5100200004885f60f84a3010000'
    '4989f84589ca48ffc7440fb7bd70020000458d4a014889f566443bbe72020000'
    '73ce4885ff0f84a10000004e8d0cfe4981c18002000040f6c7070f8494000000'
    '450fb6d24183e2074531db0f1f440000498b294c8d8d7802000049ffc34d39da'
    '75ee4c29df4983f80772460f1f4400004d8b014d8b80780200004d8b80780200'
    '004d8b80780200004d8b80780200004d8b80780200004d8b8078020000498ba8'
    '780200004c8d8d780200004883c7f875bf31ff4e8bb4fe180200004989ff4939'
    'ce0f8294feffffe9c80000004889f5e96ffeffff4983f8077396ebd5488b7424'
    '18483b34247522ba01000000b90800000041b8080000004889e7e8a1d8f9ff48'
    '8b442408488b7424184c8934f048ffc648897424184889742410b201b9000000'
    '004d85ed4c8b5424380f853ffcffffeb2b4989c84883f9080f8372fdffffe9ae'
    'fdffff48c7030000000048c743080800000048c7431000000000eb19488b4424'
    '1048894310488b0424488903488b442408488943084889d84883c4785b415c41'
    '5d415e415f5dc3488d3d92491703ff150c0c1f03488d3d85491703ff15ff0b1f'
    '03eb1c488d3dc67c1403ff15f00b1f03eb0d488d3db77c1403ff15e10b1f030f'
    '0bbf08000000be20000000ff1517071f03488d3d485f1403ebc1eb040f0b0f0b'
    '4889c3488b34244885f67411488b7c240848c1e60331d2ff1543071f034889df'
    'e83b280e03'
)
BODY_SHA256 = '0b2e7f848983c79da94ccb0d47cfdea9f3ce9fefc5dedbea34c351e2f0d37906'
BRANCHES = [
    (0x1f, '0f84fe040000', 2, 6, 0x257d813),
    (0x32, 'eb1d', 1, 2, 0x257d341),
    (0x4b, '0f84d2040000', 2, 6, 0x257d813),
    (0x5b, '0f8306050000', 2, 6, 0x257d857),
    (0xa3, '749b', 1, 2, 0x257d330),
    (0xd2, '0f8568ffffff', 2, 6, 0x257d330),
    (0xe6, '0f84b5040000', 2, 6, 0x257d891),
    (0x134, '0f8402040000', 2, 6, 0x257d82c),
    (0x151, '0f845a040000', 2, 6, 0x257d8a1),
    (0x15a, '741b', 1, 2, 0x257d467),
    (0x166, '0f83b4000000', 2, 6, 0x257d510),
    (0x172, 'e9cf000000', 1, 5, 0x257d536),
    (0x17a, '742b', 1, 2, 0x257d497),
    (0x186, '7424', 1, 2, 0x257d49c),
    (0x19d, '75f1', 1, 2, 0x257d480),
    (0x1a5, 'eb08', 1, 2, 0x257d49f),
    (0x1aa, 'eb52', 1, 2, 0x257d4ee),
    (0x1b3, '7249', 1, 2, 0x257d4ee),
    (0x1fc, '75c2', 1, 2, 0x257d4b0),
    (0x20d, '0f8259ffffff', 2, 6, 0x257d45c),
    (0x22a, '0f8462030000', 2, 6, 0x257d882),
    (0x244, '73da', 1, 2, 0x257d510),
    (0x249, '0f849e000000', 2, 6, 0x257d5dd),
    (0x261, '0f84aa020000', 2, 6, 0x257d801),
    (0x280, '75ee', 1, 2, 0x257d560),
    (0x28c, '7243', 1, 2, 0x257d5c1),
    (0x2cf, '75bf', 1, 2, 0x257d580),
    (0x2e6, '7224', 1, 2, 0x257d5fc),
    (0x2e8, 'e987020000', 1, 5, 0x257d864),
    (0x306, '0f8368020000', 2, 6, 0x257d864),
    (0x313, 'eb26', 1, 2, 0x257d62b),
    (0x335, '0f8339020000', 2, 6, 0x257d864),
    (0x379, '7434', 1, 2, 0x257d69f),
    (0x3a9, '0f840d010000', 2, 6, 0x257d7ac),
    (0x3b2, '0f8484010000', 2, 6, 0x257d82c),
    (0x3c2, '0f8258ffffff', 2, 6, 0x257d610),
    (0x3da, '0f84a3010000', 2, 6, 0x257d873),
    (0x400, '73ce', 1, 2, 0x257d6c0),
    (0x405, '0f84a1000000', 2, 6, 0x257d79c),
    (0x41a, '0f8494000000', 2, 6, 0x257d7a4),
    (0x440, '75ee', 1, 2, 0x257d720),
    (0x449, '7246', 1, 2, 0x257d781),
    (0x48f, '75bf', 1, 2, 0x257d740),
    (0x4a1, '0f8294feffff', 2, 6, 0x257d62b),
    (0x4a7, 'e9c8000000', 1, 5, 0x257d864),
    (0x4af, 'e96ffeffff', 1, 5, 0x257d613),
    (0x4b8, '7396', 1, 2, 0x257d740),
    (0x4ba, 'ebd5', 1, 2, 0x257d781),
    (0x4c5, '7522', 1, 2, 0x257d7d9),
    (0x509, '0f853ffcffff', 2, 6, 0x257d43e),
    (0x50f, 'eb2b', 1, 2, 0x257d82c),
    (0x518, '0f8372fdffff', 2, 6, 0x257d580),
    (0x51e, 'e9aefdffff', 1, 5, 0x257d5c1),
    (0x53a, 'eb19', 1, 2, 0x257d845),
    (0x581, 'eb1c', 1, 2, 0x257d88f),
    (0x590, 'eb0d', 1, 2, 0x257d88f),
    (0x5b8, 'ebc1', 1, 2, 0x257d86b),
    (0x5ba, 'eb04', 1, 2, 0x257d8b0),
    (0x5ca, '7411', 1, 2, 0x257d8cd),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x257d307, 0x27e09e0),
    (0x257d333, 0x27e09e0),
    (0x257d7ca, 0x251b070),
    (0x257d8d0, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x257d3cd, 0x576dfd8),
    (0x257d85e, 0x576e470),
    (0x257d86b, 0x576e470),
    (0x257d87a, 0x576e470),
    (0x257d889, 0x576e470),
    (0x257d89b, 0x576dfb8),
    (0x257d8c7, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x257d857, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x257d864, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x257d873, 0x56c5540, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x257d882, 0x56c5540, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
]
CALLERS = [0x27e61fd]
CALLER_FUNCTIONS = {'0x27e61fd': ('0x27e61a0', '0x27e6422')}
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

