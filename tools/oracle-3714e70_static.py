#!/usr/bin/env python3
"""Authenticated node94 oracle-3714e70 binding (0x3714e70).

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

START, END = 0x3714e70, 0x37153e4
FDE_VA = 0xe4c15c
FDE = bytes.fromhex(
    '4800000048ac16000c8d8c027405000000410e10420e18420e20420e28420e30'
    '410e38440e7083078c068d058e048f0386020303050e38410e30420e28420e20'
    '420e18420e10410e08410e70'
)
BODY = bytes.fromhex(
    '554157415641554154534883ec384d89cd4c89442410894c24044989d64989ff'
    '0fb69f3002000049bc4b598638d6c56d3480fb030f852b0100004c89f049f7e4'
    '48c1ea0b493b57300f85ce0400004c89f049f7e448c1ea0b4869c2102700004c'
    '89f74829c7493b7f100f83ad040000498b4708488d2c7f4889e948c1e104807c'
    '0828000f84dc000000498b77704839f70f83d1040000498b4f6848c1e5058b44'
    '29588944242048894c2408488b4429504889442418488d74241c488d7c2428ba'
    '3c00000031c9ff156c990502488b44243048b9000000004057ffff4801c148ba'
    '81aefeff7faefeff4839d10f824d0400008b5c2428448b64242c8b7c241848b9'
    '572951cea0c8451848f7e94889d648c1ee3f48c1ea0d01d6ff152299050285c0'
    '0f8418040000488b4c24084801e94883c140413945000f9ec00f85cc00000041'
    '395d040f96c00f85bf00000045396508448b5424044c8b5c24100f87b9000000'
    'e9c5000000498b87880200004885c07473498b8f900200000fb7b0ba00000089'
    'f7c1e70348c7c2ffffffff0f1f4400004885ff742b4c3b74d010410f97c04180'
    'd80048ffc24883c7f84180f80174e1410fb6f085f6741ceb0a0f1f8000000000'
    '4889f24883e901721b488b84d0c0000000eba5f20f1044d060f20f11442408e9'
    'c90100004c89ff4c89f6ff15880d06023c060f839c010000f20f1005f856affc'
    'f20f11442408e9a201000084c0448b5424044c8b5c24107511498b4768488944'
    '2408488d0c284883c120488b01498b8fa8020000f20f100d9458affc4885c974'
    '61498b97b00200000fb7b9ba0000004189f841c1e00348c7c6ffffffff0f1f00'
    '4d85c074244c3b74f110410f97c14180d90048ffc64983c0f84180f90174e141'
    '0fb6f985ff7415eb034889fe4883ea017210488b8cf1c0000000ebacf20f104c'
    'f16066490f6ed3f30f7e1d61edaefc660f62d3660f282575ddaefc660f5cd466'
    '0f28c2660f15c2f20f58c266480f6ed0660f62d3660f5cd4660f28e2660f15e2'
    'f20f58e2660f28d8f20f5edcf20f10151451affcf20f58da4584d27508f20f10'
    '15bb55affcf20f59da660f2ecb0f82b3010000498b87c0020000f20f100dc651'
    'affc4885c00f84a5010000498b8fc80200000fb7b0ba00000089f7c1e70348c7'
    'c2ffffffff66662e0f1f8400000000004885ff74284c3b74d010410f97c04180'
    'd80048ffc24883c7f84180f80174e1410fb6f085f60f844f010000eb034889f2'
    '4883e9010f8246010000488b84d0c0000000eb9e0fb6c0f20f2ac0f20f100d1d'
    '55affcf20f5ec8f20f114c24084c89f049f7e448c1ea0b4869c2102700004929'
    'c6498b77704939f60f835b01000031c080fb030f94c04d8b6768488d0d6f0daf'
    'fcf20f1004c14f8d347649c1e605438b443458894424304b8b44345048894424'
    '28488d7c2418488d742428ff15379d0502418b45003b4424180f9ec07521418b'
    '45043b44241c0f96c07514418b45083b442420770e4b8d04344883c040eb1984'
    'c075f2498b476880fb0375054c01f0eb074c01f04883c0208b4c2404488b5424'
    '1066480f6ecaf30f7e15a2ebaefc660f62ca660f281db6dbaefc660f5ccb660f'
    '28c1660f15c1f20f58c1f30f7e08660f62ca660f5ccb660f28d1660f15d1f20f'
    '58d1f20f5ec2f20f58055a4faffc84c97408660f5705c62faffcf20f104c2408'
    '660f2ec8734531c0eb43f20f104cd060488b442408f20f101c280f141d2febae'
    'fc660f5c1d47dbaefc660f28e3660f15e3f20f58e3f20f5ec4f20f5805074faf'
    'fcf20f59d0660f2eca72bbb0014883c4385b415c415d415e415f5dc3488d3d2d'
    'cefd01ff15d790050280fb037529488d1583c9fd014c89f7ff151a8c0502488d'
    '3d6a4cb0fc488d155c5bf501be26000000ff15a1900502488d15e2c8fd014c89'
    'f7ff15f18b0502488d15d2c8fd01ff15e48b0502'
)
BODY_SHA256 = 'aaed1063f7feb3f81997ca2c331373365018d75b191e457db4c8ade04ec98bcc'
BRANCHES = [
    (0x34, '0f852b010000', 2, 6, 0x3714fd5),
    (0x48, '0f85ce040000', 2, 6, 0x371538c),
    (0x69, '0f83ad040000', 2, 6, 0x371538c),
    (0x83, '0f84dc000000', 2, 6, 0x3714fd5),
    (0x90, '0f83d1040000', 2, 6, 0x37153d7),
    (0xeb, '0f824d040000', 2, 6, 0x37153ae),
    (0x120, '0f8418040000', 2, 6, 0x37153ae),
    (0x139, '0f85cc000000', 2, 6, 0x371507b),
    (0x146, '0f85bf000000', 2, 6, 0x371507b),
    (0x15a, '0f87b9000000', 2, 6, 0x3715089),
    (0x160, 'e9c5000000', 1, 5, 0x371509a),
    (0x16f, '7473', 1, 2, 0x3715054),
    (0x193, '742b', 1, 2, 0x3715030),
    (0x1ad, '74e1', 1, 2, 0x3715000),
    (0x1b5, '741c', 1, 2, 0x3715043),
    (0x1b7, 'eb0a', 1, 2, 0x3715033),
    (0x1c7, '721b', 1, 2, 0x3715054),
    (0x1d1, 'eba5', 1, 2, 0x3714fe8),
    (0x1df, 'e9c9010000', 1, 5, 0x371521d),
    (0x1f2, '0f839c010000', 2, 6, 0x3715204),
    (0x206, 'e9a2010000', 1, 5, 0x371521d),
    (0x217, '7511', 1, 2, 0x371509a),
    (0x23f, '7461', 1, 2, 0x3715112),
    (0x263, '7424', 1, 2, 0x37150f9),
    (0x27d, '74e1', 1, 2, 0x37150d0),
    (0x285, '7415', 1, 2, 0x371510c),
    (0x287, 'eb03', 1, 2, 0x37150fc),
    (0x290, '7210', 1, 2, 0x3715112),
    (0x29a, 'ebac', 1, 2, 0x37150b8),
    (0x2fb, '7508', 1, 2, 0x3715175),
    (0x30d, '0f82b3010000', 2, 6, 0x3715336),
    (0x325, '0f84a5010000', 2, 6, 0x3715340),
    (0x353, '7428', 1, 2, 0x37151ed),
    (0x36d, '74e1', 1, 2, 0x37151c0),
    (0x375, '0f844f010000', 2, 6, 0x371533a),
    (0x37b, 'eb03', 1, 2, 0x37151f0),
    (0x384, '0f8246010000', 2, 6, 0x3715340),
    (0x392, 'eb9e', 1, 2, 0x37151a2),
    (0x3c8, '0f835b010000', 2, 6, 0x3715399),
    (0x41c, '7521', 1, 2, 0x37152af),
    (0x429, '7514', 1, 2, 0x37152af),
    (0x433, '770e', 1, 2, 0x37152b3),
    (0x43d, 'eb19', 1, 2, 0x37152c8),
    (0x441, '75f2', 1, 2, 0x37152a5),
    (0x44a, '7505', 1, 2, 0x37152c1),
    (0x44f, 'eb07', 1, 2, 0x37152c8),
    (0x4b0, '7408', 1, 2, 0x371532a),
    (0x4c4, '7345', 1, 2, 0x371537b),
    (0x4c8, 'eb43', 1, 2, 0x371537d),
    (0x509, '72bb', 1, 2, 0x3715336),
    (0x52c, '7529', 1, 2, 0x37153c7),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3714f36, 0x576e8a8),
    (0x3714f88, 0x576e8b0),
    (0x371505a, 0x5775de8),
    (0x371527b, 0x576efb8),
    (0x3715393, 0x576e470),
    (0x37153a8, 0x576dfc8),
    (0x37153c1, 0x576e468),
    (0x37153d1, 0x576dfc8),
    (0x37153de, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x371538c, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x371539e, 0x56f1d28, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 202, 18),
    (0x37153b5, 0x566af18, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f6461746574696d652f6d6f642e7273'), 1631, 38),
    (0x37153c7, 0x56f1cb0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
    (0x37153d7, 0x56f1cb0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774860']
GOT_SITES = {'0x5774860': ['0x26ecd21', '0x26edcba', '0x27376de', '0x42ff3d6', '0x4300d16', '0x4311edc', '0x4312cd1', '0x4315b3c', '0x4316931']}


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

