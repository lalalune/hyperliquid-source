#!/usr/bin/env python3
"""Authenticated node94 oracle-37d79e0 binding (0x37d79e0).

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

START, END = 0x37d79e0, 0x37d7f0c
FDE_VA = 0x11aabb8
FDE = bytes.fromhex(
    '5000000090cf1e0020ce62022c05000004335f90ff410e10420e18420e20420e'
    '28420e30410e38470e800283078c068d058e048f03860203cc040e38410e3042'
    '0e28420e20420e18420e10410e08410e80020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecc80000004489442434894c243048897c24384c'
    '8b1e488b46084885c00f95c1488b5e184885db400f95c74020cf4080ff010f85'
    '76040000498b790848897c2448498b791048897c2440488b7e104531e44d89da'
    '4531ed4531ff8954240ceb200f1f40004c89ed4d89e6b1014d89f44989edb800'
    '00000048ffcb0f8436040000f6c1010f84620400004d85ff7426410fb78f2203'
    '00004839cf0f83c50000004c89f94989f9e9e2000000662e0f1f840000000000'
    '4885ff74384889f94989c74883e107743131f6666666662e0f1f840000000000'
    '4d8bbf2803000048ffc64839f175f14889f84829f04883ff087315eb514989c7'
    'eb4c4889f84883ff0872430f1f440000498b8f28030000488b8928030000488b'
    '8928030000488b8928030000488b8928030000488b8928030000488b89280300'
    '004c8bb9280300004883c0f875c231c031ff410fb78f220300004839cf0f8248'
    'ffffff666666662e0f1f840000000000498b8fc00200004885c90f8468030000'
    '48ffc0450fb78f200300004989cf66443b892203000073d84885c00f848f0000'
    '004a8d34c94881c6300300004889c74883e7070f84b70100004531c00f1f4000'
    '4c8b3e498db72803000049ffc04c39c775ee4889c74c29c74883f80872436690'
    '488b06488b8028030000488b8028030000488b8028030000488b802803000048'
    '8b8028030000488b80280300004c8bb828030000498db7280300004883c7f875'
    'bf31ff4c89c848c1e00684d27414eb1c498d79014989cf4c89c848c1e00684d2'
    '750a833c01000f8524feffff48897c24184c89dd4d89d64801c84a8bbcc9c802'
    '00000f10000f1048100f1050200f1058300f299c24b00000000f299424a00000'
    '000f298c24900000000f298424800000004889f848b94b598638d6c56d3448f7'
    'e148c1ea0b4869c2102700004829c7483b7c24400f834a020000488d047f48c1'
    'e005488b4c2448488b5401200fb64c2430440fb6442434488d7c2450488db424'
    '800000004c8b8c2400010000ff1506caf901807c24500048896c242874124c8b'
    '4c2470eb0e66662e0f1f8400000000004531c94d89f0488b4c2458488b6c2460'
    '488b7424684c89f04801c88b54240c70514989c2488b7c24184989ee4d01e60f'
    '82930000004889f54c01ed0f82d6000000488b7424284889f04c01c80f800f01'
    '00004989c3e90cfdffff660f1f4400004889c74883f8080f82a4feffffe95efe'
    'ffff48c1f83f48ba00000000000000804831d04901c84c0f40c031ff48897424'
    '20488d3508bdf1014d89c64c894c2410ff15fab3f901488b7424204c8b4c2410'
    '4d89f28b54240c488b7c24184989ee4d01e60f836dffffff31ff488974242048'
    '8d35e2bcf1014d89d64c894c2410ff15bcb3f901488b7424204c8b4c2410488b'
    '7c24184d89f28b54240c4c01e548c7c0ffffffff480f42e84989ee4889f54c01'
    'ed0f832affffff31ff4889f5488d3595bcf1014d89d44c894c2410ff156fb3f9'
    '014c8b4c2410488b7c24184d89e28b54240c4c01ed48c7c0ffffffff480f42e8'
    '488b7424284889f04c01c80f81f1feffff48c1f83f48b9000000000000008048'
    '31c84c01ce480f40f0488974242831ff488d3519bcf1014c89542410ff150eb3'
    'f901488b7c24184c8b5c24284c8b5424108b54240ce9bcfbffff31ed4531f64d'
    '89da488b4424384c89104c897008488968104c8958184881c4c80000005b415c'
    '415d415e415f5dc3488d3d1921f101ff159b65f9010f0b488d3d420cf101ff15'
    '8c65f901488b4424384c89304c8960084c89681048896818488d1531bbf10148'
    '8b742440ff15be60f9010f0b'
)
BODY_SHA256 = '88aae16a5718ae33eff7e94811a74b9c9a589402b75444f830d5e16d8bd467d4'
BRANCHES = [
    (0x3e, '0f8576040000', 2, 6, 0x37d7e9a),
    (0x6a, 'eb20', 1, 2, 0x37d7a6c),
    (0x86, '0f8436040000', 2, 6, 0x37d7ea2),
    (0x8f, '0f8462040000', 2, 6, 0x37d7ed7),
    (0x98, '7426', 1, 2, 0x37d7aa0),
    (0xa5, '0f83c5000000', 2, 6, 0x37d7b50),
    (0xb1, 'e9e2000000', 1, 5, 0x37d7b78),
    (0xc3, '7438', 1, 2, 0x37d7add),
    (0xcf, '7431', 1, 2, 0x37d7ae2),
    (0xed, '75f1', 1, 2, 0x37d7ac0),
    (0xf9, '7315', 1, 2, 0x37d7af0),
    (0xfb, 'eb51', 1, 2, 0x37d7b2e),
    (0x100, 'eb4c', 1, 2, 0x37d7b2e),
    (0x109, '7243', 1, 2, 0x37d7b2e),
    (0x14c, '75c2', 1, 2, 0x37d7af0),
    (0x15d, '0f8248ffffff', 2, 6, 0x37d7a8b),
    (0x17a, '0f8468030000', 2, 6, 0x37d7ec8),
    (0x196, '73d8', 1, 2, 0x37d7b50),
    (0x19b, '0f848f000000', 2, 6, 0x37d7c10),
    (0x1b3, '0f84b7010000', 2, 6, 0x37d7d50),
    (0x1d0, '75ee', 1, 2, 0x37d7ba0),
    (0x1dc, '7243', 1, 2, 0x37d7c01),
    (0x21f, '75bf', 1, 2, 0x37d7bc0),
    (0x22c, '7414', 1, 2, 0x37d7c22),
    (0x22e, 'eb1c', 1, 2, 0x37d7c2c),
    (0x240, '750a', 1, 2, 0x37d7c2c),
    (0x246, '0f8524feffff', 2, 6, 0x37d7a50),
    (0x2b4, '0f834a020000', 2, 6, 0x37d7ee4),
    (0x2fc, '7412', 1, 2, 0x37d7cf0),
    (0x303, 'eb0e', 1, 2, 0x37d7cf3),
    (0x32f, '7051', 1, 2, 0x37d7d62),
    (0x33f, '0f8293000000', 2, 6, 0x37d7db8),
    (0x34b, '0f82d6000000', 2, 6, 0x37d7e07),
    (0x35c, '0f800f010000', 2, 6, 0x37d7e51),
    (0x365, 'e90cfdffff', 1, 5, 0x37d7a56),
    (0x377, '0f82a4feffff', 2, 6, 0x37d7c01),
    (0x37d, 'e95efeffff', 1, 5, 0x37d7bc0),
    (0x3d2, '0f836dffffff', 2, 6, 0x37d7d25),
    (0x421, '0f832affffff', 2, 6, 0x37d7d31),
    (0x46b, '0f81f1feffff', 2, 6, 0x37d7d42),
    (0x4b5, 'e9bcfbffff', 1, 5, 0x37d7a56),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x37d7ccc, 0x57746d8),
    (0x37d7d90, 0x5773190),
    (0x37d7dce, 0x5773190),
    (0x37d7e1b, 0x5773190),
    (0x37d7e7c, 0x5773190),
    (0x37d7ecf, 0x576e470),
    (0x37d7ede, 0x576e470),
    (0x37d7f04, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x37d7ec8, 0x56e9fe8, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x37d7ed7, 0x56e8b20, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
    (0x37d7ef8, 0x56f3a30, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5773178']
GOT_SITES = {'0x5773178': ['0x1e62426', '0x270c0aa', '0x270c555', '0x270f934', '0x2727fca', '0x2752926', '0x2753482', '0x27583c1', '0x276895f', '0x2a22fc9', '0x324cadb', '0x36f5f94', '0x36f75a0', '0x36fa730', '0x36fe8e5', '0x36ffa9d', '0x3700b08', '0x370190a', '0x3708c30', '0x370b74c', '0x37d73b7', '0x37d7888', '0x3955ed8', '0x395905a', '0x3959635', '0x3959aab', '0x3bfce30', '0x46e8bee', '0x46e9600', '0x4cf6f2e', '0x4cf73d5', '0x4cfcbce', '0x4cfd075', '0x4d2fffa', '0x4d3097a', '0x4d81041', '0x4d811b1', '0x4d9ca3f', '0x4d9d61f']}


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

