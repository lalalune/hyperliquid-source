#!/usr/bin/env python3
"""Authenticated node94 oracle-48826c0 binding (0x48826c0).

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

START, END = 0x48826c0, 0x4882ddc
FDE_VA = 0x12a11d0
FDE = bytes.fromhex(
    '50000000a8352e00e8145e031c070000043b228eff410e10420e18420e20420e'
    '28420e30410e38440e800183078c068d058e048f0386020368020e38410e3042'
    '0e28420e20420e18420e10410e08500e80010000'
)
BODY = bytes.fromhex(
    '554157415641554154534883ec484989f74989fe6666662e0f1f840000000000'
    '4c89ffe8081901004885c0742a488b5a104885db0f98c20f9fc128d174e24c89'
    '7424384c8b204d8b77500fb6c183f801752140b501eb1e49c7060000000049c7'
    '46080800000049c7461000000000e9fc01000031ed48b94b598638d6c56d344c'
    '89e048f7e148c1ea0b4869c2102700004c89e74829c7498b76704839f70f8330'
    '060000498b4748f20f10004084ed7408660f5705785b98fb498b4668488d0c7f'
    '48c1e105f20f104c08200f140def1698fb660f5c0d070798fb660f28d1660f15'
    'd1f20f58d1f20f5805837f98fbf20f59c2ff1521cfee00660f57c9f20f5fc166'
    '480f7ec048b9ffffffffffffff7f4821c848b9ffffffffffffef7f660f57d248'
    '39c87f16660f2e05247d98fb660f28d07608f20f1015167d98fbf2480f2cc248'
    '89c1660f28c2f20f5c05e27f98fbf2480f2cd048c1f93f4821ca4809c231c066'
    '0f2ed1480f43c2660f2e15e97998fb49c7c5ffffffff4c0f46e84983fd014983'
    'd5004c89f74c89e64c89eae8b04da4ff4889c14c89e84809c848c1e820740a4c'
    '89e831d248f7f1eb074489e831d2f7f14889c248ffc249c7c6ffffffff490f44'
    'd64084ed480f44d04889d048f7e170034989c6bf80000000ff153ab7ee004885'
    'c00f84f90400004989c14889d848f7d8480f48c34983fe014983d6004d89314d'
    '896108498941104188691848c7442410040000004c894c241848c74424200100'
    '0000410fb6374d8b6708498b47104d8b7718498b5f40498b4f4848894c244049'
    '8b4f5048894c2408b90100000048894c24284883eb01736d488b4424204c8b74'
    '2438498946100f10442410410f11064c89f04883c4485b415c415d415e415f5d'
    'c36666666666662e0f1f8400000000004c8d72014989cc4889d048c1e0064c8b'
    '7c01104d85ff0f98c0400f9fc64028c6400fb6c640b60184c00f85bc01000048'
    '83eb01729340f6c6010f84e60300004d85e4742c410fb78c24220300004939ce'
    '0f83ca0000004c89e14c89f2e9e80000006666666666662e0f1f840000000000'
    '4d85f674394c89f14989c44883e107743231d2666666662e0f1f840000000000'
    '4d8ba4242803000048ffc24839d175f04c89f04829d04983fe087314eb514989'
    'c4eb4c4c89f04983fe0872430f1f4000498b8c2428030000488b892803000048'
    '8b8928030000488b8928030000488b8928030000488b8928030000488b892803'
    '00004c8ba1280300004883c0f875c14531f631c0410fb78c24220300004939ce'
    '0f8240ffffff662e0f1f840000000000498b8c24c00200004885c90f84e50200'
    '0048ffc0410fb79424200300004989cc663b912203000073d74885c00f84aefe'
    'ffff488d34d14881c6300300004889c74883e7070f84760000004531c00f1f00'
    '4c8b26498db4242803000049ffc04c39c775ed4889c74c29c74883f808724390'
    '488b06488b8028030000488b8028030000488b8028030000488b802803000048'
    '8b8028030000488b80280300004c8ba028030000498db424280300004883c7f8'
    '75be4531f6e92dfeffff660f1f4400004889c74883f80873a7ebe783f8017505'
    '41b001eb034531c0488bbcd1c80200004889f848b94b598638d6c56d3448f7e1'
    '48c1ea0b4869c21027000048897c24304829c7488b442408488b70704839f70f'
    '83ff010000488b442440f20f100044894424044c89cd4584c07408660f57054d'
    '5798fb488b442408488b4068488d0c7f48c1e105f20f104c08200f140dbf1298'
    'fb660f5c0dd70298fb660f28d1660f15d1f20f58d1f20f5805537b98fbf20f59'
    'c2ff15f1caee00660f57c9f20f5fc166480f7ec048b9ffffffffffffff7f4821'
    'c848b9ffffffffffffef7f4839c87f16660f2e05f87898fb660f28c87608f20f'
    '100dea7898fbf2480f2cc14889c148c1f93f660f28c1f20f5c05b27b98fbf248'
    '0f2cd04821ca4809c2660f57c0660f2ec841bd000000004c0f43ea660f2e0db5'
    '7598fb48c7c0ffffffff4c0f47e84983fd014983d500488b7c2408488b742430'
    '4c89eae87849a4ff4889c14c89e84809c848c1e8204989e9740a4c89e831d248'
    'f7f1eb074489e831d2f7f18b7c24044889c248ffc248c7c6ffffffff480f44d6'
    '4084ff480f44d04889d048f7e10f80870000004989c54983fd014983d5004c89'
    'fd48f7dd490f48ef4c8b7c24284c3b7c24107522ba01000000b90800000041b8'
    '20000000488d7c24104c89fee8bfc8ccff4c8b4c24184c89f848c1e0054d892c'
    '01488b4c243049894c010849896c01108b4c240441884c011849ffc74c897c24'
    '284c897c242040b60131c04883eb010f8330fcffffe9befbffff49c7c5ffffff'
    'ffe970ffffff488d3de311eb00ff15fdb6ee00eb1c488d3d0402eb00ff15eeb6'
    'ee00eb0d488d1575e4eb00ff1537b2ee000f0b488d1566e4eb00ff1528b2ee00'
    'bf08000000be80000000ff1508b2ee00eb02eb004889c3488b7424104885f674'
    '11488b7c241848c1e60531d2ff153eb2ee004889dfe836d3dd000f0b'
)
BODY_SHA256 = '52440d5e340165d86563a27c25de13bc56804b02f097f3c633d32b575c1a527b'
BRANCHES = [
    (0x2b, '742a', 1, 2, 0x4882717),
    (0x3c, '74e2', 1, 2, 0x48826e0),
    (0x50, '7521', 1, 2, 0x4882733),
    (0x55, 'eb1e', 1, 2, 0x4882735),
    (0x6e, 'e9fc010000', 1, 5, 0x488292f),
    (0x9d, '0f8330060000', 2, 6, 0x4882d93),
    (0xae, '7408', 1, 2, 0x4882778),
    (0x122, '7f16', 1, 2, 0x48827fa),
    (0x130, '7608', 1, 2, 0x48827fa),
    (0x19d, '740a', 1, 2, 0x4882869),
    (0x1a7, 'eb07', 1, 2, 0x4882870),
    (0x1ce, '7003', 1, 2, 0x4882893),
    (0x1e1, '0f84f9040000', 2, 6, 0x4882da0),
    (0x256, '736d', 1, 2, 0x4882985),
    (0x2b9, '0f85bc010000', 2, 6, 0x4882b3b),
    (0x2c3, '7293', 1, 2, 0x4882918),
    (0x2c9, '0f84e6030000', 2, 6, 0x4882d75),
    (0x2d2, '742c', 1, 2, 0x48829c0),
    (0x2e0, '0f83ca000000', 2, 6, 0x4882a70),
    (0x2ec, 'e9e8000000', 1, 5, 0x4882a99),
    (0x303, '7439', 1, 2, 0x48829fe),
    (0x30f, '7432', 1, 2, 0x4882a03),
    (0x32e, '75f0', 1, 2, 0x48829e0),
    (0x33a, '7314', 1, 2, 0x4882a10),
    (0x33c, 'eb51', 1, 2, 0x4882a4f),
    (0x341, 'eb4c', 1, 2, 0x4882a4f),
    (0x34a, '7243', 1, 2, 0x4882a4f),
    (0x38d, '75c1', 1, 2, 0x4882a10),
    (0x3a0, '0f8240ffffff', 2, 6, 0x48829a6),
    (0x3bb, '0f84e5020000', 2, 6, 0x4882d66),
    (0x3d7, '73d7', 1, 2, 0x4882a70),
    (0x3dc, '0f84aefeffff', 2, 6, 0x4882950),
    (0x3f4, '0f8476000000', 2, 6, 0x4882b30),
    (0x411, '75ed', 1, 2, 0x4882ac0),
    (0x41d, '7243', 1, 2, 0x4882b22),
    (0x460, '75be', 1, 2, 0x4882ae0),
    (0x465, 'e92dfeffff', 1, 5, 0x4882957),
    (0x477, '73a7', 1, 2, 0x4882ae0),
    (0x479, 'ebe7', 1, 2, 0x4882b22),
    (0x47e, '7505', 1, 2, 0x4882b45),
    (0x483, 'eb03', 1, 2, 0x4882b48),
    (0x4bf, '0f83ff010000', 2, 6, 0x4882d84),
    (0x4d9, '7408', 1, 2, 0x4882ba3),
    (0x54e, '7f16', 1, 2, 0x4882c26),
    (0x55c, '7608', 1, 2, 0x4882c26),
    (0x5d8, '740a', 1, 2, 0x4882ca4),
    (0x5e2, 'eb07', 1, 2, 0x4882cab),
    (0x60d, '0f8087000000', 2, 6, 0x4882d5a),
    (0x632, '7522', 1, 2, 0x4882d16),
    (0x68f, '0f8330fcffff', 2, 6, 0x4882985),
    (0x695, 'e9befbffff', 1, 5, 0x4882918),
    (0x6a1, 'e970ffffff', 1, 5, 0x4882cd6),
    (0x6b3, 'eb1c', 1, 2, 0x4882d91),
    (0x6c2, 'eb0d', 1, 2, 0x4882d91),
    (0x6f0, 'eb02', 1, 2, 0x4882db4),
    (0x6f2, 'eb00', 1, 2, 0x4882db4),
    (0x6ff, '7411', 1, 2, 0x4882dd2),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x48826e3, 0x4893ff0),
    (0x488284b, 0x42c7600),
    (0x4882c83, 0x42c7600),
    (0x4882d0c, 0x454f5d0),
    (0x4882dd5, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x48827b1, 0x576f6d8),
    (0x4882898, 0x576dfd8),
    (0x4882be1, 0x576f6d8),
    (0x4882d6d, 0x576e470),
    (0x4882d7c, 0x576e470),
    (0x4882d8b, 0x576dfc8),
    (0x4882d9a, 0x576dfc8),
    (0x4882daa, 0x576dfb8),
    (0x4882dcc, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4882d66, 0x5733f50, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 534, 47),
    (0x4882d75, 0x5732f80, bytes.fromhex('2f72757374632f653430383934376266643230306166343264623332326461663066616466653765323664336264312f6c6962726172792f616c6c6f632f7372632f636f6c6c656374696f6e732f62747265652f6e617669676174652e7273'), 161, 36),
    (0x4882d84, 0x5741200, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
    (0x4882d93, 0x5741200, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 197, 18),
]
CALLERS = [0x4cf7942, 0x4cfd5e2]
CALLER_FUNCTIONS = {'0x4cf7942': ('0x4cf37f0', '0x4cf949d'), '0x4cfd5e2': ('0x4cf94a0', '0x4cff13d')}
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

