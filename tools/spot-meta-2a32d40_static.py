#!/usr/bin/env python3
"""Authenticated node94 spot-meta-2a32d40 binding (0x2a32d40).

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

START, END = 0x2a32d40, 0x2a33237
FDE_VA = 0xda9480
FDE = bytes.fromhex(
    '4c0000006c7f0c00b898c801f704000000410e10420e18420e20420e28420e30'
    '410e38470ef00183078c068d058e048f03860203a3020e38410e30420e28420e'
    '20420e18420e10410e08410ef0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecb80000004889fb4889742418488baad0000000'
    '4885ed0f847a0200004989ce488b82d80000000fb7bdf20700004c69c7b00000'
    '0048c7c1ffffffff4531e40f1f4400004d39e0742b483bb4cda0070000410f97'
    'c14180d9004981c4b000000048ffc14180f90174db410fb6f985ff741aeb0490'
    '4889f94883e8010f8216020000488baccdf8070000eb9c48895424504a8b4425'
    'a84a8b4c25c8488944245848894c24604a8b4425904a8b4c25b0488944246848'
    '894c2470488d4424684889842498000000488d44245848898424a0000000488d'
    '44241848898424a80000004c89b424b0000000488d7c2478488db42498000000'
    'e8ab62ffff488b5424184885d248895c24284c897424480f84d1000000498b8e'
    '880100004839ca0f83a3030000498b86800100004869f2e8000000488b543058'
    '4c8b4c30604d8b8668010000498bb67001000049c1e1034531d2660f1f440000'
    '4d39d10f849f0000004a8b3c124839f70f836703000048c1e7054983c2084983'
    '7c38080075da498b14384839ca0f833d0300000fb648494869d2e80000002a4c'
    '10480f8242030000b8010000004889442408f2420f10842560ffffff0f14057d'
    '0f7dfd660f5c0595ff7cfd660f28c8660f15c8f20f58c80fb6c1488d0d97e49e'
    'fdf20f5e0cc1660f294c2430eb23b8010000004889442408f20f1005f0777dfd'
    '660f29442430eb0948c744240800000000498d3c2c4881c750ffffffff15061c'
    'd4024a8b44259048894424104af76425a84989c64889d3f20f114424204e8b7c'
    '25b049bd00407a10f35a00004889c74889d64c89ea31c9ff150bb2d3024889c1'
    '4989d04889d6490faff549f7e54801f24929c64819d34531ed4c09f3410f95c5'
    '4901cd4983d0004c89f84af76425c848b9ff3f7a10f35a00004839ca7621488b'
    '5c242848c703020000004889d84881c4b80000005b415c415d415e415f5dc34c'
    '89fb48837c241000410f94c64d85ed0f9544241048b900407a10f35a00004889'
    'c74889d64889ca31c94d89c7ff1576b1d3024889d14885db0f94c24885c0400f'
    '95c64d85ff7597442274241075904020f2758b4885c0745931ffbe000000004d'
    '85ff75234889c64c89e849b800407a10f35a000049f7e04889c74889f04d0faf'
    'f84901d74c89fe4889c2ff1518b1d3024885d20f8545ffffff48b900407a10f3'
    '5a00004839c8480f42c8f2480f2ac1eb04660f57c0488b7424080f28742430f2'
    '0f107c2420488b442418488b542448483b8288010000488b4c24500f832f0100'
    '00f20f100d27777dfdf20f5ec1f20f1091c80000000f1415840d7dfd660f5c15'
    '9cfd7cfd660f28da660f15daf20f58daf20f5ed9f20f100d14767dfdf2420f10'
    'a42568ffffff0f1425530d7dfd660f5c256bfd7cfdf20f5ccb660f28d4660f15'
    'd4f20f58d4660f28dff20f59d8488b8a800100004869c0e80000000fb6440149'
    '488d0da119b5fdf20f5e14c1f20f59cb660f57db4283bc2550ffffff01488b5c'
    '24287525f2420f10a42558ffffff0f1425eb0c7dfd660f5c2503fd7cfd660f28'
    'dc660f15dcf20f58dcf20f5e1d5f767dfd488b842488000000f20f10a4249000'
    '0000488b4c2478f20f10ac248000000048c70301000000f20f11430848897310'
    'f20f11731848894320f20f11632848894b30f20f116b38f20f117b40f20f114b'
    '48f20f115350f20f115b58e9dafdffff488d3dd9efcb02ff1553b2d302488d15'
    'b4edcb02ff159eadd302488d3d27f0cb02ff1519afd302'
)
BODY_SHA256 = '9d64fd13736a8b7e89966ec60cbea55cd460ce0302f5edf4da3726426f1ea420'
BRANCHES = [
    (0x23, '0f847a020000', 2, 6, 0x2a32fe3),
    (0x53, '742b', 1, 2, 0x2a32dc0),
    (0x73, '74db', 1, 2, 0x2a32d90),
    (0x7b, '741a', 1, 2, 0x2a32dd7),
    (0x7d, 'eb04', 1, 2, 0x2a32dc3),
    (0x87, '0f8216020000', 2, 6, 0x2a32fe3),
    (0x95, 'eb9c', 1, 2, 0x2a32d73),
    (0x117, '0f84d1000000', 2, 6, 0x2a32f2e),
    (0x127, '0f83a3030000', 2, 6, 0x2a33210),
    (0x163, '0f849f000000', 2, 6, 0x2a32f48),
    (0x170, '0f8367030000', 2, 6, 0x2a3321d),
    (0x184, '75da', 1, 2, 0x2a32ea0),
    (0x18d, '0f833d030000', 2, 6, 0x2a33210),
    (0x1a2, '0f8242030000', 2, 6, 0x2a3322a),
    (0x1ec, 'eb23', 1, 2, 0x2a32f51),
    (0x206, 'eb09', 1, 2, 0x2a32f51),
    (0x29c, '7621', 1, 2, 0x2a32fff),
    (0x305, '7597', 1, 2, 0x2a32fde),
    (0x30c, '7590', 1, 2, 0x2a32fde),
    (0x311, '758b', 1, 2, 0x2a32fde),
    (0x316, '7459', 1, 2, 0x2a330b1),
    (0x322, '7523', 1, 2, 0x2a33087),
    (0x353, '0f8545ffffff', 2, 6, 0x2a32fde),
    (0x36f, 'eb04', 1, 2, 0x2a330b5),
    (0x39b, '0f832f010000', 2, 6, 0x2a33210),
    (0x442, '7525', 1, 2, 0x2a331a9),
    (0x4cb, 'e9dafdffff', 1, 5, 0x2a32fea),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x2a32e40, 0x2a290f0),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x2a32f5c, 0x5774b68),
    (0x2a32f97, 0x576e1a8),
    (0x2a3302c, 0x576e1a8),
    (0x2a3308a, 0x576e1a8),
    (0x2a33217, 0x576e470),
    (0x2a33224, 0x576dfc8),
    (0x2a33231, 0x576e150),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2a33210, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2a3321d, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x2a3322a, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774f28']
GOT_SITES = {'0x5774f28': ['0x27dc7bf', '0x28c255b']}


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

