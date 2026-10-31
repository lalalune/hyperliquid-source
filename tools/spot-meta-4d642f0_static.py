#!/usr/bin/env python3
"""Authenticated node94 spot-meta-4d642f0 binding (0x4d642f0).

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

START, END = 0x4d642f0, 0x4d649f3
FDE_VA = 0x12e46cc
FDE = bytes.fromhex(
    'a0000000a46a32001cfca7030307000004e7268dff410e10420e18420e20420e'
    '28420e30410e38470ea00383078c068d058e048f03860202852e0002702e005b'
    '2e0003b0012e0002972e0002482e00512e00025e2e00038b012e007a2e10670e'
    'a803410eb003490ea003025b0e38410e30420e28420e20420e18420e10410e08'
    '410ea0032e004d2e004d2e004d2e004d2e004f2e004d2e00502e00502e004a2e'
    '00482e00'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec680100004c8b214c3ba6180200000f835a0600'
    '004989cd4989d74989f64889fb4c89442410488b86100200004969ece8000000'
    '48837c2860000f84ac000000498d86a83d000031c94183bea83d000002480f45'
    'c8418b4710898424a8000000410f10070f1184249800000048c7842480000000'
    '0000000066c78424ac000000000048898c2490000000488d7c2420488d942480'
    '0000004c89f6e85581ffff0fb74424203d860100000f853c0100000fb6442438'
    '884424078b442439894424088b44243c8944240bf30f6f442428660f7f842450'
    '0100008b4424088b4c240b89442418894c241be9ac010000498db6c042000049'
    '8b8e08430000488d7c24204c89faff1544eda00066817c242086010f845c0100'
    '00488d7c2420e8755061fe660fefc0660f7f442420c744243000000000f3410f'
    '6f0f66410f6e5710660f74d0660f74c8660fdbca660fd7c13dffff00000f841a'
    '010000418b471089842491000000f3410f6f07f30f7f8424810000004d3ba618'
    '0200000f8335050000498b861002000080bc28d20000000175404801e8f30f6f'
    '80d3000000f30f6f8c2481000000660f74c8660f6e80e3000000660f6e942491'
    '000000660f74d0660fdbd1660fd7c23dffff00000f84c500000066c703df0048'
    '8d057a0e9bfb4889430848c7431012000000e972040000488b4c243048898c24'
    'ee0000000f104424220f298424e00000000fb64c24388b542439895424088b54'
    '243c8954240b0f104424700f1143500f104424600f1143400f104424500f1143'
    '300f104424400f114320488b9424ee00000048895310660f6f8424e0000000f3'
    '0f7f43028b5424088b74240b89531989731c668903884b18e9ec0300004d3ba6'
    '180200000f83fe030000498b861002000080bc28d2000000000f853bffffffc6'
    '44240702498db690000000418b4668898424e8000000498b466048898424e000'
    '0000f3410f6f4500660f7f842480000000488d7c2420488d9424e0000000488d'
    '8c2480000000ff155406a1000fb74424203d860100000f85400100004c8b6c24'
    '28498bb6000200004939f50f83ba0300004c89e948c1e105498bb6f801000049'
    '8b9618020000488b440e084839d00f8361030000488b0c0e4839d10f83610300'
    '00498b96100200004869c0e80000000fb64402494869c9e80000002a440a480f'
    '82760300000fb6c8488dbc2480000000488b742410ba01000000ff15d8f1a000'
    '0fb78424800000003d860100000f85f90000004c896c24104c8bac2488000000'
    '66c74424203d014d85ed0f8450010000488d7c2420e8f6ad0400498dbe003e00'
    '004c8b6424104c89e64c89eae8ff34ecff0fb64424073c020f8445020000660f'
    '6f842450010000660f7f842430010000888424400100008b4424188b4c241b89'
    '842441010000898c244401000041833e010f85a2010000498b4e08498b562841'
    '0fb6b672130000488dbc24800000004531c0e88935c2fee9930100000fb74c24'
    '2666894b068b4c2422894b02488b4c24280f104424400f1143200f104424500f'
    '1143300f104424600f1143400f104424700f114350f30f6f442430f30f7f4310'
    '66890348894b08e9dd0100000fb78c248600000066894c240c8b8c2482000000'
    '894c2408488b8c24880000000f108424900000000f298424e00000000f108424'
    'a00000000f298424f00000000f108424b00000000f298424000100000f108424'
    'c00000000f29842410010000f30f6f8424d0000000660f7f842420010000eb04'
    '66b83d0166894424208b442408894424220fb744240c668944242648894c2428'
    '0f288424200100000f11442470660f6f8424e0000000660f6f8c24f000000066'
    '0f6f9424000100000f289c24100100000f115c2460f30f7f542450f30f7f4c24'
    '40f30f7f442430498b86000200004885c0740a48ffc8498986000200004d3ba6'
    '180200000f8325010000498b8610020000488b4c28604885c9740a4801e848ff'
    'c94889486066c7033d01488d7c2420e8fcab0400e9b0000000660fefc0660f7f'
    '842490000000660f7f842480000000498d86a83d000031c94183bea83d000002'
    '480f44c14c8d15d539f7ff488d7c2420488d8c24300100004c8d842480000000'
    '4c89f64c89fa4531c9415250e81f4d96ff4883c41066817c2420860175104c8b'
    '6424104c89630866c7038601eb3b0f104424700f1143500f104424600f114340'
    'f30f6f442420f30f6f4c2430f30f6f5424400f105c24500f115b30f30f7f5320'
    'f30f7f4b10f30f7f034881c4680100005b415c415d415e415f5dc3488d3d7ed8'
    '9800ff15f89aa000488d3d71d89800ff15eb9aa000488d3d64d89800ff15de9a'
    'a000488d3d57d89800ff15d19aa000488d3d62d89800ff15c49aa0000f0b488d'
    '3d3bd89800ff15b59aa000488d1516d698004c89efff15fd95a000488d3d86d8'
    '9800ff157897a0004889c3488d7c2420e8bbaa04004889dfe823b78f00ff1535'
    '97a000'
)
BODY_SHA256 = 'fe7d9e1a256580eb5491324062a7f5a8b09ab1ce44bd48b6dc51a501d81915a3'
BRANCHES = [
    (0x1b, '0f835a060000', 2, 6, 0x4d6496b),
    (0x46, '0f84ac000000', 2, 6, 0x4d643e8),
    (0xb5, '0f853c010000', 2, 6, 0x4d644e7),
    (0xf3, 'e9ac010000', 1, 5, 0x4d64594),
    (0x11b, '0f845c010000', 2, 6, 0x4d6456d),
    (0x15d, '0f841a010000', 2, 6, 0x4d6456d),
    (0x183, '0f8335050000', 2, 6, 0x4d649ae),
    (0x198, '7540', 1, 2, 0x4d644ca),
    (0x1d4, '0f84c5000000', 2, 6, 0x4d6458f),
    (0x1f2, 'e972040000', 1, 5, 0x4d64959),
    (0x278, 'e9ec030000', 1, 5, 0x4d64959),
    (0x284, '0f83fe030000', 2, 6, 0x4d64978),
    (0x299, '0f853bffffff', 2, 6, 0x4d644ca),
    (0x2f6, '0f8540010000', 2, 6, 0x4d6472c),
    (0x30b, '0f83ba030000', 2, 6, 0x4d649bb),
    (0x32e, '0f8361030000', 2, 6, 0x4d64985),
    (0x33b, '0f8361030000', 2, 6, 0x4d64992),
    (0x35f, '0f8276030000', 2, 6, 0x4d649cb),
    (0x38d, '0f85f9000000', 2, 6, 0x4d6477c),
    (0x3aa, '0f8450010000', 2, 6, 0x4d647f0),
    (0x3d8, '0f8445020000', 2, 6, 0x4d64913),
    (0x411, '0f85a2010000', 2, 6, 0x4d648a9),
    (0x437, 'e993010000', 1, 5, 0x4d648bf),
    (0x487, 'e9dd010000', 1, 5, 0x4d64959),
    (0x4fe, 'eb04', 1, 2, 0x4d647f4),
    (0x571, '740a', 1, 2, 0x4d6486d),
    (0x584, '0f8325010000', 2, 6, 0x4d6499f),
    (0x599, '740a', 1, 2, 0x4d64895),
    (0x5b4, 'e9b0000000', 1, 5, 0x4d64959),
    (0x61c, '7510', 1, 2, 0x4d6491e),
    (0x62c, 'eb3b', 1, 2, 0x4d64959),
]
DIRECT_CALLS = [
    (0x4d64396, 0x4d5c4f0),
    (0x4d64416, 0x3379490),
    (0x4d646a5, 0x4daf4a0),
    (0x4d646bc, 0x4c27bc0),
    (0x4d64722, 0x3987cb0),
    (0x4d6489f, 0x4daf4a0),
    (0x4d648fc, 0x46c9620),
    (0x4d649e0, 0x4daf4a0),
    (0x4d649e8, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4d643fe, 0x5773148),
    (0x4d645d6, 0x5774c30),
    (0x4d6466a, 0x5773848),
    (0x4d64972, 0x576e470),
    (0x4d6497f, 0x576e470),
    (0x4d6498c, 0x576e470),
    (0x4d64999, 0x576e470),
    (0x4d649a6, 0x576e470),
    (0x4d649b5, 0x576e470),
    (0x4d649c5, 0x576dfc8),
    (0x4d649d2, 0x576e150),
    (0x4d649ed, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4d6496b, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d64978, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d64985, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d64992, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d6499f, 0x56f2208, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 119, 37),
    (0x4d649ae, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4d649bb, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x4d649cb, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x4d62f67, 0x4d6dd12, 0x4d6def1, 0x4d72167]
CALLER_FUNCTIONS = {'0x4d62f67': ('0x4d62900', '0x4d630bb'), '0x4d6dd12': ('0x4d6d570', '0x4d6e373'), '0x4d6def1': ('0x4d6d570', '0x4d6e373'), '0x4d72167': ('0x4d72080', '0x4d721b4')}
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

