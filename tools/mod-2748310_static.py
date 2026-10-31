#!/usr/bin/env python3
"""Authenticated node94 mod-2748310 binding (0x2748310).

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

START, END = 0x2748310, 0x2748b79
FDE_VA = 0x10f0350
FDE = bytes.fromhex(
    '5000000028271300b87f6501690800000453fc92ff410e10420e18420e20420e'
    '28420e30410e38470e800483078c068d058e048f0386020373070e38410e3042'
    '0e28420e20420e18420e10410e08410e80040000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecc8010000488b29483bae180200000f836e0700'
    '004989cc4989d74989f64889fb4c89442418488b86100200004c69ede8000000'
    '4a837c2860000f8493000000498d862833000031c94183be2833000002480f45'
    'c8418b471089842418010000f3410f6f07f30f7f84240801000048c78424f000'
    '00000000000066c784241c010000000048898c2400010000488d7c2440488d94'
    '24f00000004c89f6e863bcffff0fb74424403d860100000f8522010000488b44'
    '24484889442410488b44245048894424200fb64424588844240fe98f01000049'
    '8db640380000498b8e88380000488d7c24404c89faff153dad020366817c2440'
    '86010f843e010000488d7c2440e86e10c300660fefc0660f7f442440c7442450'
    '00000000f3410f6f0f66410f6e5710660f74d0660f74c8660fdbca660fd7c13d'
    'ffff00000f84fc000000418b471089842401010000f3410f6f07f30f7f8424f1'
    '000000493bae180200000f831f060000498b86100200004280bc28d200000001'
    '75404c01e8f30f6f80d3000000f30f6f8c24f1000000660f74c8660f6e80e300'
    '0000660f6e942401010000660f74d0660fdbd1660fd7c23dffff00000f84a700'
    '000066c703df00488d05717acafd4889430848c7431012000000e99e0500000f'
    'b74c244666894b068b4c2442894b020fb64c24588b54245c89531c8b54245989'
    '53190f10442460f30f6f4c2470f30f6f9424800000000f109c24900000000f11'
    '4320f30f7f4b30f30f7f53400f115b50f30f6f442448668903f30f7f4308884b'
    '18e937050000493bae180200000f833c050000498b86100200004280bc28d200'
    '0000000f8559ffffffc644240f02498db690000000418b466889842478010000'
    '498b46604889842470010000f3410f6f0424660f7f8424f0000000488d7c2440'
    '488d942470010000488d8c24f00000004889b42458010000ff1562c602030fb7'
    '4424403d860100000f850f0100004c8b642448498bb6000200004939f40f8311'
    '0500004c89e148c1e105498bb6f8010000498b9618020000488b440e084839d0'
    '0f8389040000488b0c0e4839d10f837c040000498b96100200004869c0e80000'
    '000fb64402494869c9e80000002a440a480f82cd0400000fb6c8488dbc24f000'
    '0000488b742418ba01000000ff15e6b102030fb78424f00000003d860100000f'
    '85ce0000004c896424184c8ba424f800000066c74424403d014d85e40f842501'
    '0000488d7c2440e804650300498dbe803300004c8b6c24184c89ee4c89e2e8ed'
    '04e6ff807c240f020f84bf03000041833e010f85ae010000498b4e08498b5628'
    '410fb6b6f2080000488dbc24f00000004531c0e8c8f52301e99f0100000fb74c'
    '244666894b068b4c2442894b02488b4c24480f104424600f1143200f10442470'
    '0f1143300f108424800000000f1143400f108424900000000f114350f30f6f44'
    '2450f30f7f431066890348894b08e94a0300000fb78c24f600000066894c242c'
    '8b8c24f2000000894c2428488b8c24f80000000f108424000100000f29842470'
    '0100000f108424100100000f298424800100000f108424200100000f29842490'
    '0100000f108424300100000f298424a0010000f30f6f842440010000660f7f84'
    '24b0010000eb0466b83d0166894424408b442428894424420fb744242c668944'
    '244648894c24480f288424b00100000f11842490000000660f6f842470010000'
    '660f6f8c2480010000660f6f9424900100000f289c24a00100000f119c248000'
    '0000f30f7f542470f30f7f4c2460f30f7f442450498b86000200004885c0740a'
    '48ffc849898600020000493bae180200000f8365020000498b86100200004a8b'
    '4c28604885c9740a4c01e848ffc94889486066c7033d01488d7c2440e82f6303'
    '00e917020000660fefc0660f7f842400010000660f7f8424f0000000488b4c24'
    '104d8ba628330000498dae80000000418b471089442450f3410f6f07660f7f44'
    '2440488d7424404889ef488b542420ff156bbe020384c00f84bb0100004183fc'
    '020f94c00a44240fa801751749c7862833000001000000488b44241049898630'
    '330000418b471089442450410f10070f29442440488d7424404889ef4c8b6424'
    '204c89e2b9010000004c8b6c24104d89e84531c9e8f747fd00498db620040000'
    '488d6c24404889ef4c89e2e8803610004889efe8180613004c8b204c89e14c01'
    'e90f8264010000488908bf14000000ff15735602034885c00f84770100004889'
    'c5498d4660418b4f10894d10f3410f6f07f30f7f450048c74424280100000048'
    '896c243048c7442438010000008b4808898c2468010000488b00488984246001'
    '0000488dbc24700100004c8b7c24204c89fe488b942458010000ff15e8bc0203'
    '4d3bbe180200000f8318010000498b86100200004969cfe80000000fb6440849'
    'f20f104424100f140583b4abfd660f5c059ba4abfd660f28c8660f15c8f20f58'
    'c8488d0df0c0e3fdf20f5e0cc14981c6f3080000488b84248001000048894424'
    '58f30f6f842470010000f30f7f442448f20f114c246048b81300000000000080'
    '4889442440488d742428488d942460010000488d8c24f00000004c8d4424404c'
    '89f7ff15c0bc02034c8b6c24184c896b0866c7038601eb0566c70379014881c4'
    'c80100005b415c415d415e415f5dc3488d3d4a97fa02ff15c4590203488d3d55'
    '97fa02ff15b7590203eb47488d35b672f90231ff4989c5ff15c3a602034c89e8'
    '4c0364241048c7c1ffffffff490f43cce972feffffbf01000000be14000000ff'
    '152b550203488d3df496fa02ff156e5902030f0b488d15cd94fa024c89e7ff15'
    'b4540203488d3d3d97fa02ff152f5602034889c3eb204889c3488bb424700100'
    '004885f67410488bbc247801000031d2ff15ca540203be140000004889ef31d2'
    'ff15ba5402034889dfe8b275f1024889c3488d7c2440e8356003004889dfe89d'
    '75f102ff15af550203'
)
BODY_SHA256 = '744796ffc553b5967e31c94c8bcf0ee5b4c59c180790300e9937f9ddfb6011ac'
BRANCHES = [
    (0x1b, '0f836e070000', 2, 6, 0x2748a9f),
    (0x46, '0f8493000000', 2, 6, 0x27483ef),
    (0xb7, '0f8522010000', 2, 6, 0x27484ef),
    (0xda, 'e98f010000', 1, 5, 0x274857e),
    (0x102, '0f843e010000', 2, 6, 0x2748556),
    (0x144, '0f84fc000000', 2, 6, 0x2748556),
    (0x16a, '0f831f060000', 2, 6, 0x2748a9f),
    (0x180, '7540', 1, 2, 0x27484d2),
    (0x1bc, '0f84a7000000', 2, 6, 0x2748579),
    (0x1da, 'e99e050000', 1, 5, 0x2748a8d),
    (0x241, 'e937050000', 1, 5, 0x2748a8d),
    (0x24d, '0f833c050000', 2, 6, 0x2748a9f),
    (0x263, '0f8559ffffff', 2, 6, 0x27484d2),
    (0x2c8, '0f850f010000', 2, 6, 0x27486ed),
    (0x2dd, '0f8311050000', 2, 6, 0x2748b04),
    (0x300, '0f8389040000', 2, 6, 0x2748a9f),
    (0x30d, '0f837c040000', 2, 6, 0x2748a9f),
    (0x331, '0f82cd040000', 2, 6, 0x2748b14),
    (0x35f, '0f85ce000000', 2, 6, 0x2748743),
    (0x37c, '0f8425010000', 2, 6, 0x27487b7),
    (0x3a8, '0f84bf030000', 2, 6, 0x2748a7d),
    (0x3b2, '0f85ae010000', 2, 6, 0x2748876),
    (0x3d8, 'e99f010000', 1, 5, 0x274888c),
    (0x42e, 'e94a030000', 1, 5, 0x2748a8d),
    (0x4a5, 'eb04', 1, 2, 0x27487bb),
    (0x51e, '740a', 1, 2, 0x274883a),
    (0x531, '0f8365020000', 2, 6, 0x2748aac),
    (0x546, '740a', 1, 2, 0x2748862),
    (0x561, 'e917020000', 1, 5, 0x2748a8d),
    (0x5b7, '0f84bb010000', 2, 6, 0x2748a88),
    (0x5ca, '7517', 1, 2, 0x27488f3),
    (0x641, '0f8264010000', 2, 6, 0x2748abb),
    (0x658, '0f8477010000', 2, 6, 0x2748ae5),
    (0x6c7, '0f8318010000', 2, 6, 0x2748af5),
    (0x776, 'eb05', 1, 2, 0x2748a8d),
    (0x7a9, 'eb47', 1, 2, 0x2748b02),
    (0x7d0, 'e972feffff', 1, 5, 0x2748957),
    (0x814, 'eb20', 1, 2, 0x2748b46),
    (0x824, '7410', 1, 2, 0x2748b46),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x27483b8, 0x2744020),
    (0x274841d, 0x3379490),
    (0x2748697, 0x277eba0),
    (0x27486ae, 0x25a8ba0),
    (0x27486e3, 0x3987cb0),
    (0x274886c, 0x277eba0),
    (0x2748924, 0x371d120),
    (0x274893b, 0x284bfc0),
    (0x2748943, 0x2878f60),
    (0x2748b59, 0x5660110),
    (0x2748b66, 0x277eba0),
    (0x2748b6e, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x2748405, 0x5773148),
    (0x27485c8, 0x5774c30),
    (0x274865c, 0x5773848),
    (0x27488bf, 0x5774730),
    (0x274895f, 0x576dfd8),
    (0x27489ca, 0x57746b8),
    (0x2748a72, 0x5774738),
    (0x2748aa6, 0x576e470),
    (0x2748ab3, 0x576e470),
    (0x2748ac7, 0x5773190),
    (0x2748aef, 0x576e020),
    (0x2748afc, 0x576e470),
    (0x2748b0e, 0x576dfc8),
    (0x2748b1b, 0x576e150),
    (0x2748b40, 0x576e010),
    (0x2748b50, 0x576e010),
    (0x2748b73, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2748a9f, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2748aac, 0x56f2208, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 119, 37),
    (0x2748af5, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x2748b04, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x2748b14, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x27479f7, 0x274d3e3, 0x274d5dd, 0x274f947]
CALLER_FUNCTIONS = {'0x27479f7': ('0x2747390', '0x2747b4b'), '0x274d3e3': ('0x274c9f0', '0x274daf5'), '0x274d5dd': ('0x274c9f0', '0x274daf5'), '0x274f947': ('0x274f860', '0x274f994')}
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

