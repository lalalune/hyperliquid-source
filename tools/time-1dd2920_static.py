#!/usr/bin/env python3
"""Authenticated node94 time-1dd2920 binding (0x1dd2920).

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

START, END = 0x1dd2920, 0x1dd2ebc
FDE_VA = 0x1041588
FDE = bytes.fromhex(
    '50000000603908009013d9009c05000004aff394ff410e10420e18420e20420e'
    '28420e30410e38470ef00183078c068d058e048f03860203bb040e38410e3042'
    '0e28420e20420e18420e10410e08410ef0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecb80000004989cd4989f44889fb49be00000000'
    '00000080488b364889f048f7d8711a48895c24284d8b7c242841807f0c02751c'
    '4c896c244831c0eb4241807c241c020f859f00000031c0e9ba0000004889d348'
    '8d7c24104c89feba02000000e83f727d00488b4424104883f8020f854c010000'
    '4c896c24484c89f04889da488944247848c78424800000000100000048c78424'
    '88000000000000004c89bc2490000000c784249800000002000000488d7c2410'
    '488d742478e8b6a60300498d5e0448395c24100f85c20000004c8b7c24784d39'
    'f70f85fe0100004c8bac2490000000e98f020000498b4424104839c60f84d503'
    '0000498b4c2408c604019248ffc049894424104c89f0488944245048c7442458'
    '0100000048c7442460000000004c89642468c744247002000000488d7c241048'
    '8d742450e857ac03004d8d7e044c397c24107518488b4424504c39f00f858400'
    '0000488b6c2468e93f010000488b44242048894424400f104424100f29442430'
    '4c8b7424504a8d0475000000004885c00f8486020000e9a5020000488b442420'
    '488b4c2428488941100f104424100f11014c8b7424784a8d0475000000004885'
    'c00f84fe020000e9e6020000488b4c2418488b5424284c89324889420848894a'
    '10e9df0200004889442408bf3bf90a00ff157abd990385c00f8414030000488b'
    '6c24688b542470488dbc24a80000004889eee8696f7d00488b8424a800000048'
    '83f8020f858b0100004c89bc24a00000004c896c244848895c24284c8b7c2458'
    '4c8b6c24604d85ed743531db0f1f4000410fb6141f488dbc24a80000004889ee'
    'e8bb917d00488b8424a80000004883f8020f855101000048ffc34939dd75d148'
    '8b7424084885f6740b4c89ff31d2ff155cb499034c89742450488b5c24284c8b'
    '6c24484c8bbc24a0000000488d7c24104c89ee4889eae885af98004c397c2410'
    '0f852b010000488d7c2430488d742450e88bfe03004c397c24300f8443010000'
    'e972010000bf3bf90a00ff1580bc990385c00f84290200004c8bac2490000000'
    '8b942498000000488d7c24304c89eee89c6f7d00488b4424304883f8020f859b'
    '0000004c897c24084c8bbc24800000004c8ba424880000004d85e4742c31ed90'
    '410fb6142f488d7c24304c89eee85e947d00488b4424304883f8020f85090100'
    '0048ffc54939ec75d7488b7424084885f6740b4c89ff31d2ff1572b399034c89'
    '742478488d7c2410488b7424484c89eae87bab980048395c2410488b7c24280f'
    '85e6000000488d742478e8f1fe0300e911010000488b8c24b0000000eb1f488b'
    '4c2438e9ac000000488b8c24b0000000488b5c24284c8bbc24a00000004c8974'
    '2410488944241848894c24204c8b742408488b4424204889442440488b442410'
    '4889442430488b44241848894424384a8d0475000000004885c075244c397c24'
    '307534418b44242083f8ff0f84d4000000ffc041894424204c893be985000000'
    '488b7c24584c89f631d2ff15a0b299034c397c243074cc488b44244048894310'
    '0f284424300f1103eb5b488b4c24384c8b7c24084c8974241048894424184889'
    '4c24204d89fe488b7c2428488b44242048894710488b442410488907488b4424'
    '18488947084a8d0475000000004885c07413488bbc24800000004c89f631d2ff'
    '152bb299034881c4b80000005b415c415d415e415f5dc34989df4889d3ba0100'
    '0000b90100000041b8010000004c89e7e85b8274004889da4c89fb498b442410'
    'e9fdfbffff488d3d2cbc8b03ff15e6b29903488d3dbf7c8903ff1531b69903eb'
    '0d488d3db07c8903ff1522b699030f0b4889c3eb124889c3eb364889c3488b44'
    '24784889442408488b442408488d0445000000004885c0743b488bbc24800000'
    '00eb244889c3488b4424504889442408488b442408488d0445000000004885c0'
    '7412488b7c2458488b74240831d2ff155cb199034889dfe854d28803'
)
BODY_SHA256 = 'ea509608f8f5dd4195b9eb5fa2e84e8ba43de0f392a2e0312bd679c36c084c65'
BRANCHES = [
    (0x2d, '711a', 1, 2, 0x1dd2969),
    (0x3e, '751c', 1, 2, 0x1dd297c),
    (0x47, 'eb42', 1, 2, 0x1dd29ab),
    (0x4f, '0f859f000000', 2, 6, 0x1dd2a14),
    (0x57, 'e9ba000000', 1, 5, 0x1dd2a36),
    (0x7a, '0f854c010000', 2, 6, 0x1dd2aec),
    (0xd3, '0f85c2000000', 2, 6, 0x1dd2abb),
    (0xe1, '0f85fe010000', 2, 6, 0x1dd2c05),
    (0xef, 'e98f020000', 1, 5, 0x1dd2ca3),
    (0xfc, '0f84d5030000', 2, 6, 0x1dd2df7),
    (0x152, '7518', 1, 2, 0x1dd2a8c),
    (0x15c, '0f8584000000', 2, 6, 0x1dd2b06),
    (0x167, 'e93f010000', 1, 5, 0x1dd2bcb),
    (0x190, '0f8486020000', 2, 6, 0x1dd2d3c),
    (0x196, 'e9a5020000', 1, 5, 0x1dd2d60),
    (0x1c1, '0f84fe020000', 2, 6, 0x1dd2de5),
    (0x1c7, 'e9e6020000', 1, 5, 0x1dd2dd2),
    (0x1e1, 'e9df020000', 1, 5, 0x1dd2de5),
    (0x1f8, '0f8414030000', 2, 6, 0x1dd2e32),
    (0x223, '0f858b010000', 2, 6, 0x1dd2cd4),
    (0x248, '7435', 1, 2, 0x1dd2b9f),
    (0x271, '0f8551010000', 2, 6, 0x1dd2ce8),
    (0x27d, '75d1', 1, 2, 0x1dd2b70),
    (0x287, '740b', 1, 2, 0x1dd2bb4),
    (0x2c0, '0f852b010000', 2, 6, 0x1dd2d11),
    (0x2da, '0f8443010000', 2, 6, 0x1dd2d43),
    (0x2e0, 'e972010000', 1, 5, 0x1dd2d77),
    (0x2f2, '0f8429020000', 2, 6, 0x1dd2e41),
    (0x31d, '0f859b000000', 2, 6, 0x1dd2cde),
    (0x33b, '742c', 1, 2, 0x1dd2c89),
    (0x35b, '0f8509010000', 2, 6, 0x1dd2d8a),
    (0x367, '75d7', 1, 2, 0x1dd2c60),
    (0x371, '740b', 1, 2, 0x1dd2c9e),
    (0x39f, '0f85e6000000', 2, 6, 0x1dd2dab),
    (0x3af, 'e911010000', 1, 5, 0x1dd2de5),
    (0x3bc, 'eb1f', 1, 2, 0x1dd2cfd),
    (0x3c3, 'e9ac000000', 1, 5, 0x1dd2d94),
    (0x41a, '7524', 1, 2, 0x1dd2d60),
    (0x421, '7534', 1, 2, 0x1dd2d77),
    (0x42b, '0f84d4000000', 2, 6, 0x1dd2e25),
    (0x43b, 'e985000000', 1, 5, 0x1dd2de5),
    (0x455, '74cc', 1, 2, 0x1dd2d43),
    (0x468, 'eb5b', 1, 2, 0x1dd2de5),
    (0x4b0, '7413', 1, 2, 0x1dd2de5),
    (0x500, 'e9fdfbffff', 1, 5, 0x1dd2a22),
    (0x51f, 'eb0d', 1, 2, 0x1dd2e4e),
    (0x533, 'eb12', 1, 2, 0x1dd2e67),
    (0x538, 'eb36', 1, 2, 0x1dd2e90),
    (0x557, '743b', 1, 2, 0x1dd2eb4),
    (0x561, 'eb24', 1, 2, 0x1dd2ea7),
    (0x580, '7412', 1, 2, 0x1dd2eb4),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x1dd298c, 0x25a9bd0),
    (0x1dd29e5, 0x1e0d0a0),
    (0x1dd2a64, 0x1e0d6c0),
    (0x1dd2b32, 0x25a9aa0),
    (0x1dd2b80, 0x25abd40),
    (0x1dd2bd6, 0x275db60),
    (0x1dd2bf0, 0x1e12a80),
    (0x1dd2c2f, 0x25a9bd0),
    (0x1dd2c6d, 0x25ac0d0),
    (0x1dd2cb0, 0x275d830),
    (0x1dd2cca, 0x1e12bc0),
    (0x1dd2e10, 0x251b070),
    (0x1dd2eb7, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x1dd2b10, 0x576e890),
    (0x1dd2bae, 0x576e010),
    (0x1dd2c0a, 0x576e890),
    (0x1dd2c98, 0x576e010),
    (0x1dd2d6a, 0x576e010),
    (0x1dd2ddf, 0x576e010),
    (0x1dd2e2c, 0x576e118),
    (0x1dd2e39, 0x576e470),
    (0x1dd2e48, 0x576e470),
    (0x1dd2eae, 0x576e010),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x1dd2e25, 0x568ea58, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f726d702d73657264652d312e332e302f7372632f656e636f64652e7273'), 525, 17),
    (0x1dd2e32, 0x566aaf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f74696d652e7273'), 74, 55),
    (0x1dd2e41, 0x566aaf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f74696d652e7273'), 74, 55),
]
CALLERS = [0x1e4ad6f, 0x1e4ae9e]
CALLER_FUNCTIONS = {'0x1e4ad6f': ('0x1e4acb0', '0x1e4af3b'), '0x1e4ae9e': ('0x1e4acb0', '0x1e4af3b')}
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

