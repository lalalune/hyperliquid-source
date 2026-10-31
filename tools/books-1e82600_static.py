#!/usr/bin/env python3
"""Authenticated node94 books-1e82600 binding (0x1e82600).

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

START, END = 0x1e82600, 0x1e82a71
FDE_VA = 0xd1f2c4
FDE = bytes.fromhex(
    '4c000000b0dd0300343316017104000000410e10420e18420e20420e28420e30'
    '410e38470e800283078c068d058e048f0386020321040e38410e30420e28420e'
    '20420e18420e10410e08410e80020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ecc80000004989f64889fb488b0e4c8b6e08498b'
    '7d0048ba4b598638d6c56d344889f848f7e248c1ea0b4869c2102700004829c7'
    '488b71104839f70f830a0400004d8b6618493b5424300f85e1030000493b7c24'
    '100f83d6030000488d047f498b5424084889c648c1e6040fb654322a4883fa07'
    '0f83c4030000488b490848c1e00549bfffffffffffff0f00be06000000f20f10'
    '04010f1405d71738fe29d6660f5c05ed0738fe660f28c8660f15c8f20f58c8c1'
    'e603488d05c7e755fef20f5e0c0666480f7ec848bdffffffffffffff7f4889c1'
    '4821e948ba000000000000f07f4839d10f8d860000004889c248c1ea344889c1'
    '4c21f981e2ff070000742248c1e92089442430c74424380000000081c9000010'
    '00894c243481c2cdfbffffeb1e4885c9746548c1e92089442430894c2434c744'
    '243800000000bacefbffff31c94885c00f99c1488d7c2408488d74243041b801'
    '00000041b901000000e8d29f0203807c24080066c7442430ac00754366c74424'
    '30ac00488d7c2430e863b00200c744240400000000eb7248c1e83fc1e01f8944'
    '240c488b05fb5538fe48894424108b05f85538fe8944241866c7442430ac008b'
    '44240c89442420488b44241048894424248b4424188944242c488d7c2430e82d'
    'fd8d01660f10442420660f118424b8000000660f11442434660f298424900000'
    '00c744240401000000498b4e10498b7d004889f849be4b598638d6c56d3449f7'
    'e648c1ea0b4869c2102700004829c7488b71104839f70f83280200004869ffd8'
    '00000048037908e814de85004889c1498b75004889f049f7e648c1ea0b493b54'
    '24300f85d50100004869c2102700004829c6493b7424100f83c0010000498b44'
    '2408488d147648c1e2040fb644102a4883f8070f83b1010000ba0600000029c2'
    '66480f6ec1660f6205d31538fe660f5c05eb0538fe660f28c8660f15c8f20f58'
    'c8c1e203488d05c5e555fef20f5e0c0266480f7ec84821c548b9000000000000'
    'f07f4839cd7c098b6c2404e98c0000004889c248c1ea344921c781e2ff070000'
    '742449c1ef2089442430c7442438000000004181cf0000100044897c243481c2'
    'cdfbffffeb1f4d85ff746649c1ef208944243044897c2434c744243800000000'
    'bacefbffff31c94885c00f99c1488d7c2408488d74243041b80100000041b901'
    '000000e8d89d02038b44240866c7442430ac0083f8018b6c2404744166c74424'
    '30ac00488d7c2430e863ae020031c0eb7348c1e83fc1e01f8944240c488b0501'
    '5438fe48894424108b05fe5338fe8944241866c7442430ac008b6c24048b4424'
    '0c89442420488b44241048894424248b4424188944242c488d7c2430e82ffb8d'
    '01660f10442420660f118424b8000000660f11442434660f298424a0000000b8'
    '01000000892b0f288424900000000f1143048943140f288424a00000000f1143'
    '18c74328000000004889d84881c4c80000005b415c415d415e415f5dc3488d3d'
    '7cf78603ff1526ba8e03488d3dff088703ff15f9b68e03488d1542d88003ff15'
    '64b58e03488d15f5898303ff1557b58e03'
)
BODY_SHA256 = '6108cfe177fb497839b9784dd36f0148f635e54ba4394cee866923d9c4346c90'
BRANCHES = [
    (0x47, '0f830a040000', 2, 6, 0x1e82a57),
    (0x56, '0f85e1030000', 2, 6, 0x1e82a3d),
    (0x61, '0f83d6030000', 2, 6, 0x1e82a3d),
    (0x80, '0f83c4030000', 2, 6, 0x1e82a4a),
    (0xf0, '0f8d86000000', 2, 6, 0x1e8277c),
    (0x109, '7422', 1, 2, 0x1e8272d),
    (0x12b, 'eb1e', 1, 2, 0x1e8274b),
    (0x130, '7465', 1, 2, 0x1e82797),
    (0x17a, '7543', 1, 2, 0x1e827bf),
    (0x195, 'eb72', 1, 2, 0x1e82809),
    (0x236, '0f8328020000', 2, 6, 0x1e82a64),
    (0x262, '0f85d5010000', 2, 6, 0x1e82a3d),
    (0x277, '0f83c0010000', 2, 6, 0x1e82a3d),
    (0x293, '0f83b1010000', 2, 6, 0x1e82a4a),
    (0x2e5, '7c09', 1, 2, 0x1e828f0),
    (0x2eb, 'e98c000000', 1, 5, 0x1e8297c),
    (0x300, '7424', 1, 2, 0x1e82926),
    (0x324, 'eb1f', 1, 2, 0x1e82945),
    (0x329, '7466', 1, 2, 0x1e82991),
    (0x37a, '7441', 1, 2, 0x1e829bd),
    (0x38f, 'eb73', 1, 2, 0x1e82a04),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x1e82769, 0x4eac740),
    (0x1e82788, 0x1ead7f0),
    (0x1e827de, 0x3762510),
    (0x1e82847, 0x26e0660),
    (0x1e82963, 0x4eac740),
    (0x1e82988, 0x1ead7f0),
    (0x1e829dc, 0x3762510),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x1e82a44, 0x576e470),
    (0x1e82a51, 0x576e150),
    (0x1e82a5e, 0x576dfc8),
    (0x1e82a6b, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x1e82a3d, 0x56f21c0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 194, 38),
    (0x1e82a4a, 0x56f3350, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f706572705f6d6574612e7273'), 319, 28),
    (0x1e82a57, 0x56902a0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 202, 18),
    (0x1e82a64, 0x56bb460, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
]
CALLERS = [0x2572277]
CALLER_FUNCTIONS = {'0x2572277': ('0x2572180', '0x2572333')}
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

