#!/usr/bin/env python3
"""Authenticated node94 spot-meta-3790200 binding (0x3790200).

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

START, END = 0x3790200, 0x379061e
FDE_VA = 0xe5b554
FDE = bytes.fromhex(
    '4c00000040a01700a44c93021e04000000410e10420e18420e20420e28420e30'
    '410e38470ea00983078c068d058e048f038602032c020e38410e30420e28420e'
    '20420e18420e10410e08410ea0090000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec680400004c8bbaf00100000fb6822402000088'
    '44240f488b9af80100004885db74654989f548894c24188844240d48897c2428'
    '488b867001000048894424104939c70f83a10300004989d4488b820002000048'
    '894424204d8bb5680100004c89fd48c1e505498b342e4c89efff15192ffe013c'
    '02731a488b7c242848c70702000000e99f010000c6470809e98f010000498b44'
    '2e084889442440488dbc24980000004c89ee4c89fa4c89f14c8b7c24104d89f8'
    'e8fb6ff9ff80bc249800000001750d0fb68c2499000000e948010000488b8c24'
    'a0000000488b5120493b95880100000f83f4020000498b85800100004869d2e8'
    '00000048837c1060010f8513010000498dac2418020000488b7118b1084829de'
    '0f82fe000000b1090f84f60000004801d04883c050488b4008488b1848897424'
    '484c39fb0f83c102000048897424304889d848c1e005498b0406488944245048'
    '8b44242048894424380fb644240d34018844240e488b4c24184885c90f84c600'
    '0000488d44240f488944245848894c2460488d44240e48894424684c896c2470'
    '488d4424504889442478488d4424384889842480000000488d44244848898424'
    '88000000488d4424404889842490000000488dbc2498000000488d5424584c89'
    'e6e85a8148004c8bac2498000000440fb6bc24a00000004983fd02741d4c8bb4'
    '24900100000fb68424980100004983fe020f85940000004189c74489f9e90901'
    '000031c9488b7c2428884f0848c707030000004889f84881c4680400005b415c'
    '415d415e415f5dc348895c24108844240d4d8b2c24450fb67c2408498d742409'
    '488dbc2479030000488b1d71dbfd01baef000000ffd34d8bb424f8000000410f'
    'b6842400010000884424184981c401010000488dbc248a020000baef0000004c'
    '89e6ffd34c8b642420eb4f8844241848895c2410488db424a10000004c8da424'
    '99010000488dbc2479030000488b1d0ddbfd01baef000000ffd3488dbc248a02'
    '0000baef0000004c89e6ffd30fb644240e8844240d4c8b642438488b44243049'
    'f7e40f90c148bafeffffffffffff7f4839d00f97c24983fe02400f94c64008ce'
    '4008d6b1114080fe01750d488b7c2428884f08e9f4feffff488b5c2428488d7b'
    '09488db4248a020000baef0000004889442420ff1587dafd014c89abf8000000'
    '4488bb00010000488dbb01010000488db42479030000baef000000ff155fdafd'
    '01488b442430488983f0010000488b442410488983f80100004c89a300020000'
    '488b4424204889830802000048c7831002000000000000488b45004889831802'
    '00008b45088983200200004889df0fb644240d8883240200004c89330fb64424'
    '18884308e94afeffff488d3d001cf601ff157adefd01488d15db19f6014c89ff'
    '488b742410ff15bdd9fd01488d15c619f6014889df4c89feff15aad9fd01'
)
BODY_SHA256 = 'be24b749ef69841ef5995e1172ca27fed8c2b5cd48ae90ef6fc97546d42fbbeb'
BRANCHES = [
    (0x2d, '7465', 1, 2, 0x3790294),
    (0x4f, '0f83a1030000', 2, 6, 0x37905f6),
    (0x81, '731a', 1, 2, 0x379029d),
    (0x8f, 'e99f010000', 1, 5, 0x3790433),
    (0x98, 'e98f010000', 1, 5, 0x379042c),
    (0xcd, '750d', 1, 2, 0x37902dc),
    (0xd7, 'e948010000', 1, 5, 0x3790424),
    (0xef, '0f83f4020000', 2, 6, 0x37905e9),
    (0x109, '0f8513010000', 2, 6, 0x3790422),
    (0x120, '0f82fe000000', 2, 6, 0x3790424),
    (0x128, '0f84f6000000', 2, 6, 0x3790424),
    (0x144, '0f83c1020000', 2, 6, 0x379060b),
    (0x17c, '0f84c6000000', 2, 6, 0x3790448),
    (0x1fb, '741d', 1, 2, 0x379041a),
    (0x211, '0f8594000000', 2, 6, 0x37904ab),
    (0x21d, 'e909010000', 1, 5, 0x379052b),
    (0x2a9, 'eb4f', 1, 2, 0x37904fa),
    (0x329, '750d', 1, 2, 0x3790538),
    (0x333, 'e9f4feffff', 1, 5, 0x379042c),
    (0x3e4, 'e94afeffff', 1, 5, 0x3790433),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x37902c0, 0x37272c0),
    (0x37903e1, 0x3c18540),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x3790279, 0x5773198),
    (0x3790553, 0x576dfe0),
    (0x379057b, 0x576dfe0),
    (0x37905f0, 0x576e470),
    (0x3790605, 0x576dfc8),
    (0x3790618, 0x576dfc8),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x37905e9, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x37905f6, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x379060b, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5774370']
GOT_SITES = {'0x5774370': ['0x24f9b7f', '0x2512bca', '0x444d8c3', '0x44727b1']}


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

