#!/usr/bin/env python3
"""Authenticated node94 stake-requirement-2512770 binding (0x2512770).

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

START, END = 0x2512770, 0x2512ac8
FDE_VA = 0x10c7b7c
FDE = bytes.fromhex(
    '50000000549f1000ecab44015803000004a3c493ff410e10420e18420e20420e'
    '28420e30410e38470ec00283078c068d058e048f03860203b1020e38410e3042'
    '0e28420e20420e18420e10410e08410ec0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec080100004989ff66c744247086010f10060f10'
    '4e100f1056200f295424500f294c24400f29442430488d542470488954246048'
    '8d7c2430488d74240fe812311a00a8010f84720100004889d3488b4424606681'
    '3886017533488b442450488b4c24584889ca4801c20f82730200004883fa040f'
    '92c2be040000004829c64839ce0f92c084c20f85650200004c897c2428bf2000'
    '0000ff15c0b725034885c00f842b0200004889c548891848c744241004000000'
    '488944241848c744242001000000488b44246048898424000100000f28442430'
    '0f284c24400f285424500f299424f00000000f298c24e00000000f298424d000'
    '000041be010000004c8dbc24d00000004c8d64240f4c8d6c2410eb310f1f4000'
    'ba01000000b90800000041b8080000004c89ef4c89f6e8c5870000488b6c2418'
    '4a895cf50049ffc64c89742420488b9424000100004c89ff4c89e6e800301a00'
    'a80174794889d34c3b74241075d2488b842400010000668138860175a3488b84'
    '24f0000000488b8c24f80000004889ca4801c20f82340100004883fa040f92c2'
    'be040000004829c64839ce0f92c084c20f846affffff488d3d83581a03ff151d'
    'b82503e94201000066817c24708601753bbf0800000031f64531f6eb18488b74'
    '2410488b7c241866817c2470860175684c8b7c24284989770849897f104d8977'
    '186641c7078601e9ac0000000f108424c0000000410f1147500f108424b00000'
    '00410f1147400f104424700f108c24800000000f109424900000000f109c24a0'
    '000000410f115f30410f115720410f114f10410f1107eb600f108424c0000000'
    '4c8b7c2428410f1147500f108424b0000000410f1147400f104424700f108c24'
    '800000000f109424900000000f109c24a0000000410f115f30410f115720410f'
    '114f10410f11074885f6740c48c1e60331d2ff15e8b525034c89f84881c40801'
    '00005b415c415d415e415f5dc3488d3d6c571a03ff15ceb62503eb2ebf080000'
    '00be20000000ff155cb52503eb1c488d3d4b571a03ff15adb62503eb0d488d3d'
    '3c571a03ff15d6b625030f0b4889c3eb264889c3eb0d4889c34c8b7424104d85'
    'f67414488b7c241849c1e6034c89f631d2ff1569b5250366817c24708601740a'
    '488d7c2470e8863bffff4889dfe84ed61403ff1560b62503'
)
BODY_SHA256 = '4b198eb18d175d64eec2f5b94bb91862bae95df787a7e758b61fcef0ad94c3cb'
BRANCHES = [
    (0x50, '0f8472010000', 2, 6, 0x2512938),
    (0x63, '7533', 1, 2, 0x2512808),
    (0x75, '0f8273020000', 2, 6, 0x2512a5e),
    (0x92, '0f8565020000', 2, 6, 0x2512a6d),
    (0xab, '0f842b020000', 2, 6, 0x2512a4c),
    (0x11a, 'eb31', 1, 2, 0x25128bd),
    (0x162, '7479', 1, 2, 0x251294d),
    (0x16c, '75d2', 1, 2, 0x25128b0),
    (0x17b, '75a3', 1, 2, 0x2512890),
    (0x193, '0f8234010000', 2, 6, 0x2512a3d),
    (0x1b0, '0f846affffff', 2, 6, 0x2512890),
    (0x1c3, 'e942010000', 1, 5, 0x2512a7a),
    (0x1cf, '753b', 1, 2, 0x251297c),
    (0x1db, 'eb18', 1, 2, 0x2512965),
    (0x1ee, '7568', 1, 2, 0x25129c8),
    (0x207, 'e9ac000000', 1, 5, 0x2512a28),
    (0x256, 'eb60', 1, 2, 0x2512a28),
    (0x2aa, '740c', 1, 2, 0x2512a28),
    (0x2da, 'eb2e', 1, 2, 0x2512a7a),
    (0x2ec, 'eb1c', 1, 2, 0x2512a7a),
    (0x2fb, 'eb0d', 1, 2, 0x2512a7a),
    (0x30f, 'eb26', 1, 2, 0x2512aa7),
    (0x314, 'eb0d', 1, 2, 0x2512a93),
    (0x321, '7414', 1, 2, 0x2512aa7),
    (0x33e, '740a', 1, 2, 0x2512aba),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x25127b9, 0x26b58d0),
    (0x25128a6, 0x251b070),
    (0x25128cb, 0x26b58d0),
    (0x2512ab5, 0x2506640),
    (0x2512abd, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x2512812, 0x576dfd8),
    (0x251292d, 0x576e150),
    (0x2512a22, 0x576e010),
    (0x2512a44, 0x576e118),
    (0x2512a56, 0x576dfb8),
    (0x2512a65, 0x576e118),
    (0x2512a74, 0x576e150),
    (0x2512aa1, 0x576e010),
    (0x2512ac2, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x2512926, 0x56b81b0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f7374616b655f726571756972656d656e742e7273'), 5, 62),
    (0x2512a3d, 0x56b81b0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f7374616b655f726571756972656d656e742e7273'), 5, 62),
    (0x2512a5e, 0x56b81b0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f7374616b655f726571756972656d656e742e7273'), 5, 62),
    (0x2512a6d, 0x56b81b0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f65786368616e67652f7374616b655f726571756972656d656e742e7273'), 5, 62),
]
CALLERS = [0x26fc8ec, 0x2751e21, 0x27588a8]
CALLER_FUNCTIONS = {'0x26fc8ec': ('0x26fbab0', '0x26fd364'), '0x2751e21': ('0x2751b30', '0x2751fbc'), '0x27588a8': ('0x2758800', '0x2758adb')}
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

