#!/usr/bin/env python3
"""Authenticated node94 mod-4322350 binding (0x4322350).

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

START, END = 0x4322350, 0x4322655
FDE_VA = 0xec3364
FDE = bytes.fromhex(
    '48000000501e1e00e4ef45030503000000410e10420e18420e20420e28420e30'
    '410e38440e7083078c068d058e048f03860203ee010e38410e30420e28420e20'
    '420e18420e10410e08410e70'
)
BODY = bytes.fromhex(
    '554157415641554154534883ec384c8b5630488b46104885c00f84b901000048'
    '8b6e084c8b9df80100004c8bad000200004c8ba5080200004883f801753c4d89'
    'e94c89e1498d41ff4839c80f83870100004989d04889c84c09c848c1e8200f84'
    '680100004889c831d249f7f14939c90f8763010000e98d0100004869c0280200'
    '004805d8fdffff4531ff4c8d05b7db40016666666666662e0f1f840000000000'
    '4a8b8c3d2004000048894c24304e8bb43d280400004a8b9c3d300400004d89f1'
    '4d01e9722e4889d94c01e10f828b0000004c395c24300f85fc0000004981c728'
    '0200004d89cd4989cc4c39f875b2e951ffffff48897c242031ff48897424184c'
    '89c648895424104c895424284c895c240848890424ff15250d45014c8d0526db'
    '4001488b04244c8b5c24084c8b542428488b542410488b742418488b7c24204d'
    '01ee48c7c1ffffffff4c0f42f14d89f14889d94c01e10f8375ffffff48897c24'
    '2031ff4889742418488d35f1da400148895424104d89d54c895c24084d89ce48'
    '890424ff15b70c45014c8d05b8da4001488b04244d89f14c8b5c24084d89ea48'
    '8b542410488b742418488b7c24204c01e348c7c1ffffffff480f42d94889d94c'
    '395c24300f8412ffffffeb0c89c831d241f7f14939c9762f66490f6ec2b0010f'
    'b64e48884f110f104e380f114f01f20f11471888074889f84883c4385b415c41'
    '5d415e415f5dc3498b88700100004939cb0f83ce0000004c89cb49c1e3054d8b'
    '8868010000498b90880100004b8b4c19084839d10f839e0000004f8b0c194939'
    'd10f83910000004d8b80800100004869c9e8000000410fb65408494969c9e800'
    '0000410fb64c084838ca0f828800000028ca66480f6ec0f30f7e0db118eefb66'
    '0f62c1660f2815c508eefb660f5cc2660f28d8660f15d8f20f58d80fb6c2488d'
    '157b4e3dfcf20f5e1cc266480f6ee3660f62e1660f5ce2660f28c4660f15c4f2'
    '0f58c4f20f5e04caf20f115f204c89572831c0e907ffffff488d3dc1fb3c01ff'
    '153bbe4401488d159cf93c014c89df4889ceff1580b94401488d3d09fc3c01ff'
    '15fbba4401'
)
BODY_SHA256 = '5ee07e138be7b841a1e58894584cca3f9e8595ec1df0abbab23dfbc5f4d2650d'
BRANCHES = [
    (0x19, '0f84b9010000', 2, 6, 0x4322528),
    (0x3c, '753c', 1, 2, 0x43223ca),
    (0x4b, '0f8387010000', 2, 6, 0x4322528),
    (0x5e, '0f8468010000', 2, 6, 0x432251c),
    (0x6f, '0f8763010000', 2, 6, 0x4322528),
    (0x75, 'e98d010000', 1, 5, 0x4322557),
    (0xc3, '722e', 1, 2, 0x4322443),
    (0xcb, '0f828b000000', 2, 6, 0x43224ac),
    (0xd6, '0f85fc000000', 2, 6, 0x4322528),
    (0xec, '75b2', 1, 2, 0x43223f0),
    (0xee, 'e951ffffff', 1, 5, 0x4322394),
    (0x156, '0f8375ffffff', 2, 6, 0x4322421),
    (0x1c4, '0f8412ffffff', 2, 6, 0x432242c),
    (0x1ca, 'eb0c', 1, 2, 0x4322528),
    (0x1d6, '762f', 1, 2, 0x4322557),
    (0x211, '0f83ce000000', 2, 6, 0x4322635),
    (0x234, '0f839e000000', 2, 6, 0x4322628),
    (0x241, '0f8391000000', 2, 6, 0x4322628),
    (0x26a, '0f8288000000', 2, 6, 0x4322648),
    (0x2d3, 'e907ffffff', 1, 5, 0x432252f),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4322465, 0x5773190),
    (0x43224d3, 0x5773190),
    (0x432262f, 0x576e470),
    (0x4322642, 0x576dfc8),
    (0x432264f, 0x576e150),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4322628, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4322635, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
    (0x4322648, 0x56f2258, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 984, 9),
]
CALLERS = [0x444a668, 0x444aea8, 0x4d1d984, 0x4d1f7b4, 0x4d22339, 0x4d24bf9]
CALLER_FUNCTIONS = {'0x444a668': ('0x444a3b0', '0x444abe6'), '0x444aea8': ('0x444abf0', '0x444b426'), '0x4d1d984': ('0x4d1c1c0', '0x4d1dfe3'), '0x4d1f7b4': ('0x4d1dff0', '0x4d1fe13'), '0x4d22339': ('0x4d20cc0', '0x4d23578'), '0x4d24bf9': ('0x4d23580', '0x4d25e38')}
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

