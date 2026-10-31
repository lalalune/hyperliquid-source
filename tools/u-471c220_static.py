#!/usr/bin/env python3
"""Authenticated node94 u-471c220 binding (0x471c220).

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

START, END = 0x471c220, 0x471c759
FDE_VA = 0x1281ac8
FDE = bytes.fromhex(
    '50000000a03e2c0050a749033905000004a7b98eff410e10420e18420e20420e'
    '28420e30410e38470ee00183078c068d058e048f0386020320020e38410e3042'
    '0e28420e20420e18420e10410e08410ee0010000'
)
BODY = bytes.fromhex(
    '554157415641554154534881eca80000004889fb85d20f848f0000004c8b3e4c'
    '8b6e084c8b6610c644240d00c644240e00488d1508260101488d7c240d488d74'
    '240ee8e954c6ff4885c00f85ec010000807c240d000f84fd0000000fb66c240e'
    '48c7c1d8eeffff644c8b3425000000004901ce640fb6414883f8010f84100200'
    '0083f8020f85eb01000040886c240a4c8d64240bc644240b00488d3d28250101'
    'ff1552260501e9cf030000488b064c8b7608488b4e10488b0948894424484c89'
    '74245048c74424380100000048894c244048c744245800000000488d7c241048'
    '8d742438e837e3e0ff0f104424180f104c24280f294424600f294c2470807c24'
    '10000f85a10000000f284424600f284c24700f298c24900000000f2984248000'
    '00004c2b7424500f82130300000f288424800000000f288c24900000000f294c'
    '24200f294424100f114b180f1143084c897330e9c1000000498b04244c897c24'
    '484c896c245048c744243801000000488944244048c744245800000000488d7c'
    '2410488d742438e894e2e0ff8b4424100f104424180f294424600f104424280f'
    '2944247083f80175250f284424600f284c24700f294c24200f294424100f114b'
    '180f114308b90100000031c0eb520f284424600f284c24700f298c2490000000'
    '0f298424800000004c2b6c24500f825c0200000f288424800000000f288c2490'
    '0000000f294c24200f294424100f114b180f1143084c896b30b80100000031c9'
    '48890b488943284889d84881c4a80000005b415c415d415e415f5dc348894424'
    '384889542440488d4424384889442410488d05f9d654004889442418488d3dca'
    'dfacfb488d15d6230101488d742410ff15031c0501488d3594a685004c89f7ff'
    '153b2d050148c7c1d8eeffff64c6414801640fb7414464c641440040886c240a'
    '668944240b640fb669464080fd020f845701000064c641460240886c240f498b'
    '04244c897c24484c896c245048c744243801000000488944244048c744245800'
    '000000488d7c2410488d742438e82ee1e0ff8b4424100f104424180f29442460'
    '0f104424280f2944247083f80175250f284424600f284c24700f294c24200f29'
    '4424100f114b180f114308b90100000031c0eb520f284424600f284c24700f29'
    '8c24900000000f298424800000004c2b6c24500f82140100000f288424800000'
    '000f288c24900000000f294c24200f294424100f114b180f1143084c896b30b8'
    '0100000031c948890b4889432831ff4c8d64240be8575f85004885c00f84bc00'
    '000080784602757d4088684648c7c1d8eeffff640fb6414883f801742a83f802'
    '0f8461feffff488d3543a585004c89f7ff15ea2b050148c7c1d8eeffff64c641'
    '48014c8d64240b64807946020f8435feffff4983c628488d74240a4c89f74c89'
    'e2e86a388500e91cfeffff488d15ae300101be3d000000488d3de3f8fdfb4c8d'
    '64240beb13488d159c900301be45000000488d3dd94a0bfcff153a1a0501eb3a'
    '488d3da9190201ff15e31a0501eb2b488d3d9a190201ff15d41a0501eb1c488d'
    '3de38d0301ff158d220501eb0d488d3d7c190201ff15b61a05010f0b4889c348'
    '8dbc2480000000e8a4574000eb09ff15741a05014889c3488d7c240fff15a689'
    '05014c8d64240beb39ff15591a05014889c3488dbc2480000000e871574000eb'
    '6aff15411a05014889c3488dbc2480000000e859574000eb52ff15291a050148'
    '89c349c7c7d8eeffff64410fb6474883f801741b83f8027432488d3510a48500'
    '4c89f7ff15b72a05016441c64748016441807f460274144983c628488d74240a'
    '4c89f74c89e2e8453785004889dfe8bd39f400ff15cf190501'
)
BODY_SHA256 = '3c292fa4a8efbc0a6cf964ffdf37dbe92643e10b49c149f421cd482200d4d12a'
BRANCHES = [
    (0x16, '0f848f000000', 2, 6, 0x471c2cb),
    (0x4a, '0f85ec010000', 2, 6, 0x471c45c),
    (0x55, '0f84fd000000', 2, 6, 0x471c378),
    (0x7b, '0f8410020000', 2, 6, 0x471c4b1),
    (0x84, '0f85eb010000', 2, 6, 0x471c495),
    (0xa6, 'e9cf030000', 1, 5, 0x471c69a),
    (0x102, '0f85a1000000', 2, 6, 0x471c3c9),
    (0x127, '0f8213030000', 2, 6, 0x471c660),
    (0x153, 'e9c1000000', 1, 5, 0x471c439),
    (0x1a7, '7525', 1, 2, 0x471c3ee),
    (0x1cc, 'eb52', 1, 2, 0x471c440),
    (0x1ed, '0f825c020000', 2, 6, 0x471c66f),
    (0x2ae, '0f8457010000', 2, 6, 0x471c62b),
    (0x30d, '7525', 1, 2, 0x471c554),
    (0x332, 'eb52', 1, 2, 0x471c5a6),
    (0x353, '0f8214010000', 2, 6, 0x471c68d),
    (0x39c, '0f84bc000000', 2, 6, 0x471c67e),
    (0x3a6, '757d', 1, 2, 0x471c645),
    (0x3bb, '742a', 1, 2, 0x471c607),
    (0x3c0, '0f8461feffff', 2, 6, 0x471c447),
    (0x3ec, '0f8435feffff', 2, 6, 0x471c447),
    (0x406, 'e91cfeffff', 1, 5, 0x471c447),
    (0x423, 'eb13', 1, 2, 0x471c658),
    (0x43e, 'eb3a', 1, 2, 0x471c69a),
    (0x44d, 'eb2b', 1, 2, 0x471c69a),
    (0x45c, 'eb1c', 1, 2, 0x471c69a),
    (0x46b, 'eb0d', 1, 2, 0x471c69a),
    (0x48c, 'eb09', 1, 2, 0x471c6b7),
    (0x4a7, 'eb39', 1, 2, 0x471c702),
    (0x4bf, 'eb6a', 1, 2, 0x471c74b),
    (0x4d7, 'eb52', 1, 2, 0x471c74b),
    (0x4f2, '741b', 1, 2, 0x471c72f),
    (0x4f7, '7432', 1, 2, 0x471c74b),
    (0x515, '7414', 1, 2, 0x471c74b),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x471c262, 0x4381750),
    (0x471c304, 0x452a640),
    (0x471c3a7, 0x452a640),
    (0x471c50d, 0x452a640),
    (0x471c5b4, 0x4f72510),
    (0x471c621, 0x4f6fe90),
    (0x471c6a7, 0x4b21e50),
    (0x471c6da, 0x4b21e50),
    (0x471c6f2, 0x4b21e50),
    (0x471c746, 0x4f6fe90),
    (0x471c74e, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x471c2c0, 0x576e918),
    (0x471c48f, 0x576e098),
    (0x471c49f, 0x576f1e0),
    (0x471c5f0, 0x576f1e0),
    (0x471c658, 0x576e098),
    (0x471c667, 0x576e150),
    (0x471c676, 0x576e150),
    (0x471c685, 0x576e918),
    (0x471c694, 0x576e150),
    (0x471c6ae, 0x576e128),
    (0x471c6bc, 0x5775068),
    (0x471c6c9, 0x576e128),
    (0x471c6e1, 0x576e128),
    (0x471c6f9, 0x576e128),
    (0x471c723, 0x576f1e0),
    (0x471c753, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x471c660, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
    (0x471c66f, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
    (0x471c68d, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
]
CALLERS = [0x4b73e5f]
CALLER_FUNCTIONS = {'0x4b73e5f': ('0x4b73e10', '0x4b73f43')}
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

