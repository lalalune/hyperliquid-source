#!/usr/bin/env python3
"""Authenticated node94 u-471c760 binding (0x471c760).

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

START, END = 0x471c760, 0x471ce30
FDE_VA = 0x1281b1c
FDE = bytes.fromhex(
    '50000000f43e2c003cac4903d006000004c3b98eff410e10420e18420e20420e'
    '28420e30410e38470ee00283078c068d058e048f0386020324030e38410e3042'
    '0e28420e20420e18420e10410e08410ee0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec280100004889fb85d20f848f0000004c8b3e4c'
    '8b6e084c8b6610c644240d00c644240e00488d15c8200101488d7c240d488d74'
    '240ee8d94ec6ff4885c00f85f0020000807c240d000f84920100000fb66c240e'
    '48c7c1d8eeffff644c8b3425000000004901ce640fb6414883f8010f84260300'
    '0083f8020f850103000040886c24104c8d642411c644241100488d3de81f0101'
    'ff1512210501e96605000049bf2b00000000000080488b064c8b7608488b4e10'
    '488b0948894424684c8974247048c74424580100000048894c246048c7442478'
    '00000000488dbc2480000000488d742458e8ba1d5600488b8424800000000f10'
    '8424880000000f294424300f108424980000000f294424404c39f875240f2844'
    '24300f284c24400f294424100f294c24200f114b180f1143084c893be9330100'
    '00488b8c24c800000048898c24200100000f108424a80000000f108c24b80000'
    '000f118c24100100000f118424000100000f284424300f284c24400f118424e0'
    '0000000f118c24f000000048898424d80000004c2b7424700f8239040000488d'
    '8c24000100000f1041e00f1049f00f294c24200f29442410488b512048895348'
    '0f10010f1049100f114b380f1143284889030f284424100f284c24200f114308'
    '0f114b184c897358e93501000049be2b00000000000080498b04244c897c2468'
    '4c896c247048c744245801000000488944246048c744247800000000488dbc24'
    '80000000488d742458e8821c5600488b8424800000000f108424880000000f29'
    '4424300f108424980000000f294424404c39f075260f284424300f284c24400f'
    '294424100f294c24200f114b180f1143084c893331c0e9ac000000488b8c24c8'
    '00000048898c24200100000f108424a80000000f108c24b80000000f118c2410'
    '0100000f118424000100000f284424300f284c24400f118424e00000000f118c'
    '24f000000048898424d80000004c2b6c24700f820e030000488d8c2400010000'
    '0f1041e00f1049f00f294c24200f29442410488b5120488953480f10010f1049'
    '100f114b380f1143284889030f284424100f284c24200f1143080f114b184c89'
    '6b58b801000000488943504889d84881c4280100005b415c415d415e415f5dc3'
    '48898424d800000048899424e0000000488d8424d80000004889842480000000'
    '488d05a9d054004889842488000000488d3d77d9acfb488d15831d0101488db4'
    '2480000000ff15ad150501488d353ea085004c89f7ff15e526050148c7c1d8ee'
    'ffff64c6414801640fb7414464c641440040886c24106689442411640fb66946'
    '4080fd020f84d801000064c641460240886c240f498b04244c897c24684c896c'
    '247048c744245801000000488944246048c744247800000000488dbc24800000'
    '00488d742458e8a51a560048b92b00000000000080488b8424800000000f1084'
    '24880000000f294424300f108424980000000f294424404839c8752c0f284424'
    '300f284c24400f298424800000000f298c24900000000f114b180f1143084889'
    '0b31c0e9b8000000488b8c24c800000048898c24200100000f108424a8000000'
    '0f108c24b80000000f118c24100100000f118424000100000f284424300f284c'
    '24400f118424e00000000f118c24f000000048898424d80000004c2b6c24700f'
    '823f010000488d8c24000100000f1041e00f1049f00f298c24900000000f2984'
    '2480000000488b5120488953480f10010f1049100f114b380f1143284889030f'
    '288424800000000f288c24900000000f1143080f114b184c896b58b801000000'
    '4889435031ff4c8d642411e8805885004885c00f84bc00000080784602757d40'
    '88684648c7c1d8eeffff640fb6414883f801742a83f8020f84cefdffff488d35'
    '6c9e85004c89f7ff151325050148c7c1d8eeffff64c64148014c8d6424116480'
    '7946020f84a2fdffff4983c628488d7424104c89f74c89e2e893318500e989fd'
    'ffff488d15d7290101be3d000000488d3d0cf2fdfb4c8d642411eb13488d15c5'
    '890301be45000000488d3d02440bfcff1563130501eb3a488d3dd2120201ff15'
    '0c140501eb2b488d3dc3120201ff15fd130501eb1c488d3d0c870301ff15b61b'
    '0501eb0d488d3da5120201ff15df1305010f0b4889c3488dbc24d8000000e82d'
    '643e00eb09ff159d1305014889c3488d7c240fff15cf8205014c8d642411eb39'
    'ff15821305014889c3488dbc24d8000000e8fa633e00eb6aff156a1305014889'
    'c3488dbc24d8000000e8e2633e00eb52ff15521305014889c349c7c7d8eeffff'
    '64410fb6474883f801741b83f8027432488d35399d85004c89f7ff15e0230501'
    '6441c64748016441807f460274144983c628488d7424104c89f74c89e2e86e30'
    '85004889dfe8e632f400ff15f8120501'
)
BODY_SHA256 = '71817c9dcca481f7c75ffe56ce6a9dcf5f6219632b17b9b58391aa58a9bfd507'
BRANCHES = [
    (0x16, '0f848f000000', 2, 6, 0x471c80b),
    (0x4a, '0f85f0020000', 2, 6, 0x471caa0),
    (0x55, '0f8492010000', 2, 6, 0x471c94d),
    (0x7b, '0f8426030000', 2, 6, 0x471cb07),
    (0x84, '0f8501030000', 2, 6, 0x471caeb),
    (0xa6, 'e966050000', 1, 5, 0x471cd71),
    (0x11b, '7524', 1, 2, 0x471c8a1),
    (0x13c, 'e933010000', 1, 5, 0x471c9d4),
    (0x198, '0f8239040000', 2, 6, 0x471cd37),
    (0x1e8, 'e935010000', 1, 5, 0x471ca82),
    (0x253, '7526', 1, 2, 0x471c9db),
    (0x276, 'e9ac000000', 1, 5, 0x471ca87),
    (0x2d2, '0f820e030000', 2, 6, 0x471cd46),
    (0x3c4, '0f84d8010000', 2, 6, 0x471cd02),
    (0x43a, '752c', 1, 2, 0x471cbc8),
    (0x463, 'e9b8000000', 1, 5, 0x471cc80),
    (0x4bf, '0f823f010000', 2, 6, 0x471cd64),
    (0x533, '0f84bc000000', 2, 6, 0x471cd55),
    (0x53d, '757d', 1, 2, 0x471cd1c),
    (0x552, '742a', 1, 2, 0x471ccde),
    (0x557, '0f84cefdffff', 2, 6, 0x471ca8b),
    (0x583, '0f84a2fdffff', 2, 6, 0x471ca8b),
    (0x59d, 'e989fdffff', 1, 5, 0x471ca8b),
    (0x5ba, 'eb13', 1, 2, 0x471cd2f),
    (0x5d5, 'eb3a', 1, 2, 0x471cd71),
    (0x5e4, 'eb2b', 1, 2, 0x471cd71),
    (0x5f3, 'eb1c', 1, 2, 0x471cd71),
    (0x602, 'eb0d', 1, 2, 0x471cd71),
    (0x623, 'eb09', 1, 2, 0x471cd8e),
    (0x63e, 'eb39', 1, 2, 0x471cdd9),
    (0x656, 'eb6a', 1, 2, 0x471ce22),
    (0x66e, 'eb52', 1, 2, 0x471ce22),
    (0x689, '741b', 1, 2, 0x471ce06),
    (0x68e, '7432', 1, 2, 0x471ce22),
    (0x6ac, '7414', 1, 2, 0x471ce22),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x471c7a2, 0x4381680),
    (0x471c851, 0x4c7e610),
    (0x471c989, 0x4c7e610),
    (0x471cb66, 0x4c7e610),
    (0x471cc8b, 0x4f72510),
    (0x471ccf8, 0x4f6fe90),
    (0x471cd7e, 0x4b031b0),
    (0x471cdb1, 0x4b031b0),
    (0x471cdc9, 0x4b031b0),
    (0x471ce1d, 0x4f6fe90),
    (0x471ce25, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x471c800, 0x576e918),
    (0x471cae5, 0x576e098),
    (0x471caf5, 0x576f1e0),
    (0x471ccc7, 0x576f1e0),
    (0x471cd2f, 0x576e098),
    (0x471cd3e, 0x576e150),
    (0x471cd4d, 0x576e150),
    (0x471cd5c, 0x576e918),
    (0x471cd6b, 0x576e150),
    (0x471cd85, 0x576e128),
    (0x471cd93, 0x5775068),
    (0x471cda0, 0x576e128),
    (0x471cdb8, 0x576e128),
    (0x471cdd0, 0x576e128),
    (0x471cdfa, 0x576f1e0),
    (0x471ce2a, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x471cd37, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
    (0x471cd46, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
    (0x471cd64, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
]
CALLERS = [0x4b74325]
CALLER_FUNCTIONS = {'0x4b74325': ('0x4b742d0', '0x4b7444e')}
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

