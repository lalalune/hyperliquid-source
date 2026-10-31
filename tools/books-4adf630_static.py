#!/usr/bin/env python3
"""Authenticated node94 books-4adf630 binding (0x4adf630).

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

START, END = 0x4adf630, 0x4adfe2f
FDE_VA = 0x12bb9d0
FDE = bytes.fromhex(
    '50000000a8dd2f00583c8203ff07000004f37a8dff410e10420e18420e20420e'
    '28420e30410e38470ef00283078c068d058e048f038602039c010e38410e3042'
    '0e28420e20420e18420e10410e08410ef0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec380100004989ce48895424304989ff488b4e10'
    '488d815ffaffff483d63faffff770f6641c707cb0049894f08e9650100004889'
    '8c24c80000004c8b2e0fb65e19488b5608498db690000000488d7c2450488974'
    '24404c89e9e8f6731c000fb74424503d860100000f8587000000498db6800000'
    '004c8b6424584c893424440fb6cb488d7c2450488b5424304c89e94d89e0e89d'
    'fa97ff66817c245086010f85ad000000498bb6903300004939f50f83ed060000'
    '4c896c24204969fdd80000004903be88330000e8c88979fe49f7e40f90c248b9'
    '99999999999999194839c80f97c108d10f84c20000006641c7076900e9a20000'
    '000fb74c24566641894f068b4c245241894f02488b4c24580f10442470410f11'
    '47200f10842480000000410f1147300f10842490000000410f1147400f108424'
    'a0000000410f1147500f10442460410f1147106641890749894f08eb460f1084'
    '24a0000000410f1147500f10842490000000410f1147400f10442450660f104c'
    '24600f105424700f109c2480000000410f115f30410f11572066410f114f1041'
    '0f11074c89f84881c4380100005b415c415d415e415f5dc348898424c0000000'
    '488b4c24308b4110894424600f10010f29442450488d7424504c89f7e8cf37c1'
    'ff0fb6403c3c0473173c030f85400200004180beb1050000007413e931020000'
    '4180beb0050000000f85230200004d8ba6f83400004d85e44c897424284c89bc'
    '24b80000000f84bd000000498b86003500004889442418488b1d1aecc800498d'
    'b42410010000410fb78424ee01000048894424108d0485000000004c8d3c8049'
    'c7c5ffffffff4d89e60f1f80000000004d85ff7438488d6e14ba14000000488b'
    '7c2430ffd348984885c00f98c10f9fc028c84983c61849ffc54983c7ec4889ee'
    '3c0174cc0fb6c085c07507eb224c8b6c2410488b4424184883e801722b488944'
    '24184f8ba4ecf0010000e96fffffff498b0e4c8b742428498b86783300004885'
    'c0751ce93401000031c94c8b742428498b86783300004885c00f841d01000049'
    '8b96703300004869c0380100004801d048898424d0000000eb32660f1f440000'
    '31c04881c2380100004801c14889c848c7c6ffffffff480f42c6480f42c8483b'
    '9424d00000000f84d00000004c8b7a304d85ff74cb48894c2410488954244848'
    '8b5a38498db710010000410fb787ee01000048894424188d048500000000488d'
    '2c8049c7c4ffffffff4d89fd0f1f40004885ed744b4c8d7614ba14000000488b'
    '7c2430ff15afeac80048984885c00f98c10f9fc028c84983c51849ffc44883c5'
    'ec4c89f63c0174c80fb6c085c07516eb2f6666666666662e0f1f840000000000'
    '4c8b6424184883eb01722d4f8bbce7f0010000e96bffffff0f1f840000000000'
    '498b45004c8b742428488b4c2410488b542448e90affffff31c0ebe8493b8e40'
    '0500004c8bbc24b80000000f835701000066c74424506900488d7c2450e83e11'
    '0300488dbc24d8000000488bb424c8000000ff15a067c9006681bc24d8000000'
    '86017573488b8424e0000000486bd86448b9cb10c7bab88d06004839c8480f47'
    'd8488b8c24c00000004839d90f8301010000488b7c2440488b742420ff156e4a'
    'c9004989d64885d20f88100100004d89fd0f843b0200004989c44c89f7ff15e5'
    'e4c8004885c00f840a0300004989c74c89e0e9210200000f108424280100000f'
    '298424a00000000f108424180100000f298424900000000f108424d80000000f'
    '108c24e80000000f109424f80000000f109c24080100000f299c24800000000f'
    '295424700f294c24600f29442450498bb600020000488b7c24204839f70f837a'
    '020000498b86f801000048c1e705488b443808493b86180200000f833e020000'
    '498b8e100200004869c0e80000004c8b7401404d85f6795131ff4c89f6ff1505'
    'e4c800e9420200006641c707cc00e910fcffff48b800406352bfc601004839c1'
    '7648488b7c2440488b742420ff155e49c9004989d64885d20f890e01000031ff'
    '4c89f6ff15bfe3c8004c89fb4c8b64013874324c89f7ff15cce3c8004885c00f'
    '84e70100004989c7eb214c89f7e8bec62a003c020f85c30000006641c7078601'
    'e99efbffff41bf010000004c89ff4c89e64c89f2ff1596e3c800488d7c2450e8'
    '5c0f03004c89b424e80000004c89bc24f00000004c89b424f80000000fb78424'
    'de0000004989df668943068b8424da000000894302488b8424e8000000488b8c'
    '24f0000000488b9424f8000000488bb424000100004889431048894b18488953'
    '20488973280f10842408010000660f108c24180100000f109424280100000f11'
    '4330660f114b400f11535066c703d10048c7430800000000e9e6faffff6641c7'
    '07740041884702e9d7faffff4d89fc0f84870000004889c34c89f7ff15c7e2c8'
    '004885c00f84ec0000004989c74889d8eb7041bf0100000066480f6ec3660f62'
    '054b4172fb660f5c05633172fb660f28c8660f15c8f20f58c8f20f5e0d2fa472'
    'fb660f294c24304c89ff4889c64c89f2ff157ae2c8006641c74500d1000f2844'
    '2430f2410f1145084d8975104d897d184d89ef4d897520e947faffff41bf0100'
    '00004c89ff4889c64c89f2ff153fe2c8006641c70424d20048b800000000d012'
    '534149894424084d897424104d897c24184d89e74d89742420e905faffff488d'
    '3d1b24c100ff1595e6c800eb1d488d153c25c6004c89efff15dbe1c800488d15'
    'e421c100ff15cee1c8000f0bbf01000000e9a4fdffffbf010000004c89f6ff15'
    'a4e1c8004889c3488d7c2450e88f0d03004889dfe8e702b800ff15f9e2c800'
)
BODY_SHA256 = '2f188b7f84639bab052e80f1486459e93489a0c6f1be3d4506702363025f17cb'
BRANCHES = [
    (0x2d, '770f', 1, 2, 0x4adf66e),
    (0x39, 'e965010000', 1, 5, 0x4adf7d3),
    (0x74, '0f8587000000', 2, 6, 0x4adf731),
    (0xaa, '0f85ad000000', 2, 6, 0x4adf78d),
    (0xba, '0f83ed060000', 2, 6, 0x4adfddd),
    (0xf0, '0f84c2000000', 2, 6, 0x4adf7e8),
    (0xfc, 'e9a2000000', 1, 5, 0x4adf7d3),
    (0x15b, 'eb46', 1, 2, 0x4adf7d3),
    (0x1e7, '7317', 1, 2, 0x4adf830),
    (0x1eb, '0f8540020000', 2, 6, 0x4adfa61),
    (0x1f9, '7413', 1, 2, 0x4adf83e),
    (0x1fb, 'e931020000', 1, 5, 0x4adfa61),
    (0x208, '0f8523020000', 2, 6, 0x4adfa61),
    (0x225, '0f84bd000000', 2, 6, 0x4adf918),
    (0x273, '7438', 1, 2, 0x4adf8dd),
    (0x2a2, '74cc', 1, 2, 0x4adf8a0),
    (0x2a9, '7507', 1, 2, 0x4adf8e2),
    (0x2ab, 'eb22', 1, 2, 0x4adf8ff),
    (0x2bb, '722b', 1, 2, 0x4adf918),
    (0x2ca, 'e96fffffff', 1, 5, 0x4adf86e),
    (0x2e1, '751c', 1, 2, 0x4adf92f),
    (0x2e3, 'e934010000', 1, 5, 0x4adfa4c),
    (0x2f9, '0f841d010000', 2, 6, 0x4adfa4c),
    (0x318, 'eb32', 1, 2, 0x4adf97c),
    (0x346, '0f84d0000000', 2, 6, 0x4adfa4c),
    (0x353, '74cb', 1, 2, 0x4adf950),
    (0x393, '744b', 1, 2, 0x4adfa10),
    (0x3c6, '74c8', 1, 2, 0x4adf9c0),
    (0x3cd, '7516', 1, 2, 0x4adfa15),
    (0x3cf, 'eb2f', 1, 2, 0x4adfa30),
    (0x3e9, '722d', 1, 2, 0x4adfa48),
    (0x3f3, 'e96bffffff', 1, 5, 0x4adf993),
    (0x413, 'e90affffff', 1, 5, 0x4adf952),
    (0x41a, 'ebe8', 1, 2, 0x4adfa34),
    (0x42b, '0f8357010000', 2, 6, 0x4adfbb8),
    (0x462, '7573', 1, 2, 0x4adfb07),
    (0x48c, '0f8301010000', 2, 6, 0x4adfbc3),
    (0x4a8, '0f8810010000', 2, 6, 0x4adfbee),
    (0x4b1, '0f843b020000', 2, 6, 0x4adfd22),
    (0x4c6, '0f840a030000', 2, 6, 0x4adfe06),
    (0x4d2, 'e921020000', 1, 5, 0x4adfd28),
    (0x53d, '0f837a020000', 2, 6, 0x4adfded),
    (0x55a, '0f833e020000', 2, 6, 0x4adfdce),
    (0x576, '7951', 1, 2, 0x4adfbf9),
    (0x583, 'e942020000', 1, 5, 0x4adfdfa),
    (0x58e, 'e910fcffff', 1, 5, 0x4adf7d3),
    (0x5a0, '7648', 1, 2, 0x4adfc1a),
    (0x5b8, '0f890e010000', 2, 6, 0x4adfcfc),
    (0x5d1, '7432', 1, 2, 0x4adfc35),
    (0x5df, '0f84e7010000', 2, 6, 0x4adfdfc),
    (0x5e8, 'eb21', 1, 2, 0x4adfc3b),
    (0x5f4, '0f85c3000000', 2, 6, 0x4adfced),
    (0x600, 'e99efbffff', 1, 5, 0x4adf7d3),
    (0x6b8, 'e9e6faffff', 1, 5, 0x4adf7d3),
    (0x6c7, 'e9d7faffff', 1, 5, 0x4adf7d3),
    (0x6cf, '0f8487000000', 2, 6, 0x4adfd8c),
    (0x6e4, '0f84ec000000', 2, 6, 0x4adfe06),
    (0x6f0, 'eb70', 1, 2, 0x4adfd92),
    (0x757, 'e947faffff', 1, 5, 0x4adf7d3),
    (0x799, 'e905faffff', 1, 5, 0x4adf7d3),
    (0x7ab, 'eb1d', 1, 2, 0x4adfdfa),
    (0x7d1, 'e9a4fdffff', 1, 5, 0x4adfbaa),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x4adf695, 0x4ca6a90),
    (0x4adf6ce, 0x445f170),
    (0x4adf703, 0x32780d0),
    (0x4adf80c, 0x46f2fe0),
    (0x4adfa6d, 0x4b10bb0),
    (0x4adfc1d, 0x4d8c2e0),
    (0x4adfc4f, 0x4b10bb0),
    (0x4adfe1c, 0x4b10bb0),
    (0x4adfe24, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x4adf9d3, 0x576e488),
    (0x4adfa82, 0x5776228),
    (0x4adfacc, 0x5774540),
    (0x4adfaed, 0x576dfd8),
    (0x4adfbad, 0x576dfb8),
    (0x4adfbdc, 0x5774540),
    (0x4adfbf3, 0x576dfb8),
    (0x4adfc06, 0x576dfd8),
    (0x4adfc44, 0x576dfe0),
    (0x4adfd0b, 0x576dfd8),
    (0x4adfd60, 0x576dfe0),
    (0x4adfd9b, 0x576dfe0),
    (0x4adfdd5, 0x576e470),
    (0x4adfde7, 0x576dfc8),
    (0x4adfdf4, 0x576dfc8),
    (0x4adfe0e, 0x576dfb8),
    (0x4adfe29, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x4adfdce, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x4adfddd, 0x5742320, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
    (0x4adfded, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = [0x4d28e4c]
CALLER_FUNCTIONS = {'0x4d28e4c': ('0x4d28ba0', '0x4d2915d')}
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

