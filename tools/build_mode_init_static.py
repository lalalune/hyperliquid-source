#!/usr/bin/env python3
"""Authenticated node94 build-mode initializer binding (0x143ef30).

Binds the lazy cell's cold-path initializer (RE-001-crossroads-callees-94) to
the node #94 digest: the 1463-byte body 0x143ef30..0x143f4e7 carries the
project-source panic Locations hl/code_Mainnet/base/src/build_mode.rs:29:17
and :32:26, the assertion message "assertion failed: !arg.ends_with('/')",
the '/cham/' six-byte prefix compare, an inlined memchr for '/' built on the
0x2f2f2f2f2f2f2f2f / 0x0101010101010100 / 0x8080808080808080 constant triple
(with core/src/slice/memchr.rs Locations 132:30 and 160:9), the '--' prefix
and UTF-8 0xc0 boundary checks, and the shared alloc/dealloc entry points —
reachable only through the cell's initializer slot. Static byte/record checks
only; the captured binary is never executed.
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

START, END = 0x143ef30, 0x143f4e7
FDE_VA = 0xfcef20
CELL_VA = 0x577ab80

BUILD_MODE_PATH = (b'/home/ubuntu/hl/code_Mainnet/base/src/build_mode.rs')
MEMCHR_PATH = (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/'
                b'core/src/slice/memchr.rs')  # 80 bytes
ASSERT_MSG_VA = 0x2194b0
ASSERT_MSG = b"assertion failed: !arg.ends_with('/')"
PREFIX_VA = 0x2194aa
PREFIX = b'/cham/'
ASSERT_LOC = 0x566a0a8          # build_mode.rs:29:17
ERROR_LOC = 0x566a090           # build_mode.rs:32:26
MEMCHR_LOCS = [(0x5674908, 160, 9), (0x5674920, 132, 30)]

GOT_PANIC, PANIC_FN = 0x576e108, 0x157b7f0
GOT_STRERR, STRERR_FN = 0x576e070, 0x15793d0
GOT_ALLOC, ALLOC_FN = 0x576dfd8, 0x54c06b0
GOT_DEALLOC, DEALLOC_FN = 0x576e010, 0x54c8cb0
GOT_FMT, FMT_FN = 0x576e040, 0x1344760
GOT_ENTRY1, ENTRY1_FN = 0x576f540, 0x4edce70
GOT_ENTRY2, ENTRY2_FN = 0x576f548, 0x4f100b0
GOT_MEMRCHR, MEMRCHR_FN = 0x576f550, 0x157a8a0
GOT_SLICEP, SLICEP_FN = 0x576e2e0, 0x157a6f0

ANCHORS = [
    (0x39, 'ff15', 'entry call one'),
    (0x3f, '49bd8080808080808080', 'memchr high-bits constant'),
    (0x49, '48bd2f2f2f2f2f2f2f2f', 'memchr needle 0x2f repeated'),
    (0x53, '49bc0001010101010101', 'memchr ones constant'),
    (0x8a, 'ff15', 'entry call two'),
    (0xbb, '6641813e2d2d', 'double-dash prefix compare'),
    (0xc7, 'be06000000', 'prefix length 6'),
    (0xcc, '488d3d', 'prefix string lea'),
    (0x1f0, '43803c3ec0', 'UTF-8 continuation boundary 0xc0'),
    (0x207, 'ff15', 'alloc call'),
    (0x278, '488d35', 'format string lea'),
    (0x287, 'ff15', 'format call'),
    (0x330, 'ff15', 'reverse scan for 0x2d'),
    (0x503, 'ff15', 'assert panic call'),
    (0x53a, '0f0b', 'ud2 terminator'),
]

# Panic Location lea sites: (offset, opcode hex, Location VA).
LOC_LEAS = [
    (0x4d5, '488d0d', MEMCHR_LOCS[0][0]),
    (0x4e1, '488d0d', MEMCHR_LOCS[1][0]),
    (0x4f0, '488d3d', ASSERT_MSG_VA),
    (0x4f7, '488d15', ASSERT_LOC),
    (0x521, '4c8d05', ERROR_LOC),
]

BODY = bytes.fromhex(
'554157415641554154534881ece800000048897c243848c74424100000000048'
'c74424180100000048c744242000000000488dbc24c8000000ff15d105330449'
'bd808080808080808048bd2f2f2f2f2f2f2f2f49bc00010101010101010f1084'
'24c80000000f108c24d80000000f294c24500f2944244048c744243000000000'
'488d7c2478488d742440ff1588053304488b4c24784889c848f7d80f800b0300'
'0048890c244c8bb42480000000488b9c24880000004883fb02720c6641813e2d'
'2d0f84f7010000be06000000488d3da7a4ddfe4c89f24889d9e8e21d000084c0'
'0f843a0100004885db740c41807c1eff2f0f84f9030000498d46074883e0f84c'
'29f04889daeb15660f1f8400000000004c89fa4939df0f87040100004889d748'
'89d14839c2721689d629c683e60f4889d74889c14829f70f82a10300004889fe'
'48f7de4989d0662e0f1f8400000000004989f14d01c174184d8d78ff43807c06'
'ff2f4d89f875e9eb6b0f1f80000000004889fe4839cf7634488d7ef04d8b4436'
'f04d89c14931e94d89e24d29ca4d09c24d8b4436f84931e84d89e14d29c14d09'
'c14d21ea4d21ca4d39ea74c44839d60f871e03000066662e0f1f840000000000'
'4885f6745b4c8d7eff41807c36ff2f4c89fe75ec4939df0f8333ffffff43803c'
'3e2f0f8528ffffff49ffc74c39fb760b43803c3ec00f8c260300004c29fb0f84'
'd70000004889dfff159bee32044885c00f84ff0200004889c7e9c20000006690'
'4989df4c89f74c89fee86289fcff48894424684889542470488d442410488984'
'2490000000488d05645200004889842498000000488d44246848898424a00000'
'00488d0518e9090048898424a8000000488dbc24b0000000488d35f25cdbfe48'
'8d942490000000ff1583ee3204488b7424104885f6740d488b7c241831d2ff15'
'3cee3204488b8424c000000048894424200f108424b00000000f29442410488b'
'34244885f60f84b5fdffff4c89f731d2ff150aee3204e9a5fdffffbf01000000'
'4d01f748897c24084c89fe4889daff15bced3204488b34244885f6740b4c89f7'
'31d2ff15d8ed32044989df4c8b742408eb1366666666662e0f1f840000000000'
'4939df7746bf2d0000004c89f64c89faff15ea023304a80174314989d74839da'
'73de43803c3e2d75d74d85ff0f886801000074234c89ffff154bed32044885c0'
'0f84d60100004989c6eb124989df48891c24e9acfeffff41be010000004c89f7'
'488b7424084c89faff1522ed3204488b7c24084889de31d2ff1542ed32044c89'
'7424604c893c24e977feffff4c8b742448488b4c24584889c84c29f048baabaa'
'aaaaaaaaaaaa48f7e24c39f174314889d348c1eb044983c608eb0e0f1f440000'
'4983c61848ffcb7416498b76f84885f674ee498b3e31d2ff15e3ec3204ebe148'
'8b4424504885c07415488b7c244048c1e003488d344031d2ff15c2ec3204488b'
'7c2418488b742420e86387fcff4889d34885d2791031ff4889deff1548ec3204'
'e9f50000004885db741d4989c74889dfff1552ec32044885c00f84ac00000049'
'89c64c89f8eb0641be010000004c89f74889c64889daff1534ec3204488b4424'
'384889184c89700848895810488b7424104885f6740d488b7c241831d2ff153d'
'ec3204488b4424384881c4e80000005b415c415d415e415f5dc348891c24488b'
'5c2460488b7c24304889deff15b7eb3204eb6731ff488d0dfc542304eb0a4889'
'd6488d0d08552304ff15c2ee3204eb4a488d3d89a0ddfe488d157aac2204be25'
'000000ff15cfec3204eb2fbf01000000e922ffffffb8010000004889442430eb'
'a24c8d0538ac22044c89f74889de4c89fa4889d9ff1506ec32040f0bb8010000'
'0048894424304c8b74240848891c244c89fbe96cffffff4989c7eb104989c7eb'
'1eeb02eb004989c7488b1c244885db740e4c89f74889de31d2ff1561eb320448'
'8d7c2440e89719fbff488b7424104885f6750feb1a4989c7488b7424104885f6'
'740d488b7c241831d2ff1531eb32044c89ffe8290c2204')

FDE = bytes.fromhex(
'50000000f812010008004700b705000004ff6c95ff410e10420e18420e20420e'
'28420e30410e38470ea00283078c068d058e048f038602039e040e38410e3042'
'0e28420e20420e18420e10410e08410ea0020000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def memchr_flag(word, needle=0x2f):
    """Decoded word test: ((M - (w ^ N)) | w) & H == H means no needle byte."""
    m = 0x0101010101010100
    n = needle * 0x0101010101010101
    h = 0x8080808080808080
    u = word ^ n
    t = ((m - u) & 0xFFFFFFFFFFFFFFFF) | word
    return (t & h) == h          # True = continue scanning (no candidate)


def contains_byte(word, needle=0x2f):
    return any((word >> (8 * i)) & 0xFF == needle for i in range(8))


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
    rels = relocations(reader)

    body = reader.read(START, END - START)
    require(body == BODY, 'Initializer body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    fde = reader.read(FDE_VA, len(FDE))
    require(fde == FDE, 'Initializer FDE record changed')
    length = struct.unpack_from('<I', fde, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, hexstr, label in ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, f'Anchor changed: {label}')

    # Strings and Locations.
    require(reader.read(ASSERT_MSG_VA, len(ASSERT_MSG)) == ASSERT_MSG,
            'assertion message bytes changed')
    require(reader.read(PREFIX_VA, len(PREFIX)) == PREFIX,
            'prefix string bytes changed')
    disp = struct.unpack_from('<i', body, 0xcf)[0]
    require(START + 0xcc + 7 + disp == PREFIX_VA, 'prefix lea address changed')
    for loc_va, line, col in [(ASSERT_LOC, 29, 17), (ERROR_LOC, 32, 26)]:
        path_va = rels.get(loc_va)
        require(path_va is not None, 'build_mode Location relocation missing')
        str_len, line_, col_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((str_len, line_, col_) == (len(BUILD_MODE_PATH), line, col),
                'build_mode Location layout changed')
        require(reader.read(path_va, str_len) == BUILD_MODE_PATH,
                'build_mode path changed')
    for loc_va, line, col in MEMCHR_LOCS:
        path_va = rels.get(loc_va)
        require(path_va is not None, 'memchr Location relocation missing')
        str_len, line_, col_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((str_len, line_, col_) == (len(MEMCHR_PATH), line, col),
                'memchr Location layout changed')
        require(reader.read(path_va, str_len) == MEMCHR_PATH, 'memchr path changed')
    for offset, opcode, loc_va in LOC_LEAS:
        require(body[offset:offset + 3] == bytes.fromhex(opcode),
                f'Location lea opcode at +0x{offset:x} changed')
        disp = struct.unpack_from('<i', body, offset + 3)[0]
        require(START + offset + 7 + disp == loc_va,
                f'Location lea at +0x{offset:x} target changed')

    # GOT-mediated callees.
    for offset, got, target in [(0x39, GOT_ENTRY1, ENTRY1_FN),
                                (0x8a, GOT_ENTRY2, ENTRY2_FN),
                                (0x207, GOT_ALLOC, ALLOC_FN),
                                (0x287, GOT_FMT, FMT_FN),
                                (0x330, GOT_MEMRCHR, MEMRCHR_FN),
                                (0x4e8, GOT_SLICEP, SLICEP_FN),
                                (0x503, GOT_PANIC, PANIC_FN)]:
        disp = struct.unpack_from('<i', body, offset + 2)[0]
        require(START + offset + 6 + disp == got, f'call GOT at +0x{offset:x} changed')
        require(rels.get(got) == target, f'call target for GOT {got:#x} changed')
    require(body[0x503 - 5:0x503] == b'\xbe' + struct.pack('<I', len(ASSERT_MSG)),
            'assert panic length operand changed')

    # Memchr no-false-negative identity: any word containing 0x2f flags.
    samples = [0x2f, 0x2f << 8, 0x2f << 56, 0x6162622f64656667,
               0x2f2f2f2f2f2f2f2f, 0x6161616161616161, 0, 0x7f7f7f7f7f7f7f7f]
    for word in samples:
        if contains_byte(word):
            require(not memchr_flag(word),
                    f'memchr identity missed needle in {word:#x}')
    for word in (0x6161616161616161, 0, 0x0102030405060708):
        require(memchr_flag(word) or contains_byte(word),
                f'memchr identity changed for clean word {word:#x}')

    # Reachability: only the cell's initializer slot references this body.
    require(rels.get(CELL_VA) == START, 'cell initializer relocation changed')
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    direct, indirect, lea = [], [], []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    pos = 0
    while (pos := code.find(b'\xff\x15', pos)) >= 0:
        if pos + 6 <= len(code):
            slot = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if rels.get(slot) == START:
                indirect.append(text['address'] + pos)
        pos += 2
    for m in range(len(code) - 7):
        if code[m] == 0x48 and code[m + 1] == 0x8d and (code[m + 2] & 0xC7) == 0x05:
            d = struct.unpack_from('<i', code, m + 3)[0]
            if text['address'] + m + 7 + d == START:
                lea.append(text['address'] + m)
    require(direct == [] and indirect == [] and lea == [],
            'initializer gained code references')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        initializer=dict(start_va=hex(START), end_va_exclusive=hex(END),
                         bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                         fde_va=hex(FDE_VA), cell=hex(CELL_VA),
                         inferred_label='build-mode argument normalizer behind the '
                                        'ship-complete lazy cell'),
        project_anchors=dict(
            assertion=dict(message=ASSERT_MSG.decode(), message_va=hex(ASSERT_MSG_VA),
                           location='build_mode.rs:29:17', location_va=hex(ASSERT_LOC)),
            error_path=dict(location='build_mode.rs:32:26', location_va=hex(ERROR_LOC),
                            callee=hex(STRERR_FN)),
            prefix=PREFIX.decode(), prefix_va=hex(PREFIX_VA),
            source_file='hl/code_Mainnet/base/src/build_mode.rs'),
        memchr=dict(constants=['0x2f2f2f2f2f2f2f2f', '0x0101010101010100',
                               '0x8080808080808080'],
                    locations=['core/src/slice/memchr.rs:160:9',
                               'core/src/slice/memchr.rs:132:30'],
                    identity='no-false-negative word scan for 0x2f validated on '
                             'needle-placement samples'),
        other_anchors=dict(double_dash=0x2d2d, utf8_boundary=0xc0,
                           entry_one=hex(ENTRY1_FN), entry_two=hex(ENTRY2_FN),
                           alloc_shared_with='RE-001-alloc-shim-94',
                           format=hex(FMT_FN)),
        reachability='cell initializer slot only; zero code references',
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
