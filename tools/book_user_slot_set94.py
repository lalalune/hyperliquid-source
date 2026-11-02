#!/usr/bin/env python3
"""Static, digest-bound evidence for a user-slot set insertion on node 94.

Only fixed, manually identified x86 instruction patterns are interpreted. No
external program or captured executable is run. ELF and FDE parsing is shared
with the repository. Addresses are linked ELF virtual addresses.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (
    ('set-insert-counterpart', 0x285db90, 0x285dcef, 'bfaed318d6069719518fbe6c22f0ad464d21b636abba178b1197aa95dfa0740b'),
    ('set-node-insert-split', 0x1a788b0, 0x1a79067, 'a6054488ae596cec2d31f2072101612e9e7dbe7ee9389af49f3af9afef41c9df'),
)
# A pre-existing book-path callee is comparison context, not a selected FDE.
CONTEXT = (0x285cc70, 0x285cdcf, 'c1c52c4f50eedbe8b23b9348fa31e0d83f9dac48d2560f6e13b14b320a94cbfe')
WITNESSES = (
    ('book-return-a', 0x26ea6c7, '8b8424d0000000', 'The first caller overwrites eax after the set insertion returns.'),
    ('book-return-b', 0x26ee045, '488b4c24588b4110', 'The second caller overwrites eax after the set insertion returns.'),
    ('book-slot-flow-a', 0x26ea59a, 'e8711ec4ff488944243841803e00751049c70601000000488b4424384989460841837e10017545498b4e18488b842400010000483b080f838a150000488b842440010000488b004869c9f8000000833c08020f846e1500004801c848c7401001000000488b4c24384889481849c7461001000000488b54243849895618488b442428488d78284531e44c89fee815000e0080bc24f8000000007442488b442428488d78488b8424d000000089842490030000660f288424c0000000660f298424800300004531e4488db424800300004c89fa488b4c2448ff1599a10803488b442428488db8b80000008b8424d000000089842490030000660f288424c0000000660f298424800300004531e4488db42480030000e88dd3ebff4883c0204531e44889c7488b742438e8a9251700', 'First caller window between the slot-writer return and user-set insertion.'),
    ('book-slot-flow-b', 0x26edf1d, 'e83ee6c3ff4c8b6c24184989c741803c2400750d49c70424010000004d897c240841837c2410017541498b4c2418488b842498000000483b080f83f91b0000488b842490000000488b004869c9f8000000833c08020f84dd1b00004801c848c74010010000004c89781849c7442410010000004d897c2418488b442410488d782831db488bb424a80000004c89fae890c60d0080bc24b0000000007440488b442410488d7848488b4c24588b411089842460060000f30f6f01660f7f84245006000031db488db42450060000488b9424a80000004c89f1ff1516680803488b4424104c8db0b8000000488b4c24588b411089842460060000f30f6f01660f7f84245006000031db488db424500600004c89f7e8fc96ebff4883c02031db4889c74c89fee82bec1600', 'Second caller window between the slot-writer return and user-set insertion.'),
    ('book-allocated-slot-a', 0x26ea59a, 'e8711ec4ff4889442438', 'The allocator return is saved as the key used later in this book path.'),
    ('book-allocated-slot-b', 0x26edf1d, 'e83ee6c3ff4c8b6c24184989c7', 'The allocator return is retained in r15 for the later set call.'),
    ('book-site-a', 0x26ea6ae, 'e88dd3ebff4883c0204531e44889c7488b742438e8a9251700', 'Book user lookup result plus 0x20 is passed to the set writer.'),
    ('book-site-b', 0x26ee02f, 'e8fc96ebff4883c02031db4889c74c89fee82bec1600', 'Second book context passes the same user-entry field to the writer.'),
    ('book-set-split-call', 0x285cd83, '4c8d442430488d7c2450488d742430488d4c24084889dae811bb21ff488b4c2408', 'The book-context set writer calls the selected split body.'),
    ('set-wrapper-entry', 0x285db90, '4156534883ec684889f3488b074885c07468', 'Load set root and branch on null.'),
    ('set-wrapper-search', 0x285dba2, '488b4f080fb770624189f041c1e00348c7c2ffffffff0f1f8400000000004d85c0742b483b5cd010410f97c14180d90048ffc24983c0f84180f90174e1410fb6f185f6750ceb170f1f80000000004889f24883e9017274488b44d068eba6b0014883c4685b415ec3', 'Search live u64 keys and descend by height; equality returns one.'),
    ('set-wrapper-empty', 0x285dc0a, '4989fe48c744241800000000bf68000000ff15b703f1024885c00f849c00000048c7000000000066c74062000049890649c7460800000000', 'Allocate and initialize a 0x68-byte empty root.'),
    ('set-wrapper-first', 0x285dc42, '0fb750624883fa0b0f83860000004c89f18d72016689706248895cd00848ff411031c04883c4685b415ec3', 'Guard capacity, store key, increment tree count, return zero.'),
    ('set-wrapper-insert', 0x285dc6d, '48897c240848895c2410488944241848c7442420000000004889542428488b4424184889442430488b442420488944243848895424404c8d442430488d7c2450488d742430488d4c24084889dae8f1ab21ff488b4c2408eb99', 'Build cursor, call split helper and increment tree count.'),
    ('set-wrapper-fail', 0x285dcc6, 'bf08000000be68000000ff154a03f102488d3d83ed9afd488d1554a7e202be20000000ff151904f102', 'Allocation failure and capacity assertion sites.'),
    ('leaf-nonfull', 0x1a788be, '4989d4488b2e0fb75d624883fb0b7352488b4610488d48014839d97731488d55084989c5488d04c24989ff488d3cca4889da4c29ea48c1e2034989f64889c6ff15dd57cf034c89e84c89ff4c89f6ffc34c8964c50866895d62488b4e08e9ea050000', 'Node length below 11 takes nonfull insertion and suffix shift.'),
    ('leaf-choose', 0x1a78920, '4c8b76104983fe0548897c243848894c2450730e4c89342441be0400000031dbeb3274184983fe06751a41be05000000b30148c7042400000000eb1831db4c893424eb104983c6f94c89342441be06000000b301', 'Full-leaf pivot and side selection on index 5 and 6.'),
    ('leaf-split', 0x1a78974, '4c8b6e08bf68000000ff155556cf034885c00f84300600004989c748c7000000000066c7406200000fb745624c89f248f7d24801c266418957624883fa0c0f83eb0500004a8b44f50848894424284a8d34f5100000004801ee498d7f0848c1e203ff150556cf036644897562', 'Allocate 0x68 bytes, copy upper keys and update both lengths.'),
    ('leaf-place', 0x1a789e0, '31c084db4c89f9480f44cd490f44c548894424200fb75962488b04244839c348894c2410762f488d4108488b0c24488d34c8488b0c24488d3cc84883c70889da2b1424c1e203ff15b456cf03488b4c2410488b0424ffc34c8964c10866895962', 'Choose sibling and insert new key at its local index.'),
    ('parent-climb', 0x1a78a40, '488b45004885c00f84cd02000031c9eb246666666666662e0f1f840000000000488b6c2418488b45004c89e94885c00f84a8020000488b7424284c39e90f85dc0400004889ea4889c54c896c2430440fb77260440fb768624983fd0b4c897c244848897424400f821c030000', 'Ascend via parent pointer and check height; test parent capacity.'),
    ('parent-choose', 0x1a78aac, '664183fe05731dbb04000000c744240800000000eb4e66666666662e0f1f8400000000004983fe0574164183fe06751db00189442408bb050000004531f6eb24c7442408000000004c89f3eb174983c6f9b00189442408bb060000000f1f840000000000', 'Full-parent pivot and side selection on index 5 and 6.'),
    ('parent-split', 0x1a78b10, 'bfc8000000ff15bd54cf034885c00f84540400004989c44989c749c70424000000006641c744246200000fb745624889da48f7d24801c26641895424624883fa0c0f83d0030000488b44dd084889442428488d34dd100000004801ee498d7c240848c1e203ff156554cf0348896c241866895d62410fb76f62488d55014883fd0c0f83ac0300004129dd4139d50f85e50300004c8b6c243049ffc5498d7c2468488b442418488d34d84883c670c1e203ff151a54cf0331c00f1f8400000000004889c14839e84883d000498b54cf684c893a66894a604839e973054839e876e0', 'Allocate 0xc8-byte internal sibling and repair moved child links.'),
    ('parent-place', 0x1a78bf0, '807c2408004c0f44642418410fb75c2462498d6e014989d84d29f07651498d4424084b8d34f44883c608488d3ce84c896c24304189dd4529f541c1e5034c89ea4c89442408ff15a554cf03498d34ec4883c6684b8d3cf44883c7784c89ea4c8b6c2430ff158754cf034c8b4424088d4b01488b4424404b8944f408488d4302488b5424484b8954f4706641894c2462', 'Insert promoted key and new edge into selected parent.'),
    ('parent-repair', 0x1a78c7f, '4839c50f83d8fdffff4429f3ffc383e30374274b8d14f44883c27031c90f1f4000488b34ca4c89268d3c2966897e6048ffc14839cb75ea4801cd4983f8030f829dfdffff666666662e0f1f840000000000498b4cec684c892166896960498b4cec704c89218d550166895160498b4cec784c89218d550266895160498b8cec800000004c89218d5503668951604883c5044839c575bbe946fdffff', 'Repair child parent pointers and parent-edge indices.'),
    ('new-root', 0x1a78d1a, '4531ed488b442450488b184c8b234d85e40f849b0200004c89ed4c8b6b08bfc8000000ff159552cf034885c00f848d0200004989c648c7000000000066c7406200004c8960684c89e848ffc0488b5424100f847a0200004d8934246641c744246000004c8933488943084c39ed0f856d020000410fb746624883f80b0f83770200008d48016641894e62488b742428498974c6084d897cc6704d89376641894f604889d5488b7c2438e939010000', 'Allocate an internal root, increase height and attach both children.'),
    ('parent-nonfull', 0x1a78dc8, '418d4d014d8d6601664539ee735e488d7d084a8d34f5080000004801ee4889eb428d2ce5000000004801ef4d89ef4d29f749c1e7034c89fa894c2418ff15d652cf03488d342b4883c6684889dd4a8d3cf34883c7784c89fa4c8b7c2448ff15b552cf038b4c2418488b7424404a8974f508498d45024e897cf57066894d624139c4488b7c2438488b54241073544489e94429f1ffc14d29f583e103743e4989f94a8d34f5700000004801ee31d266662e0f1f840000000000488b3cd648892f458d0414664489476048ffc24839d175e84901d44c89cf488b5424104983fd0373074889d5eb5366904a8b4ce56848892966448961604a8b4ce570488929418d542401668951604a8b4ce578488929418d542402668951604a8b8ce580000000488929418d542403668951604983c4044939c475b4488b6c2410', 'Shift a nonfull parent and install key and edge.'),
    ('return-cursor', 0x1a78f01, '488b0424488b4c242048892f48894f08488947104889f84883c4585b415c415d415e415f5dc3', 'Return three cursor words.'),
    ('split-failure', 0x1a78f27, '488d0db2f5c0034889d6ba0b00000031ffff15a253cf03e9b5000000488d0daef5c0034889d6ba0c00000031ffff158653cf03e999000000488d3d7bae93fe488d15a3f5c003be35000000ff159051cf03bf08000000bec8000000ff159850cf03488d3d2aae93fe488d1532f5c003be28000000ff156751cf03eb55488d0d36f5c0034889d6ba0b00000031ffff152653cf03eb3cbf08000000be68000000ff155450cf03488d3d4df4c003ff159754cf03bf08000000bec8000000ff153750cf03eb0d488d3d8ef4c003ff157854cf030f0b488d3d2aad93fe488d1548f4c003be30000000ff15f550cf03488d3d463a79fe488d1547f4c003be20000000ff15dc50cf03bec80000004c89f731d2ff15d44fcf030f0b0f0b', 'Bounds, height, allocation and assertion failure arms.'),
)
# Hand-selected conditional instruction starts, checked as actual short or near
# x86 Jcc encodings. These are not asserted to be an exhaustive CFG census.
CONDITIONS = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
              's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')
BRANCH_SITES = (
    0x285dba0, 0x285dbc3, 0x285dbdd, 0x285dbe5, 0x285dbf7,
    0x285dc24, 0x285dc4a,
    0x1a788cc, 0x1a788d9, 0x1a78932, 0x1a78942, 0x1a78948,
    0x1a78986, 0x1a789b2, 0x1a78a04, 0x1a78a47, 0x1a78a6f,
    0x1a78a7d, 0x1a78aa6, 0x1a78ab1, 0x1a78ad4, 0x1a78ada,
    0x1a78b1e, 0x1a78b51, 0x1a78b91, 0x1a78b9d, 0x1a78be9,
    0x1a78bee, 0x1a78c0b, 0x1a78c82, 0x1a78c90, 0x1a78cb4,
    0x1a78cbd, 0x1a78d13, 0x1a78d2b, 0x1a78d46, 0x1a78d6b,
    0x1a78d87, 0x1a78d96, 0x1a78dd4, 0x1a78e53, 0x1a78e63,
    0x1a78e96, 0x1a78ea7, 0x1a78efa,
)
FAILURE_EDGES = (
    ('initial-root-allocation', 0x285dc24, 0x285dcc6),
    ('initial-root-capacity', 0x285dc4a, 0x285dcd6),
    ('leaf-sibling-allocation', 0x1a78986, 0x1a78fbc),
    ('leaf-copy-bound', 0x1a789b2, 0x1a78fa3),
    ('parent-height', 0x1a78a7d, 0x1a78f5f),
    ('internal-sibling-allocation', 0x1a78b1e, 0x1a78f78),
    ('internal-copy-bound', 0x1a78b51, 0x1a78f27),
    ('child-edge-bound', 0x1a78b91, 0x1a78f43),
    ('child-slice-length', 0x1a78b9d, 0x1a78f88),
    ('missing-old-root', 0x1a78d2b, 0x1a78fcc),
    ('new-root-allocation', 0x1a78d46, 0x1a78fd9),
    ('height-overflow', 0x1a78d6b, 0x1a78feb),
    ('root-height', 0x1a78d87, 0x1a78ffa),
    ('new-root-capacity', 0x1a78d96, 0x1a79013),
)
DIRECT_CALLS = (
    ('book-slot-writer-a', 0x26ea59a, 0x232c410),
    ('book-slot-writer-b', 0x26edf1d, 0x232c560),
    ('book-user-lookup-a', 0x26ea6ae, 0x25a7a40),
    ('book-set-insert-a', 0x26ea6c2, 0x285cc70),
    ('book-user-lookup-b', 0x26ee02f, 0x25a7730),
    ('book-set-insert-b', 0x26ee040, 0x285cc70),
    ('book-writer-to-split', 0x285cd9a, 0x1a788b0),
    ('counterpart-to-split', 0x285dcba, 0x1a788b0),
)
# Corresponding instruction offsets and kinds in the two 351-byte wrappers.
# Only PC-relative operand bytes are masked. Actual destinations are checked.
WRAPPER_REL = ((0x8b, 'rip6', 0x576dfd8), (0x12a, 'call5', 0x1a788b0),
               (0x140, 'rip6', 0x576e020), (0x146, 'lea7', 0x20ca60),
               (0x14d, 'lea7', 0x5688438), (0x159, 'rip6', 0x576e108))
SLOTS = (0x576dfd8, 0x576dfe0, 0x576e0e0, 0x576e020,
         0x576e108, 0x576e2e0, 0x576e470, 0x576e010)
# The message addresses and lengths, and Location slots, are read and checked
# as binary operands. The full embedded build path is deliberately not emitted.
DIAGNOSTICS = (
    ('wrapper-capacity', 0x285dcd6, 0x285dcdd, 0x285dce4, 0x20ca60, 32, 0x5688438),
    ('root-capacity', 0x1a79013, 0x1a7901a, 0x1a79021, 0x20ca60, 32, 0x5688468),
    ('parent-height', 0x1a78f5f, 0x1a78f66, 0x1a78f6d, 0x3b3de1, 53, 0x5688510),
    ('child-slice-length', 0x1a78f88, 0x1a78f8f, 0x1a78f96, 0x3b3db9, 40, 0x56884c8),
    ('root-height', 0x1a78ffa, 0x1a79001, 0x1a79008, 0x3b3d2b, 48, 0x5688450),
)

# Immediate and displacement fields within pinned instruction windows.
CONSTANTS = (
    ('node-count-offset', 0x1a788c7, 1, 'u8'),
    ('node-capacity', 0x1a788cb, 1, 'u8'),
    ('key-stride-shift', 0x1a788f6, 1, 'u8'),
    ('node-key-offset', 0x1a78912, 1, 'u8'),
    ('leaf-threshold-low', 0x1a78927, 1, 'u8'),
    ('leaf-threshold-high', 0x1a78947, 1, 'u8'),
    ('leaf-allocation-bytes', 0x1a78979, 4, 'u32le'),
    ('parent-edge-index-offset', 0x1a78a92, 1, 'u8'),
    ('internal-allocation-bytes', 0x1a78b11, 4, 'u32le'),
    ('node-children-offset', 0x1a78d5f, 1, 'u8'),
    ('header-height-offset', 0x285dba5, 1, 'u8'),
    ('header-count-offset', 0x285dc62, 1, 'u8'),
    ('user-entry-set-offset', 0x26ea6b6, 1, 'u8'),
    ('book-slot-stride', 0x26ea5e4, 4, 'u32le'),
)


class EvidenceError(ValueError):
    pass


def check_digest(data):
    got = hashlib.sha256(data).hexdigest()
    if got != SHA256:
        raise EvidenceError('target SHA-256 mismatch')
    return got


def mapping(data, secs, va, length):
    if va < 0 or length < 0:
        raise EvidenceError('negative address or length')
    hits = [s for s in secs if s['type'] != 8 and
            s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(hits) != 1:
        raise EvidenceError('address lacks unique file-backed section')
    sec = hits[0]
    off = sec['offset'] + va - sec['address']
    if off < 0 or off + length > len(data):
        raise EvidenceError('file mapping is truncated')
    return sec, off


def read_va(data, secs, va, length):
    _, off = mapping(data, secs, va, length)
    return bytes(data[off:off + length])


def verify_pins(data, secs):
    records = []
    for label, va, expected, observation in WITNESSES:
        raw = read_va(data, secs, va, len(bytes.fromhex(expected)))
        if raw != bytes.fromhex(expected):
            raise EvidenceError('byte witness changed: ' + label)
        _, off = mapping(data, secs, va, len(raw))
        records.append((label, hex(va), hex(va + len(raw)), hex(off),
                        raw.hex(), observation))
    for label, start, end, digest in FUNCTIONS:
        if hashlib.sha256(read_va(data, secs, start, end - start)).hexdigest() != digest:
            raise EvidenceError('selected body changed: ' + label)
    start, end, digest = CONTEXT
    if hashlib.sha256(read_va(data, secs, start, end - start)).hexdigest() != digest:
        raise EvidenceError('comparison context changed')
    return records


def decode_branch(data, secs, site):
    first = read_va(data, secs, site, 1)[0]
    if 0x70 <= first <= 0x7f:
        raw = read_va(data, secs, site, 2)
        disp = struct.unpack('<b', raw[1:])[0]
        cc = first & 15
    elif first == 0x0f:
        raw = read_va(data, secs, site, 6)
        if not 0x80 <= raw[1] <= 0x8f:
            raise EvidenceError('not a selected conditional branch')
        disp = struct.unpack('<i', raw[2:])[0]
        cc = raw[1] & 15
    else:
        raise EvidenceError('not a selected conditional branch')
    return raw, site + len(raw) + disp, cc


def decode_rel(data, secs, site, kind):
    length, prefix = {'call5': (5, b'\xe8'), 'rip6': (6, b'\xff\x15'),
                      'lea7': (7, b'\x48\x8d')}[kind]
    raw = read_va(data, secs, site, length)
    if not raw.startswith(prefix) or (kind == 'lea7' and raw[2] not in (0x3d, 0x15)):
        raise EvidenceError('unexpected relative instruction')
    return raw, site + length + struct.unpack('<i', raw[-4:])[0]


def get_relocations(data, secs, wanted):
    result = {}
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24 or sec['offset'] + sec['size'] > len(data):
            raise EvidenceError('invalid RELA section')
        for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if slot in wanted:
                if slot in result:
                    raise EvidenceError('duplicate relocation')
                result[slot] = (info & 0xffffffff, info >> 32, addend)
    if set(result) != set(wanted):
        raise EvidenceError('missing relocation')
    return result


def symbol_name(data, secs, index):
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    pos = sym['offset'] + index * 24
    if pos + 24 > sym['offset'] + sym['size']:
        raise EvidenceError('dynamic symbol out of range')
    name = struct.unpack_from('<I', data, pos)[0]
    if name >= strings['size']:
        raise EvidenceError('dynamic symbol name out of range')
    pos = strings['offset'] + name
    end = data.find(b'\0', pos, strings['offset'] + strings['size'])
    if end < 0:
        raise EvidenceError('unterminated dynamic symbol')
    return bytes(data[pos:end]).decode('ascii')


def split_parameters(data, secs):
    # Indices refer to immediate bytes of the pinned instructions above.
    capacity = read_va(data, secs, 0x1a788cb, 1)[0]
    threshold1 = read_va(data, secs, 0x1a78927, 1)[0]
    threshold2 = read_va(data, secs, 0x1a78947, 1)[0]
    lower_pivot = struct.unpack('<I', read_va(data, secs, 0x1a7893a, 4))[0]
    upper_pivot = struct.unpack('<I', read_va(data, secs, 0x1a7896e, 4))[0]
    parent1 = read_va(data, secs, 0x1a78ab0, 1)[0]
    parent2 = read_va(data, secs, 0x1a78ad9, 1)[0]
    stride_shift = read_va(data, secs, 0x1a788f6, 1)[0]
    if (capacity, threshold1, threshold2, lower_pivot, upper_pivot, parent1, parent2, stride_shift) != (11, 5, 6, 4, 6, 5, 6, 3):
        raise EvidenceError('split constants changed')
    return capacity, threshold1, threshold2, lower_pivot, upper_pivot, 1 << stride_shift


def project_split(index, params):
    """Synthetic full-node projection, not execution or emulation of the ELF."""
    cap, low, high, pivot_low, pivot_high, _ = params
    if not 0 <= index <= cap:
        raise EvidenceError('synthetic insertion index out of range')
    if index < low:
        pivot, side, local = pivot_low, 'left', index
    elif index == low:
        pivot, side, local = low, 'left', index
    elif index == high:
        pivot, side, local = low, 'right', 0
    else:
        pivot, side, local = pivot_high, 'right', index - (high + 1)
    keys = [2 * (i + 1) for i in range(cap)]
    key = 2 * index + 1
    left, promoted, right = keys[:pivot], keys[pivot], keys[pivot + 1:]
    (left if side == 'left' else right).insert(local, key)
    return {'index': index, 'old_keys': keys, 'new_key': key, 'pivot_index': pivot,
            'promoted': promoted, 'side': side, 'local_index': local,
            'left': left, 'right': right}



def project_nonfull(length, index, params):
    # Valid-node projection only; not an invalid-input contract for the target.
    capacity = params[0]
    if not 0 <= length < capacity or not 0 <= index <= length:
        raise EvidenceError('synthetic nonfull node outside valid range')
    return length, index, length - index, params[5] * (length - index)


def project_parent(index, params):
    # Distinct synthetic edge IDs show redistribution after one child split.
    case = project_split(index, params)
    edges = [f'old-{i}' for i in range(params[0] + 1)]
    edges.insert(index + 1, 'new')
    left_count = len(case['left']) + 1
    return (index, case['pivot_index'], case['side'], case['local_index'],
            ','.join(edges[:left_count]), ','.join(edges[left_count:]))


def compare_wrappers(data, secs):
    a0, a1, _ = CONTEXT
    b0, b1 = FUNCTIONS[0][1:3]
    a = bytearray(read_va(data, secs, a0, a1 - a0))
    b = bytearray(read_va(data, secs, b0, b1 - b0))
    differences = [i for i in range(len(a)) if a[i] != b[i]]
    masks, permitted = [], set()
    for offset, kind, expected in WRAPPER_REL:
        ra, ta = decode_rel(data, secs, a0 + offset, kind)
        rb, tb = decode_rel(data, secs, b0 + offset, kind)
        if ta != tb or ta != expected:
            raise EvidenceError('counterpart relative destinations differ')
        start = offset + len(ra) - 4
        permitted.update(range(start, start + 4))
        a[start:start + 4] = b'\0' * 4
        b[start:start + 4] = b'\0' * 4
        masks.append((hex(offset), kind, hex(start), hex(start + 4), hex(ta), ra.hex(), rb.hex()))
    if a != b or not set(differences).issubset(permitted):
        raise EvidenceError('wrapper comparison differs outside relative operands')
    return differences, masks, hashlib.sha256(a).hexdigest()


def selected_fdes(data, secs):
    summary, fdes, _ = fde_extents(data)
    if summary['unwind_start_differs_from_fde_start']:
        raise EvidenceError('unwind header and FDE starts disagree')
    functions = []
    for label, start, end, expected in FUNCTIONS:
        matches = [row for row in fdes if row['start'] == start]
        if len(matches) != 1:
            raise EvidenceError('selected FDE start is not unique: ' + label)
        fde = matches[0]
        if fde['end'] != end or 'index' not in fde or end > fde['next_index_upper_bound']:
            raise EvidenceError('selected FDE mismatch: ' + label)
        sec, off = mapping(data, secs, start, end - start)
        if not sec['flags'] & 4:
            raise EvidenceError('selected FDE is not executable')
        raw = read_va(data, secs, start, end - start)
        functions.append((label, hex(start), hex(end), hex(off), hex(fde['fde']),
                          hex(fde['cie']), '' if fde['lsda'] is None else hex(fde['lsda']),
                          fde['index'], len(raw), expected, raw.hex()))
    return functions


def collect(data):
    digest = check_digest(data)
    secs = sections(data)
    pins = verify_pins(data, secs)
    functions = selected_fdes(data, secs)
    branches = []
    for site in BRANCH_SITES:
        containing = [x for x in FUNCTIONS if x[1] <= site < x[2]]
        if len(containing) != 1:
            raise EvidenceError('branch outside selected FDEs')
        raw, target, cc = decode_branch(data, secs, site)
        if not containing[0][1] <= target < containing[0][2]:
            raise EvidenceError('branch outside selected FDE')
        branches.append((containing[0][0], hex(site), raw.hex(), hex(target), hex(cc), CONDITIONS[cc]))
    failures = []
    for label, site, expected in FAILURE_EDGES:
        raw, target, cc = decode_branch(data, secs, site)
        if target != expected:
            raise EvidenceError('failure branch changed: ' + label)
        failures.append((label, hex(site), raw.hex(), hex(target), hex(cc), CONDITIONS[cc]))
    calls = []
    for label, site, expected in DIRECT_CALLS:
        raw, target = decode_rel(data, secs, site, 'call5')
        if target != expected:
            raise EvidenceError('direct call changed: ' + label)
        calls.append((label, hex(site), raw.hex(), hex(target)))
    differences, masks, normalized_sha256 = compare_wrappers(data, secs)
    comparison_bodies = []
    for label, start, end in (('book-context', CONTEXT[0], CONTEXT[1]),
                              ('selected-counterpart', FUNCTIONS[0][1], FUNCTIONS[0][2])):
        _, offset = mapping(data, secs, start, end - start)
        raw = read_va(data, secs, start, end - start)
        comparison_bodies.append((label, hex(start), hex(end), hex(offset),
                                  hashlib.sha256(raw).hexdigest(), raw.hex()))
    relocs = get_relocations(data, secs, set(SLOTS) | {r[6] for r in DIAGNOSTICS})
    slot_rows = []
    for slot in SLOTS:
        typ, index, addend = relocs[slot]
        if typ == 8 and index == 0:
            name = ''
        elif typ == 6 and index:
            name = symbol_name(data, secs, index)
        else:
            raise EvidenceError('unexpected slot relocation')
        slot_rows.append((hex(slot), typ, index, hex(addend), name))
    diagnostics = []
    for label, message_site, location_site, length_site, address, length, slot in DIAGNOSTICS:
        _, message_target = decode_rel(data, secs, message_site, 'lea7')
        _, location_target = decode_rel(data, secs, location_site, 'lea7')
        if (message_target, location_target) != (address, slot) or read_va(data, secs, length_site, 5) != b'\xbe' + struct.pack('<I', length):
            raise EvidenceError('diagnostic operands changed')
        typ, index, pointer = relocs[slot]
        if (typ, index) != (8, 0):
            raise EvidenceError('Location is not relative')
        zero, path_length, line, column = struct.unpack('<QQII', read_va(data, secs, slot, 24))
        if zero or path_length > 512:
            raise EvidenceError('invalid Location record')
        source = read_va(data, secs, pointer, path_length).decode('utf-8')
        suffix = '/'.join(source.split('/')[-4:])
        if suffix != 'src/collections/btree/node.rs':
            raise EvidenceError('unexpected diagnostic source')
        message = read_va(data, secs, address, length).decode('ascii')
        diagnostics.append((label, hex(address), length, message, hex(slot), suffix, line, column))
    constants = []
    for label, va, length, encoding in CONSTANTS:
        raw = read_va(data, secs, va, length)
        value = int.from_bytes(raw, 'little')
        constants.append((label, hex(va), encoding, raw.hex(), value, hex(value)))
    params = split_parameters(data, secs)
    cases = [project_split(i, params) for i in range(params[0] + 1)]
    return {'target_sha256': digest, 'functions': functions, 'pins': pins,
            'branches': branches, 'failures': failures, 'calls': calls, 'masks': masks,
            'comparison_bodies': comparison_bodies,
            'difference_offsets': [hex(i) for i in differences],
            'normalized_sha256': normalized_sha256,
            'slots': slot_rows, 'diagnostics': diagnostics, 'constants': constants,
            'params': params, 'cases': cases}


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(out):
    evidence = collect(TARGET.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / 'functions.tsv', ('role','start_va','end_va','file_offset','fde_va','cie_va','lsda_va','unwind_index','bytes','sha256','raw_hex'), evidence['functions'])
    write_tsv(out / 'witnesses.tsv', ('label','start_va','end_va','file_offset','raw_hex','observation'), evidence['pins'])
    write_tsv(out / 'constants.tsv', ('label','field_va','encoding','raw_hex','value','value_hex'), evidence['constants'])
    write_tsv(out / 'branches.tsv', ('function','site_va','raw_hex','target_va','condition_code','predicate'), evidence['branches'])
    write_tsv(out / 'failure-edges.tsv', ('label','site_va','raw_hex','target_va','condition_code','predicate'), evidence['failures'])
    write_tsv(out / 'calls.tsv', ('label','site_va','raw_hex','target_va'), evidence['calls'])
    write_tsv(out / 'wrapper-bodies.tsv', ('role','start_va','end_va','file_offset','sha256','raw_hex'), evidence['comparison_bodies'])
    write_tsv(out / 'wrapper-comparison.tsv', ('offset','kind','mask_start','mask_end','resolved_target_va','context_raw','counterpart_raw'), evidence['masks'])
    write_tsv(out / 'relocations.tsv', ('slot_va','relocation_type','symbol_index','addend','symbol'), evidence['slots'])
    write_tsv(out / 'diagnostics.tsv', ('label','message_va','length','message','location_va','source_suffix','line','column'), evidence['diagnostics'])
    write_tsv(out / 'split-cases.tsv', ('index','old_keys','new_key','pivot_index','promoted','side','local_index','left','right'),
              ((x['index'], ','.join(map(str, x['old_keys'])), x['new_key'], x['pivot_index'], x['promoted'], x['side'], x['local_index'], ','.join(map(str, x['left'])), ','.join(map(str, x['right']))) for x in evidence['cases']))
    params = evidence['params']
    nonfull = [project_nonfull(length, index, params)
               for length in range(params[0]) for index in range(length + 1)]
    parents = [project_parent(index, params) for index in range(params[0] + 1)]
    write_tsv(out / 'nonfull-cases.tsv', ('length','index','shifted_keys','shift_bytes'), nonfull)
    write_tsv(out / 'parent-cases.tsv', ('index','pivot_index','side','local_index','left_edges','right_edges'), parents)
    summary = {'target_sha256': evidence['target_sha256'],
               'coordinate_system': 'linked ELF virtual addresses; half-open ranges',
               'selected_functions': len(evidence['functions']), 'witnesses': len(evidence['pins']),
               'selected_conditional_branches': len(evidence['branches']), 'failure_edges': len(evidence['failures']), 'direct_call_sites': len(evidence['calls']),
               'relative_operand_masks': len(evidence['masks']), 'comparison_windows': len(evidence['comparison_bodies']), 'raw_difference_offsets': evidence['difference_offsets'],
               'masked_wrapper_sha256': evidence['normalized_sha256'],
               'slot_relocations': len(evidence['slots']), 'diagnostic_records': len(evidence['diagnostics']), 'constant_fields': len(evidence['constants']),
               'split_parameters': evidence['params'], 'synthetic_split_cases': len(evidence['cases']),
               'synthetic_nonfull_cases': len(nonfull), 'synthetic_parent_cases': len(parents),
               'limitations': 'Static selected instruction sites and synthetic projections; no captured code execution or complete CFG claim.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        generate(args.out)
    except (EvidenceError, ValueError, OSError, StopIteration, struct.error) as exc:
        print('evidence error: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
