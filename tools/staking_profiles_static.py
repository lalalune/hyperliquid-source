#!/usr/bin/env python3
"""Authenticated node94 staking validator-profiles binding (0x3366580).

Binds the first staking-component body to the node #94 digest: the
`validator_profiles_at_epoch` reconstruction at 0x3366580 — its epoch-state
BTreeMap lookup, validator iteration (64-byte stride), delegator-balance
sum with two checked u64 adds, BTreeSet duplicate guard, the duplicate-profile
assert panic anchored to l1/src/staking.rs:243:17, the Err/Ok result tags,
four stdlib panic Locations carrying the rustc build hash, and the call
census. Static byte/record checks only; the captured binary is never executed.
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

START, END = 0x3366580, 0x3366b60
FDE_VA = 0x116bea8
BODY_LEN = 1504
PATH_VA = 0x1dee3f
PATH = b'/home/ubuntu/hl/code_Mainnet/l1/src/staking.rs'
ASSERT_MSG_VA = 0x58bfde
ASSERT_MSG = b'assertion failed: profiles.insert(validator_profile)'
ASSERT_LOC = 0x56e9c30
ASSERT_LINE, ASSERT_COL = 243, 17
PANIC_FN = 0x157b7f0
GOT_ASSERT_PANIC = 0x576e108
NAVIGATE_LOC, NAVIGATE2_LOC, ACCUM_LOC = 0x56e9fe8, 0x56e8b20, 0x56e9f88
NAVIGATE2_LINE, NAVIGATE2_COL = 161, 36
NAVIGATE_PATH = (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/alloc/'
                 b'src/collections/btree/navigate.rs')
ACCUM_PATH = (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/'
              b'src/iter/traits/accum.rs')
NAVIGATE_LINE, NAVIGATE_COL = 534, 47
ACCUM_LINE, ACCUM_COL = 204, 1
NAV_PANIC_FN, ACCUM_PANIC_FN = 0x157a9f0, 0x157b480
GOT_NAV_PANIC, GOT_ACCUM_PANIC = 0x576e470, 0x576e118
RUSTC_HASH = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
SET_GUARD_CALLEE = 0x3399380
ERR_TAG, OK_TAG = 0x97, 0x186
GOT_SELF = 0x5775c78
CALLER, CALLER_FN = 0x3369dd1, (0x3369db0, 0x336a360)

FDE = bytes.fromhex(
    '5000000080e21a00d0a61f02e005000004278391ff410e10420e18420e20420e28'
    '420e30410e38470ec00183078c068d058e048f038602034a050e38410e30420e28'
    '420e20420e18420e10410e08410ec0010000')

BODY = bytes.fromhex(
    '554157415641554154534881ec88000000488b46304885c00f84a40000004989d6488b4e'
    '38440fb7901a020000428d14d5000000004c8d049248c7c2ffffffff31f666666666662e'
    '0f1f8400000000004939f0742b4c3b74d010410f97c14180d90048ffc24883c6284180f9'
    '0174e1450fb6c14585c0750beb19660f1f4400004c89d24883e9017239488b84d0200200'
    '00eb9248c74424080000000048c744241800000000488b4c30384885c90f95c248893c24'
    '74164c8b7c30404c8b6c3048eb0d66c7079700e9850400004531ed488d6c246031db4c8d'
    '6424580f1f4400004983ed010f8248040000f6c2010f84bb0400004885db74280fb7832a'
    '0400004939c70f83c80000004889da4c89f8e9e3000000666666662e0f1f840000000000'
    '4d85ff74384c89f84889cb4883e007743131c9666666662e0f1f840000000000488b9b30'
    '04000048ffc14839c875f14c89f84829c84983ff087315eb514889cbeb4c4c89f84983ff'
    '0872430f1f440000488b8b30040000488b8930040000488b8930040000488b8930040000'
    '488b8930040000488b8930040000488b8930040000488b99300400004883c0f875c231c9'
    '4531ff0fb7832a0400004939c70f8245ffffff666666662e0f1f840000000000488b9320'
    '0400004885d20f84b003000048ffc10fb783280400004889d3663b822a04000073da4885'
    'c90f8491000000488d34c24881c6380400004889cf4883e7070f84090300004531c0660f'
    '1f440000488b1e488db33004000049ffc04c39c775ee4889cf4c29c74883f90872436690'
    '488b0e488b8930040000488b8930040000488b8930040000488b8930040000488b893004'
    '0000488b8930040000488b9930040000488db3300400004883c7f875bf4531ffeb11662e'
    '0f1f8400000000004c8d78014889d348c1e0068b4c0228894c24300f104402180f294424'
    '208b4c023c894c24500f1044022c0f29442440488b34024885f60f84040200004801c248'
    '8b42104885c00f84f4010000488b7a0831d231c9eb2a662e0f1f840000000000498d7901'
    '4c89c24b034cc8080f829d020000be0000000048ffc80f84c20100004885d2742b440fb7'
    '823e0100004c39c70f83ca0000004989d04989f9e9e30000006666666666662e0f1f8400'
    '000000004885ff74384989f84889f24983e00774314531c96666662e0f1f840000000000'
    '488b924001000049ffc14d39c875f14889fe4c29ce4883ff087315eb514889f2eb4c4889'
    'fe4883ff0872430f1f440000488b9240010000488b9240010000488b9240010000488b92'
    '40010000488b9240010000488b9240010000488b9240010000488b92400100004883c6f8'
    '75c231ff31f6440fb7823e0100004c39c70f8243ffffff666666662e0f1f840000000000'
    '4c8b024d85c00f848501000048ffc6440fb78a3c0100004c89c266453b883e01000073dc'
    '4885f60f84d3feffff4b8d3cc84881c7480100004989f24983e2070f848b0000004531db'
    '0f1f840000000000488b17488dba4001000049ffc34d39da75ee4989f24d29da4883fe08'
    '72436690488b17488b9240010000488b9240010000488b9240010000488b924001000048'
    '8b9240010000488b9240010000488b9240010000488dba400100004983c2f875bf31ff4b'
    '034cc8080f8354feffffe9ec000000666666662e0f1f8400000000004989f24883fe0873'
    '97ebd60f1f44000031c948894c24588b4424308945100f284424200f1145008b44245089'
    '45240f284424400f114514488d7c24084c89e6e8fc280300b201b90000000084c00f84cd'
    'fbffffeb5166662e0f1f8400000000004889cf4883f9080f8254fdffffe90efdffff488b'
    '442418488b3c24488947180f104424080f1147084c89772066c70786014889f84881c488'
    '0000005b415c415d415e415f5dc3488d3df15422fd488d153c313802be34000000ff1509'
    '764002eb3a488d3de0343802ff1562794002eb2b488d3dd1343802ff1553794002eb1c48'
    '8d3d62343802ff15ec754002eb0d488d3deb1f3802ff15357940020f0beb06eb040f0b0f'
    '0b4889c3488d7c2408e87eb308004889dfe8b6952f02ff15c8754002')

# Byte windows pinned by purpose: (offset, hex, label).
WINDOWS = [
    (0x25, '440fb7901a020000', 'epoch-map node count word at +0x21a'),
    (0x89, '488b84d020020000', 'epoch-map child load at +0x220'),
    (0x83, '4883e9017239', 'epoch count decrement with not-found branch'),
    (0xc2, '66c7079700', 'Err result tag 0x97 (epoch state missing)'),
    (0x54c, '66c7078601', 'Ok result tag 0x186'),
    (0x297, '48c1e006', 'validator entry stride 64'),
    (0x29b, '8b4c0228', 'profile field load at entry +0x28'),
    (0x2a3, '0f10440218', 'profile field load at entry +0x18'),
    (0x2ad, '8b4c023c', 'profile field load at entry +0x3c'),
    (0x2b5, '0f1044022c', 'profile field load at entry +0x2c'),
    (0x2f7, '4b034cc8080f829d020000', 'checked add #1 with carry branch to the accum panic'),
    (0x4a3, '4b034cc8080f8354feffff', 'checked add #2 with carry branch to the accum panic'),
    (0x2ff, '488b84d020020000'[:0], 'unused'),
    (0x315, '440fb7823e010000', 'delegator-map node count word at +0x13e'),
    (0x421, '4881c748010000', 'delegator values base +0x148'),
    (0x4ff, 'e8fc280300', 'BTreeSet duplicate-guard call'),
    (0x50b, '84c00f84cdfbffff', 'guard result test routes duplicates to the assert'),
]

# Four noreturn sites: (site va, struct va, GOT, callee, path kind).
STD_SITES = [
    (0x3366b01, NAVIGATE_LOC, GOT_NAV_PANIC, NAV_PANIC_FN, 'navigate 534:47'),
    (0x3366b10, NAVIGATE_LOC, GOT_NAV_PANIC, NAV_PANIC_FN, 'navigate 534:47'),
    (0x3366b1f, ACCUM_LOC, GOT_ACCUM_PANIC, ACCUM_PANIC_FN, 'accum 204:1'),
    (0x3366b2e, NAVIGATE2_LOC, GOT_NAV_PANIC, NAV_PANIC_FN, 'navigate 161:36'),
]


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
    require(len(body) == BODY_LEN, 'Unexpected body length')
    require(body == BODY, 'Staking body bytes changed')

    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'Staking FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, hexstr, label in WINDOWS:
        if hexstr:
            raw = bytes.fromhex(hexstr)
            require(body[offset:offset + len(raw)] == raw, f'Window changed: {label}')

    rels = relocations(reader)

    # Duplicate-profile assert: message, Location, panic callee.
    require(reader.read(ASSERT_MSG_VA, len(ASSERT_MSG)) == ASSERT_MSG, 'Assert message changed')
    require(rels.get(ASSERT_LOC) == PATH_VA, 'Assert Location relocation changed')
    length_, line, column = struct.unpack('<QII', reader.read(ASSERT_LOC + 8, 16))
    require((length_, line, column) == (len(PATH), ASSERT_LINE, ASSERT_COL),
            'Assert Location layout changed')
    require(reader.read(PATH_VA, length_) == PATH, 'staking path changed')
    require(rels.get(GOT_ASSERT_PANIC) == PANIC_FN, 'Assert panic callee changed')
    off = 0x3366ae6 - START
    require(body[off:off + 3] == b'\x48\x8d\x3d', 'Assert message lea changed')
    require(0x3366aed + struct.unpack_from('<i', body, off + 3)[0] == ASSERT_MSG_VA,
            'Assert message address changed')
    require(body[0x3366aed - START:0x3366aed - START + 3] == b'\x48\x8d\x15',
            'Assert Location lea changed')
    require(0x3366af4 + struct.unpack_from('<i', body, 0x3366aed - START + 3)[0] == ASSERT_LOC,
            'Assert Location address changed')
    require(body[0x3366af4 - START:0x3366af9 - START] == b'\xbe' + struct.pack('<I', len(ASSERT_MSG)),
            'Assert message length operand changed')

    # Stdlib panic Locations carry the rustc build hash.
    for struct_va, path, line, col in [
            (NAVIGATE_LOC, NAVIGATE_PATH, NAVIGATE_LINE, NAVIGATE_COL),
            (NAVIGATE2_LOC, NAVIGATE_PATH, NAVIGATE2_LINE, NAVIGATE2_COL),
            (ACCUM_LOC, ACCUM_PATH, ACCUM_LINE, ACCUM_COL)]:
        path_va = rels.get(struct_va)
        require(path_va is not None, 'Stdlib Location relocation missing')
        length_, sline, scol = struct.unpack('<QII', reader.read(struct_va + 8, 16))
        require((length_, sline, scol) == (len(path), line, col), 'Stdlib Location layout changed')
        require(reader.read(path_va, length_) == path, 'Stdlib Location path changed')
    require(rels.get(GOT_NAV_PANIC) == NAV_PANIC_FN, 'Navigate panic callee changed')
    require(rels.get(GOT_ACCUM_PANIC) == ACCUM_PANIC_FN, 'Accum panic callee changed')
    for site, struct_va, got, callee, kind in STD_SITES:
        off = site - START
        require(body[off:off + 3] == b'\x48\x8d\x3d', f'Stdlib site lea changed at {site:#x}')
        require(site + 7 + struct.unpack_from('<i', body, off + 3)[0] == struct_va,
                f'Stdlib site struct address changed at {site:#x}')
        call_va = site + 7
        require(body[call_va - START:call_va - START + 2] == b'\xff\x15',
                f'Stdlib site call opcode changed at {site:#x}')
        require(call_va + 6 + struct.unpack_from('<i', body, call_va - START + 2)[0] == got,
                f'Stdlib site GOT target changed at {site:#x}')

    # BTreeSet guard callee and result tags.
    off = 0x3366a7f - START
    require(body[off:off + 5] == b'\xe8' + struct.pack('<i', SET_GUARD_CALLEE - 0x3366a84),
            'Set-guard direct call target changed')

    # Call census over the whole .text.
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    require(rels.get(GOT_SELF) == START, 'Self GOT slot changed')
    pos, indirect, direct = 0, [], []
    while (pos := code.find(b'\xff\x15', pos)) >= 0:
        if pos + 6 <= len(code):
            got = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if got == GOT_SELF:
                indirect.append(text['address'] + pos)
        pos += 2
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    require(indirect == [CALLER], f'GOT-indirect caller census changed: {[hex(x) for x in indirect]}')
    require(direct == [], 'Unexpected direct references')
    require(CALLER_FN[0] <= CALLER < CALLER_FN[1], 'Caller outside the indexed function')

    # Checked-add semantics: both u64 adds branch to the same accum panic on carry.
    for off_add, branch_off in ((0x2f7, 0x2f7 + 5), (0x4a3, 0x4a3 + 5)):
        a, b = 2**64 - 1, 1
        require(((a + b) % 2**64) < a, 'carry model sanity failed')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=BODY_LEN,
                      sha256=hashlib.sha256(body).hexdigest(), fde_va=hex(FDE_VA),
                      inferred_label='staking validator_profiles_at_epoch'),
        structure=dict(
            epoch_lookup='BTreeMap walk: node count word at +0x21a, children at '
                         '+0x220, 8-byte key compare; not-found returns Err tag 0x97',
            validator_iteration='64-byte stride; profile fields copied from entry '
                                '+0x18/+0x28/+0x2c/+0x3c',
            delegator_sum='BTreeMap walk with count word +0x13e, values base +0x148; '
                          'two checked u64 adds branch on carry to the accum panic',
            duplicate_guard=dict(callee=hex(SET_GUARD_CALLEE), site='0x3366a7f',
                                 observed='result test routes the duplicate case to the assert panic'),
            result_tags=dict(err_epoch_missing=hex(ERR_TAG), ok=hex(OK_TAG),
                             ok_layout='qword +0x18, xmm +0x08, epoch qword +0x20, word tag +0x00')),
        assert_panic=dict(message=ASSERT_MSG.decode(), message_va=hex(ASSERT_MSG_VA),
                          location_va=hex(ASSERT_LOC), line=ASSERT_LINE, column=ASSERT_COL,
                          path='l1/src/staking.rs', callee=hex(PANIC_FN)),
        stdlib_panics=dict(
            rustc_commit=RUSTC_HASH,
            navigate=dict(sites=3, locations='alloc/src/collections/btree/navigate.rs:534:47 (x2) and :161:36 (x1)',
                          callee=hex(NAV_PANIC_FN)),
            accum=dict(sites=1, location='core/src/iter/traits/accum.rs:204:1',
                       callee=hex(ACCUM_PANIC_FN), note='both checked-add carry branches land here'),
            divergence='the binary panics on delegator-sum overflow instead of returning '
                       'an arithmetic-error variant; the reference sketch proposes '
                       'checked_add().ok_or(ArithmeticOverflow), which the bytes do not support'),
        call_census=dict(got_slot=hex(GOT_SELF), got_indirect=[hex(CALLER)],
                         direct_e8=0, lea_references=0,
                         containing_function=dict(start=hex(CALLER_FN[0]), end=hex(CALLER_FN[1])),
                         denominator='complete .text scan for e8 / slot-ff15 / lea encodings'),
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
