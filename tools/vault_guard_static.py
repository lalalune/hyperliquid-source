#!/usr/bin/env python3
"""Authenticated node94 vault valuation guard binding (0x395b3a0).

Binds the first vaults-component body to the node #94 digest: its
FDE-bounded body, the l1/src/vault/mod.rs:407:58 panic Location, the reused
stdlib navigate.rs Location under the rustc build hash, the f64 i64-range
guard block with three divisions by the shared 1e6 constant, the noreturn
panic tail, and the four-caller census. Static byte/record checks only; the
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

START, END, BODY_LEN = 0x395b3a0, 0x395bdc3, 2595
FDE_VA = 0x11c7884
VAULT_LOC = 0x570da30
VAULT_PATH_VA = 0x1e682a
VAULT_PATH = b'/home/ubuntu/hl/code_Mainnet/l1/src/vault/mod.rs'
NAVIGATE_LOC = 0x56e8b20
NAVIGATE_PATH = (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/alloc/'
                 b'src/collections/btree/navigate.rs')
RUSTC_HASH = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
MIN_F64_VA, MAX_F64_VA, ONE_E6_VA = 0x20acb8, 0x20a7f0, 0x20ae60
GOT_PANIC_DISPLAY, GOT_PANIC_FMT, GOT_SELF = 0x576e470, 0x576e048, 0x5774b48
PANIC_DISPLAY_FN, PANIC_FMT_FN = 0x157a9f0, 0x157aa10
CALLERS = [0x2736819, 0x395b1dc, 0x4d4275c, 0x4d46699]

FDE = bytes.fromhex('500000005c9c2000143b7902230a000004831090ff410e10420e18420e20420e28420e30410e38470eb00283078c068d058e048f0386020375080e38410e30420e28420e20420e18420e10410e08410eb0020000')

BODY = bytes.fromhex(
    '554157415641554154534881ecf80000004489cd4989cd4889d34989f64c8b3e4983ff01'
    '753df30f6f03f3410f6f8e98000000660f74c8660f6e431066410f6e96a8000000660f74'
    'd0660fdbd1660fd7c23dffff0000740b66c747081600e90c0800004180bead0000000075'
    '3df30f6f03f3410f6f8e98000000660f74c8660f6e431066410f6e96a8000000660f74d0'
    '660fdbd1660fd7c23dffff0000740b66c747081700e9c50700004c8944244848897c2428'
    '488b842430010000488b08488b5008488b401048894c241048898c249000000048899424'
    '880000004889942498000000488984248000000048898424a0000000498db68400000048'
    '8dbc24900000004889742430e8d3a9ffff4989c44183ff0248895c24384c897c2420896c'
    '24080f8281020000498b4608498b5e184885c00f95c14885db0f95c220ca80fa010f8562'
    '0200004c89f54d8b7e104531f66666666666662e0f1f840000000000f6c1010f84790800'
    '004d85f67422410fb78ee60000004939cf0f83c10000004c89f14c89fae9d9000000660f'
    '1f4400004d85ff0f848d0000004c89f94989c64883e1070f84b501000031d20f1f440000'
    '4d8bb6e800000048ffc24839d175f14c89f84829d04983ff0872430f1f440000498b8ee8'
    '000000488b89e8000000488b89e8000000488b89e8000000488b89e8000000488b89e800'
    '0000488b89e80000004c8bb1e80000004883c0f875c24531ff31c0410fb78ee600000049'
    '39cf0f825bffffffeb1a4531ff4989c631c0410fb78ee60000004939cf0f8240ffffff90'
    '498b0e4885c90f84f606000048ffc0410fb796e40000004989ce663b91e600000073dd48'
    '85c00f8494000000488d34d14881c6f00000004889c74883e7070f84cc0000004531c066'
    '0f1f8400000000004c8b36498db6e800000049ffc04c39c775ee4889c74c29c74883f808'
    '72436690488b06488b80e8000000488b80e8000000488b80e8000000488b80e800000048'
    '8b80e8000000488b80e80000004c8bb0e8000000498db6e80000004883c7f875bf4531ff'
    'eb11662e0f1f8400000000004c8d7a014989ce488d04928b54811889542460f30f6f4481'
    '08660f7f442450488dbc2490000000488d742450e8afa7ffff4c89e14801c170374989cc'
    'b101b80000000048ffcb0f8514feffffeb5e66904889c74883f8087298e952ffffff4c89'
    'f84983ff080f8365feffffe99efeffff48c1f93f48ba00000000000000804831d14901c4'
    '4c0f40e131ff488d35b722db01ff15597ae101b101b80000000048ffcb0f85b9fdffffeb'
    '034c89f54d85e47913488b7c2430ff15d47ae10184c00f84db030000807c2408004c896c'
    '24404989ef747b4c8b742438418b461089442460410f10060f29442450418b4610898424'
    'a0000000f3410f6f06660f7f842490000000488db42490000000488b7c2410ff15ab8ee1'
    '014d85ed0f88de0500004c39e80f835b01000066c78424900000003300488dbc24900000'
    '00e892df0300488b7c242866c747082c00e921040000488b442438f30f6f00f3410f6f8f'
    '98000000660f74c8660f6e401066410f6e97a8000000660f74d0660fdbd1660fd7ca31c0'
    '81f9ffff00000f95c1837c2420010f843fffffff88c885c00f8435ffffff488b7c2430ff'
    '15df79e10184c00f8522ffffff498b47504885c00f84a60300004d8db7980000004c897c'
    '2470498b4f5848894c2420488db0180200000fb788f602000048894424084c8d78d04889'
    '4c24788d048d000000004c8d2c8048c7c3ffffffff6666666666662e0f1f840000000000'
    '4d85ed7442488d6e14ba140000004c89f7ff15c12be10148984885c00f98c10f9fc028c8'
    '4983c73048ffc34983c5ec4889ee3c0174ca0fb6c085c04c8b6c2440750ae95802000048'
    '8b5c2478488b4c24204883e901488b4424080f82f402000048894c2420488b84d8f80200'
    '00e951ffffff488d742450488b5c24104889df4c89eaff15a090e101488b9b3802000048'
    '89d84c29e80f80e6020000488b5c241048898338020000488b4c24308b4110898424a000'
    '0000f30f6f01660f7f842490000000488db424900000004889df4c89eae86a3bdaff488b'
    '9b380200004889d84c01e80f80c9020000488b4c24104889813802000048898c24900000'
    '00488b8424880000004889842498000000488b84248000000048898424a00000004c8d8c'
    '24900000004c89ff4c89f64c89ea4c89e14c8b442448e8d5e8ffff4d8b77504d85f60f84'
    '97030000498b475848894424104c8b25802ae101498db618020000410fb786f602000049'
    '8d5ed848894424088d0485000000004c8d2c8048c7c5ffffffff66666666662e0f1f8400'
    '000000004d85ed74394c8d7e14ba14000000488b7c243841ffd448984885c00f98c10f9f'
    'c028c84883c33048ffc54983c5ec4c89fe3c0174cb0fb6c085c07507eb26488b6c240848'
    '8b4424104883e8010f82fd02000048894424104d8bb4eef8020000e964ffffff4c8b334c'
    '89f04c8b7c24404c01f80f82d90100004889034c8b73084c89f04c01f84c8b6424480f80'
    'e301000048894308418b442408894324498b04244889431c488b4424300f1000488b7c24'
    '280f1147108b401066490f6ec7660f62057b838afc894720660f5c0590738afc660f28c8'
    '660f15c8f20f58c8f20f5e0d3cf38afc48b819000000000000804883c0eb488907f20f11'
    '4f08e9dd000000488b7c242866c747080900e9c00000000f57c0f2490f2ac4f2410f5907'
    '66480f7ec148b8ffffffffffffff7f4821c1660fefc948baffffffffffffef7f4839d14c'
    '8b7c24707f2ef20f10152af18afc660f2ed07710660f2e0554ec8afc7706660f6fc8eb10'
    'f20f5fd0f20f100d40ec8afcf20f5dcaf2480f2cc9660f2e0d07e78afc480f47c831db66'
    '0f2ec9480f4acb0f57d2f2480f2ad1f20f5e1581f28afc4d85e4490f4fdc4889d84c01e8'
    '0f82ff000000f20f1005fef18afc660f2ec20f8628010000488b7c242866c74708020048'
    'b819000000000000804889074889f84881c4f80000005b415c415d415e415f5dc30f99c0'
    '0fb6c048b9ffffffffffffff7f4801c14c29eb488d35aa60d901480f40d931ffff153675'
    'e1014889d8e9e9fcffff48c1f83f48b900000000000000804831c14c01eb488d35d35fd9'
    '01480f40d931ffff150775e1014889d8e908fdffff488d359890db0131ffff15f074e101'
    '4d01fe48c7c0ffffffff490f43c6e905feffff48c1f83f48b900000000000000804831c1'
    '4d01fe488d35ba90db014c0f40f131ffff15b674e1014c89f0e9eefdffff488d3dffe2d8'
    '01ff158127e1010f0b488d352090db0131fff20f11542408ff158a74e101f20f10542408'
    '4c01eb48c7c0ffffffff480f43c3f20f1005d6f08afc660f2ec20f87d8feffff66480f6e'
    'c8660f620d47818afc660f5c0d5f718afc660f28c1660f15c1f20f58c1f20f5e050bf18a'
    'fcf20f100d23f38afc660f2ec80f879dfefffff20f5ed0f20f10054de78afc660f2ec20f'
    '86f6f9ffffe982feffff488d3d97cdd801ff15e126e101488d3d9a1cdb01ff15d426e101'
    '488d3db0dcc3fc488d0d8665d9014c8d052f5fd901488d54241fbe2b000000ff158722e1'
    '010f0b')

WINDOWS = [
    (0x77c, 'f20f5e0d3cf38afc', 'divsd by 1e6'),
    (0x7e6, 'f20f10152af18afc', 'load i64::MIN as f64'),
    (0x7ee, '660f2ed0', 'ucomisd min vs value'),
    (0x7f4, '660f2e0554ec8afc', 'ucomisd value vs i64::MAX as f64'),
    (0x837, 'f20f5e1581f28afc', 'second divsd by 1e6'),
    (0x97a, 'f20f1005d6f08afc', 'reload i64::MIN as f64'),
    (0x9ad, 'f20f5e050bf18afc', 'third divsd by 1e6'),
    (0x9c7, 'f20f5ed0', 'register divsd'),
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
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
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
    require(body == BODY, 'Vault guard body bytes changed')

    eh = reader.by_name['.eh_frame']
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'Vault guard FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, hexstr, label in WINDOWS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, 'Window changed: ' + label)

    rels = relocations(reader)
    require(rels.get(VAULT_LOC) == VAULT_PATH_VA, 'Vault Location relocation changed')
    length_, line, column = struct.unpack('<QII', reader.read(VAULT_LOC + 8, 16))
    require((length_, line, column) == (len(VAULT_PATH), 407, 58), 'Vault Location layout changed')
    require(reader.read(VAULT_PATH_VA, length_) == VAULT_PATH, 'vault path changed')
    path_va = rels.get(NAVIGATE_LOC)
    require(path_va is not None, 'Navigate Location relocation missing')
    nlen, nline, ncol = struct.unpack('<QII', reader.read(NAVIGATE_LOC + 8, 16))
    require((nlen, nline, ncol) == (len(NAVIGATE_PATH), 161, 36), 'Navigate Location layout changed')
    require(reader.read(path_va, nlen) == NAVIGATE_PATH, 'Navigate path changed')

    LEA3D = bytes.fromhex('488d3d')
    FF15 = bytes.fromhex('ff15')
    off = 0x395bd82 - START
    require(body[off:off + 3] == LEA3D, 'First noreturn lea changed')
    require(0x395bd89 + struct.unpack_from('<i', body, off + 3)[0] == NAVIGATE_LOC,
            'First noreturn target changed')
    off = 0x395bd8f - START
    require(body[off:off + 3] == LEA3D, 'Second noreturn lea changed')
    require(0x395bd96 + struct.unpack_from('<i', body, off + 3)[0] == VAULT_LOC,
            'Second noreturn target changed')
    for site in (0x395bd89, 0x395bd96):
        c = site - START
        require(body[c:c + 2] == FF15, 'Noreturn call opcode changed')
        require(site + 6 + struct.unpack_from('<i', body, c + 2)[0] == GOT_PANIC_DISPLAY,
                'Noreturn call target changed')
    require(rels.get(GOT_PANIC_DISPLAY) == PANIC_DISPLAY_FN, 'Panic display callee changed')
    require(rels.get(GOT_PANIC_FMT) == PANIC_FMT_FN, 'Panic fmt callee changed')

    require(reader.read(MIN_F64_VA, 8) == struct.pack('<d', -2.0**63), 'i64::MIN f64 constant changed')
    require(reader.read(MAX_F64_VA, 8) == struct.pack('<d', float(2**63 - 1)), 'i64::MAX f64 constant changed')
    require(reader.read(ONE_E6_VA, 8) == struct.pack('<d', 1e6), 'Shared 1e6 constant changed')

    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    require(rels.get(GOT_SELF) == START, 'Self GOT slot changed')
    pos, indirect, direct = 0, [], []
    while (pos := code.find(FF15, pos)) >= 0:
        if pos + 6 <= len(code):
            got = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if got == GOT_SELF:
                indirect.append(text['address'] + pos)
        pos += 2
    pos = 0
    E8 = bytes.fromhex('e8')
    while (pos := code.find(E8, pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    require(indirect == CALLERS, 'GOT-indirect caller census changed: ' + repr([hex(x) for x in indirect]))
    require(direct == [], 'Unexpected direct references')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=BODY_LEN,
                      sha256=hashlib.sha256(body).hexdigest(), fde_va=hex(FDE_VA),
                      inferred_label='vault valuation guard with f64 i64-range checks'),
        locations=dict(vault=dict(location_va=hex(VAULT_LOC), line=407, column=58,
                                  path='l1/src/vault/mod.rs'),
                       stdlib=dict(location_va=hex(NAVIGATE_LOC),
                                   path='alloc/src/collections/btree/navigate.rs:161:36',
                                   rustc_commit=RUSTC_HASH)),
        float_guard=dict(observed='three divisions by the shared 1e6 constant; comparisons '
                                  'against i64::MIN/MAX as f64; NaN checks via ucomisd reg,reg',
                         constants=dict(min_f64=hex(MIN_F64_VA), max_f64=hex(MAX_F64_VA),
                                        one_e6=hex(ONE_E6_VA),
                                        one_e6_shared_with='0x1447130 Time Sub helper')),
        noreturn_tail=dict(sites=['0x395bd89', '0x395bd96'],
                           callees=dict(display=hex(PANIC_DISPLAY_FN), fmt=hex(PANIC_FMT_FN))),
        call_census=dict(got_slot=hex(GOT_SELF), got_indirect=[hex(x) for x in CALLERS],
                         direct_e8=0,
                         denominator='complete .text scan for e8 / slot-ff15 encodings'),
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
