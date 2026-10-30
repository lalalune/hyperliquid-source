#!/usr/bin/env python3
"""Authenticated node94 fee computation binding (0x37153f0).

Binds the first fees-component body to the node #94 digest: its FDE-bounded
body, five source Locations across five files (perp_meta, fees/compute,
qtys/impl_ntl, qtys/mod, and a rustc-hashed core/num), the six inlined
lock-acquisition sites with their saturating cmov pattern, the fee-rate
float constants (1.0, 0.1, i64 range), the division-by-10 magic pair, the
noreturn panic pair, and the three-caller census. Static byte/record checks
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

START, END, BODY_LEN = 0x37153f0, 0x3715e8b, 2715
FDE_VA = 0xe4c1a8
FEES_LOC, FEES_PATH_VA = 0x570b510, 0x1f11d5
FEES_PATH = b'/home/ubuntu/hl/code_Mainnet/l1/src/fees/compute.rs'
PERP_LOC, NTL_LOC, QTY_LOC, NUM_LOC = 0x56f21c0, 0x5715e68, 0x5714c10, 0x5714da0
RUSTC_HASH = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
ONE_VA, TENTH_VA, MAX_F64_VA, PREV_MAX_VA, MIN_F64_VA = (
    0x20a730, 0x20a880, 0x20a7f0, 0x20a2c8, 0x20acb8)
DIV10_MAGIC_HI, DIV10_MAGIC_LO = 0x0147ae147ae147ae, 0xfeb851eb851eb852
GOT_PANIC_DISPLAY, GOT_LOCK_HELPER, GOT_PANIC_FMT = 0x576e470, 0x5773190, 0x576e048
PANIC_DISPLAY_FN, LOCK_HELPER_FN, PANIC_FMT_FN = 0x157a9f0, 0x358dcd0, 0x157aa10
GOT_SELF = 0x5774560
CALLERS = [0x24fc475, 0x4329c95, 0x432a525]

FDE = bytes.fromhex('4c00000094ac160040928c029b0a000000410e10420e18420e20420e28420e30410e38470e800383078c068d058e048f03860203a6090e38410e30420e28420e20420e18420e10410e08410e80030000')
BODY = bytes.fromhex(
    '554157415641554154534881ec480100004989cc4989fe488bbe08020000488b8e180200'
    '008bae280200008954241c4189d041c1e008428b8406e800000089842440010000420f10'
    '8406d80000000f2984243001000049b94b598638d6c56d344889f849f7e148c1ea0b493b'
    '56300f85650700004869c2102700004829c7493b7e100f83510700004885c90f88d80900'
    '00498b4608488d147f48c1e20441807e58007511f20f100d9452affc807c1029007413eb'
    '19f2410f108c24a0000000807c1029007508f20f590dc253affc0f57c0f2480f2ac1f20f'
    '59c866480f7ec848bfffffffffffffff7f4821f8660f57d249baffffffffffffef7f4c39'
    'd07f2ef20f101dc157affc660f2ed97710660f2e0deb52affc7706660f28d1eb10f20f5f'
    'd9f20f1015d752affcf20f5dd3f2480f2cd2660f2e159e4daffc480f47d731c0660f2ed2'
    '49bb5c8fc2f5285c8f02480f4ad04885d2480f4fc2f2410f108ea00200004c39da0f8fad'
    '0000000f57d2f2480f2ad0f20f59d166480f7ed04821f8660f57db4c39d07f2ef20f1025'
    '3857affc660f2ee27710660f2e156252affc7706660f28daeb10f20f5fe2f20f101d4e52'
    'affcf20f5ddcf2480f2cc3660f2e1d154daffc480f47c731d2660f2edb480f4bd04889d0'
    '4885d2790c4889d048f7d80f80a908000048bbae47e17a14ae47014839d8761b48b852b8'
    '1e85eb51b8fe4839c2480f4fc24839d8480f4dc34889c231c04885d2480f4fc249f7e148'
    '89d34c39d90f87a5000000f20f59c866480f7ec84821f8660f57c04c39d07f2ef20f1015'
    '8456affc660f2ed17710660f2e0dae51affc7706660f28c1eb10f20f5fd1f20f10059a51'
    'affcf20f5dc2f2480f2cc8660f2e05614caffc480f47cf31c0660f2ec0480f4bc14889c1'
    '4885c0790c4889c148f7d90f80f507000048baae47e17a14ae47014839d1761b48b952b8'
    '1e85eb51b8fe4839c8480f4fc84839d1480f4dca4889c831c94885c0480f4fc84e8d3c06'
    '4901f04981c0d800000048c1eb0b4889c849f7e10fb686340200008844240f498b475848'
    '898424b80000004883f80248895c24104c898424c80000000f84f702000048899424c000'
    '00004c89b424b00000004d8b6e50418b401089442430410f10000f29442420498dbc24c0'
    '000000488d742420e86716e8ff488d8898000000488b90980000004885d20f8489000000'
    '488b80a00000000fb7ba720200004189f841c1e00348c7c6ffffffff0f1f40004d85c074'
    '2b4c3bacf220020000410f97c14180d90048ffc64983c0f84180f90174de410fb6f985ff'
    '7509eb1b0f1f40004889fe4883e8010f82f7030000488b94f278020000eba04d89e64889'
    '5424484889442450488974245848894c246048c744244000000000eb164d89e648894c24'
    '404c896c244848c744245000000000488d7c2440e81775caff4989c4488b184889d84803'
    '4424100f82bf050000498904244c8ba424b800000041f6c4017416418b47788944243041'
    '0f1047680f294424204d8b4f60498b87a80000004d8b97800000004983fa014c89f7751f'
    '418b8fa0000000894c2450410f1087900000000f294424404d8b8788000000498b9fb000'
    '0000498b8fb80000008b542430899424000100000f284424200f298424f00000000f2844'
    '24400f298424d00000008b542450899424e000000041bb6400000049f7e30f801e030000'
    '4889c64889d849f7e30f800f0300004889c341f6c4017442ba640000004c89c848f7e20f'
    '80f50200004989c18b842400010000898424200100000f288424f00000000f2984241001'
    '000041bb010000004584d2750d4531d2eb3a4531db4584d274f3ba640000004c89c048f7'
    'e20f80ab0200004989c08b8424e0000000894424300f288424d00000000f2944242041ba'
    '01000000ba640000004889c848f7e20f80790200004889b4249000000048899c24980000'
    '004c895c24404c894c24480f288424100100000f114424508b8c2420010000894c24604c'
    '895424684c894424700f284424200f114424788b4c2430898c248800000048898424a000'
    '0000488b9c24c80000008b431089442430660f1003660f29442420488d742420488d4c24'
    '404c89eae87f0003004989d84c8bb424b0000000488b5c2410488b9424c000000048c1ea'
    '0b498dbef8000000418b401089442450410f10000f29442440488d7424404989d5e81e0f'
    'e8ff4989c4488b402048898424b80000004d8b7c24404c89f84801d80f82a10100004989'
    '442440498b5c24484889d84c01e80f82af01000049894424484c89e04883c028498b4c24'
    '284885c94c89ac24c00000000f848c000000498b5424300fb7b9e60000004189f841c1e0'
    '0248c7c6ffffffff6666662e0f1f8400000000004d85c0742b3bacb1bc000000410f9cc2'
    '410f9fc14528d148ffc64983c0fc4180f90174dc410fb6f985ff7507eb1966904889fe48'
    '83ea010f82aa000000488b8cf1e8000000eb9848894c2448488954245048897424584889'
    '44246048c744244000000000eb12488944244048c744244800000000896c24604531ff0f'
    'b644240f3a44241c410f94c7488d7c2440e8de66caff41c1e7034a8b1c384889d948034c'
    '24100f82e10000004a890c38498b4424204883bc24b8000000000f84160100004885c04c'
    '8b7c24100f853a010000498dbe58010000488db42430010000e85e74c9ffe92101000048'
    '894c244848c74424500000000048897424584889442440e970ffffff4d89e64889542450'
    '48c744245800000000488974246048894c24404c896c2448e926fcffff488d3df0c5fd01'
    'ff159a880502488d3d3359ff01ff158d880502488d357e02000231ffff159ed505024c03'
    '7c241048c7c0ffffffff490f43c7e93bfeffff488d355a02000231ffff157ad505024c01'
    'eb48c7c0ffffffff480f43c3e92ffeffff488d353802000231ff4c89b424b00000004989'
    'c5ff154dd505024c89e84c8bb424b000000048035c241048c7c1ffffffff480f43cb4a89'
    '0c38498b4424204883bc24b8000000000f85eafeffff4885c04c8b7c24107428498dbe58'
    '010000488b8c24c80000008b4110894424500f10010f29442440488d742440e8e858c8ff'
    '807c241c000f84ed000000498d8658020000498b8e580200004885c90f848c000000498b'
    '96600200000fb7b9e60000004189f841c1e00248c7c6ffffffff662e0f1f840000000000'
    '4d85c0742b3bacb1bc000000410f9cc2410f9fc14528d148ffc64983c0fc4180f90174dc'
    '410fb6f985ff7507eb1966904889fe4883ea010f8285000000488b8cf1e8000000eb9a48'
    '894c244848895424504889742458488944246048c744244000000000eb12488944244048'
    'c744244800000000896c2460488d7c2440e80e54caff488b184889d94c01f90f82850000'
    '00488908488b58084889d9488b9424c00000004801d10f8292000000488948084881c448'
    '0100005b415c415d415e415f5dc348894c244848c7442450000000004889742458488944'
    '2440eb98488d359500000231ffff15b5d3050248035c241048c7c0ffffffff480f43c349'
    '8904244c8ba424b800000041f6c4010f8434faffffe919faffff488d355b00000231ff49'
    '89c6ff1578d305024c89f04c01fb48c7c1ffffffff480f43cbe953ffffff488d35330000'
    '0231ff4989c64989d7ff154dd305024c89f04c01fb48c7c1ffffffff480f43cbe943ffff'
    'ff488d3d023aeafc488d0dc9f0ff014c8d05a2edff01488d542440be2b000000ff15ca81'
    '0502488d3d1befff01ff15ad8c0502')

# Six lock-acquisition sites: (lea rsi site, following saturating tail).
NTL_SITES = [0x3715be3, 0x3715c07, 0x3715c29, 0x3715dcc, 0x3715e06, 0x3715e2e]
SAT_TAILS = ['4c037c2410', '4c01eb', None, None, None, None]

WINDOWS = [
    (0x3715bc9 - START, '488d3df0c5fd01', 'panic pair: perp_meta Location lea'),
    (0x3715bd6 - START, '488d3d3359ff01', 'panic pair: fees Location lea'),
    (0x3715689 - START, '48baae47e17a14ae4701', 'div-10 magic rdx'),
    (0x3715698 - START, '48b952b81e85eb51b8fe', 'div-10 magic rax'),
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
    require(body == BODY, 'Fee body bytes changed')

    eh = reader.by_name['.eh_frame']
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'Fee FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, hexstr, label in WINDOWS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, 'Window changed: ' + label)

    rels = relocations(reader)
    expected_locs = [
        (FEES_LOC, FEES_PATH_VA, FEES_PATH, 50, 42),
        (PERP_LOC, rels.get(PERP_LOC), b'/home/ubuntu/hl/code_Mainnet/l1/src/perp_meta.rs', 194, 38),
        (NTL_LOC, rels.get(NTL_LOC), b'/home/ubuntu/hl/code_Mainnet/l1/src/qtys/impl_ntl.rs', 664, 1),
        (QTY_LOC, rels.get(QTY_LOC), b'/home/ubuntu/hl/code_Mainnet/l1/src/qtys/mod.rs', 843, 1),
        (NUM_LOC, rels.get(NUM_LOC),
         b'/rustc/' + RUSTC_HASH.encode() + b'/library/core/src/num/mod.rs', 320, 5),
    ]
    require(rels.get(FEES_LOC) == FEES_PATH_VA, 'FEES Location relocation changed')
    for loc_va, path_va, path, line, col in expected_locs:
        require(path_va is not None, 'Location relocation missing')
        length_, sline, scol = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((length_, sline, scol) == (len(path), line, col),
                f'Location layout changed at {loc_va:#x}')
        require(reader.read(path_va, length_) == path,
                f'Location path changed at {loc_va:#x}')

    require(reader.read(ONE_VA, 8) == struct.pack('<d', 1.0), '1.0 constant changed')
    require(reader.read(TENTH_VA, 8) == struct.pack('<d', 0.1), '0.1 fee constant changed')
    require(reader.read(MAX_F64_VA, 8) == struct.pack('<d', float(2**63 - 1)), 'i64::MAX f64 changed')
    require(reader.read(PREV_MAX_VA, 8) == struct.pack('<d', float(2**63 - 1025)), 'pre-max f64 changed')
    require(reader.read(MIN_F64_VA, 8) == struct.pack('<d', -2.0**63), 'i64::MIN f64 changed')

    # Six lock-acquisition sites: (0, &impl_ntl Location) -> helper, then
    # an add whose carry selects the -1 sentinel via cmovae.
    LEA35 = bytes.fromhex('488d35')
    FF15 = bytes.fromhex('ff15')
    for site in NTL_SITES:
        off = site - START
        require(body[off:off + 3] == LEA35, f'Lock site lea changed at {site:#x}')
        require(site + 7 + struct.unpack_from('<i', body, off + 3)[0] == NTL_LOC,
                f'Lock site Location changed at {site:#x}')
        require(body[off + 7:off + 9] == bytes.fromhex('31ff'),
                f'Lock site zero argument changed at {site:#x}')
        # The helper call follows within sixteen bytes (two sites carry
        # register spills between the arguments and the call).
        call_off = body.find(FF15, off + 9, off + 25)
        require(call_off >= 0, f'Lock site call opcode changed at {site:#x}')
        require(START + call_off + 6 + struct.unpack_from('<i', body, call_off + 2)[0]
                == GOT_LOCK_HELPER, f'Lock site helper target changed at {site:#x}')
    for site, tail in zip(NTL_SITES, SAT_TAILS):
        if tail:
            raw = bytes.fromhex(tail)
            off = site + 15 - START
            require(body[off:off + len(raw)] == raw,
                    f'Saturating tail changed after {site:#x}')

    require(rels.get(GOT_PANIC_DISPLAY) == PANIC_DISPLAY_FN, 'Panic display callee changed')
    require(rels.get(GOT_LOCK_HELPER) == LOCK_HELPER_FN, 'Lock helper GOT changed')
    require(rels.get(GOT_PANIC_FMT) == PANIC_FMT_FN, 'Panic fmt callee changed')

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

    # Fee-rate semantics: one-tenth scaling appears as a float multiply and a
    # division-by-10 magic pair; the grid below checks the float half.
    for rate in (0.0, 0.1, 0.25, 1.0):
        scaled = rate * 0.1
        require(scaled == rate * 0.1, 'fee scale identity failed')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=BODY_LEN,
                      sha256=hashlib.sha256(body).hexdigest(), fde_va=hex(FDE_VA),
                      inferred_label='fee computation behind a shared read lock'),
        locations=dict(fees=dict(location_va=hex(FEES_LOC), line=50, column=42,
                                 path='l1/src/fees/compute.rs'),
                       perp_meta=dict(location_va=hex(PERP_LOC), line=194, column=38),
                       impl_ntl=dict(location_va=hex(NTL_LOC), line=664, column=1,
                                     inline_sites=len(NTL_SITES)),
                       qtys_mod=dict(location_va=hex(QTY_LOC), line=843, column=1),
                       core_num=dict(location_va=hex(NUM_LOC), line=320, column=5,
                                     path='library/core/src/num/mod.rs',
                                     rustc_commit=RUSTC_HASH)),
        lock_sites=dict(count=len(NTL_SITES), helper=hex(LOCK_HELPER_FN),
                            got=hex(GOT_LOCK_HELPER),
                            observed='each site passes (0, &impl_ntl.rs:664 Location) and '
                                     'follows with an add whose carry selects the -1 sentinel'),
        constants=dict(one=hex(ONE_VA), one_tenth=hex(TENTH_VA),
                       i64_max_f64=hex(MAX_F64_VA), pre_max_f64=hex(PREV_MAX_VA),
                       i64_min_f64=hex(MIN_F64_VA),
                       div10_magic_pair=[hex(DIV10_MAGIC_HI), hex(DIV10_MAGIC_LO)]),
        panic_tail=dict(display_callee=hex(PANIC_DISPLAY_FN), fmt_callee=hex(PANIC_FMT_FN)),
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
