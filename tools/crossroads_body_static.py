#!/usr/bin/env python3
"""Authenticated node94 crossroads body binding (0x44aa5a0).

Binds the 4027-byte body 0x44aa5a0..0x44ab55b — the only caller of the
date-difference float-seconds wrapper (RE-001-datediff-callers-94) and a
crossroads of the series: it also calls the NaiveTime addition 0x15206e0 and
the NaiveDate day shift 0x151f870 (RE-001-chrono-callees-94 anchors), the std
Once state machine 0x4ee3b20 (RE-001-once-state-94), and three panic callees,
carrying the std sync/once.rs:219:20 and chrono naive/datetime/mod.rs:1631:38
panic Locations. Static byte/record checks only; the captured binary is never
executed.
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

START, END = 0x44aa5a0, 0x44ab55b
FDE_VA = 0x124c0b8

STD_ONCE_LOC = 0x5669f50
CHRONO_DT_LOC = 0x566af18
STD_ONCE_PATH = (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/'
                 b'std/src/sync/once.rs')
CHRONO_DT_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
                  b'chrono-0.4.38/src/naive/datetime/mod.rs')

# (body offset, GOT slot, relocation target) — all thirteen call sites.
CALL_SITES = [
    (0xc6, 0x576e978, 0x143d010),
    (0x253, 0x576e8a8, 0x15206e0),   # NaiveTime addition
    (0x2b0, 0x576e8b0, 0x151f870),   # NaiveDate day shift
    (0xc12, 0x576f6c8, 0x1450a60),   # datediff float-seconds wrapper
    (0xc73, 0x5773628, 0x4b31e70),
    (0xe75, 0x57769d0, 0x454e5b0),
    (0xeec, 0x576e8b8, 0x4ee3b20),   # std Once state machine
    (0xf09, 0x576f488, 0x14385c0),
    (0xf28, 0x576e470, 0x157a9f0),   # display panic
    (0xf46, 0x576e470, 0x157a9f0),
    (0xf61, 0x576e468, 0x157a9b0),
    (0xf93, 0x576e128, 0x157b63b),
    (0xfb1, 0x576e128, 0x157b63b),
]

# (body offset, Location VA, path, line, column).
LOCATION_SITES = [
    (0xed8, STD_ONCE_LOC, STD_ONCE_PATH, 219, 20),
    (0xf55, CHRONO_DT_LOC, CHRONO_DT_PATH, 1631, 38),
]

CALLERS = [0x44ae32a, 0x44ae350, 0x44b180c]
CALLER_FN = (0x44adfa0, 0x44b303a)

BODY = bytes.fromhex(
'554157415641554154534881ec280400004889fb488bb7180900004c8db73009'
'00004889742470483bb7880900000f869d000000488d838809000048c7842460'
'02000000000000c784247002000000000000c684247402000000c68424700200'
'0001488d4c247048894c24204889842410030000488d44242048898424f00000'
'00488d0568230e0048898424f8000000488d8c241003000048898c2400010000'
'4889842408010000488d35f9e5d3fb488d0d12e02801488dbc2460020000488d'
'9424f0000000ff150c432c01488b74247049bc01000000000000804c89f7e8ad'
'f2e1ff4885c00f84e90000004989d74c89b424e8000000488b44247048898424'
'f8000000498d44242748898424f0000000488dbc24f0000000e8b2fb66008b83'
'fc0a00008984240001000048891c240f1083ec0a00000f298424f00000004d8b'
'274d85e40f84b10000004d8b6f084c8dbc24f0000000498d742460410fb78424'
'3e01000048894424088d048500000000488d2c8048c7c3ffffffff0f1f440000'
'4885ed743b4c8d7614ba140000004c89ffff15513d2c0148984885c00f98c10f'
'9fc028c848ffc34883c5ec4c89f63c0174ce0fb6c085c0750ceb600f1f440000'
'488b5c24084983ed0172304d8ba4dc40010000eb81488b4424704983c4274c89'
'a424f000000048898424f8000000488dbc24f0000000e8f53efdff8b05f7032d'
'0185c00f85a20c00004881c4280400005b415c415d415e415f5dc34c8b342441'
'8b86b80a000089842468020000498b86b00a00004889842460020000488db424'
'64020000488dbc24f000000031d2b980f0fa02ff15af402c01488b8424f80000'
'0048b9000000004057ffff4801c148ba81aefeff7faefeff4839d10f82cd0c00'
'008bac24f00000008b9c24f40000008bbc246002000048b9572951cea0c84518'
'48f7e94889d648c1ee3f48c1ea0d01d6ff155a402c0185c00f84900c00004139'
'86c80a00000f9cc0751b4139aecc0a00000f92c0750f41399ed00a00000f8226'
'ffffffeb0884c00f851cffffff498d8ec80a00008b41088944246848894c2458'
'488b014889442460498b96b8010000498b86c80100004885d20f95c14885c040'
'0f95c64020ce4080fe010f85d9feffff4c8b0424498b88c00100004885c9746e'
'4889ce4883e6070f84d700000031ff90488b92180c000048ffc74839fe75f148'
'89ce4829fe4883f90872430f1f440000488b8a180c0000488b89180c0000488b'
'89180c0000488b89180c0000488b89180c0000488b89180c0000488b89180c00'
'00488b91180c00004883c6f875c2498b88200900006683ba120c000000740f45'
'31c04889d7498d7001e90301000040b6014531c96666662e0f1f840000000000'
'488bba600100004885ff0f844f0b00004189f349ffc1440fb782100c0000418d'
'73014889fa66443b87120c000073d14c89ce4883ee01731e4889fa498d7001e9'
'ad0000004889ce4883f9080f833fffffffe978ffffff4e8d14c74981c2200c00'
'0041f6c1077430450fb6db4183e30731db6666666666662e0f1f840000000000'
'498b124c8d92180c000048ffc34939db75ee4929d9eb004883fe07730431f6eb'
'5031f6666666662e0f1f840000000000498b12488b92180c0000488b92180c00'
'00488b92180c0000488b92180c0000488b92180c0000488b92180c0000488b92'
'180c00004c8d92180c00004983c1f875bf48ffc84d69c0f80000004e8d3c0749'
'81c7680100004885c00f843b010000498bbf88000000eb430f1f840000000000'
'4989d04c8d4e0148ffc84869f6f80000004d8d14304981c268010000498bb430'
'f00100004839f74d0f46fa480f46fe4c89ce4885c00f84e6000000440fb78212'
'0c00004c39c672b841b2014531c966904c8b82600100004d85c00f84c1090000'
'4489d349ffc10fb7b2100c0000448d53014c89c266413bb0120c000073d24d89'
'cb4983eb0173094c89c2e974ffffff904d8d14f04981c2200c000041f6c10774'
'780fb6db83e3074531f6660f1f440000498b124c8d92180c000049ffc64c39f3'
'75ee4d29f14983fb0772460f1f440000498b12488b92180c0000488b92180c00'
'00488b92180c0000488b92180c0000488b92180c0000488b92180c0000488b92'
'180c00004c8d92180c00004983c1f875bf4531c9e9eefeffff4983fb0773b1eb'
'f04d85ff0f84dffbffff498b87880000004839c80f86cffbffff488b0c24483b'
'81980100000f86befbffff488b1c24488d83b00a000048898424a80000004d8d'
'af88000000488d83a001000048898424b0000000488dbc24b8030000488db424'
'f00000004c89f848c78424f000000000000000488944241048898424f8000000'
'e80b140a00488b839801000048898424b8000000493945000f863b010000488b'
'442410488b40104885c00f84290100004889c1488b0424488b80a00100004889'
'8424d00000004885c00f848d060000488b4424104c8b680848c1e1054c01e948'
'898c24c0000000488b0424488b80a801000048898424c8000000498d45204889'
'8424d8000000488b8424c80000004889442408488bb424d00000000fb7ae3205'
'00004c8db6200100004889ac24e0000000c1e50548c7c3ffffffff4889742418'
'4885ed743a4c8d6620ba200000004c89efff1571372c0148984885c00f98c10f'
'9fc028c84983c65848ffc34883c5e04c89e63c0174ca0fb6c085c0750aeb2e48'
'8b9c24e0000000488b4424084883e8010f82c60500004889442408488b742418'
'488bb4de38050000e96effffff48b801000000000000804939060f849c050000'
'488b8424d80000004989c5483b8424c00000000f8521ffffff488b4424100f10'
'40480f1048580f298c24800000000f294424704c8b2c244d8ba5b80100004d85'
'e40f8487050000498b85c00100004889442408450fb7b424120c00004d8dac24'
'f80000004c8974241841c1e60548c7c3ffffffff4c89e6660f1f840000000000'
'4d85f6743f488d6e20ba20000000488d7c2470ff156f362c0148984885c00f98'
'c10f9fc028c84981c5f800000048ffc34983c6e04889ee3c0174c50fb6c085c0'
'7507eb2a488b5c2418488b4424084883e8014c8b2c240f82f204000048894424'
'084d8ba4dc180c0000e965ffffff488b4c24108b8190000000413b45080f9ec0'
'75208b8194000000413b450c0f96c075118b8198000000413b4510770de907f9'
'ffff84c00f85fff8ffff498d8578ffffff488b8c24b800000049394d00488b1c'
'24488dbc24b8030000488db424f00000000f8750fdffff498d5718488dbc24f0'
'0000004889dee815e9000080bc24f0000000010f84b0f8ffff488b8424080100'
'0048898424a00000000f108424f80000000f298424900000004d8b77104d85f6'
'488b9c24b00000000f849d000000498b6f0849c1e605488b04244883c0384889'
'4424084531e44c8dac24f0000000420f10442500420f104c25100f298c240001'
'00000f298424f00000004889df4c89eee8abcf47004885c00f841905000048b9'
'0100000000000080483948100f8405050000807850000f85fb040000488dbc24'
'900000004c89eee8f4cc47004885c00f85e2040000488b7c24084c89eee8eead'
'eaff4983c4204d39e67583488dbc24f00000004c89fee8d5a201004c8bb424f0'
'0000000f108424f80000000f294424200f108424080100000f294424300f1084'
'24180100000f29442440488b84242801000048894424500f108424300100000f'
'298424100300000f108424400100000f298424200300000f108424500100000f'
'298424300300000f108424600100000f298424400300000f108424700100000f'
'298424500300000f108424800100000f298424600300000f108424900100000f'
'29842470030000488dbc2490000000e8ac1150004c89f048f7d84c8b2c240f80'
'05f7ffff48b801000000000000804939c60f8407030000488b44245048898424'
'980200000f284424200f284c24300f285424400f119424880200000f118c2478'
'0200000f118424680200000f288424100300000f288c24200300000f28942430'
'0300000f289c24400300000f118424a00200000f118c24b00200000f119424c0'
'0200000f119c24d00200000f288424500300000f118424e00200000f28842460'
'0300000f118424f0020000660f28842470030000660f118424000300004c89b4'
'2460020000488b9c24e8020000493b9d180900000f852f0300004180bd010b00'
'00000f8521030000488dbc24f0020000488b4c24588b4108898424f800000048'
'8b0148898424f0000000488db424f0000000ff1510452c01660f2e0548f8d5fb'
'0f87e9020000488dbc2410030000488d942460020000488b3424e8912b000080'
'bc2410030000000f84c20200004c8bb4244803000048ffc348c7c2ffffffff48'
'0f45d3488dbc24d8030000488bb424e8000000ff150f842c0148b80100000000'
'0000804883c02948398424d80300000f859b020000488d8424180300008b8c24'
'f0030000898c24a00100000f108424e00300000f11842490010000488b3c244c'
'89b720090000488b5424588b4a08488bb424a8000000894e08488b0a48890e48'
'81c7d00400000f10000f1048100f1050200f119424180100000f118c24080100'
'000f118424f80000004c89b424280100000f1080880000000f11842480010000'
'0f1040780f11842470010000660f1040380f1048480f1050580f1058680f119c'
'24600100000f119424500100000f118c2440010000660f1184243001000048c7'
'8424f000000004000000488db424f0000000e869700100e993010000488dbc24'
'f0000000488d542460488d8c24b8030000f20f1005cfefd5fb41b8010000004c'
'8b2c244c89ee41b903000000eb29488dbc24f0000000488d542460488d4c2470'
'f20f1005a0efd5fb41b8010000004c89ee41b904000000e8d4cc000080bc24f0'
'000000020f841ff4ffff488b84242001000048894424500f108424f00000000f'
'108c24000100000f109424100100000f295424400f294c24300f29442420488b'
'44245048898424280100000f284424200f284c24300f285424400f1194241801'
'00000f118c24080100000f118424f800000048c78424f00000000a000000498b'
'9de0040000493b9dd0040000750d498dbdd0040000ff15b5b52c014869fb6801'
'00004903bdd8040000488db424f0000000ba68010000ff15a42b2c0148ffc349'
'899de0040000e95ef3ffff488d052ef72c014889842460020000488d84246002'
'000048898424f0000000488d3d27f72c01488d0df0ea1b014c8d05d1ea1b0148'
'8d9424f0000000be01000000ff1526342c01e912f3ffff488dbc2490000000e8'
'9c0d5000e900f3ffffff15d93f2c01488dbc2460020000e80431fdffe9e8f2ff'
'ff488d3d888a2801ff15a22f2c01eb1c488dbc24d8030000e8b331fdffebd048'
'8d3d6a8a2801ff15842f2c010f0b488d3d2aebd6fb488d151cfa1b01be260000'
'00ff15612f2c014889c3488dbc2460020000e8a930fdff4889dfe8f14b1b01eb'
'184889c3488dbc24f0000000e8af2dfdffeb16ff15ef2b2c014889c3488dbc24'
'90000000e8f70c50004889dfe8bf4b1b01ff15d12b2c010f0b0f0b')

FDE = bytes.fromhex(
'5000000090e42800e0e42503bb0f0000049b648fff410e10420e18420e20420e'
'28420e30410e38470ee00883078c068d058e048f03860203ff010e38410e3042'
'0e28420e20420e18420e10410e08410ee0080000')


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
    rels = relocations(reader)

    body = reader.read(START, END - START)
    require(body == BODY, 'Crossroads body bytes changed')
    eh = reader.by_name['.eh_frame']
    require(eh['address'] <= FDE_VA < eh['address'] + eh['size'], 'FDE outside .eh_frame')
    fde = reader.read(FDE_VA, len(FDE))
    require(fde == FDE, 'Crossroads FDE record changed')
    length = struct.unpack_from('<I', fde, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    for offset, got, target in CALL_SITES:
        require(body[offset:offset + 2] == bytes.fromhex('ff15'),
                f'call opcode at +0x{offset:x} changed')
        disp = struct.unpack_from('<i', body, offset + 2)[0]
        require(START + offset + 6 + disp == got, f'call GOT at +0x{offset:x} changed')
        require(rels.get(got) == target, f'call target for GOT {got:#x} changed')

    for offset, loc_va, path, line, column in LOCATION_SITES:
        require(body[offset:offset + 2] == bytes.fromhex('488d')
                or body[offset:offset + 2] == bytes.fromhex('4c8d'),
                f'Location lea opcode at +0x{offset:x} changed')
        require((body[offset + 2] & 0xC7) == 0x05,
                f'Location lea modrm at +0x{offset:x} changed')
        disp = struct.unpack_from('<i', body, offset + 3)[0]
        require(START + offset + 7 + disp == loc_va, f'Location address at +0x{offset:x} changed')
        path_va = rels.get(loc_va)
        require(path_va is not None, 'Location relocation missing')
        str_len, line_, column_ = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((str_len, line_, column_) == (len(path), line, column),
                'Location layout changed')
        require(reader.read(path_va, str_len) == path, 'Location path changed')

    # Census over the whole .text: exactly three direct callers, no GOT slot,
    # no lea references.
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
    require(direct == CALLERS, f'Caller census changed: {[hex(x) for x in direct]}')
    require(indirect == [], 'Unexpected GOT-mediated callers')
    require(lea == [], 'Unexpected lea references')
    for site in CALLERS:
        require(CALLER_FN[0] <= site < CALLER_FN[1], f'Caller {site:#x} left its FDE')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        crossroads=dict(start_va=hex(START), end_va_exclusive=hex(END),
                        bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                        fde_va=hex(FDE_VA),
                        inferred_label='the only caller of the datediff '
                                       'float-seconds wrapper, spanning the chrono '
                                       'pair, the Once machinery and three panic '
                                       'callees'),
        call_sites=[dict(offset=hex(o), got=hex(g), target=hex(t))
                    for o, g, t in CALL_SITES],
        panic_locations=[
            dict(va=hex(STD_ONCE_LOC), file='std/src/sync/once.rs', line=219, column=20,
                 note='shared with the read-lock helper packet (PR#112 family)'),
            dict(va=hex(CHRONO_DT_LOC), file='chrono-0.4.38/src/naive/datetime/mod.rs',
                 line=1631, column=38,
                 note='the NaiveDateTime + TimeDelta overflow Location shared with '
                      'the ema window guard packet (PR#95)')],
        cross_links=dict(
            datediff_wrapper='0x1450a60 at +0xc12 (RE-001-datediff-callers-94)',
            naive_time='0x15206e0 at +0x253 (RE-001-chrono-callees-94)',
            naive_date='0x151f870 at +0x2b0 (RE-001-chrono-callees-94)',
            once_state_machine='0x4ee3b20 at +0xeec (RE-001-once-state-94)'),
        call_census=dict(direct_callers=[hex(x) for x in CALLERS],
                         direct_e8=3, got_indirect=0, lea_refs=0,
                         caller_fde='0x44adfa0..0x44b303a (one parent body)',
                         note='byte-pattern census over the complete .text for '
                              'e8/ff15/lea encodings'),
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
