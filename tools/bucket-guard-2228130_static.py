#!/usr/bin/env python3
"""Authenticated node94 bucket-guard-2228130 binding (0x2228130).

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

START, END = 0x2228130, 0x2228a0d
FDE_VA = 0x1090d38
FDE = bytes.fromhex(
    '5000000010310d00f0731901dd080000046f5194ff410e10420e18420e20420e'
    '28420e30410e38470ed00283078c068d058e048f038602032f070e38410e3042'
    '0e28420e20420e18420e10410e08410ed0020000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec180100000fb647203c010f851c0700004989d4'
    '4989f74989fe8844240fbf01000000e89cb6cb024889c389d548c74424280000'
    '000048c74424300800000048c744243800000000498b87c80500004885c04c89'
    'b424e80000000f849c0300004c89642458896c246c48899c24000100004c897c'
    '24604d8bb7c00500004869c0f00200004c01f04889442420488b2d79b85403eb'
    '1d6666666666662e0f1f8400000000004981c6f00200004c3b742420746b4d8b'
    '6e104d85ed74e94531ffeb1d0f1f4000488b4424304c8924d848ffc348895c24'
    '3849ffc74d39fd74c7b81027000049f766300f80a00600004989c44d01fc0f82'
    'a60600004c89f74c89e6ffd584c074d1488b5c2438483b5c242875b4488d7c24'
    '28ff15f9b75403eba7488b44242848898424e0000000488b7c2430488b442438'
    '48894424184885c00f848d02000048c164241803488b4c24588b01894424748b'
    '4104894424708b4108894424684531ed4c8da4248000000048897c24100f1f00'
    '4a8b2c2f4c89e7488b7424604889eae8acd95200488b84249800000048894424'
    '20488b9c24a0000000488b8424900000004889442450660f1084248000000066'
    '0f294424404889e848b94b598638d6c56d3448f7e14989d649c1ee0b4c3bb3c8'
    '0500000f83e90500004d69fef00200004c03bbc005000066c784248000000041'
    '014c89e7e8571115014180bf3002000003753d498b77704889e848b94b598638'
    'd6c56d3448f7e148c1ea0b4869c2102700004829c54839f50f822f010000e9c3'
    '050000666666662e0f1f8400000000004969c6102700004829c5493b6f700f83'
    'fc000000498b4f684c8d246d000000004901ec49c1e405428b44215889842410'
    '01000048894c24584a8b4c215048898c2408010000898424f800000048898c24'
    'f0000000ba08070000488dbc2480000000488db424f400000031c9ff15b76454'
    '03488b84248800000048b9000000004057ffff4801c148ba81aefeff7faefeff'
    '4839d10f822f0500008b8c2480000000894c247c8b8c2484000000894c24788b'
    'bc24f000000048b9572951cea0c8451848f7e94889d648c1ee3f48c1ea0d01d6'
    'ff155a64540385c00f84ea040000488b4c24584c01e14883c140394424740f9e'
    'c075198b44247c394424700f96c0750c8b442478394424687706eb2484c07520'
    '498b77704839f50f8399040000488d0c6d000000004801e948c1e10549034f68'
    '488b31488b7c24204889da488d4c2440e8fbc34b00488b442450488984249000'
    '0000660f28442440660f298424800000004c8da424800000004c89e74c89f648'
    '89dae819312d004983c5084c396c2418488b7c24100f85a5fdffff488bb424e0'
    '0000004885f64c8bb424e8000000488b9c24000100008b6c246c740c48c1e603'
    '31d2ff15d85a5403bf01000000e8beb2cb0248894424288954243048895c2440'
    '896c2448488dbc2480000000488d742428488d5c24404889dae8c2b1cb0280bc'
    '248000000000660f57d2743d4c8b25dd655403418b44242085c07579b10131c0'
    'f0410fb00c240f85b8000000498b6e084885ed0f89d600000031ff4889eeff15'
    '045a5403e9a8030000f20f108424880000000f57d2f20f2a9424900000000f14'
    '05abb8fdfd660f5c05c3a8fdfd660f28c8660f15c8f20f58c8f20f5e152f1cfe'
    'fdf20f58d14c8b2564655403418b44242085c074874c8964244048899c248000'
    '0000498d7c2420488d0d125847034c8d0533584703488d942480000000be0100'
    '0000f20f11542410ff157a625403f20f10542410b10131c0f0410fb00c240f84'
    '48ffffff488b3d05655403ba00ca9a3bf20f11542410ff15c4685403f20f1054'
    '2410498b6e084885ed0f882afffffff20f115424104d8b3e74174889efff1545'
    '5954034885c00f84c70200004989c6eb0641be010000004c89f74c89fe4889ea'
    'ff152a595403498b4c24084885c90f8413010000498b4424104889442418488d'
    '81281a000048894c24200fb789321b000048894c24608d0ccd000000004c8d3c'
    '4949c7c4ffffffff0f1f8400000000004d85ff744a4c8d6818488b7008488b50'
    '104889eb4829d3480f42d54c89f7ff15645d5403489885c0480f45d84885db0f'
    '98c00f9fc128c149ffc44983c7e84c89e880f90174ba0fb6c185c0742deb054c'
    '8b642460488b4c2420488b4424184883e8010f821301000048894424184a8b8c'
    'e1381b0000e954ffffff488b4424204889842488000000488b44241848898424'
    '900000004c89a424980000004c8b25bd635403498d44240848898424a0000000'
    '48b8000000000000008048898424800000004885ed74414c89f74889ee31d2ff'
    '153b585403eb314889ac24800000004c89b424880000004889ac249000000049'
    '8d442408488984249800000048c78424a000000000000000488b8c24e8000000'
    '488d411048894c24404883c118488944244848894c2450488dbc248000000048'
    '8d742440e8370c6500488d1560584703be010000004889c7f20f10442410ff15'
    '5c67540331c9b001f0410fb00c240fb644240f0f85800000004881c418010000'
    '5b415c415d415e415f5dc348898c24a000000048c78424a8000000000000004c'
    '89a424b00000004889ac24800000004c89b424880000004889ac24900000004c'
    '8b25aa625403498d4424084889842498000000e940ffffff488d3db97b4703ff'
    '15db585403e987000000488d3da77b4703ff1531585403eb78488b3d70625403'
    '31f6ff15406654030fb644240fe967ffffff66c78424800000004101488d3d66'
    '3736fe488d0df6154c034c8d05bf114c03488d942480000000be2b000000ff15'
    '14575403eb2b488d15bb5147034889efff1582565403eb19488d3dd016fffd48'
    '8d15c2254403be26000000ff15075b54030f0bbf01000000e93efcffffeb21eb'
    '1feb004889c3eb254889c3488dbc2480000000e8080b1501eb09ff1598575403'
    '4889c3488d7c2440e8c3340100488bb424e00000004885f6488b7c2410751ceb'
    '3dff1571575403eb004889c3488b7424284885f67428488b7c243048c1e60331'
    'd2ff15395654034889dfe8317743034889c331c9b001f0410fb00c2475084889'
    'dfe81a774303488b3d6361540331f6ff1533655403ebe7ff151b575403'
)
BODY_SHA256 = '76413d238cb81f088a1e4490a87cc9ef08d86f85cc7decd72ade808f872ab86c'
BRANCHES = [
    (0x17, '0f851c070000', 2, 6, 0x2228869),
    (0x66, '0f849c030000', 2, 6, 0x2228538),
    (0x9f, 'eb1d', 1, 2, 0x22281ee),
    (0xbc, '746b', 1, 2, 0x2228259),
    (0xc5, '74e9', 1, 2, 0x22281e0),
    (0xca, 'eb1d', 1, 2, 0x2228219),
    (0xe7, '74c7', 1, 2, 0x22281e0),
    (0xf2, '0f80a0060000', 2, 6, 0x22288c8),
    (0xfe, '0f82a6060000', 2, 6, 0x22288da),
    (0x10e, '74d1', 1, 2, 0x2228211),
    (0x11a, '75b4', 1, 2, 0x2228200),
    (0x127, 'eba7', 1, 2, 0x2228200),
    (0x148, '0f848d020000', 2, 6, 0x222850b),
    (0x1e3, '0f83e9050000', 2, 6, 0x2228902),
    (0x211, '753d', 1, 2, 0x2228380),
    (0x238, '0f822f010000', 2, 6, 0x222849d),
    (0x23e, 'e9c3050000', 1, 5, 0x2228936),
    (0x25e, '0f83fc000000', 2, 6, 0x2228490),
    (0x2e3, '0f822f050000', 2, 6, 0x2228948),
    (0x328, '0f84ea040000', 2, 6, 0x2228948),
    (0x341, '7519', 1, 2, 0x222848c),
    (0x34e, '750c', 1, 2, 0x222848c),
    (0x358, '7706', 1, 2, 0x2228490),
    (0x35a, 'eb24', 1, 2, 0x22284b0),
    (0x35e, '7520', 1, 2, 0x22284b0),
    (0x367, '0f8399040000', 2, 6, 0x2228936),
    (0x3d5, '0f85a5fdffff', 2, 6, 0x22282b0),
    (0x3fa, '740c', 1, 2, 0x2228538),
    (0x44a, '743d', 1, 2, 0x22285b9),
    (0x45a, '7579', 1, 2, 0x2228605),
    (0x466, '0f85b8000000', 2, 6, 0x2228654),
    (0x473, '0f89d6000000', 2, 6, 0x222867f),
    (0x484, 'e9a8030000', 1, 5, 0x2228961),
    (0x4d3, '7487', 1, 2, 0x222858c),
    (0x51e, '0f8448ffffff', 2, 6, 0x222859c),
    (0x549, '0f882affffff', 2, 6, 0x22285a9),
    (0x558, '7417', 1, 2, 0x22286a1),
    (0x566, '0f84c7020000', 2, 6, 0x2228963),
    (0x56f, 'eb06', 1, 2, 0x22286a7),
    (0x58e, '0f8413010000', 2, 6, 0x22287d7),
    (0x5d3, '744a', 1, 2, 0x222874f),
    (0x614, '74ba', 1, 2, 0x2228700),
    (0x61b, '742d', 1, 2, 0x222877a),
    (0x61d, 'eb05', 1, 2, 0x2228754),
    (0x632, '0f8213010000', 2, 6, 0x222887b),
    (0x645, 'e954ffffff', 1, 5, 0x22286ce),
    (0x695, '7441', 1, 2, 0x2228808),
    (0x6a5, 'eb31', 1, 2, 0x2228808),
    (0x733, '0f8580000000', 2, 6, 0x22288e9),
    (0x793, 'e940ffffff', 1, 5, 0x2228808),
    (0x7a5, 'e987000000', 1, 5, 0x2228961),
    (0x7b7, 'eb78', 1, 2, 0x2228961),
    (0x7cd, 'e967ffffff', 1, 5, 0x2228869),
    (0x804, 'eb2b', 1, 2, 0x2228961),
    (0x816, 'eb19', 1, 2, 0x2228961),
    (0x838, 'e93efcffff', 1, 5, 0x22285ab),
    (0x83d, 'eb21', 1, 2, 0x2228990),
    (0x83f, 'eb1f', 1, 2, 0x2228990),
    (0x841, 'eb00', 1, 2, 0x2228973),
    (0x846, 'eb25', 1, 2, 0x222899d),
    (0x858, 'eb09', 1, 2, 0x2228993),
    (0x87d, '751c', 1, 2, 0x22289cb),
    (0x87f, 'eb3d', 1, 2, 0x22289ee),
    (0x887, 'eb00', 1, 2, 0x22289b9),
    (0x894, '7428', 1, 2, 0x22289ee),
    (0x8bc, '7508', 1, 2, 0x22289f6),
    (0x8d5, 'ebe7', 1, 2, 0x22289ee),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x222815f, 0x4ee3800),
    (0x22282bf, 0x2755c70),
    (0x2228334, 0x3379490),
    (0x22284c0, 0x26e48c0),
    (0x22284f2, 0x24fb610),
    (0x222853d, 0x4ee3800),
    (0x2228569, 0x4ee3730),
    (0x2228834, 0x2879470),
    (0x2228983, 0x3379490),
    (0x2228998, 0x223be60),
    (0x22289da, 0x5660110),
    (0x22289f1, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x2228251, 0x5773a50),
    (0x22283eb, 0x576e8a8),
    (0x2228450, 0x576e8b0),
    (0x2228532, 0x576e010),
    (0x22285ae, 0x576dfb8),
    (0x2228638, 0x576e8b8),
    (0x2228666, 0x576ef30),
    (0x222868d, 0x576dfd8),
    (0x22286b0, 0x576dfe0),
    (0x222871e, 0x576e488),
    (0x22287cf, 0x576e010),
    (0x222884e, 0x576efb0),
    (0x22288cf, 0x576e1b0),
    (0x22288e1, 0x576e118),
    (0x22288f2, 0x576ef38),
    (0x222892e, 0x576e048),
    (0x2228940, 0x576dfc8),
    (0x222895b, 0x576e468),
    (0x222898a, 0x576e128),
    (0x22289b1, 0x576e128),
    (0x22289d1, 0x576e010),
    (0x22289ff, 0x576ef38),
    (0x2228a07, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x22288da, 0x56a0488, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f61737365742f7064692e7273'), 30, 14),
    (0x2228936, 0x569daf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f636c656172696e67686f7573652f6f7261636c652f6f7261636c652e7273'), 202, 18),
    (0x222894f, 0x566af18, bytes.fromhex('2f686f6d652f7562756e74752f2e636172676f2f72656769737472792f7372632f696e6465782e6372617465732e696f2d313934396366386336623562353537662f6368726f6e6f2d302e342e33382f7372632f6e616976652f6461746574696d652f6d6f642e7273'), 1631, 38),
]
CALLERS = [0x2229b8b]
CALLER_FUNCTIONS = {'0x2229b8b': ('0x22297c0', '0x222af3e')}
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

