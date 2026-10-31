#!/usr/bin/env python3
"""Authenticated node94 books-24f7bd0 binding (0x24f7bd0).

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

START, END = 0x24f7bd0, 0x24f84b5
FDE_VA = 0x10c3b68
FDE = bytes.fromhex(
    '50000000405f100060404301e5080000043be993ff410e10420e18420e20420e'
    '28420e30410e38470eb00383078c068d058e048f0386020396010e38410e3042'
    '0e28420e20420e18420e10410e08410eb0030000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec780100004989ce48899424900000004989ff48'
    '8b4e10488d815ffaffff483d63faffff770f6641c707cb0049894f08e95c0100'
    '0048898c24c00000004c8b260fb65e19488b5608498db690000000488d7c2420'
    '4889b424a00000004c89e1e8a034e1ff0fb74424203d860100000f858d000000'
    '498db680000000488b6c24284c893424440fb6cb488d7c2420488b9424900000'
    '004c89e14989e8e874a01d0066817c242086010f85a7000000498bb690330000'
    '4939f40f83ca0700004c89a424800000004969fcd80000004903be88330000e8'
    '1c04d80048f7e50f90c148ba99999999999999194839d00f97c208ca0f84b000'
    '00006641c7076900e9900000000fb74c24266641894f068b4c242241894f0248'
    '8b4c24280f10442440410f1147200f10442450410f1147300f10442460410f11'
    '47400f10442470410f1147500f10442430410f1147106641890749894f08eb3d'
    '0f10442470410f1147500f10442460410f1147400f10442420660f104c24300f'
    '105424400f105c2450410f115f30410f11572066410f114f10410f11074c89f8'
    '4881c4780100005b415c415d415e415f5dc348898424b8000000488b8c249000'
    '00008b4110894424300f10010f29442420488d7424204c89f7e852d625000fb6'
    '403c3c0473173c030f85590200004180beb1050000007413e94a0200004180be'
    'b0050000000f853c020000498baef83400004885ed4c89b424880000004c89bc'
    '24b00000000f84c3000000498b86003500004889442418488b1d7a662703488d'
    'b5100100000fb785ee01000048894424108d0485000000004c8d3c8049c7c4ff'
    'ffffff4989ee662e0f1f8400000000004d85ff743b4c8d6e14ba14000000488b'
    'bc2490000000ffd348984885c00f98c10f9fc028c84983c61849ffc44983c7ec'
    '4c89ee3c0174c90fb6c085c07507eb224c8b642410488b4424184883e801722e'
    '48894424184a8bace5f0010000e96cffffff498b0e4c8bb42488000000498b86'
    '783300004885c0751fe94401000031c94c8bb42488000000498b867833000048'
    '85c00f842a010000498b96703300004869c0380100004801d048898424c80000'
    '00eb39666666662e0f1f84000000000031c04881c2380100004801c14889c848'
    'c7c6ffffffff480f42c6480f42c8483b9424c80000000f84d60000004c8b7a30'
    '4d85ff74cb48894c241048899424a8000000488b5a38498db710010000410fb7'
    '87ee01000048894424188d0485000000004c8d2c8048c7c5ffffffff4d89fc90'
    '4d85ed744b4c8d7614ba14000000488bbc2490000000ff15fc64270348984885'
    'c00f98c10f9fc028c84983c41848ffc54983c5ec4c89f63c0174c50fb6c085c0'
    '7513eb2c6666662e0f1f840000000000488b6c24184883eb0172334d8bbceff0'
    '010000e96effffff0f1f840000000000498b04244c8bb42488000000488b4c24'
    '10488b9424a8000000e904ffffff31c0ebe2493b8e400500004c8bbc24b00000'
    '000f834b01000066c74424206900488d7c2420e818e60000f20f108c24c00000'
    '000f140d48bed0fd660f5c0d60aed0fd660f28c1660f15c1f20f58c1f20f5905'
    '5428d1fd488dbc240c010000ff15d6c4270366c7442420ac0080bc240c010000'
    '000f84e50000000f108424100100000f11842432010000488d7c2420e87fa426'
    '010f108424320100000f118424680100000f118424560100000f118424440100'
    '000f29842420010000488d7c2420488db42420010000ba02000000b906000000'
    'ff1572b727030fb74424203d860100000f8587000000488b442428486bd86448'
    'b9cb10c7bab88d06004839c8480f47d8488b8424b80000004839d80f830d0200'
    '00488bbc24a0000000488bb42480000000ff1519c427034989d64885d20f8818'
    '0200004d89fd0f84660200004989c44c89f7ff15905e27034885c00f843b0300'
    '004989c74c89e0e94c02000066b8ac00eb626641c707cc00e900fcffff0fb74c'
    '242666894c240c8b4c2422894c24080f10442428488b4c2438488b5424400f10'
    '4c24480f298c24d00000000f104c24580f298c24e0000000660f104c2468660f'
    '298c24f0000000488b7424784889b4240001000066894424208b442408894424'
    '220fb744240c66894424260f1144242848894c24384889542440488b84240001'
    '000048894424780f288424d00000000f288c24e00000000f289424f00000000f'
    '115424680f114c24580f11442448498bb600020000488bbc24800000004839f7'
    '0f833d020000498b86f801000048c1e705488b443808493b86180200000f8301'
    '020000498b8e100200004869c0e80000004c8b7401404d85f6791031ff4c89f6'
    'ff15425d2703e9050200004c89fb4c8b64013874174c89f7ff154a5d27034885'
    'c00f84eb0100004989c7eb0641bf010000004c89ff4c89e64c89f2ff152f5d27'
    '03488d7c2420e885e300000fb744240c668943068b4424088943024c8973104c'
    '897b184989df4c897320488b842400010000488943580f288424d0000000660f'
    '288c24e00000000f289424f00000000f115348660f114b380f11432866c703d1'
    '0048c7430800000000e94ffaffff48b900406352bfc601004839c87629488bbc'
    '24a0000000488bb42480000000ff15fdc127034989d64885d2793131ff4c89f6'
    'ff15625c27034c89f7e8027726003c02750b6641c7078601e900faffff6641c7'
    '07740041884702e9f1f9ffff4d89fc0f848d0000004889c34c89f7ff15475c27'
    '034885c00f84f20000004989c74889d8eb7641bf0100000066480f6ec3660f62'
    '05cbbad0fd660f5c05e3aad0fd660f28c8660f15c8f20f58c8f20f5e0daf1dd1'
    'fd660f298c24900000004c89ff4889c64c89f2ff15f75b27036641c74500d100'
    '0f28842490000000f2410f1145084d8975104d897d184d89ef4d897520e95bf9'
    'ffff41bf010000004c89ff4889c64c89f2ff15b95b27036641c70424d20048b8'
    '00000000d012534149894424084d897424104d897c24184d89e74d89742420e9'
    '19f9ffff488d3d959d1f03ff150f602703eb1d488d15f62f1c034c89e7ff1555'
    '5b2703488d155e9b1f03ff15485b27030f0bbf01000000e9e1fdffffbf010000'
    '004c89f6ff151e5b27034889c3488d7c2420e899e100004889dfe8617c1603ff'
    '15735c2703'
)
BODY_SHA256 = 'c347349f8001bcdb6a0c68fe40c446dbb8b1e8ed956efc89ea06e57bf56ec934'
BRANCHES = [
    (0x30, '770f', 1, 2, 0x24f7c11),
    (0x3c, 'e95c010000', 1, 5, 0x24f7d6d),
    (0x7a, '0f858d000000', 2, 6, 0x24f7cdd),
    (0xb3, '0f85a7000000', 2, 6, 0x24f7d30),
    (0xc3, '0f83ca070000', 2, 6, 0x24f8463),
    (0xfc, '0f84b0000000', 2, 6, 0x24f7d82),
    (0x108, 'e990000000', 1, 5, 0x24f7d6d),
    (0x15e, 'eb3d', 1, 2, 0x24f7d6d),
    (0x1e4, '7317', 1, 2, 0x24f7dcd),
    (0x1e8, '0f8559020000', 2, 6, 0x24f8017),
    (0x1f6, '7413', 1, 2, 0x24f7ddb),
    (0x1f8, 'e94a020000', 1, 5, 0x24f8017),
    (0x205, '0f853c020000', 2, 6, 0x24f8017),
    (0x225, '0f84c3000000', 2, 6, 0x24f7ebe),
    (0x273, '743b', 1, 2, 0x24f7e80),
    (0x2a5, '74c9', 1, 2, 0x24f7e40),
    (0x2ac, '7507', 1, 2, 0x24f7e85),
    (0x2ae, 'eb22', 1, 2, 0x24f7ea2),
    (0x2be, '722e', 1, 2, 0x24f7ebe),
    (0x2cd, 'e96cffffff', 1, 5, 0x24f7e0e),
    (0x2e7, '751f', 1, 2, 0x24f7ed8),
    (0x2e9, 'e944010000', 1, 5, 0x24f8002),
    (0x302, '0f842a010000', 2, 6, 0x24f8002),
    (0x321, 'eb39', 1, 2, 0x24f7f2c),
    (0x356, '0f84d6000000', 2, 6, 0x24f8002),
    (0x363, '74cb', 1, 2, 0x24f7f00),
    (0x3a3, '744b', 1, 2, 0x24f7fc0),
    (0x3d9, '74c5', 1, 2, 0x24f7f70),
    (0x3e0, '7513', 1, 2, 0x24f7fc5),
    (0x3e2, 'eb2c', 1, 2, 0x24f7fe0),
    (0x3f9, '7233', 1, 2, 0x24f7ffe),
    (0x403, 'e96effffff', 1, 5, 0x24f7f46),
    (0x429, 'e904ffffff', 1, 5, 0x24f7f02),
    (0x430, 'ebe2', 1, 2, 0x24f7fe4),
    (0x441, '0f834b010000', 2, 6, 0x24f8162),
    (0x4a1, '0f84e5000000', 2, 6, 0x24f815c),
    (0x510, '0f8587000000', 2, 6, 0x24f816d),
    (0x53b, '0f830d020000', 2, 6, 0x24f831e),
    (0x55d, '0f8818020000', 2, 6, 0x24f834b),
    (0x566, '0f8466020000', 2, 6, 0x24f83a2),
    (0x57b, '0f843b030000', 2, 6, 0x24f848c),
    (0x587, 'e94c020000', 1, 5, 0x24f83a8),
    (0x590, 'eb62', 1, 2, 0x24f81c4),
    (0x598, 'e900fcffff', 1, 5, 0x24f7d6d),
    (0x660, '0f833d020000', 2, 6, 0x24f8473),
    (0x67d, '0f8301020000', 2, 6, 0x24f8454),
    (0x699, '7910', 1, 2, 0x24f827b),
    (0x6a6, 'e905020000', 1, 5, 0x24f8480),
    (0x6b3, '7417', 1, 2, 0x24f829c),
    (0x6c1, '0f84eb010000', 2, 6, 0x24f8482),
    (0x6ca, 'eb06', 1, 2, 0x24f82a2),
    (0x749, 'e94ffaffff', 1, 5, 0x24f7d6d),
    (0x75b, '7629', 1, 2, 0x24f8356),
    (0x779, '7931', 1, 2, 0x24f837c),
    (0x790, '750b', 1, 2, 0x24f836d),
    (0x798, 'e900faffff', 1, 5, 0x24f7d6d),
    (0x7a7, 'e9f1f9ffff', 1, 5, 0x24f7d6d),
    (0x7af, '0f848d000000', 2, 6, 0x24f8412),
    (0x7c4, '0f84f2000000', 2, 6, 0x24f848c),
    (0x7d0, 'eb76', 1, 2, 0x24f8418),
    (0x83d, 'e95bf9ffff', 1, 5, 0x24f7d6d),
    (0x87f, 'e919f9ffff', 1, 5, 0x24f7d6d),
    (0x891, 'eb1d', 1, 2, 0x24f8480),
    (0x8b7, 'e9e1fdffff', 1, 5, 0x24f826d),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x24f7c3b, 0x230b0e0),
    (0x24f7c77, 0x26d1cf0),
    (0x24f7caf, 0x32780d0),
    (0x24f7da9, 0x2755400),
    (0x24f8023, 0x2506640),
    (0x24f808c, 0x3762510),
    (0x24f82b6, 0x2506640),
    (0x24f8359, 0x275fa60),
    (0x24f84a2, 0x2506640),
    (0x24f84aa, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x24f7f86, 0x576e488),
    (0x24f805c, 0x5774538),
    (0x24f80d0, 0x5773848),
    (0x24f8121, 0x5774540),
    (0x24f8142, 0x576dfd8),
    (0x24f8270, 0x576dfb8),
    (0x24f8288, 0x576dfd8),
    (0x24f82ab, 0x576dfe0),
    (0x24f833d, 0x5774540),
    (0x24f8350, 0x576dfb8),
    (0x24f838b, 0x576dfd8),
    (0x24f83e3, 0x576dfe0),
    (0x24f8421, 0x576dfe0),
    (0x24f845b, 0x576e470),
    (0x24f846d, 0x576dfc8),
    (0x24f847a, 0x576dfc8),
    (0x24f8494, 0x576dfb8),
    (0x24f84af, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x24f8454, 0x56f21f0, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 113, 33),
    (0x24f8463, 0x56bb460, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f626f6f6b732e7273'), 14, 16),
    (0x24f8473, 0x56f1fd8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6c312f7372632f73706f745f6d6574612e7273'), 565, 25),
]
CALLERS = [0x2722a87]
CALLER_FUNCTIONS = {'0x2722a87': ('0x2722790', '0x2723c67')}
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

