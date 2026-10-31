#!/usr/bin/env python3
"""Authenticated node94 u-471b880 binding (0x471b880).

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

START, END = 0x471b880, 0x471bfb6
FDE_VA = 0x1281a24
FDE = bytes.fromhex(
    '50000000fc3d2c00549e4903360700000497b98eff410e10420e18420e20420e'
    '28420e30410e38470eb00383078c068d058e048f038602035c030e38410e3042'
    '0e28420e20420e18420e10410e08410eb0030000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec780100004889fb85d20f848f0000004c8b3e4c'
    '8b6e084c8b6610c644240d00c644240e00488d15a82f0101488d7c240d488d74'
    '240ee8495bc6ff4885c00f8528030000807c240d000f849c0100000fb66c240e'
    '48c7c1d8eeffff644c8b3425000000004901ce640fb6414883f8010f845e0300'
    '0083f8020f853903000040886c24104c8d642411c644241100488d3dc82e0101'
    'ff15f22f0501e9cc050000488b064c8b7608488b4e10488b0948894424684c89'
    '74247048c74424580100000048894c246048c744247800000000488dbc248000'
    '0000488d742458e8b48ef5ff488b8424800000000f108424880000000f294424'
    '300f108424980000000f294424404883f8080f843e0100000f108424e8000000'
    '0f118424680100000f108424a80000000f108c24b80000000f109424c8000000'
    '0f109c24d80000000f119c24580100000f119424480100000f118c2438010000'
    '0f118424280100000f284424300f284c24400f118424080100000f118c241801'
    '000048898424000100004c2b7424700f82a8040000488d8c24280100000f1041'
    'e00f1049f00f294c24200f294424100f1041400f1143680f10010f1049100f10'
    '51200f1059300f115b580f1153480f114b380f1143284889030f284424100f28'
    '4c24200f1143080f114b184c89b380000000e963010000498b04244c897c2468'
    '4c896c247048c744245801000000488944246048c744247800000000488dbc24'
    '80000000488d742458e8728df5ff488b8424800000000f108424880000000f29'
    '4424300f108424980000000f294424404883f808752a0f284424300f284c2440'
    '0f294424100f294c24200f114b180f11430848c7030800000031c0e9df000000'
    '0f108424e80000000f118424680100000f108424a80000000f108c24b8000000'
    '0f109424c80000000f109c24d80000000f119c24580100000f11942448010000'
    '0f118c24380100000f118424280100000f284424300f284c24400f1184240801'
    '00000f118c241801000048898424000100004c2b6c24700f824f030000488d8c'
    '24280100000f1041e00f1049f00f294c24200f294424100f1041400f1143680f'
    '10010f1049100f1051200f1059300f115b580f1153480f114b380f1143284889'
    '030f284424100f284c24200f1143080f114b184c89ab80000000b80100000048'
    '8943784889d84881c4780100005b415c415d415e415f5dc34889842400010000'
    '4889942408010000488d8424000100004889842480000000488d0551df540048'
    '89842488000000488d3d1fe8acfb488d152b2c0101488db42480000000ff1555'
    '240501488d35e6ae85004c89f7ff158d35050148c7c1d8eeffff64c641480164'
    '0fb7414464c641440040886c24106689442411640fb669464080fd020f840602'
    '000064c641460240886c240f498b04244c897c24684c896c247048c744245801'
    '000000488944246048c744247800000000488dbc2480000000488d742458e85d'
    '8bf5ff488b8424800000000f108424880000000f294424300f10842498000000'
    '0f294424404883f80875300f284424300f284c24400f298424800000000f298c'
    '24900000000f114b180f11430848c7030800000031c0e9eb0000000f108424e8'
    '0000000f118424680100000f108424a80000000f108c24b80000000f109424c8'
    '0000000f109c24d80000000f119c24580100000f119424480100000f118c2438'
    '0100000f118424280100000f284424300f284c24400f118424080100000f118c'
    '241801000048898424000100004c2b6c24700f8252010000488d8c2428010000'
    '0f1041e00f1049f00f298c24900000000f298424800000000f1041400f114368'
    '0f10010f1049100f1051200f1059300f115b580f1153480f114b380f11432848'
    '89030f288424800000000f288c24900000000f1143080f114b184c89ab800000'
    '00b8010000004889437831ff4c8d642411e8fa6685004885c00f84bc00000080'
    '784602757d4088684648c7c1d8eeffff640fb6414883f801742a83f8020f84a0'
    'fdffff488d35e6ac85004c89f7ff158d33050148c7c1d8eeffff64c64148014c'
    '8d64241164807946020f8474fdffff4983c628488d7424104c89f74c89e2e80d'
    '408500e95bfdffff488d1551380101be3d000000488d3d8600fefb4c8d642411'
    'eb13488d153f980301be45000000488d3d7c520bfcff15dd210501eb3a488d3d'
    '4c210201ff1586220501eb2b488d3d3d210201ff1577220501eb1c488d3d8695'
    '0301ff15302a0501eb0d488d3d1f210201ff15592205010f0b4889c3488dbc24'
    '00010000e8a7174000eb09ff15172205014889c3488d7c240fff15499105014c'
    '8d642411eb39ff15fc2105014889c3488dbc2400010000e874174000eb6aff15'
    'e42105014889c3488dbc2400010000e85c174000eb52ff15cc2105014889c349'
    'c7c7d8eeffff64410fb6474883f801741b83f8027432488d35b3ab85004c89f7'
    'ff155a3205016441c64748016441807f460274144983c628488d7424104c89f7'
    '4c89e2e8e83e85004889dfe86041f400ff1572210501'
)
BODY_SHA256 = 'acbe9e27fdbe65ee18ab2b86524d9551b68ed5907868ba6f7abeba3fa69b4810'
BRANCHES = [
    (0x16, '0f848f000000', 2, 6, 0x471b92b),
    (0x4a, '0f8528030000', 2, 6, 0x471bbf8),
    (0x55, '0f849c010000', 2, 6, 0x471ba77),
    (0x7b, '0f845e030000', 2, 6, 0x471bc5f),
    (0x84, '0f8539030000', 2, 6, 0x471bc43),
    (0xa6, 'e9cc050000', 1, 5, 0x471bef7),
    (0x112, '0f843e010000', 2, 6, 0x471bad6),
    (0x18f, '0f82a8040000', 2, 6, 0x471bebd),
    (0x1f2, 'e963010000', 1, 5, 0x471bbda),
    (0x254, '752a', 1, 2, 0x471bb00),
    (0x27b, 'e9df000000', 1, 5, 0x471bbdf),
    (0x2f7, '0f824f030000', 2, 6, 0x471becc),
    (0x3fc, '0f8406020000', 2, 6, 0x471be88),
    (0x469, '7530', 1, 2, 0x471bd1b),
    (0x496, 'e9eb000000', 1, 5, 0x471be06),
    (0x512, '0f8252010000', 2, 6, 0x471beea),
    (0x599, '0f84bc000000', 2, 6, 0x471bedb),
    (0x5a3, '757d', 1, 2, 0x471bea2),
    (0x5b8, '742a', 1, 2, 0x471be64),
    (0x5bd, '0f84a0fdffff', 2, 6, 0x471bbe3),
    (0x5e9, '0f8474fdffff', 2, 6, 0x471bbe3),
    (0x603, 'e95bfdffff', 1, 5, 0x471bbe3),
    (0x620, 'eb13', 1, 2, 0x471beb5),
    (0x63b, 'eb3a', 1, 2, 0x471bef7),
    (0x64a, 'eb2b', 1, 2, 0x471bef7),
    (0x659, 'eb1c', 1, 2, 0x471bef7),
    (0x668, 'eb0d', 1, 2, 0x471bef7),
    (0x689, 'eb09', 1, 2, 0x471bf14),
    (0x6a4, 'eb39', 1, 2, 0x471bf5f),
    (0x6bc, 'eb6a', 1, 2, 0x471bfa8),
    (0x6d4, 'eb52', 1, 2, 0x471bfa8),
    (0x6ef, '741b', 1, 2, 0x471bf8c),
    (0x6f4, '7432', 1, 2, 0x471bfa8),
    (0x712, '7414', 1, 2, 0x471bfa8),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x471b8c2, 0x4381410),
    (0x471b967, 0x4674820),
    (0x471baa9, 0x4674820),
    (0x471bcbe, 0x4674820),
    (0x471be11, 0x4f72510),
    (0x471be7e, 0x4f6fe90),
    (0x471bf04, 0x4b1d6b0),
    (0x471bf37, 0x4b1d6b0),
    (0x471bf4f, 0x4b1d6b0),
    (0x471bfa3, 0x4f6fe90),
    (0x471bfab, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x471b920, 0x576e918),
    (0x471bc3d, 0x576e098),
    (0x471bc4d, 0x576f1e0),
    (0x471be4d, 0x576f1e0),
    (0x471beb5, 0x576e098),
    (0x471bec4, 0x576e150),
    (0x471bed3, 0x576e150),
    (0x471bee2, 0x576e918),
    (0x471bef1, 0x576e150),
    (0x471bf0b, 0x576e128),
    (0x471bf19, 0x5775068),
    (0x471bf26, 0x576e128),
    (0x471bf3e, 0x576e128),
    (0x471bf56, 0x576e128),
    (0x471bf80, 0x576f1e0),
    (0x471bfb0, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x471bebd, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
    (0x471becc, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
    (0x471beea, 0x573e010, bytes.fromhex('2f686f6d652f7562756e74752f686c2f62696e636f64652d666f726b2f7372632f6c69622e7273'), 170, 22),
]
CALLERS = [0x4b744a5]
CALLER_FUNCTIONS = {'0x4b744a5': ('0x4b74450', '0x4b74622')}
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

