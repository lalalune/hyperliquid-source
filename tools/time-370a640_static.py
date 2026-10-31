#!/usr/bin/env python3
"""Authenticated node94 time-370a640 binding (0x370a640).

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

START, END = 0x370a640, 0x370afc1
FDE_VA = 0x11a5224
FDE = bytes.fromhex(
    '50000000fc751e00145456028109000004df7c90ff410e10420e18420e20420e'
    '28420e30410e38470ee00883078c068d058e048f0386020378070e38410e3042'
    '0e28420e20420e18420e10410e08410ee0080000'
)
BODY = bytes.fromhex(
    '554157415641554154534881ec280400004d89cc4d89c74989cd4889d5488974'
    '24584989fe48c7c390fbffff64488b0425000000004801d84889442410b20164'
    '807b10004c890c240f844607000064488b3364488b4308488d4e016448890b0f'
    '10155a73fe010f299424a00100000f101d5b73fe010f299c24b00100004889b4'
    '24c001000048898424c801000048c78424080100000000000048c78424180100'
    '000000000048c78424100300000000000048c78424200300000000000084d20f'
    '84e5060000488d5101644889130f288424a00100000f288c24b0010000488b94'
    '24c0010000488bb424c80100000f298424600200000f298c2470020000488994'
    '24800200004889b424880200000f108424080100000f298424c0020000488b94'
    '241801000048899424d0020000c6842408030000000f108424100300000f1184'
    '24d8020000488b94242003000048899424e80200000f299424900200000f299c'
    '24a002000048898c24b002000048898424b802000048c78424f0020000000000'
    '0048c78424000300000000000048c78424100300000000000048c78424180300'
    '000800000048c784242003000000000000488dbc24a00100004c89eeff15c6b5'
    '0602488dbc24c80300004c8d8424100300004c8d8c24a00100004889ee4c89ea'
    '4c89f9ff15a7b5060248c78424080100000000000048c7842410010000080000'
    '000f57c00f1184241801000048b80000000000004e404889842480010000c784'
    '248801000000000000c78424940100000000000048c784246001000000000000'
    '0f118424300100000f1184244801000048b89a9999999999a93f488984246801'
    '000048c784247001000000000000c68424780100000248c74424600000000048'
    'c74424700000000048c74424780000000048c78424880000000000000048c784'
    '24900000000000000048c78424a000000000000000bf3bf90a00ff15903f0602'
    '89c585c00f842b05000048c78424a80000000000000048c78424b80000000000'
    '000048c78424c00000000000000048c78424d0000000000000004c89e04d8b24'
    '2448b900000000000000804939cc896c240c0f853c01000048c78424f0000000'
    '0000000048c78424000100000000000048c78424d80000000000000048c78424'
    'e80000000000000048c78424100300000000000048c784242003000000000000'
    'bfa8fa0a00ff15e53e060285c00f849104000089c6c1fe0d8d4eff31d285f67f'
    '22ba0100000029f24869d21f85eb5148c1ea27ffc269f29001000001f169d24f'
    'c5fdffc1e80425ff01000001d069d1b5050000c1fa024863c94869c91f85eb51'
    '4889ce48c1ee3f48c1f92501f129c8c1f90201d001c805c506f5ff48984869c0'
    '005c26054531e44885c0490f4ec448b9956588635ddc460348f7e14889d348c1'
    'eb07488b8424e800000048894424300f108424d80000000f294424200f108424'
    '180300000f298424a00100000f108424f00000000f298424b00100000f57c00f'
    '2944241041bd10270000b003890424e911010000488b88b800000048894c2448'
    '4c8d78084c8ba8c0000000488b80e000000048894424504c89a4241003000048'
    '8dbc2418030000bab00000004c89feff150b350602bf3bf90a00ff15b03d0602'
    '8944240885c00f84670300004c89a424a0010000488dbc24a8010000bab00000'
    '004c89feff15d6340602bfb8000000ff15c33406024885c00f84f40200004889'
    'c54c896c24404c89204889c74883c708bab00000004c89feff15a23406026480'
    '7b10000f84db020000640f10030f294424106448ff03488b04244805c8000000'
    '0f10000f29442420488b401048894424300f1005886efe010f298424a0010000'
    '0f1005896efe010f298424b0010000c70424000000004c8b6424504c8b6c2448'
    '488b5c24400f10842418040000410f1146500f10842408040000410f1146400f'
    '108424c80300000f108c24d80300000f109424e80300000f109c24f803000041'
    '0f115e30410f115620410f114e10410f1106498dbef8000000488db424600200'
    '004c8b3dd8330602bab000000041ffd7498d7e60488db42408010000ba980000'
    '0041ffd70f57c0410f11863802000041c686ec0200000149c786480200000000'
    '000049c7865002000020a10700488b442470498986680200000f10442460410f'
    '118658020000488b842488000000498986800200000f10442478410f11867002'
    '00000f10842490000000410f118688020000488b8424a0000000498986980200'
    '0041c686ed020000328b44240c418986e002000049c786e40200000000000048'
    'b8000000000000f03f498986a0020000488b8424b8000000498986b80200000f'
    '108424a8000000410f1186a80200000f108424c0000000410f1186c002000048'
    '8b8424d0000000498986d00200004d89aea801000049899eb0010000488b4424'
    '30498986c80100000f28442420410f1186b80100004d89a6d00100000f288424'
    'a00100000f288c24b0010000410f118ee8010000410f1186d80100000f284424'
    '10410f1186f80100004989ae0802000049c78610020000000000008b44240841'
    '89861802000049c7861c02000000000000488b4c2458488b0149898624020000'
    '8b41084189862c0200008b04244188863002000049c786d8020000000000004c'
    '89f04881c4280400005b415c415d415e415f5dc3488b7c241031f6e85012e9ff'
    '640fb65310e9a4f8ffff488b7c241031f6e83a12e9ff64488b0b64488b43080f'
    '1015fa6bfe010f101d036cfe01e9f3f8ffffbf08000000beb8000000ff15fe31'
    '0602eb3c488b7c241031f6e80012e9ffe914fdffff488d3dbcfcf501ff152e36'
    '0602eb1c488d3dadfcf501ff151f360602eb0d488d3d9efcf501ff1510360602'
    '0f0b4989c64889efe8c39d0500e9b70000004989c6488dbc2410030000e8de97'
    'ceff488dbc2408010000e8619eceff488dbc24a0010000e8b4d2dcffe9f00000'
    '00ff15813206024989c6e9e20000004989c6488dbc2410030000e8417d0500eb'
    '68ff15613206024989c6488dbc2410030000e88997ceff488dbc24d8000000e8'
    '7c97ceff488dbc24f0000000e86f6bceffeb36ff152f3206024989c6eb104989'
    'c6488dbc2410030000e8a2a90500b301eb6e4989c6b301eb2c4989c6488dbc24'
    'a0010000e8d77c0500488dbc24c0000000e82a97ceff488dbc24a8000000e81d'
    '97ceff31db488dbc2490000000e80e97ceff488d7c2478e8046bceff488d7c24'
    '60e88a7eceff488dbc2408010000e85d970500488dbc24c8030000e8507d0500'
    '488dbc2460020000e83398050084db741c488b042448b9000000000000008048'
    '39087409488b3c24e8537c05004c89f7e85b51f501ff156d310602ff15673106'
    '02'
)
BODY_SHA256 = '0053019db265740683c3a1e3551f899a73d58ad09341431369114e74cb8b3c7c'
BRANCHES = [
    (0x48, '0f8446070000', 2, 6, 0x370add4),
    (0xbf, '0f84e5060000', 2, 6, 0x370adea),
    (0x2c4, '0f842b050000', 2, 6, 0x370ae35),
    (0x312, '0f853c010000', 2, 6, 0x370aa94),
    (0x36d, '0f8491040000', 2, 6, 0x370ae44),
    (0x37f, '7f22', 1, 2, 0x370a9e3),
    (0x44f, 'e911010000', 1, 5, 0x370aba5),
    (0x4a6, '0f8467030000', 2, 6, 0x370ae53),
    (0x4d8, '0f84f4020000', 2, 6, 0x370ae12),
    (0x503, '0f84db020000', 2, 6, 0x370ae24),
    (0x7a5, 'e9a4f8ffff', 1, 5, 0x370a68e),
    (0x7cd, 'e9f3f8ffff', 1, 5, 0x370a705),
    (0x7e2, 'eb3c', 1, 2, 0x370ae60),
    (0x7f0, 'e914fdffff', 1, 5, 0x370ab49),
    (0x802, 'eb1c', 1, 2, 0x370ae60),
    (0x811, 'eb0d', 1, 2, 0x370ae60),
    (0x82d, 'e9b7000000', 1, 5, 0x370af29),
    (0x85c, 'e9f0000000', 1, 5, 0x370af91),
    (0x86a, 'e9e2000000', 1, 5, 0x370af91),
    (0x87f, 'eb68', 1, 2, 0x370af29),
    (0x8b1, 'eb36', 1, 2, 0x370af29),
    (0x8bc, 'eb10', 1, 2, 0x370af0e),
    (0x8d0, 'eb6e', 1, 2, 0x370af80),
    (0x8d7, 'eb2c', 1, 2, 0x370af45),
    (0x94f, '741c', 1, 2, 0x370afad),
    (0x962, '7409', 1, 2, 0x370afad),
]
# Direct tail jumps leaving the FDE extent (observed call edges).
TAIL_CALLS = [
]
DIRECT_CALLS = [
    (0x370addb, 0x359c030),
    (0x370adf1, 0x359c030),
    (0x370ae2b, 0x359c030),
    (0x370ae68, 0x3764c30),
    (0x370ae7d, 0x33f4660),
    (0x370ae8a, 0x33f4cf0),
    (0x370ae97, 0x34d8150),
    (0x370aeba, 0x3762c00),
    (0x370aed2, 0x33f4660),
    (0x370aedf, 0x33f4660),
    (0x370aeec, 0x33f1a60),
    (0x370af09, 0x37658b0),
    (0x370af24, 0x3762c00),
    (0x370af31, 0x33f4660),
    (0x370af3e, 0x33f4660),
    (0x370af4d, 0x33f4660),
    (0x370af57, 0x33f1a60),
    (0x370af61, 0x33f2df0),
    (0x370af6e, 0x37646d0),
    (0x370af7b, 0x3762cd0),
    (0x370af88, 0x37647c0),
    (0x370afa8, 0x3762c00),
    (0x370afb0, 0x5660110),
]
# GOT-mediated call sites: (site, slot); slot targets via relocations.
INDIRECT_CALLS = [
    (0x370a7fc, 0x5775dc8),
    (0x370a823, 0x5775dd0),
    (0x370a8fa, 0x576e890),
    (0x370a9a5, 0x576e890),
    (0x370aacf, 0x576dfe0),
    (0x370aada, 0x576e890),
    (0x370ab04, 0x576dfe0),
    (0x370ab0f, 0x576dfd8),
    (0x370ab38, 0x576dfe0),
    (0x370ae1c, 0x576e020),
    (0x370ae3c, 0x576e470),
    (0x370ae4b, 0x576e470),
    (0x370ae5a, 0x576e470),
    (0x370aea1, 0x576e128),
    (0x370aec1, 0x576e128),
    (0x370aef3, 0x576e128),
    (0x370afb5, 0x576e128),
    (0x370afbb, 0x576e128),
]
# Panic Locations: (lea site, Location struct VA, path bytes, line, column).
LOCATIONS = [
    (0x370ae35, 0x566aaf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f74696d652e7273'), 74, 55),
    (0x370ae44, 0x566aaf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f74696d652e7273'), 74, 55),
    (0x370ae53, 0x566aaf8, bytes.fromhex('2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f74696d652e7273'), 74, 55),
]
CALLERS = []
CALLER_FUNCTIONS = {}
LEA_REFS = 0
OWN_GOT_SLOTS = ['0x5775978']
GOT_SITES = {'0x5775978': ['0x3331b59']}


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

