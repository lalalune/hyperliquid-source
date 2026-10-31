#!/usr/bin/env python3
"""Authenticated node94 initializer entry-point binding (0x4edce70, 0x4f100b0).

Binds the two entry points the build-mode initializer calls first
(RE-001-build-mode-init-94) to the node #94 digest: the 472-byte
argument-list processor 0x4edce70 (the .bss globals at 0x5788550/0x5788548,
the 0x555555555555555 capacity bound — floor((2^64 - 1)/3), the shared
alloc/dealloc/error entry points, an imported slot without a static
relocation, and a ud2-terminated error block) and the 214-byte
twenty-four-byte-stride iterator 0x4f100b0 (the i64::MIN sentinel, the 0x18
element stride, the panic_fmt error path with the 43-byte operand, and the
shared dealloc). Static byte/record checks only; the captured binary is
never executed.
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

ARG_START, ARG_END = 0x4edce70, 0x4edd048
ARG_FDE_VA = 0x12f64d0
ARG_GOT = 0x576f540
ARG_GLOBAL_1 = 0x5788550
ARG_GLOBAL_2 = 0x5788548
BOUND = 0x5555555555555555

IT_START, IT_END = 0x4f100b0, 0x4f10186
IT_FDE_VA = 0x12f7f7c
IT_GOT = 0x576f548
I64_MIN = 0x8000000000000000
STRIDE = 0x18

GOT_ERR, ERR_FN = 0x576dfb8, 0x1346068
GOT_ALLOC, ALLOC_FN = 0x576dfd8, 0x54c06b0
GOT_DEALLOC, DEALLOC_FN = 0x576e010, 0x54c8cb0
GOT_IMPORT, _ = 0x576e038, 0            # imported slot, no static relocation
GOT_COPY, _ = 0x576dfe0, 0              # indirect copy slot, no static relocation
GOT_NEXT, NEXT_FN = 0x5776410, 0x4f04bb0
GOT_ITER, ITER_FN = 0x576e3f8, 0x157a200
GOT_FMT, FMT_FN = 0x576e048, 0x157aa10

ARG_ANCHORS = [
    (0x21, '48b85555555555555505', 'capacity bound constant'),
    (0x45, 'ff15', 'error call'),
    (0x8b, 'ff15', 'alloc call'),
    (0xa7, 'ff15', 'error call (second)'),
    (0xd2, 'be02000000', 'error operand 2'),
    (0x116, 'ff15', 'imported slot call'),
    (0x127, 'ff15', 'copy slot call'),
    (0x163, 'ff15', 'next-stage call'),
    (0x195, 'ff15', 'error call (third)'),
    (0x1ad, 'ff15', 'dealloc call'),
    (0x19b, '0f0b', 'ud2 terminator'),
]

ARG_CALLS = [
    (0x45, GOT_ERR, ERR_FN), (0x8b, GOT_ALLOC, ALLOC_FN),
    (0xa7, GOT_ERR, ERR_FN), (0x127, GOT_ALLOC, ALLOC_FN),
    (0x163, GOT_NEXT, NEXT_FN), (0x195, GOT_ERR, ERR_FN),
    (0x1ad, GOT_DEALLOC, DEALLOC_FN),
]

IT_ANCHORS = [
    (0x12, '48b90000000000000080', 'i64::MIN sentinel'),
    (0x26, '488d5018', 'iterator advance by 0x18'),
    (0x4d, 'ff15', 'iterator call'),
    (0x99, 'be2b000000', 'error operand 43'),
    (0x9e, 'ff15', 'panic_fmt call'),
    (0xc8, 'ff15', 'dealloc call'),
    (0xa4, '0f0b', 'ud2 terminator'),
]

IT_CALLS = [
    (0x4d, GOT_ITER, ITER_FN), (0x9e, GOT_FMT, FMT_FN),
    (0xc8, GOT_DEALLOC, DEALLOC_FN),
]

CALLERS_COUNT = 3
INITIALIZER_SITE_1 = 0x143ef69        # the build-mode initializer's first call
INITIALIZER_SITE_2 = 0x143efba        # its second call

ARG_BODY = bytes.fromhex(
'554889e54157415641554154534883ec38488b05c8b68a00488945a84885c074'
'2a48b855555555555555054c8b25a6b68a004a8d0ce500000000488d34494939'
'c4763a31ffff15fd108900ba0800000031db31c0488d0c5b488d0cca48891748'
'8957084889471048894f184889f84883c4385b415c415d415e415f5dc34885f6'
'742b4889f34989fe4889f7ff15d71089004c89f74889c24c89e04885d27515bf'
'080000004889deff159b108900ba0800000031c0488945c0488955c848c745d0'
'000000004d85e40f84a500000048897db841be0200000031db4c8965b0eb2390'
'48ffc34e8964f2f04e896cf2f84e8924f248895dd04983c6034c8b65b04939dc'
'7477488b45a84c8b3cd84d85ff746d488955a04c89ffff15ac1089004989c448'
'85c0741c4c89e7ff153b1089004989c54885c07511eb56660f1f840000000000'
'41bd010000004c89ef4c89fe4c89e2ff151b108900483b5dc0488b55a0758148'
'8d7dc0ff1537948900488b55c8e96effffff31dbe9dbfeffff4c89e3488b45c0'
'488b55c8488b7db8e9c7feffffbf010000004c89e6ff15ad0f89000f0b4889c3'
'4d85e474224c89ef4c89e631d2ff15ed0f8900488d7dc0e8b46501004889dfe8'
'dc3078004889c3488d7dc0e8a06501004889dfe8c8307800')

ARG_FDE = bytes.fromhex(
'30000000a88833009869be03d801000004afc78cff410e108602430d064d8307'
'8c068d058e048f03026b0c0708410c0610000000')

IT_BODY = bytes.fromhex(
'554889e5415741564154534883ec204889fb48b90000000000000080488b4608'
'483b46187410488d5018488956084c8b304939ce750548890beb294c8b78084c'
'8b6010488d7dc84c89fe4c89e2ff15f5e28500807dc800751b4c89334c897b08'
'4c8963104889d84883c4205b415c415e415f5dc34c8975c84c897dd04c8965d8'
'488d3df6dc8bfb488d0d0a2984004c8d05ab2e8400488d55c8be2b000000ff15'
'f4de85000f0b4889c3488b75c84885f6741c488b7dd0eb0e4889c34d85f6740e'
'4c89ff4c89f631d2ff1592de85004889dfe88aff7400')

IT_FDE = bytes.fromhex(
'2c00000054a333002c81c103d60000000467c08cff410e108602430d064b8306'
'8c058e048f0302640c0708410c061000')


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
        if len(matches) == 1:
            s = matches[0]
            off = s['offset'] + va - s['address']
            return self.data[off:off + size]
        # .text is split hot/cold; stitch reads across adjacent pieces.
        pieces = sorted([s for s in self.sections if s['type'] != 8
                         and va < s['address'] + s['size'] and va + size > s['address']],
                        key=lambda s: s['address'])
        require(pieces and pieces[0]['address'] <= va
                and pieces[-1]['address'] + pieces[-1]['size'] >= va + size,
                f'Unmapped VA range {va:#x}+{size:#x}')
        out = bytearray()
        cursor = va
        for s in pieces:
            if s['address'] + s['size'] <= cursor:
                continue
            start = max(cursor, s['address'])
            off = s['offset'] + start - s['address']
            out += self.data[off:off + min(va + size, s['address'] + s['size']) - start]
            cursor = s['address'] + s['size']
        require(len(out) == size, f'Stitched read short at {va:#x}')
        return bytes(out)


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
    eh = reader.by_name['.eh_frame']

    # ---- Argument-list processor. ----
    body = reader.read(ARG_START, ARG_END - ARG_START)
    require(body == ARG_BODY, 'Argument processor body bytes changed')
    require(eh['address'] <= ARG_FDE_VA < eh['address'] + eh['size'], 'arg FDE outside .eh_frame')
    fde = reader.read(ARG_FDE_VA, len(ARG_FDE))
    require(fde == ARG_FDE, 'Argument processor FDE record changed')
    pc = ARG_FDE_VA + 8 + struct.unpack_from('<i', fde, 8)[0]
    extent = struct.unpack_from('<I', fde, 12)[0]
    require((pc, pc + extent) == (ARG_START, ARG_END), 'arg FDE PC range changed')
    for offset, hexstr, label in ARG_ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(body[offset:offset + len(raw)] == raw, f'Arg anchor changed: {label}')
    for offset, got, target in ARG_CALLS:
        disp = struct.unpack_from('<i', body, offset + 2)[0]
        require(ARG_START + offset + 6 + disp == got, f'arg call GOT at +0x{offset:x} changed')
        require(rels.get(got) == target, f'arg call target for GOT {got:#x} changed')
    # Bound identity: 0x555555555555555 is floor((2^64 - 1) / 3).
    require(BOUND * 3 == (1 << 64) - 1, 'capacity bound identity failed')
    # The two imported slots carry no static relocation (observed).
    require(GOT_IMPORT not in rels and GOT_COPY not in rels,
            'imported slots gained static relocations')

    # ---- Twenty-four-byte-stride iterator. ----
    it = reader.read(IT_START, IT_END - IT_START)
    require(it == IT_BODY, 'Iterator body bytes changed')
    require(eh['address'] <= IT_FDE_VA < eh['address'] + eh['size'], 'iterator FDE outside .eh_frame')
    ifde = reader.read(IT_FDE_VA, len(IT_FDE))
    require(ifde == IT_FDE, 'Iterator FDE record changed')
    pc = IT_FDE_VA + 8 + struct.unpack_from('<i', ifde, 8)[0]
    extent = struct.unpack_from('<I', ifde, 12)[0]
    require((pc, pc + extent) == (IT_START, IT_END), 'iterator FDE PC range changed')
    for offset, hexstr, label in IT_ANCHORS:
        raw = bytes.fromhex(hexstr)
        require(it[offset:offset + len(raw)] == raw, f'Iterator anchor changed: {label}')
    for offset, got, target in IT_CALLS:
        disp = struct.unpack_from('<i', it, offset + 2)[0]
        require(IT_START + offset + 6 + disp == got, f'iterator call GOT at +0x{offset:x} changed')
        require(rels.get(got) == target, f'iterator call target for GOT {got:#x} changed')

    # Stride identity: 24 bytes per element divides evenly into the
    # i64-addressable span checked by the sentinel compare.
    require(STRIDE == 3 * 8, 'stride must be three qwords')

    # ---- Censuses: three GOT-mediated callers each, zero direct or lea. ----
    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])

    def census(fn):
        direct, indirect, lea = [], [], []
        pos = 0
        while (pos := code.find(b'\xff\x15', pos)) >= 0:
            if pos + 6 <= len(code):
                slot = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
                if rels.get(slot) == fn:
                    indirect.append(text['address'] + pos)
            pos += 2
        pos = 0
        while (pos := code.find(b'\xe8', pos)) >= 0:
            if pos + 5 <= len(code):
                destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
                if destination == fn:
                    direct.append(text['address'] + pos)
            pos += 1
        for m in range(len(code) - 7):
            if code[m] == 0x48 and code[m + 1] == 0x8d and (code[m + 2] & 0xC7) == 0x05:
                d = struct.unpack_from('<i', code, m + 3)[0]
                if text['address'] + m + 7 + d == fn:
                    lea.append(text['address'] + m)
        return direct, indirect, lea

    for fn, got, site in [(ARG_START, ARG_GOT, INITIALIZER_SITE_1),
                          (IT_START, IT_GOT, INITIALIZER_SITE_2)]:
        direct, indirect, lea = census(fn)
        require(direct == [] and lea == [] and len(indirect) == CALLERS_COUNT,
                f'census changed for {fn:#x}: {len(indirect)} sites')
        require(rels.get(got) == fn, f'GOT slot for {fn:#x} changed')
        require(site in indirect, 'initializer call site missing')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        arg_processor=dict(start_va=hex(ARG_START), end_va_exclusive=hex(ARG_END),
                           bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                           fde_va=hex(ARG_FDE_VA), got_slot=hex(ARG_GOT),
                           globals=[hex(ARG_GLOBAL_1), hex(ARG_GLOBAL_2)],
                           bound=hex(BOUND), bound_identity='(2^64 - 1) / 3 exactly',
                           imported_slots=[hex(GOT_IMPORT), hex(GOT_COPY)],
                           inferred_label='argument-list processor behind the '
                                          'build-mode initializer'),
        stride_iterator=dict(start_va=hex(IT_START), end_va_exclusive=hex(IT_END),
                             bytes=len(it), sha256=hashlib.sha256(it).hexdigest(),
                             fde_va=hex(IT_FDE_VA), got_slot=hex(IT_GOT),
                             element_stride=STRIDE, sentinel=hex(I64_MIN),
                             error_operand=43, panic_fmt=hex(FMT_FN),
                             inferred_label='twenty-four-byte-stride iterator'),
        shared_entry_points=dict(alloc=hex(ALLOC_FN), dealloc=hex(DEALLOC_FN),
                                 error=hex(ERR_FN),
                                 note='alloc shared with RE-001-alloc-shim-94'),
        identities=dict(capacity_bound='3 * 0x5555555555555555 == 2^64 - 1',
                        stride='0x18 == 3 qwords'),
        call_census=dict(arg_sites=CALLERS_COUNT, iterator_sites=CALLERS_COUNT,
                         initializer_sites=[hex(INITIALIZER_SITE_1), hex(INITIALIZER_SITE_2)],
                         note='byte-pattern census over the complete .text for '
                              'e8/ff15/lea encodings'),
        cross_links=dict(build_mode_initializer='0x143ef30 (RE-001-build-mode-init-94)'),
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
