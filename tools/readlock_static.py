#!/usr/bin/env python3
"""Authenticated node94 shared read-lock helper binding (0x358dcd0).

Binds the parking_lot-anchored read-guard acquisition helper to the node #94
digest: its FDE-bounded body, the std once.rs:219:20 and parking_lot-0.12.3
raw_rwlock.rs:1145:45 Locations, the 1e9-nanosecond spin constant, seven call
targets, and the 952-site / 358-function census. Static byte/record checks
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

START, END, BODY_LEN = 0x358dcd0, 0x358de41, 369
FDE_VA = 0x1187dac
ONCE_LOC, RWLOC_LOC = 0x56ee7b0, 0x56f16f8
ONCE_PATH = (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/'
             b'src/sync/once.rs')
RWLOCK_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
               b'parking_lot-0.12.3/src/raw_rwlock.rs')
RUSTC_HASH = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
PARKING_LOT = 'parking_lot-0.12.3'
GOT_SITES = [
    (0x358dd92, 0x576e8b8, 0x4ee3b20),
    (0x358ddc7, 0x576f600, 0x4e0c150),
    (0x358ddf0, 0x576e118, 0x157b480),
    (0x358ddff, 0x576f608, 0x4e0d2c0),
    (0x358de33, 0x576f608, 0x4e0d2c0),
    (0x358de3b, 0x576e128, 0x157b63b),
]
GOT_SELF = 0x5773190
SITES, FUNCTIONS = 952, 358
STRUCT_VA, STRUCT_TARGET = 0x5786278, 0x35ab620
ONE_E9_IMM = 0x3b9aca00

FDE = bytes.fromhex('3800000084a11c001c5f40027101000004ef1a91ff420e10410e18440e5083038e02027a0e18410e10420e08410e5002b40e18410e10420e08410e50')
BODY = bytes.fromhex(
    '4156534883ec388b05bb851f0285c07574b90800000031c0f0480fb10d87851f020f85bc'
    '000000488d057a851f02488d0d74851f024839c10f82db0000000f10068b46100f114424'
    '0889442418400fb6d7488d3558851f02488d7c2420488d4c2408e8d98de0ff31c9b80800'
    '0000f0480fb10d31851f020f85a90000004883c4385b415ec3488d051c851f0248894424'
    '20488d4424204889442408488d0526851f02488d0d0f0a16024c8d05300a1602488d5424'
    '0889fb4889c74989f6be01000000ff15200b1e024c89f689dfb90800000031c0f0480fb1'
    '0dcb841f020f8444ffffff488d05be841f0289fb4889c7ba00ca9a3b4989f6ff1533181e'
    '024c89f689df488d059f841f02488d0d99841f024839c10f8325ffffff488d3d08391602'
    'ff1522031e02488d3d7b841f0231f6ff1503181e024883c4385b415ec34889c331c9b808'
    '000000f0480fb10d58841f0275084889dfe8e6220d02488d3d47841f0231f6ff15cf171e'
    '02ebe7ff15e7021e02')


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
    require(body == BODY, 'Read-lock body bytes changed')

    eh = reader.by_name['.eh_frame']
    record = reader.read(FDE_VA, len(FDE))
    require(record == FDE, 'Read-lock FDE record changed')
    length = struct.unpack_from('<I', record, 0)[0]
    pc = FDE_VA + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require(length == len(FDE) - 4, 'FDE length changed')
    require((pc, pc + extent) == (START, END), 'FDE PC range changed')

    rels = relocations(reader)
    for loc_va, path, line, col in [
            (ONCE_LOC, ONCE_PATH, 219, 20),
            (RWLOC_LOC, RWLOCK_PATH, 1145, 45)]:
        path_va = rels.get(loc_va)
        require(path_va is not None, 'Location relocation missing')
        length_, sline, scol = struct.unpack('<QII', reader.read(loc_va + 8, 16))
        require((length_, sline, scol) == (len(path), line, col),
                f'Location layout changed at {loc_va:#x}')
        require(reader.read(path_va, length_) == path,
                f'Location path changed at {loc_va:#x}')

    require(rels.get(STRUCT_VA) == STRUCT_TARGET, 'Descriptor struct relocation changed')

    FF15 = bytes.fromhex('ff15')
    for site, got, target in GOT_SITES:
        off = site - START
        require(body[off:off + 2] == FF15, f'Call opcode changed at {site:#x}')
        require(site + 6 + struct.unpack_from('<i', body, off + 2)[0] == got,
                f'Call GOT address changed at {site:#x}')
        require(rels.get(got) == target, f'Call target changed at {site:#x}')
    require(body.find(struct.pack('<I', ONE_E9_IMM), 0, BODY_LEN) >= 0,
            '1e9 nanosecond constant changed')

    text = reader.by_name['.text']
    code = reader.read(text['address'], text['size'])
    require(rels.get(GOT_SELF) == START, 'Self GOT slot changed')
    import bisect
    index = ROOT / 'work/index/node-94-unwind.tsv'
    require(index.is_file(), 'Missing unwind index; run tools/elf_index.py --release 94')
    fn_starts = sorted(int(line.split('\t')[1], 16)
                       for line in index.read_text().splitlines()[1:])
    pos, sites, functions = 0, 0, set()
    while (pos := code.find(FF15, pos)) >= 0:
        if pos + 6 <= len(code):
            got = text['address'] + pos + 6 + struct.unpack_from('<i', code, pos + 2)[0]
            if got == GOT_SELF:
                sites += 1
                i = bisect.bisect_right(fn_starts, text['address'] + pos) - 1
                require(i >= 0, 'Caller outside indexed text')
                functions.add(fn_starts[i])
        pos += 2
    require(sites == SITES, f'Site census changed: {sites}')
    require(len(functions) == FUNCTIONS, f'Function census changed: {len(functions)}')

    return dict(
        target_release='94', target_sha256=SHA256,
        coordinate_system='ELF virtual addresses, no runtime rebase',
        helper=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=BODY_LEN,
                    sha256=hashlib.sha256(body).hexdigest(), fde_va=hex(FDE_VA),
                    inferred_label='parking_lot read-guard acquisition helper'),
        dependency_anchors=dict(
            std_once=dict(location_va=hex(ONCE_LOC), line=219, column=20,
                          path='library/std/src/sync/once.rs', rustc_commit=RUSTC_HASH),
            parking_lot=dict(location_va=hex(RWLOC_LOC), line=1145, column=45,
                             path='parking_lot-0.12.3/src/raw_rwlock.rs',
                             crate=PARKING_LOT)),
        observed=dict(descriptor_struct=dict(va=hex(STRUCT_VA), target=hex(STRUCT_TARGET)),
                      spin_constant_ns=ONE_E9_IMM,
                      call_targets=[hex(t) for _, _, t in GOT_SITES]),
        call_census=dict(got_slot=hex(GOT_SELF), sites=SITES, distinct_functions=FUNCTIONS,
                         denominator='complete .text scan for slot-targeted ff15 encodings',
                         note='the dominant shared helper in the binary by call-site count'),
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
