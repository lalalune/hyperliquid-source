#!/usr/bin/env python3
"""RE-001: pinned node94 consensus latency label/conditional remainder-gate evidence.

Static bytes only. No random generator, captured instructions, or target is executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SCOPES = ((0x4a11410, 0x4a117be), (0x13c9e20, 0x13c9ff5))


def require(value, message):
    if not value:
        raise ValueError(message)


def check_identity(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Expected exact node94 SHA-256')


def analyze(data):
    """Structural observations below the separate identity gate for corruption controls."""
    secs = sections(data)

    def read(va, size):
        offsets = {s['offset'] + va - s['address'] for s in secs
                   if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']}
        require(len(offsets) == 1, 'No unique file-backed coordinate')
        offset = offsets.pop()
        return data[offset:offset + size]

    def expect(va, raw):
        require(read(va, len(raw)) == raw, f'Control changed at {va:#x}')

    _, fdes = eh_frame_records(data, secs)
    windows = []
    for start, end in SCOPES:
        matches = [f for f in fdes if f['start'] == start and f['end'] == end]
        require(len(matches) == 1, 'Scoped FDE changed')
        f = matches[0]
        raw = read(start, end - start)
        length = struct.unpack('<I', read(f['fde'], 4))[0] + 4
        cie_length = struct.unpack('<I', read(f['cie'], 4))[0] + 4
        windows.append(dict(start_va=hex(start), end_va_exclusive=hex(end), bytes=len(raw),
                            sha256=hashlib.sha256(raw).hexdigest(), body_hex=raw.hex(),
                            fde_va=hex(f['fde']), fde_hex=read(f['fde'], length).hex(),
                            cie_va=hex(f['cie']), cie_hex=read(f['cie'], cie_length).hex()))

    # Original instruction bytes, including branch destinations and register widths.
    controls = {
        0x4a11425: '400fb6c631c93c0f488d40f2480f43c8',
        0x4a1143a: '488d05f323cffb48630c884801c1ffe1',
        0x4a11519: '31c0e98a000000',
        0x4a1155c: 'b001b101eb4a',
        0x4a115a8: 'b00131c9',
        0x4a115cd: '88442406884c2405',
        0x4a116a2: '488d4424064889442458488d4424054889442460',
        0x4a116c0: 'e8cb66f4ff4889c3',
        0x4a116c8: '807c240500740fbf32000000ff151ed2d50084c0741e',
        0x4a116de: '488d154350d200be010000004889dff20f108424b0000000ff15b4d8d500',
        0x13c9e29: '4889fb',
        0x13c9f73: '4c89f04809d848c1e820740a4c89f031d248f7f3eb074489f031d2f7f34885d20f94c0',
    }
    for va, raw in controls.items():
        expect(va, bytes.fromhex(raw))

    table_va = 0x4a11441 + struct.unpack('<i', read(0x4a1143d, 4))[0]
    targets = [table_va + struct.unpack('<i', read(table_va + i * 4, 4))[0] for i in range(6)]
    require(targets == [0x4a1144a, 0x4a11520, 0x4a114a6, 0x4a114e0, 0x4a11486, 0x4a11562],
            'Scoped dispatch table changed')
    labels = {
        'HandleAllStateInputs': read(0x4a1153b + struct.unpack('<i', read(0x4a11537, 4))[0], 16)
                                + read(0x4a11541, 4),
        'WallClockBlockGap': read(0x4a114fb + struct.unpack('<i', read(0x4a114f7, 4))[0], 16)
                             + read(0x4a11501, 1),
        'BlockGap': read(0x4a114bc, 8),
        'TxCommit': read(0x4a1149c, 8),
        'ExpensiveStatus': read(0x4a11586, 8) + read(0x4a11578, 8)[1:],
    }
    for label, raw in labels.items():
        require(raw == label.encode(), f'Label bytes changed: {label}')
    expect(0x1fd774, b'\x12HandleStateInput::\xc0\x00')
    expect(0x1e0786, b'\x0aconsensus/\xc0\x00')

    rel = next(s for s in secs if s['name'] == '.rela.dyn')
    require(rel['size'] % 24 == 0 and rel['type'] != 8, 'Invalid relocation contents')
    relocations = {}
    for offset in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        if slot in (0x5736728, 0x576e8f8, 0x576efb0):
            require(slot not in relocations, 'Duplicate scoped relocation')
            relocations[slot] = (info, addend)
    require(relocations == {0x5736728: (8, 0x1fea2d), 0x576e8f8: (8, 0x13c9e20),
                            0x576efb0: (8, 0x14027b0)}, 'Scoped relocation changed')
    path = b'/home/ubuntu/hl/code_Mainnet/node/src/consensus/latency_samplers.rs'
    expect(0x1fea2d, path)
    expect(0x5736728, struct.pack('<QQII', 0, len(path), 38, 21))
    for slot in (0x576e8f8, 0x576efb0):
        expect(slot, b'\0' * 8)

    return dict(target_release='94', target_sha256=SHA256,
                coordinates='linked ELF VA, no runtime rebase', windows=windows,
                dispatch=dict(table_va=hex(table_va), table_hex=read(table_va, 24).hex(),
                              six_targets=[hex(t) for t in targets],
                              tested_raw_id_domain='0..19 only; larger IDs/admission unresolved'),
                labels={k: v.decode() for k, v in sorted(labels.items())},
                controls={hex(k): v for k, v in controls.items()},
                source_location=dict(path=path.decode(), line=38, column=21, location_va='0x5736728'),
                relocations={hex(k): dict(info=v[0], addend=hex(v[1])) for k, v in sorted(relocations.items())},
                observations=['pre-builder flag pair at stack+6/+5 is (1,0) for the default and ExpensiveStatus paths, (1,1) for HandleAllStateInputs, (0,0) for the other three fixed labels',
                              'post-builder byte at stack+5 equal to zero bypasses the helper; otherwise helper argument is50 and low-byte-zero return bypasses the metric call',
                              'helper normal-return tail chooses unsigned32 or unsigned64 division by the saved input divisor, then AL is1 iff remainder is0'],
                unresolved=['builder receives addresses of both flag bytes; their preservation across opaque calls is not established',
                            'TLS refill routines, randomness distribution and exact1/50 probability are not proved',
                            'metric helper behavior, allocation/map ABI, complete caller domain and elapsed-time units are not recovered'],
                captured_binaries_executed=False, progress_gate_requested=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    p.add_argument('--check', type=Path)
    args = p.parse_args()
    data = args.binary.read_bytes()
    check_identity(data)
    report = analyze(data)
    if args.check:
        require(report == json.loads(args.check.read_text(encoding='utf-8')), 'Retained report differs')
        print('Consensus latency gate evidence reproduces exactly.')
    else:
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
