#!/usr/bin/env python3
"""RE-001: pinned periodic slice consumer; never run the target, wc, or nanosleep."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SCOPES = ((0x432f9c0, 0x432fc09), (0x144a890, 0x144accc))
CONTROLS = {
    "0x432f9f0": "41bf3c00000031c0",
    "0x432fa1c": "48894c241848894424204929cf4889df4889de41ffd4",
    "0x432fa32": "83f8ff75c941ffd58b008944241083f8040f85310100004c037c2418488b442420ebad",
    "0x432fa65": "4d8d6f1031c0b101f0410fb04f100f85a6000000",
    "0x432fa7d": "4d8b6f20498b6f284885ed74",
    "0x432fab6": "4c89ff4c89ee4889eaff151be54301",
    "0x432fac5": "b00131c9488b3c24f00fb00f4c8b2d00ee43017558",
    "0x432fae4": "4c89ff4889ee488d15ef703301ff1599ee4301a8017408488b024889d7ff10",
    "0x432fb03": "4885ed0f84e4feffff4c89ff4889ee31d2ff15f6e44301e9d1feffff",
    "0x144a8ab": "4883fe047218817c37fc2e6c7a34750e",
    "0x144a8c9": "488d0580f3dcfe488944242048c744242802000000488d056df3dcfe488944243048c74424380200000048897c24404889742448488d4c2450c644240700488d7c2408488d742407488d542420e8e5b20000",
    "0x144ab55": "4883fe11736b",
    "0x144ab70": "0fb63c1183c7d083ff097778488d048089ff488d044748ffc24839d675e2e9a0000000",
    "0x144abd0": "4839fe745e49f7e00fb61439707583c2d083fa0a730e89d248ffc74801d073e0b002eb02b001",
    "0x144ac17": "b8010000004889da4881c4980000005b415c415d415e415f5dc3",
    "0x144ac4c": "4889c331c0ebc9"
}


def require(value, message):
    if not value:
        raise ValueError(message)


def check_identity(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Expected exact node94 SHA-256')


def analyze(data):
    secs = sections(data)

    def read(va, size):
        offsets = {s['offset'] + va - s['address'] for s in secs if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']}
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
        body = read(start, end - start)
        raw_record = lambda va: read(va, struct.unpack('<I', read(va, 4))[0] + 4).hex()
        windows.append(dict(start_va=hex(start), end_va_exclusive=hex(end), bytes=len(body),
                            sha256=hashlib.sha256(body).hexdigest(), body_hex=body.hex(),
                            fde_va=hex(f['fde']), fde_hex=raw_record(f['fde']),
                            cie_va=hex(f['cie']), cie_hex=raw_record(f['cie'])))
    for va, raw in CONTROLS.items():
        expect(int(va, 16), bytes.fromhex(raw))
    expect(0x219c50, b'wc-l')
    source_path = b'/home/ubuntu/hl/code_Mainnet/base/src/u.rs'
    sleep_path = b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sys/thread/unix.rs'
    expect(0x1ef2de, source_path)
    expect(0x5666be0, struct.pack('<QQII', 0, len(source_path), 361, 11))
    expect(0x1e451a, sleep_path)
    expect(0x5752288, struct.pack('<QQII', 0, len(sleep_path), 550, 17))
    named = {0x576e8d0: 'nanosleep', 0x576e8d8: '__errno_location', 0x576dfe0: 'memcpy'}
    relative = {0x576e990: 0x144a890, 0x5666be0: 0x1ef2de, 0x5752288: 0x1e451a}
    wanted = set(named) | set(relative)
    rel = next(s for s in secs if s['name'] == '.rela.dyn')
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    require(all(s['type'] != 8 for s in (rel, sym, strings)) and rel['size'] % 24 == 0,
            'Invalid dynamic metadata')
    strdata = read(strings['address'], strings['size'])
    bindings = {}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        require(slot not in bindings, 'Duplicate scoped relocation')
        expect(slot, b'\0' * 8)
        if slot in relative:
            require((info, addend) == (8, relative[slot]), 'Scoped relative binding changed')
            bindings[hex(slot)] = dict(info=info, addend=hex(addend))
        else:
            require(info & 0xffffffff == 6, 'Expected GLOB_DAT import')
            index = info >> 32
            require(index * 24 + 24 <= sym['size'], 'Symbol outside .dynsym')
            nameoff = struct.unpack('<I', read(sym['address'] + index * 24, 4))[0]
            require(nameoff < len(strdata), 'Name outside .dynstr')
            end = strdata.find(b'\0', nameoff)
            require(end >= 0, 'Unterminated symbol name')
            name = strdata[nameoff:end].decode('ascii')
            require(name == named[slot], 'Named import changed')
            bindings[hex(slot)] = dict(info=info, symbol_index=index, name=name)
    require(len(bindings) == len(wanted), 'Missing scoped relocation')
    return dict(target_release='94', target_sha256=SHA256,
                coordinates='linked ELF VA, no runtime rebase', windows=windows,
                controls=CONTROLS, bindings=bindings,
                locations=[dict(location_va='0x5666be0', path=source_path.decode(), line=361, column=11),
                           dict(location_va='0x5752288', path=sleep_path.decode(), line=550, column=17)],
                observations=['loop resets the requested seconds to60; raw nanosleep -1 calls errno accessor and only errno4 takes the remaining-timespec retry route',
                              'fast byte lock changes0 to1 at state+0x10 before reading slice pointer+0x20 and length+0x28',
                              'the copied slice is passed to the consumer after release-CAS1 to0 and any selected slow-release helper',
                              'consumer builds slice records wc/-l plus supplied slice before opaque helper1455c00; it has an .lz4 suffix guard and unsigned decimal parse instructions',
                              'consumer normal returns use raw tag0 with numeric word or tag1 with error carrier; caller ignores the zero-tag payload and conditionally calls through the nonzero carrier before looping'],
                unresolved=['slow lock/release helpers and complete synchronization contract',
                            'command helper/allocator/cleanup ABI, all filesystem or process effects, and purpose of periodic sampling',
                            'full Unicode trimming and numeric-parser behavior; the reference periodic-writer label is not established'],
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
        print('Periodic slice-consumer evidence reproduces exactly.')
    else:
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
