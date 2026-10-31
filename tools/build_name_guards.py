#!/usr/bin/env python3
"""RE-001: pin node94 build-name input guards, not a reconstructed argument parser."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SCOPES = ((0x143ef30, 0x143f4e7),)


def require(value, message):
    if not value:
        raise ValueError(message)


def check_identity(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Expected exact node94 SHA-256')


def signed_boundary_branch(byte):
    """Architectural CMP r/m8,0xc0; JL truth only, not captured execution."""
    require(type(byte) is int and 0 <= byte < 256, 'Expected one byte')
    result = (byte - 0xc0) & 255
    sign = bool(result & 0x80)
    overflow = bool((byte ^ 0xc0) & (byte ^ result) & 0x80)
    return sign != overflow


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
    start, end = SCOPES[0]
    matches = [f for f in fdes if f['start'] == start and f['end'] == end]
    require(len(matches) == 1, 'Scoped FDE changed')
    f = matches[0]
    body = read(start, end - start)
    controls = {
        0x143efc5: '4889c848f7d80f800b030000',
        0x143efe5: '4883fb02720c6641813e2d2d0f84f7010000',
        0x143eff7: 'be06000000488d3da7a4ddfe4c89f24889d9e8e21d000084c00f843a010000',
        0x143f016: '4885db740c41807c1eff2f0f84f9030000',
        0x143f104: '4939df0f8333ffffff43803c3e2f0f8528ffffff49ffc7',
        0x143f11b: '4c39fb760b43803c3ec00f8c26030000',
        0x143f12b: '4c29fb0f84d7000000',
        0x143f1ee: '488b34244885f60f84b5fdffff',
        0x143f200: 'ff150aee3204e9a5fdffff',
        0x143f420: '488d3d89a0ddfe488d157aac2204be25000000ff15cfec3204',
        0x143f451: '4c8d0538ac22044c89f74889de4c89fa4889d9ff1506ec3204',
    }
    for va, raw in controls.items():
        expect(va, bytes.fromhex(raw))
    expect(0x2194aa, b'/cham/')
    expect(0x2194b0, b"assertion failed: !arg.ends_with('/')")
    path = b'/home/ubuntu/hl/code_Mainnet/base/src/build_mode.rs'
    expect(0x200676, path)
    locations = {0x566a090: (32, 26), 0x566a0a8: (29, 17)}
    for va, (line, col) in locations.items():
        expect(va, struct.pack('<QQII', 0, len(path), line, col))
    rel = next(s for s in secs if s['name'] == '.rela.dyn')
    require(rel['type'] != 8 and rel['size'] % 24 == 0, 'Invalid relocations')
    bindings = {}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in locations:
            require(slot not in bindings, 'Duplicate scoped relocation')
            bindings[slot] = (info, addend)
    require(bindings == {va: (8, 0x200676) for va in locations}, 'Source relocation changed')

    def raw_record(va):
        return read(va, struct.unpack('<I', read(va, 4))[0] + 4).hex()

    reject_target = 0x143f12b + struct.unpack('<i', read(0x143f127, 4))[0]
    require(reject_target == 0x143f451, 'Signed-boundary destination changed')
    return dict(target_release='94', target_sha256=SHA256,
                coordinates='linked ELF virtual addresses, no runtime rebase',
                windows=[dict(start_va=hex(start), end_va_exclusive=hex(end), bytes=len(body),
                              body_hex=body.hex(), sha256=hashlib.sha256(body).hexdigest(),
                              fde_va=hex(f['fde']), fde_hex=raw_record(f['fde']),
                              cie_va=hex(f['cie']), cie_hex=raw_record(f['cie']))],
                controls={hex(k): v for k, v in controls.items()},
                source_locations=[dict(location_va=hex(k), path=path.decode(), line=v[0], column=v[1])
                                  for k, v in sorted(locations.items())],
                predicate_call=dict(call_va='0x143f009', target_va='0x1440df0',
                                    first_pointer_va='0x2194aa', first_length=6, first_bytes='/cham/'),
                signed_boundary_guard=dict(compare_va='0x143f120', jump_va='0x143f125',
                                           diagnostic_target=hex(reject_target),
                                           isolated_model_domain=256,
                                           isolated_rejected_bytes=[b for b in range(256) if signed_boundary_branch(b)]),
                observations=['a slice shorter than2 avoids the first-two-byte load; a double-dash prefix takes the iterator-loop route before the predicate call',
                              'only the nonzero predicate-result route reaches the final-slash guard; empty slices avoid that byte load',
                              'the final-slash diagnostic uses build_mode.rs:29:17',
                              'after the local split-position bounds check, CMP byte,0xc0 plus signed JL selects exactly0x80..0xbf; its diagnostic uses32:26'],
                unresolved=['iterator backend and complete argument admissibility',
                            'predicate helper semantics, full reverse/slash scanner, formatter and complete name extraction',
                            'validity of the original input as UTF8 and high-level BuildMode API'],
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
        print('Build-name guard evidence reproduces exactly.')
    else:
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
