#!/usr/bin/env python3
"""Bind the node #115 hyperliquid_data state files and the blocking abci state writer (34th stage).

Continues #5999 (linked abci state) and #6001 (periodic paths). #6001 found that
0x5942870 builds {root}/hyperliquid_data/{name}.{rmp|json} and that the step
passes flag 1 to 0x4e45a30, which runs 0x4e363c0 as a blocking call. This tool
binds:

1. the other two callers of 0x5942870: the wrapper 0x5942b40 (name in rdi,
   value in rsi, Location in rdx; path then 0x50de010) and 0x5a396d3 in
   0x5a39630; every name they pass is the static slice `visor_abci_state`;
2. the value writer 0x50de010: an `rmp` extension (3-byte compare) serialises
   through 0x51ae110 with config dword 0x01000400, any other extension through
   0x51adf60 with the two-byte indent "  "; both results go to the file writer
   slot 0x64e09e8 -> 0x15024a0;
3. 0x5a39630 (reached only through the relocation at 0x64b8b30): it builds a
   daily then hourly line writer named `visor_abci_states`, calls 0x5648400
   with `get_visor_state`, and writes the result to visor_abci_state.json
   through 0x50de010 (Location node/src/node.rs:914:42);
4. the blocking call chain of the step: 0x548604b passes edx 1 to 0x4e45a30,
   which calls 0x4e363c0; 0x4e363c0 calls 0x5a9dd40 (tokio
   "can call blocking only when running..." string) and the closure body
   0x4e4b3f0; 0x4e4b3f0 reads the box height (+0x28), serialises the box with
   0x5481900 under config 0x01000400, writes the bytes through slot 0x64e09e8
   (Location l1/src/abci/state.rs:195:17), measures CLOCK_MONOTONIC elapsed
   seconds (nanos / 1e9), logs one WARN line through template 0x43df63 and
   returns the byte Vec (cap, ptr, len) through its first argument.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import (RELATIVE, SHA256, TARGET, direct_calls, fixed, frame, read_va,
                                 relative_relocations, rip_target)

PACKET = ROOT / 'research/work-items/RE-008-hyperliquid-data-files-115'

PATH_FN = 0x5942870
WRAPPER = 0x5942b40
WRITER = 0x50de010
VISOR_LOOP = 0x5a39630
BLOCKING = 0x4e45a30
INNER = 0x4e363c0
CLOSURE = 0x4e4b3f0
BLOCK_IN_PLACE = 0x5a9dd40
FILE_WRITER = 0x15024a0
FILE_WRITER_SLOT = 0x64e09e8
NAME_RECORDS = (0x64aaf70, 0x64b7f70)
CONFIG = 0x01000400

FIXED = {
    # wrapper 0x5942b40: name in rdi moves to rsi for the path builder
    0x5942b4f: '4889fe',                    # mov rsi, rdi
    0x5942b52: '488d7c2408',                # lea rdi, [rsp+0x8]
    # value writer: extension compare against "rmp"
    0x50de0ff: 'b903000000',                # mov ecx, 3
    0x50de109: '84c0',                      # test al, al
    0x50de10b: '7471',                      # je 0x50de17e (not rmp -> json path)
    0x50de12f: 'c784249000000000040001',    # mov dword [rsp+0x90], 0x01000400
    0x50de1b9: '48c744244802000000',        # mov qword [rsp+0x48], 2 (indent length)
    # step: blocking flag
    0x5486043: '4c89f6',                    # mov rsi, r14
    0x5486046: 'ba01000000',                # mov edx, 1
    # closure body 0x4e4b3f0
    0x4e4b412: 'bf01000000',                # mov edi, 1 (CLOCK_MONOTONIC)
    0x4e4b421: '498b442428',                # mov rax, [r12+0x28] (height)
    0x4e4b461: 'c744241800040001',          # mov dword [rsp+0x18], 0x01000400
    0x4e4b5be: '48c78424a000000016000000',  # time format length 22
    0x4e4b60d: '48c74424182b000000',        # message slice length 0x2b
    0x4e4b6d4: '488b8c24c8000000',          # mov rcx, [rsp+0xc8] (out pointer)
    0x4e4b6dc: '488919',                    # mov [rcx], rbx       (cap)
    0x4e4b6df: '488b442420',                # mov rax, [rsp+0x20]
    0x4e4b6e4: '48894108',                  # mov [rcx+0x8], rax   (ptr)
    0x4e4b6e8: '4c896110',                  # mov [rcx+0x10], r12  (len)
    # visor loop 0x5a39630
    0x5a39658: 'ba11000000',                # mov edx, 17 (len "visor_abci_states")
    0x5a396b0: 'b90f000000',                # mov ecx, 15 (len "get_visor_state")
}
CALLS = (
    # (call va, target)
    (0x5942b57, PATH_FN),
    (0x5942b6f, WRITER),
    (0x5443a82, WRAPPER),
    (0x59ec380, WRAPPER),
    (0x5a08250, WRAPPER),
    (0x5a08ab0, WRAPPER),
    (0x5a396d3, PATH_FN),
    (0x5a396c4, 0x5648400),
    (0x5a396ef, WRITER),
    (0x50de104, 0x159fca0),
    (0x50de152, 0x51ae110),
    (0x50de1d8, 0x51adf60),
    (0x548604b, BLOCKING),
    (0x4e45ac9, INNER),
    (0x4e45b69, INNER),
    (0x4e3642f, BLOCK_IN_PLACE),
    (0x4e3649d, CLOSURE),
    (0x4e36569, CLOSURE),
    (0x4e4b417, 0x5c842e0),
    (0x4e4b480, 0x5481900),
    (0x4e4b4ec, 0x5c842e0),
    (0x4e4b51b, 0x5c84210),
)
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5443a71, b'\x48\x8d\x3d', 7, 0x64aaf70),
    (0x5443a78, b'\x48\x8d\x15', 7, 0x64aaf80),
    (0x59ec36d, b'\x48\x8d\x3d', 7, 0x64b7f70),
    (0x59ec374, b'\x48\x8d\x15', 7, 0x64b8a50),
    (0x5a0823f, b'\x48\x8d\x3d', 7, 0x64b7f70),
    (0x5a08246, b'\x48\x8d\x15', 7, 0x64b7f80),
    (0x5a08a9f, b'\x48\x8d\x3d', 7, 0x64b7f70),
    (0x5a08aa6, b'\x48\x8d\x15', 7, 0x64b7f80),
    (0x5a396cc, b'\x48\x8d\x35', 7, 0x64b7f70),
    (0x5a39649, b'\x48\x8d\x35', 7, 0x93b0d0),
    (0x5a396bd, b'\x48\x8d\x15', 7, 0x93b0e1),
    (0x5a396e8, b'\x48\x8d\x0d', 7, 0x64b8b38),
    (0x5a3965d, b'\xff\x15', 6, 0x64e0f98),
    (0x5a39670, b'\xff\x15', 6, 0x64e0fa0),
    (0x50de0f8, b'\x48\x8d\x15', 7, 0x4659e5),
    (0x50de1ad, b'\x48\x8d\x05', 7, 0x91b3c4),
    (0x50de21b, b'\xff\x15', 6, FILE_WRITER_SLOT),
    (0x4e4b4be, b'\x4c\x8d\x05', 7, 0x649da28),
    (0x4e4b4d3, b'\xff\x15', 6, FILE_WRITER_SLOT),
    (0x4e4b559, b'\xf2\x0f\x5e\x0d', 8, 0x458d50),
    (0x4e4b5af, b'\x48\x8d\x05', 7, 0x91872a),
    (0x4e4b601, b'\x48\x8d\x05', 7, 0x91875b),
    (0x4e4b6a3, b'\x48\x8d\x3d', 7, 0x43df63),
    (0x5a9de33, b'\x48\x8d\x05', 7, 0x93bdd4),
)
RELOCATIONS = {
    FILE_WRITER_SLOT: FILE_WRITER,
    0x64e0f98: 0x1546700,   # daily line writer (#5872)
    0x64e0fa0: 0x1546000,   # hourly line writer (#5872)
    0x64b8b30: VISOR_LOOP,
}
STRINGS = {
    0x4659e5: b'rmp',
    0x91b3c4: b'  ',
    0x93b0d0: b'visor_abci_states',
    0x93b0e1: b'get_visor_state',
    0x91872a: b'%Y-%m-%dT%H:%M:%S%.3fZ',
    0x91875b: b'serialized abci state',
    0x93bdd4: b'can call blocking only when running',
}
LOCATIONS = {
    # record va: (file, line, column)
    0x64aaf80: ('node/src/node.rs', 659, 50),
    0x64b8a50: ('node/src/node.rs', 659, 50),
    0x64b7f80: ('l1/src/abci/engine.rs', 316, 46),
    0x64b8b38: ('node/src/node.rs', 914, 42),
    0x649da28: ('l1/src/abci/state.rs', 195, 17),
}


def str_record(data, rel, va):
    """A (ptr, len) slice record whose pointer word is filled by an R_X86_64_RELATIVE entry."""
    ptr = rel.get(va)
    if ptr is None:
        raise ValueError(f'record {va:#x} has no relocation')
    length = struct.unpack('<Q', read_va(data, va + 8, 8))[0]
    return read_va(data, ptr, length)


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS:
        if call_target(data, va) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, expect in STRINGS.items():
        if read_va(data, va, len(expect)) != expect:
            raise ValueError(f'string at {va:#x} changed')
    for va in NAME_RECORDS:
        if str_record(data, rel, va) != b'visor_abci_state':
            raise ValueError(f'name record {va:#x} changed')
    for va, (name, line, col) in LOCATIONS.items():
        if str_record(data, rel, va) != name.encode() or struct.unpack('<II', read_va(data, va + 16, 8)) != (line, col):
            raise ValueError(f'Location {va:#x} changed')
    if struct.unpack('<d', read_va(data, 0x458d50, 8))[0] != 1e9:
        raise ValueError('nanosecond divisor changed')
    template = read_va(data, 0x43df63, 56)
    if b' WARN >>> ' not in template or b'[height: ' not in template or b'[elapsed: ' not in template:
        raise ValueError('log template changed')

    path_callers = direct_calls(data, PATH_FN)
    wrapper_callers = direct_calls(data, WRAPPER)
    if wrapper_callers != [0x5443a82, 0x59ec380, 0x5a08250, 0x5a08ab0]:
        raise ValueError('wrapper caller census changed')
    if direct_calls(data, VISOR_LOOP) or direct_calls(data, CLOSURE) != [0x4e3649d, 0x4e36569]:
        raise ValueError('closure or visor loop census changed')
    if direct_calls(data, BLOCKING) != [0x548604b] or direct_calls(data, INNER) != [0x4e45ac9, 0x4e45b69]:
        raise ValueError('blocking census changed')
    serializer_callers = direct_calls(data, 0x5481900)

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'path_builder': {
            'fn': hex(PATH_FN),
            'direct_callers': [hex(v) for v in path_callers],
            'wrapper': '%s (rdi name -> rsi at 0x5942b4f, path at 0x5942b57, write 0x50de010 at 0x5942b6f)' % hex(WRAPPER),
            'wrapper_callers': {hex(v): hex(frame(fdes, v)) for v in wrapper_callers},
            'names_passed': 'visor_abci_state (records %s) at every wrapper call and at 0x5a396d3'
                            % ', '.join(hex(v) for v in NAME_RECORDS),
            'wrapper_locations': {hex(k): '%s:%d:%d' % v for k, v in LOCATIONS.items() if k != 0x649da28},
        },
        'value_writer': {
            'fn': hex(WRITER),
            'rmp': 'extension equals "rmp" (0x4659e5, 3 bytes, compare 0x159fca0) -> 0x51ae110 with config %s'
                   % hex(CONFIG),
            'other': 'else -> 0x51adf60 with a 0x80-byte buffer and indent "  " (0x91b3c4, 2 bytes)',
            'write': 'slot %s -> %s' % (hex(FILE_WRITER_SLOT), hex(FILE_WRITER)),
        },
        'visor_loop': {
            'fn': hex(VISOR_LOOP),
            'reached_through': 'R_X86_64_RELATIVE at 0x64b8b30; no direct calls',
            'line_writer': 'visor_abci_states (17 bytes) via daily slot 0x64e0f98 then hourly slot 0x64e0fa0',
            'step': '0x5648400 with get_visor_state (15 bytes), then hyperliquid_data/visor_abci_state path, '
                    'then 0x50de010 with Location node/src/node.rs:914:42',
        },
        'blocking_chain': {
            'step_call': '0x548604b: 0x4e45a30 with edx 1',
            '0x4e45a30': 'calls 0x4e363c0 at 0x4e45ac9 and 0x4e45b69',
            '0x4e363c0': 'calls 0x5a9dd40 (string "can call blocking only when running" at 0x5a9de33) and '
                         'the closure 0x4e4b3f0 at 0x4e3649d / 0x4e36569',
        },
        'closure': {
            'fn': hex(CLOSURE),
            'clock': 'CLOCK_MONOTONIC (edi 1) via 0x5c842e0 before and after; elapsed via 0x5c84210; '
                     'seconds + nanos / 1e9',
            'height': '[box+0x28] at 0x4e4b421',
            'serialise': '0x5481900 into an empty Vec with config %s (same dword as the rmp path of 0x50de010)'
                         % hex(CONFIG),
            'serialiser_direct_callers': [hex(v) for v in serializer_callers],
            'write': 'slot %s with Location l1/src/abci/state.rs:195:17' % hex(FILE_WRITER_SLOT),
            'log': 'template 0x43df63 (WARN, height, elapsed); time format %Y-%m-%dT%H:%M:%S%.3fZ; '
                   'message slice 0x91875b len 0x2b, first 21 bytes "serialized abci state"',
            'returns': 'Vec (cap, ptr, len) stored at [out], [out+8], [out+0x10]',
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print('path callers=%d wrapper callers=%d' % (len(result['path_builder']['direct_callers']),
                                                   len(result['path_builder']['wrapper_callers'])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
