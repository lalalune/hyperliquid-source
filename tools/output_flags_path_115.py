#!/usr/bin/env python3
"""Bind the path from node #115 output flags to the output setter's argument (twelfth stage).

The eleventh stage found that the flag reader 0x564d390 writes a 0x28-byte
struct (String at +0x0, write-* bytes at +0x18..+0x1e, then
disable-output-file-buffering +0x1f, batch-by-block +0x20,
stream-with-block-info +0x21, serve-evm-rpc +0x22, serve-info +0x23,
replica-cmds-style +0x24), and that the setter 0x51cf360 reads the same
flags one byte later. This tool binds the conversion between them in both
pollers that call the setter (0x2aeaef0 -> 0x2aec025 and 0x2cb6500 ->
0x2cb7645). In each:

1. the initial state copies the 0x28-byte argument at future +0x0 to +0x48;
2. the String goes to +0x78 and then +0x90; qword +0x60 (argument +0x18) and
   qword +0x68 (argument +0x20) and byte +0x6c (argument +0x24) are loaded;
3. on the branch where byte +0x38 is 2, a straight run of bytes builds the
   setter struct at +0x90: a constant 0 at +0xa8 (struct +0x18), the qword
   at +0xa9 (struct +0x19..+0x20), the low dword of the second qword at
   +0xb1 (struct +0x21..+0x24) and the style byte at +0xc8 (struct +0x38);
4. the 0x40-byte struct is copied +0x90 -> +0xd8 -> +0x118 -> stack ->
   +0xae8, and its first 0x28 bytes are copied to the stack slot passed as
   the setter's rsi.

So setter byte s = argument byte s - 1 for s in +0x19..+0x24, and setter
+0x18 is the constant 0 on this path. With the reader's offsets, setter
+0x23 is serve-evm-rpc and setter +0x24 (not read) is serve-info.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-output-flags-path-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SETTER, SETTER_SLOT = 0x51cf360, 0x64e7428
READER = 0x564d390
GET_FLAG, GET_STRING = 0x4e4c8e0, 0x4e4ca30
# (lea va, name, length, call va, callee, result va, result bytes, struct offset)
LOOKUPS = (
    (0x564d3a4, 'write-trades', 0x0c, 0x564d3b3, GET_FLAG, 0x564d3b8, '8844240e', '+0x18'),
    (0x564d3bc, 'write-fills', 0x0b, 0x564d3cb, GET_FLAG, 0x564d3d0, '8844240d', '+0x19'),
    (0x564d3d4, 'write-raw-book-diffs', 0x14, 0x564d3e3, GET_FLAG, 0x564d3e8, '8844240c', '+0x1a'),
    (0x564d3ec, 'write-order-statuses', 0x14, 0x564d3fb, GET_FLAG, 0x564d400, '8844240b', '+0x1b'),
    (0x564d404, 'write-misc-events', 0x11, 0x564d413, GET_FLAG, 0x564d418, '8844240a', '+0x1c'),
    (0x564d41c, 'write-hip3-oracle-updates', 0x19, 0x564d42b, GET_FLAG, 0x564d430, '88442409', '+0x1d'),
    (0x564d434, 'write-user-clearinghouse-states', 0x1f, 0x564d443, GET_STRING, None, None, '+0x0..+0x18'),
    (0x564d4a9, 'write-system-and-core-writer-actions', 0x24, 0x564d4b8, GET_FLAG, 0x564d4bd, '88442408', '+0x1e'),
    (0x564d4c1, 'disable-output-file-buffering', 0x1d, 0x564d4d0, GET_FLAG, 0x564d4d5, '88442407', '+0x1f'),
    (0x564d4d9, 'batch-by-block', 0x0e, 0x564d4e8, GET_FLAG, 0x564d4ed, '88442406', '+0x20'),
    (0x564d4f1, 'stream-with-block-info', 0x16, 0x564d500, GET_FLAG, 0x564d505, '4189c7', '+0x21'),
    (0x564d508, 'serve-evm-rpc', 0x0d, 0x564d517, GET_FLAG, 0x564d51c, '89c5', '+0x22'),
    (0x564d51e, 'serve-info', 0x0a, 0x564d52d, GET_FLAG, 0x564d532, '4189c5', '+0x23'),
    (0x564d535, 'replica-cmds-style', 0x12, 0x564d544, GET_STRING, None, None, '+0x24'),
)

# 0x564d5ad .. 0x564d628: write the output struct from the saved results
ASSEMBLY = (0x564d5ad, '4c8933488b4c241048894b080fb64c240a0fb6542409c1e20809ca0fb64c240e0fb674240d'
                       'c1e60809ce0fb64c240cc1e11009f10fb674240bc1e61809ce660f6ec6660fc4c2020fb64c2408'
                       '0fb6542407c1e20809ca660fc4c2034c897310660fd643180fb64c2406884b2044887b2140886b'
                       '2244886b23884324')
# 0x51cf383 .. 0x51cf401: the setter reads bytes +0x18..+0x23, sets the global, checks the pair
SETTER_READS = (0x51cf383, '0fb64618884424130fb646190fb66e1a440fb6661b0fb64e1c884c24170fb64e1d884c24160fb6'
                           '4e1e884c2415488b3e488b4e0848894c2418488b4e1048894c24200fb64e1f884c24140fb65621'
                           '0fb64e22440fb67623807e2000740a488b35a11b3101c6060148897c240884d20f84b5000000b3'
                           '0184c90f85b9160000')
SETTER_PANIC = 0x51d0aba
# (test va, test bytes, setter byte, je va, lea va, writer name va, writer name)
GATES = (
    (0x51cf40b, '84c0', '+0x19', 0x51cf412, 0x51cf418, 0x91fcc0, 'node_trades'),
    (0x51cf4cf, '4084ed', '+0x1a', 0x51cf4d2, 0x51cf4d8, 0x91fccb, 'node_fills'),
    (0x51cf742, '4584e4', '+0x1b', 0x51cf745, 0x51cf74b, 0x91fce7, 'node_raw_book_diffs'),
    (0x51cfe07, '807c241700', '+0x1c', 0x51cfe0c, 0x51cfe12, 0x91fcfa, 'node_order_statuses'),
    (0x51cfc14, '807c241600', '+0x1d', 0x51cfc19, 0x51cfc1f, 0x91fd0d, 'misc_events'),
    (0x51d0031, '807c241500', '+0x1e', 0x51d0036, 0x51d003c, 0x91fd18, 'hip3_oracle_updates'),
    (0x51d0262, '807c241400', '+0x1f', 0x51d0267, 0x51d026d, 0x91fd2b, 'system_and_core_writer_actions'),
)


# Byte runs identical in both pollers: (name, caller-1 va, caller-2 va, hex)
SHARED = (
    ('initial copy +0x0 -> +0x48', 0x2aeaf73, 0x2cb6583,
     '660f1003660f104b10660f114348660f114b58488b4b2048894b68'),
    ('String +0x48 -> +0x78; flag loads; style-2 branch', 0x2aeb5ad, 0x2cb6bcd,
     '4c8d7b78f30f6f4348f30f7f4378488b435848898388000000'
     '4c8b6b6066490f6ecdf30f7e53680fb66b6c807b38020f8428050000'),
    ('build struct at +0x90, copy to +0xd8 and +0x118', 0x2aebb0a, 0x2cb712a, None),
    ('lea r13, [rbx+0xae8]', 0x2aebde4, 0x2cb7404, '4c8dabe80a0000'),
    ('load +0x118 (0x40 bytes)', 0x2aebe97, 0x2cb74b7,
     'f30f6f8318010000f30f6f8b28010000f30f6f9338010000660f109b48010000'),
)
BUILD_LENGTH = 0x133   # 0x2aebb0a .. 0x2aebc3d (no jump, call or ret in objdump)
# The two build runs differ only in three scratch stack displacements (0x3e3/0x3ef/0x3e0
# against 0x733/0x73f/0x730), so each run is pinned by its SHA-256.
BUILD_SHA256 = {
    0x2aebb0a: '545b1317d2932620769ac60a72ce14d35cf9d11662154e559f60eeaa1367a78f',
    0x2cb712a: 'bfa79fa82d67a307ab8fe366746310e2e299f2577b560ba7d11678b3f8149069',
}
# Per-caller runs whose stack offsets differ: (va, hex)
STACK = {
    0x2aec025: (
        (0x2aebeb7, '660f299c2410040000660f7f942400040000660f7f8c24f0030000660f7f8424e0030000'),
        (0x2aebeed, '0f288424e0030000660f6f8c24f0030000660f6f942400040000660f289c2410040000'
                    '660f299c24d0030000660f7f9424c0030000660f7f8c24b00300000f298424a0030000'
                    '66410f115d30f3410f7f5520f3410f7f4d10410f114500'),
        (0x2aebfe9, '498b45204889842400040000f3410f6f4500f3410f6f4d10660f7f8c24f0030000'
                    '660f7f8424e00300004c8db3300b0000488db424e00300004c89f7ff15'),
    ),
    0x2cb7645: (
        (0x2cb74d7, '660f299c2460070000660f7f942450070000660f7f8c2440070000660f7f842430070000'),
        (0x2cb750d, '0f28842430070000660f6f8c2440070000660f6f942450070000660f289c2460070000'
                    '660f299c24d0030000660f7f9424c0030000660f7f8c24b00300000f298424a0030000'
                    '66410f115d30f3410f7f5520f3410f7f4d10410f114500'),
        (0x2cb7609, '498b45204889842450070000f3410f6f4500f3410f6f4d10660f7f8c2440070000'
                    '660f7f8424300700004c8db3300b0000488db424300700004c89f7ff15'),
    ),
}
# Fields read from pinned instructions in the build run (offset in run, size)
ARG_BASE = (0x2aeaf7c - 0x2aeaf73 + 4, 1)          # movupd [rbx+0x48], xmm0 -> 0x48
STRUCT_BASE = (0x2aebb3f - 0x2aebb0a + 3, 4)       # lea r13, [rbx+0x90] -> 0x90
LOADS = {                                          # in the flag-load run (from 0x2aeb5ad)
    'qword_a': (0x2aeb5c6 - 0x2aeb5ad + 3, 1),     # mov r13, [rbx+0x60]
    'qword_b': (0x2aeb5cf - 0x2aeb5ad + 4, 1),     # movq xmm2, [rbx+0x68]
    'style': (0x2aeb5d4 - 0x2aeb5ad + 3, 1),       # movzx ebp, byte [rbx+0x6c]
}
STORES = {                                         # in the build run (from 0x2aebb0a)
    'zero': (0x2aebb5c - 0x2aebb0a + 2, 4),        # mov byte [rbx+0xa8], 0
    'qword_a': (0x2aebb63 - 0x2aebb0a + 4, 4),     # movq [rbx+0xa9], xmm1
    'qword_b_low_dword': (0x2aebb6b - 0x2aebb0a + 4, 4),   # movd [rbx+0xb1], xmm2
    'style': (0x2aebb8f - 0x2aebb0a + 3, 4),       # mov [rbx+0xc8], bpl
}


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def relative(data, slot):
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if va == slot and info & 0xffffffff == 8:
                return addend
    return None


def field(raw, at):
    offset, size = at
    return int.from_bytes(raw[offset:offset + size], 'little')


def reader_offsets(data):
    """Flag name for each reader output byte, from the pinned lookups and struct writes."""
    fixed(data, ASSEMBLY[0], ASSEMBLY[1])
    names = {}
    for lea, name, length, call, callee, result, result_bytes, offset in LOOKUPS:
        target = rip_target(data, lea, b'\x48\x8d\x35', 7)
        if read_va(data, target, length) != name.encode() or read_va(data, lea + 7, 5) != b'\xba' + struct.pack('<I', length):
            raise ValueError(f'lookup {name} changed')
        if read_va(data, call, 1) != b'\xe8' or call + 5 + struct.unpack('<i', read_va(data, call + 1, 4))[0] != callee:
            raise ValueError(f'lookup call for {name} changed')
        if result is not None:
            fixed(data, result, result_bytes)
            names[int(offset[1:], 16)] = name
    return names


def setter_gates(data):
    fixed(data, SETTER_READS[0], SETTER_READS[1])
    gates = {}
    for test, test_bytes, byte, je, lea, name_va, name in GATES:
        fixed(data, test, test_bytes)
        if rip_target(data, lea, b'\x48\x8d\x05', 7) != name_va or read_va(data, name_va, len(name)) != name.encode():
            raise ValueError(f'gate {name} changed')
        gates[int(byte[1:], 16)] = name
    return gates


def bind(data):
    if relative(data, SETTER_SLOT) != SETTER:
        raise ValueError('setter slot changed')
    callers = {}
    for name, first, second, expect in SHARED:
        for va in (first, second):
            if expect is not None:
                fixed(data, va, expect)
    for va, digest in BUILD_SHA256.items():
        if hashlib.sha256(read_va(data, va, BUILD_LENGTH)).hexdigest() != digest:
            raise ValueError(f'build run at {va:#x} changed')
    for call, runs in STACK.items():
        for va, expect in runs:
            fixed(data, va, expect)
        if rip_target(data, call, b'\xff\x15', 6) != SETTER_SLOT:
            raise ValueError(f'setter call at {call:#x} changed')
        callers[hex(call)] = 'rsi -> 0x28-byte stack copy of +0xae8 (qword +0x20, two xmm words)'
    # The two style-2 branches land on the build runs.
    for je, run in ((0x2aeb5dc, 0x2aebb0a), (0x2cb6bfc, 0x2cb712a)):
        if rip_target(data, je, b'\x0f\x84', 6) != run:
            raise ValueError(f'branch at {je:#x} changed')

    initial = read_va(data, SHARED[0][1], 27)
    loads = read_va(data, SHARED[1][1], 53)
    build = read_va(data, 0x2aebb0a, BUILD_LENGTH)
    arg_base = field(initial, ARG_BASE)
    struct_base = field(build, STRUCT_BASE)
    load = {k: field(loads, v) - arg_base for k, v in LOADS.items()}
    store = {k: field(build, v) - struct_base for k, v in STORES.items()}

    # setter byte -> argument byte (None = constant zero); qword a is 8 bytes, dword of b is 4
    shift = {store['zero']: None}
    for i in range(8):
        shift[store['qword_a'] + i] = load['qword_a'] + i
    for i in range(4):
        shift[store['qword_b_low_dword'] + i] = load['qword_b'] + i
    reader = reader_offsets(data)
    gates = setter_gates(data)
    for byte, writer in gates.items():
        arg = shift[byte]
        if arg not in reader or reader[arg] != 'write-' + writer.removeprefix('node_').replace('_', '-'):
            raise ValueError(f'gate {writer} does not line up with the reader')
    setter_bytes = {hex(b): ('constant 0' if a is None else 'argument %s = %s' % (hex(a), reader.get(a, '?')))
                    for b, a in sorted(shift.items())}
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'setter_calls': callers,
        'argument_copy': 'future +0x0..+0x28 -> +0x48..+0x70 (initial state, base %s)' % hex(arg_base),
        'struct_base': hex(struct_base),
        'loads_from_argument': {k: hex(v) for k, v in load.items()},
        'stores_into_struct': {k: hex(v) for k, v in store.items()},
        'struct_copies': '+0x90 -> +0xd8 -> +0x118 (0x40 each, in the build run); +0x118 -> stack -> '
                         '+0xae8 (0x40); +0xae8 -> stack (0x28) -> setter rsi',
        'setter_bytes': setter_bytes,
        'gates_line_up': sorted(gates.values()),
        'style_byte': 'argument %s -> struct %s (past the 0x28 bytes passed to the setter)'
                      % (hex(load['style']), hex(store['style'])),
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
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
    print('setter +0x18 = %s; setter +0x23 = %s' % (result['setter_bytes']['0x18'], result['setter_bytes']['0x23']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
