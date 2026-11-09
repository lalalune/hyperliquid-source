#!/usr/bin/env python3
"""Bind node #115 output command-line flags to their struct bytes (eleventh stage).

Continues the observer and line-writer packets. The tenth stage found that
the setter 0x51cf360 sets the global extra-flush byte 0x64ffe50 when its
argument byte +0x20 is set, and panics when bytes +0x21 and +0x22 are both
set. This tool binds:

1. the flag reader 0x564d390 (slot 0x64ebcb8; called at 0x56550de for the
   `run-non-validator` subcommand, tag 2, and at 0x56551e9 for
   `run-validator`, tag 3): it looks up 14 long names by pointer and length,
   12 through 0x4e4c8e0 (byte result) and 2 through 0x4e4ca30 (string
   result), and stores each result at a fixed offset of its output struct;
2. the `replica-cmds-style` value match: "actions" -> 0,
   "actions-and-responses" -> 1, "recent-actions" -> 2, else a panic;
3. the setter's byte reads and the seven writer names it gates with bytes
   +0x19 .. +0x1f; with +0x20 (global flush) and +0x21/+0x22 (the
   batch_by_block / stream_with_block_info panic) the setter's order matches
   the reader's order shifted by one byte.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-output-flags-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

READER, READER_SLOT = 0x564d390, 0x64ebcb8
SETTER, SETTER_SLOT = 0x51cf360, 0x64e7428
GET_FLAG, GET_STRING = 0x4e4c8e0, 0x4e4ca30
GLOBAL_SLOT = 0x64e0f88
PANIC_TEXT = (0x91fd5f, b'cannot set both batch_by_block and stream_with_block_info')
SUBCOMMANDS = (
    # (call va, tag stored after it, name evidence)
    (0x56550de, 2, 'run-non-validator'),
    (0x56551e9, 3, 'run-validator'),
)

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
# packed qword at +0x18: byte i comes from these saved-result slots
PACKED = ('[rsp+0xe]', '[rsp+0xd]', '[rsp+0xc]', '[rsp+0xb]', '[rsp+0xa]', '[rsp+0x9]', '[rsp+0x8]', '[rsp+0x7]')
# 0x564d56c .. 0x564d5ad: replica-cmds-style 7- and 14-byte matches
STYLE = (0x564d56c, 'b9616374693308ba696f6e7333500309ca0f85e600000031c0eb2648b9726563656e742d61483308'
                    '48ba2d616374696f6e7348335006b0024809ca0f85bc000000')
STYLE_21 = ((0x564d64b, 0x450640), (0x564d643, 0x454130))   # pcmpeqb constants, 16 bytes each, overlap 5

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


def slot_calls(data, slot):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    code, base = data[sec['offset']:sec['offset'] + sec['size']], sec['address']
    return [base + m.start() for m in re.finditer(rb'\xff\x15', code)
            if base + m.start() + 6 + struct.unpack_from('<i', code, m.start() + 2)[0] == slot]


def bind(data):
    if relative(data, READER_SLOT) != READER or relative(data, SETTER_SLOT) != SETTER:
        raise ValueError('slot relocation changed')
    reader_calls = slot_calls(data, READER_SLOT)
    if reader_calls != [v for v, _, _ in SUBCOMMANDS]:
        raise ValueError('reader call census changed')
    fixed(data, 0x56550e4, '48c70302000000')                     # mov qword [rbx], 2
    fixed(data, 0x56551ef, '48c70303000000')                     # mov qword [rbx], 3
    fixed(data, 0x5654e03, '48b972756e2d76616c69')               # "run-vali"
    fixed(data, 0x5654e10, '48ba616c696461746f72')               # "alidator" at +5
    name2 = (rip_target(data, 0x56550ae, b'\x66\x0f\x74\x05', 8), rip_target(data, 0x56550b6, b'\x66\x0f\x74\x0d', 8))
    run_non_validator = read_va(data, name2[0], 16) + read_va(data, name2[1], 1)
    if run_non_validator != b'run-non-validator' or read_va(data, name2[1] + 1, 15) != bytes(15):
        raise ValueError('subcommand name changed')

    lookups = []
    for lea, name, length, call, callee, result, result_hex, offset in LOOKUPS:
        target = rip_target(data, lea, b'\x48\x8d\x35', 7)
        if read_va(data, target, length) != name.encode():
            raise ValueError(f'flag name at {lea:#x} changed')
        fixed(data, lea + 7, 'ba' + struct.pack('<I', length).hex())
        if rip_target(data, call, b'\xe8', 5) != callee:
            raise ValueError(f'lookup call at {call:#x} changed')
        if result is not None:
            fixed(data, result, result_hex)
        lookups.append({'name': name, 'name_va': hex(target), 'lookup': hex(callee), 'offset': offset})
    fixed(data, ASSEMBLY[0], ASSEMBLY[1])
    fixed(data, STYLE[0], STYLE[1])
    lo = read_va(data, rip_target(data, STYLE_21[0][0], b'\x66\x0f\x74\x05', 8), 16)
    hi = read_va(data, rip_target(data, STYLE_21[1][0], b'\x66\x0f\x74\x0d', 8), 16)
    if lo + hi[11:] != b'actions-and-responses':
        raise ValueError('replica-cmds-style value changed')

    fixed(data, SETTER_READS[0], SETTER_READS[1])
    if rip_target(data, 0x51cf3e0, b'\x48\x8b\x35', 7) != GLOBAL_SLOT:
        raise ValueError('global slot changed')
    if rip_target(data, SETTER_PANIC, b'\x48\x8d\x3d', 7) != PANIC_TEXT[0] \
            or read_va(data, PANIC_TEXT[0], len(PANIC_TEXT[1])) != PANIC_TEXT[1]:
        raise ValueError('setter panic changed')
    gates = []
    for test, test_hex, offset, je, lea, name_va, name in GATES:
        fixed(data, test, test_hex)
        if read_va(data, je, 2) != b'\x0f\x84' or je + 6 != lea:
            raise ValueError(f'gate branch at {je:#x} changed')
        if rip_target(data, lea, b'\x48\x8d\x05', 7) != name_va or read_va(data, name_va, len(name)) != name.encode():
            raise ValueError(f'writer name at {lea:#x} changed')
        gates.append({'setter_byte': offset, 'test': hex(test), 'writer_name': name})

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'reader': {
            'fn': hex(READER), 'slot': hex(READER_SLOT),
            'callers': [{'call': hex(v), 'tag': t, 'subcommand': s} for v, t, s in SUBCOMMANDS],
            'lookups': lookups,
            'packed_qword_plus_0x18_bytes_from': list(PACKED),
            'replica_cmds_style': {'actions': 0, 'actions-and-responses': 1, 'recent-actions': 2, 'other': 'panic'},
        },
        'setter': {
            'fn': hex(SETTER), 'slot': hex(SETTER_SLOT),
            'reads': '+0x0, +0x8, +0x10 (qwords) and bytes +0x18 .. +0x23',
            'global_flush': '+0x20 != 0 -> mov byte [slot %s], 1 at 0x51cf3e7' % hex(GLOBAL_SLOT),
            'pair_panic': '+0x21 and +0x22 both set -> %s %r' % (hex(SETTER_PANIC), PANIC_TEXT[1].decode()),
            'gates': gates,
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
    print(f"lookups={len(result['reader']['lookups'])} gates={len(result['setter']['gates'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
