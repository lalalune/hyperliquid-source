#!/usr/bin/env python3
"""Bind the node #115 abci_digest_quorum line writer and its one record (52nd stage).

Continues the abci digest packets (#6023 check, #6024 BLAKE3, #6027 slots,
#6029/#6030 tree encoding, #6031 hex callers) and the line writer owners
packet (#5874), which listed `abci_digest_quorum` as one of the fixed writer
names (daily constructor call 0x5a6c42c). This tool binds:

1. creation in 0x5a6bfb0: daily constructor (slot 0x64e0f98 -> 0x1546700)
   with the 18-byte name at 0x93a6d8, hourly conversion (slot 0x64e0fa0 ->
   0x1546000) into rsp+0xa0, and the same pair for `abci_hashes` (0x93a6ea,
   11 bytes) into rsp+0xe20; no flush byte store follows either conversion;
2. placement: the two 0xb0-byte writers are copied to rsp+0x14c0 and
   rsp+0x1570, after the 0x260-byte observer at rsp+0x1260, inside the
   0x438-byte engine value that starts at rsp+0x1240 (copied whole to
   rsp+0x5508); so engine value +0x20 = observer, +0x280 = abci_digest_quorum
   writer, +0x330 = abci_hashes writer;
3. the only two calls of the writer function 0x4e3a020: in the step wrappers
   0x5a04e40 (A, 0x5a05c5e) and 0x5a06600 (B, 0x5a0748e); each passes
   engine value +0x280, a wall-clock time from slot 0x64e0990 (0x1629690),
   and a 0x28-byte record built from the 0x68-byte entry: entry +0x48..+0x68
   (the quorum digest #6023 compares) at record +0x0 and entry +0x0 (the
   height key) at record +0x20;
4. the write: rotation sink slot 0x64e0f80 (0x1546570), open slot 0x64e0020
   (0x14c3b30) when the writer has a path, serialiser 0x50e6fe0 -> 0x537d7b0
   ('{', "height" from record +0x20, "d" from record +0x0, '}'), '\\n', then
   0x14c37f0; the extra flush runs only when writer +0xaa and the global byte
   behind slot 0x64e0f88 (0x64ffe50) are both set;
5. the digest field: 0x5073b20 -> 0x4e1c250 with capacity 0x42 and length
   0x20, which calls the hex slot 0x64e4d08 (0x2eabb50) with trim 0, so the
   value is a quoted "0x" + 64 lowercase hex string.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, frame, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-digest-quorum-log-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

BUILDER = 0x5a6bfb0
WRAP_A, WRAP_B = 0x5a04e40, 0x5a06600
WRITE = 0x4e3a020
SERIALISE, RECORD = 0x50e6fe0, 0x537d7b0
DIGEST_FIELD, HEX_WRAP = 0x5073b20, 0x4e1c250

RELOCATIONS = {
    0x64e0f98: 0x1546700,   # daily writer constructor
    0x64e0fa0: 0x1546000,   # hourly conversion
    0x64e0990: 0x1629690,   # wall clock
    0x64e0f80: 0x1546570,   # rotation sink
    0x64e0020: 0x14c3b30,   # liner open
    0x64e0f88: 0x64ffe50,   # global flush byte
    0x64e4d08: 0x2eabb50,   # 0x-prefixed hex encoder
}
STRINGS = {
    0x93a6d8: b'abci_digest_quorum',
    0x93a6ea: b'abci_hashes',
    0x924ed9: b'height',
    0x9247d0: b'd',
}
FIXED = {
    # builder 0x5a6bfb0: names, hourly outputs, copies into the engine value
    0x5a6c427: 'ba12000000',              # mov edx, 18
    0x5a6c432: '488dbc24a0000000',        # lea rdi, [rsp+0xa0]   (hourly out, quorum)
    0x5a6c43a: '488db424b0020000',        # lea rsi, [rsp+0x2b0]  (daily writer)
    0x5a6c457: 'ba0b000000',              # mov edx, 11
    0x5a6c462: '488dbc24200e0000',        # lea rdi, [rsp+0xe20]  (hourly out, hashes)
    0x5a6c4e8: '488dbc2400020000',        # lea rdi, [rsp+0x200]
    0x5a6c4f0: '488db424a0000000',        # lea rsi, [rsp+0xa0]
    0x5a6c4f8: 'bab0000000',              # mov edx, 0xb0
    0x5a6c500: '488dbc2450010000',        # lea rdi, [rsp+0x150]
    0x5a6c508: '488db424200e0000',        # lea rsi, [rsp+0xe20]
    0x5a6c547: '488dbc2460120000',        # lea rdi, [rsp+0x1260] (observer, engine +0x20)
    0x5a6c557: 'ba60020000',              # mov edx, 0x260
    0x5a6c55f: '488dbc24c0140000',        # lea rdi, [rsp+0x14c0] (engine +0x280)
    0x5a6c567: '488db42400020000',        # lea rsi, [rsp+0x200]  (quorum writer)
    0x5a6c56f: 'bab0000000',
    0x5a6c577: '488dbc2470150000',        # lea rdi, [rsp+0x1570] (engine +0x330)
    0x5a6c57f: '488db42450010000',        # lea rsi, [rsp+0x150]  (hashes writer)
    0x5a6c587: 'bab0000000',
    0x5a6c5c3: '488dbc2408550000',        # lea rdi, [rsp+0x5508]
    0x5a6c5cb: '488db42440120000',        # lea rsi, [rsp+0x1240] (engine value base)
    0x5a6c5d3: 'ba38040000',              # mov edx, 0x438
    # wrapper A: per-entry record and call
    0x5a05c14: '498d9c2480020000',        # lea rbx, [r12+0x280]
    0x5a05c36: '498b4500',                # mov rax, [r13]        (height key)
    0x5a05c3a: '410f104558',              # movups xmm0, [r13+0x58]
    0x5a05c3f: '0f29442420',              # movaps [rsp+0x20], xmm0
    0x5a05c44: 'f3410f6f4548',            # movdqu xmm0, [r13+0x48]
    0x5a05c4a: '660f7f442410',            # movdqa [rsp+0x10], xmm0
    0x5a05c50: '4889442430',              # mov [rsp+0x30], rax   (record +0x20)
    0x5a05c55: '4889df',                  # mov rdi, rbx
    0x5a05c63: '4983c568',                # add r13, 0x68
    # wrapper B: same shape
    0x5a07442: '498d9f80020000',          # lea rbx, [r15+0x280]
    0x5a07466: '498b4500',
    0x5a0746a: '410f104558',
    0x5a0746f: '0f29442430',
    0x5a07474: 'f3410f6f4548',
    0x5a0747a: '660f7f442420',
    0x5a07480: '4889442440',              # mov [rsp+0x40], rax   (record +0x20)
    0x5a07485: '4889df',
    # writer 0x4e3a020: extra flush gate
    0x4e3a176: '4180beaa00000000',        # cmp byte [r14+0xaa], 0
    0x4e3a17e: '7437',                    # je  exit
    0x4e3a187: '0fb600',                  # movzx eax, byte [rax] (global flush byte)
    # serialiser: newline then line write
    0x50e70db: 'c604030a',                # mov byte [rbx+rax], '\n'
    # record serialiser 0x537d7b0
    0x537d7d0: 'c604017b',                # '{'
    0x537d7e7: '488d4b20',                # lea rcx, [rbx+0x20]   (height value)
    0x537d7f7: 'ba06000000',              # mov edx, 6            ("height")
    0x537d819: 'ba01000000',              # mov edx, 1            ("d")
    0x537d81e: '4889d9',                  # mov rcx, rbx          (digest value)
    0x537d850: 'c604307d',                # '}'
    # digest field: 32 bytes into 66 hex characters, no trim
    0x5073be9: 'be42000000',              # mov esi, 0x42
    0x5073bee: 'b920000000',              # mov ecx, 0x20
    0x4e1c25d: '4531c0',                  # xor r8d, r8d          (trim 0)
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x5a6c418, b'\x48\x8d\x35', 7, 0x93a6d8),
    (0x5a6c42c, b'\xff\x15', 6, 0x64e0f98),
    (0x5a6c442, b'\xff\x15', 6, 0x64e0fa0),
    (0x5a6c448, b'\x48\x8d\x35', 7, 0x93a6ea),
    (0x5a6c45c, b'\xff\x15', 6, 0x64e0f98),
    (0x5a6c472, b'\xff\x15', 6, 0x64e0fa0),
    (0x5a05c24, b'\x4c\x8b\x3d', 7, 0x64e0990),
    (0x5a05c5e, b'\xe8', 5, WRITE),
    (0x5a07451, b'\x4c\x8b\x3d', 7, 0x64e0990),
    (0x5a0748e, b'\xe8', 5, WRITE),
    (0x4e3a060, b'\xff\x15', 6, 0x64e0f80),
    (0x4e3a0e3, b'\xff\x15', 6, 0x64e0020),
    (0x4e3a15c, b'\xe8', 5, SERIALISE),
    (0x4e3a180, b'\x48\x8b\x05', 7, 0x64e0f88),
    (0x50e702e, b'\xe8', 5, RECORD),
    (0x50e70f0, b'\xe8', 5, 0x14c37f0),
    (0x537d7eb, b'\x48\x8d\x35', 7, 0x924ed9),
    (0x537d80d, b'\x48\x8d\x35', 7, 0x9247d0),
    (0x537d821, b'\xe8', 5, DIGEST_FIELD),
    (0x5073bf9, b'\xe8', 5, HEX_WRAP),
    (0x4e1c260, b'\xff\x15', 6, 0x64e4d08),
)


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, raw in STRINGS.items():
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'string at {va:#x} changed')

    write_calls = direct_calls(data, WRITE)
    if write_calls != [0x5a05c5e, 0x5a0748e]:
        raise ValueError('writer call census changed')
    if [frame(fdes, v) for v in write_calls] != [WRAP_A, WRAP_B]:
        raise ValueError('writer callers moved')
    if frame(fdes, 0x5a6c42c) != BUILDER:
        raise ValueError('builder moved')
    if direct_calls(data, SERIALISE) != [0x4e3a15c] or direct_calls(data, RECORD) != [0x50e702e]:
        raise ValueError('serialiser census changed')
    # no flush-byte store between the conversions and the copies (#5874 pattern: mov byte [..+0xaa], 1)
    span = read_va(data, 0x5a6c448, 0x5a6c4e8 - 0x5a6c448)
    if b'\xaa\x00\x00\x00\x01' in span:
        raise ValueError('a flush byte store appeared')

    engine = 0x1240
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'creation': {
            'builder': hex(BUILDER),
            'abci_digest_quorum': 'daily 0x5a6c42c (name 0x93a6d8, 18 bytes) -> hourly 0x5a6c442 into rsp+0xa0',
            'abci_hashes': 'daily 0x5a6c45c (name 0x93a6ea, 11 bytes) -> hourly 0x5a6c472 into rsp+0xe20',
            'flush_byte_set': False,
        },
        'engine_value': {
            'base': 'rsp+%#x, 0x438 bytes copied to rsp+0x5508' % engine,
            'observer': '+%#x' % (0x1260 - engine),
            'abci_digest_quorum_writer': '+%#x' % (0x14c0 - engine),
            'abci_hashes_writer': '+%#x' % (0x1570 - engine),
        },
        'writes': {
            'function': hex(WRITE),
            'calls': {hex(v): hex(frame(fdes, v)) for v in write_calls},
            'per_entry': 'time = wall clock (slot 0x64e0990 -> 0x1629690); record +0x0..+0x20 = entry '
                         '+0x48..+0x68 (quorum digest), record +0x20 = entry +0x0 (height key); entries are '
                         '0x68 bytes (add r13, 0x68)',
            'path': 'rotation sink 0x1546570, open 0x14c3b30 when the writer has a path',
            'extra_flush': 'only if writer +0xaa and global byte 0x64ffe50 are both non-zero',
        },
        'line': {
            'serialiser': '%s -> %s' % (hex(SERIALISE), hex(RECORD)),
            'format': '{"height":<u64>,"d":"0x<64 lowercase hex>"}\\n',
            'digest_field': '%s -> %s: capacity 0x42, length 0x20, trim 0, hex slot 0x64e4d08' % (
                hex(DIGEST_FIELD), hex(HEX_WRAP)),
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
    print('writer calls=%s' % ','.join(result['writes']['calls']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
