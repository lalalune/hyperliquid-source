#!/usr/bin/env python3
"""Bind where the node #115 output setter's result goes, and the second parent future (14th stage).

Continues #5892 and #5902. The setter 0x51cf360 (slot 0x64e7428) writes a
0xb70-byte result whose +0xae0 and +0xb18 hold the two optional values built
from setter byte +0x18. This tool binds:

1. the result's path: both pollers (0x2aeaef0, 0x2cb6500) call the setter with
   rdi = state +0xb30, later copy 0xb70 bytes from that state offset
   (r12 = rbx, the state) to the stack and pass them as rsi through slot
   0x64e7440 to 0x5a6bfb0; 0x5a6bfb0 copies them again (0xb70) and passes
   them as rsi to 0x548ce30; 0x548ce30 copies them to rsp+0x7e0, which is
   +0x7c0 of the 0x1700-byte block at rsp+0x20, copies that block to
   rsp+0x1720, and boxes 0x4e38 bytes from rsp+0x1720. So setter +0xae0 and
   +0xb18 sit at +0x12a0 and +0x12d8 of that 0x4e38-byte box;
2. the second parent future 0x2cde430: it calls 0x2b7b640 (rdi = rsp+0x410),
   rejects tag 0x10, copies the first 0x40 bytes to +0xc0, switches on
   [+0xc0] - 2 through table 0x60bfc0 (tag 2 -> 0x2cde67c, tag 3 ->
   0x2cdf519), and both cases copy +0xc8..+0xf0 to +0x220..+0x248, store mode
   byte 2 or 1 at +0x248 and call the poller 0x2cb6500 with rdi = +0x220;
3. the tagged value's origin on that path: 0x2b7b640 formats the command
   name `hl-node`, maps an error result (0x8000000000000001) to tag 0x10, and
   otherwise calls 0x564cce0 (slot 0x64e73c8) and copies its 0x98-byte
   result to rbx; 0x564cce0 calls the subcommand matcher 0x5654bf0 (slot
   0x64ebcb0) with rdi = rsp+0x20, rejects tag 0x10, and copies rsp+0x20..
   +0x98 to rbx+0x0..+0x78; the matcher stores tag 2 or 3 at [rbx] with
   rbx = rdi after calling the reader with rdi = rbx+0x8 (#5902).

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-output-setter-consumers-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

SETTER_SLOT, SETTER = 0x64e7428, 0x51cf360
HANDOFF_SLOT, HANDOFF = 0x64e7440, 0x5a6bfb0
CONSUMER = 0x548ce30
MEMCPY_SLOT, ALLOC_SLOT = 0x64df508, 0x64df480
PARENT, POLLER = 0x2cde430, 0x2cb6500
CLI, CONVERT_SLOT, CONVERT = 0x2b7b640, 0x64e73c8, 0x564cce0
MATCHER_SLOT, MATCHER, READER_SLOT = 0x64ebcb0, 0x5654bf0, 0x64ebcb8
TABLE = 0x60bfc0
NAME = (0x92a890, b'hl-node')
RESULT_SIZE, BLOCK_OFFSET, BOX_SIZE = 0xb70, 0x7c0, 0x4e38
OPTION_OFFSETS = (0xae0, 0xb18)

FIXED = {
    # poller 0x2aeaef0: setter call and later hand-off of the result
    0x2aec013: '4c8db3300b0000',        # lea r14, [rbx+0xb30]
    0x2aec022: '4c89f7',                # mov rdi, r14
    0x2aec369: '4989dc',                # mov r12, rbx
    0x2aec3c2: '498db424300b0000',      # lea rsi, [r12+0xb30]
    0x2aec3ca: '4c8db424e0030000',      # lea r14, [rsp+0x3e0]
    0x2aec3d2: 'ba700b0000',            # mov edx, 0xb70
    0x2aec3d7: '4c89f7',                # mov rdi, r14
    0x2aec3ec: '4c89f6',                # mov rsi, r14
    # poller 0x2cb6500: the same
    0x2cb7633: '4c8db3300b0000',        # lea r14, [rbx+0xb30]
    0x2cb7989: '4989dc',                # mov r12, rbx
    0x2cb79e2: '498db424300b0000',      # lea rsi, [r12+0xb30]
    0x2cb79ea: '4c8db42430070000',      # lea r14, [rsp+0x730]
    0x2cb79f2: 'ba700b0000',            # mov edx, 0xb70
    0x2cb79f7: '4c89f7',                # mov rdi, r14
    0x2cb7a0c: '4c89f6',                # mov rsi, r14
    # 0x5a6bfb0: copy the result again and pass it to 0x548ce30
    0x5a6c01d: '4989f6',                # mov r14, rsi
    0x5a6c08e: '4c8da42440120000',      # lea r12, [rsp+0x1240]
    0x5a6c096: 'ba700b0000',            # mov edx, 0xb70
    0x5a6c09b: '4c89e7',                # mov rdi, r12
    0x5a6c09e: '4c89f6',                # mov rsi, r14
    0x5a6c0a1: '41ffd5',                # call r13 (memcpy)
    0x5a6c0a7: '4c89e6',                # mov rsi, r12
    # 0x548ce30: place it at block +0x7c0, copy the block, box 0x4e38 bytes
    0x548ce9b: '4989f6',                # mov r14, rsi
    0x548d6f5: '488dbc24e0070000',      # lea rdi, [rsp+0x7e0]
    0x548d6fd: 'ba700b0000',            # mov edx, 0xb70
    0x548d702: '4c89f6',                # mov rsi, r14
    0x548d705: '41ffd7',                # call r15 (memcpy)
    0x548d708: '488dbc2420170000',      # lea rdi, [rsp+0x1720]
    0x548d710: '488d742420',            # lea rsi, [rsp+0x20]
    0x548d715: 'ba00170000',            # mov edx, 0x1700
    0x548d82f: 'bf384e0000',            # mov edi, 0x4e38
    0x548d83f: '488db42420170000',      # lea rsi, [rsp+0x1720]
    0x548d847: 'ba384e0000',            # mov edx, 0x4e38
    0x548d84c: '4889c7',                # mov rdi, rax
    # parent 0x2cde430: CLI value, copy, switch, two poller calls
    0x2cde52b: '488dbc2410040000',      # lea rdi, [rsp+0x410]
    0x2cde538: '83bc241004000010',      # cmp dword [rsp+0x410], 0x10
    0x2cde5f9: '0f10842410040000',      # movups xmm0, [rsp+0x410]
    0x2cde631: '410f1185c0000000',      # movups [r13+0xc0], xmm0
    0x2cde64b: '498d85c0000000',        # lea rax, [r13+0xc0]
    0x2cde652: '488b00',                # mov rax, [rax]
    0x2cde658: '4883e902',              # sub rcx, 2
    0x2cde65c: 'ba0c000000',            # mov edx, 12
    0x2cde6a2: '410f1085c8000000',      # movups xmm0, [r13+0xc8]
    0x2cde6aa: '410f118520020000',      # movups [r13+0x220], xmm0
    0x2cde6d0: '41c6854802000002',      # mov byte [r13+0x248], 2
    0x2cde6e7: '4d8db520020000',        # lea r14, [r13+0x220]
    0x2cde6ee: '4c89f7',                # mov rdi, r14
    0x2cdf539: '410f1085c8000000',      # movups xmm0, [r13+0xc8]
    0x2cdf541: '410f118520020000',      # movups [r13+0x220], xmm0
    0x2cdf567: '41c6854802000001',      # mov byte [r13+0x248], 1
    0x2cdf57e: '4d8da520020000',        # lea r12, [r13+0x220]
    0x2cdf585: '4c89e7',                # mov rdi, r12
    # 0x2b7b640: command name, error tag, conversion
    0x2b7b64c: '4889fb',                # mov rbx, rdi
    0x2b7b6be: '48b80100000000000080',  # movabs rax, 0x8000000000000001
    0x2b7b6f2: '48c70310000000',        # mov qword [rbx], 0x10
    0x2b7b732: '488dbc24a0020000',      # lea rdi, [rsp+0x2a0]
    0x2b7b74d: '488db424a0020000',      # lea rsi, [rsp+0x2a0]
    0x2b7b755: 'ba98000000',            # mov edx, 0x98
    0x2b7b75a: '4889df',                # mov rdi, rbx
    # 0x564cce0: matcher call and copy of its 0x78 bytes
    0x564ccf4: '4889fb',                # mov rbx, rdi
    0x564ce4d: '488d7c2420',            # lea rdi, [rsp+0x20]
    0x564ce5d: '837c242010',            # cmp dword [rsp+0x20], 0x10
    0x564ce92: '0f10442420',            # movups xmm0, [rsp+0x20]
    0x564ceb2: '0f1103',                # movups [rbx], xmm0
    # matcher: rbx = rdi; payload at +0x8; tags 2 and 3
    0x5654c01: '4889fb',                # mov rbx, rdi
    0x56550da: '488d7b08',              # lea rdi, [rbx+8]
    0x56550e4: '48c70302000000',        # mov qword [rbx], 2
    0x56551e5: '488d7b08',              # lea rdi, [rbx+8]
    0x56551ef: '48c70303000000',        # mov qword [rbx], 3
}
FIXED.update({
    0x2cde655: '4889c1',                # mov rcx, rax
    0x2cde661: '480f43d1',              # cmovae rdx, rcx
    0x2cde673: '48631491',              # movsxd rdx, [rcx+rdx*4]
    0x2cde677: '4801ca',                # add rdx, rcx
    0x2cde67a: 'ffe2',                  # jmp rdx
})
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x2aec025, b'\xff\x15', 6, SETTER_SLOT),
    (0x2aec3da, b'\xff\x15', 6, MEMCPY_SLOT),
    (0x2aec3ef, b'\xff\x15', 6, HANDOFF_SLOT),
    (0x2cb7645, b'\xff\x15', 6, SETTER_SLOT),
    (0x2cb79fa, b'\xff\x15', 6, MEMCPY_SLOT),
    (0x2cb7a0f, b'\xff\x15', 6, HANDOFF_SLOT),
    (0x5a6c07c, b'\x4c\x8b\x2d', 7, MEMCPY_SLOT),
    (0x5a6c0aa, b'\xe8', 5, CONSUMER),
    (0x548cecb, b'\x4c\x8b\x3d', 7, MEMCPY_SLOT),
    (0x548d834, b'\xff\x15', 6, ALLOC_SLOT),
    (0x548d852, b'\xff\x15', 6, MEMCPY_SLOT),
    (0x2cde533, b'\xe8', 5, CLI),
    (0x2cde540, b'\x0f\x84', 6, 0x2ce00c2),
    (0x2cde66c, b'\x48\x8d\x0d', 7, TABLE),
    (0x2cde6f4, b'\xe8', 5, POLLER),
    (0x2cdf58b, b'\xe8', 5, POLLER),
    (0x2b7b663, b'\x8b\x0d', 6, NAME[0] + 3),
    (0x2b7b66c, b'\x8b\x0d', 6, NAME[0]),
    (0x2b7b73f, b'\xff\x15', 6, CONVERT_SLOT),
    (0x2b7b75d, b'\xff\x15', 6, MEMCPY_SLOT),
    (0x564ce57, b'\xff\x15', 6, MATCHER_SLOT),
    (0x56550de, b'\xff\x15', 6, READER_SLOT),
    (0x56551e9, b'\xff\x15', 6, READER_SLOT),
)
RELOCATIONS = {SETTER_SLOT: SETTER, HANDOFF_SLOT: HANDOFF, CONVERT_SLOT: CONVERT,
               MATCHER_SLOT: MATCHER, READER_SLOT: 0x564d390}
FRAMES = (0x2aeaef0, POLLER, HANDOFF, CONSUMER, PARENT, CLI, CONVERT, MATCHER)
CASES = {2: 0x2cde67c, 3: 0x2cdf519}


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def relative_relocations(data):
    rel = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
    return rel


def frame_of(fdes, va):
    for f in fdes:
        if f['start'] <= va < f['end']:
            return f['start'], f['end']
    raise ValueError(f'{va:#x} has no FDE')


def bind(data, fdes):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in RELOCATIONS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    if read_va(data, NAME[0], len(NAME[1])) != NAME[1]:
        raise ValueError('command name changed')

    frames = {hex(a): [hex(v) for v in frame_of(fdes, a)] for a in FRAMES}
    for a in FRAMES:
        if frame_of(fdes, a)[0] != a:
            raise ValueError(f'{a:#x} is not an FDE start')
    for va, _, _, _ in REFERENCES[:6] + REFERENCES[12:16]:
        frame_of(fdes, va)
    cases = {}
    for tag, expect in CASES.items():
        target = TABLE + struct.unpack('<i', read_va(data, TABLE + 4 * (tag - 2), 4))[0]
        if target != expect or frame_of(fdes, target)[0] != PARENT:
            raise ValueError('parent switch changed')
        cases[str(tag)] = hex(target)

    box = {name: hex(BLOCK_OFFSET + off) for name, off in zip(('first', 'second'), OPTION_OFFSETS)}
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'frames': frames,
        'result_path': {
            'setter_call': {'0x2aec025': 'rdi = state+0xb30', '0x2cb7645': 'rdi = state+0xb30'},
            'handoff': {
                '0x2aec3c2': 'r12 = state (0x2aec369); 0xb70 bytes from state+0xb30 to rsp+0x3e0; '
                             'slot %s -> %s, rsi = rsp+0x3e0' % (hex(HANDOFF_SLOT), hex(HANDOFF)),
                '0x2cb79e2': 'r12 = state (0x2cb7989); 0xb70 bytes from state+0xb30 to rsp+0x730; '
                             'slot %s -> %s, rsi = rsp+0x730' % (hex(HANDOFF_SLOT), hex(HANDOFF)),
            },
            'in_0x5a6bfb0': 'r14 = rsi; 0xb70 bytes to rsp+0x1240; call %s with rsi = rsp+0x1240' % hex(CONSUMER),
            'in_0x548ce30': 'r14 = rsi; 0xb70 bytes to rsp+0x7e0 (= block rsp+0x20 + %s); 0x1700-byte block to '
                            'rsp+0x1720; 0x4e38 bytes from rsp+0x1720 into a new allocation (returned)'
                            % hex(BLOCK_OFFSET),
            'setter_offsets_in_box': box,
        },
        'parent_0x2cde430': {
            'cli_value': 'call %s with rdi = rsp+0x410; tag 0x10 -> 0x2ce00c2' % hex(CLI),
            'copy': 'rsp+0x410..+0x450 -> +0xc0..+0x100',
            'switch': 'qword [+0xc0] - 2 (else 12) indexes %s' % hex(TABLE),
            'cases': cases,
            'per_case': '+0xc8..+0xf0 -> +0x220..+0x248; mode byte +0x248 = 2 (tag 2) or 1 (tag 3); '
                        'call %s with rdi = +0x220' % hex(POLLER),
        },
        'tag_origin': {
            '0x2b7b640': 'command name %r at %s; result 0x8000000000000001 -> [rbx] = 0x10; else slot %s -> %s '
                         'with rdi = rsp+0x2a0, then 0x98 bytes to rbx'
                         % (NAME[1].decode(), hex(NAME[0]), hex(CONVERT_SLOT), hex(CONVERT)),
            '0x564cce0': 'slot %s -> %s with rdi = rsp+0x20; tag 0x10 rejected; rsp+0x20.. -> rbx+0x0..'
                         % (hex(MATCHER_SLOT), hex(MATCHER)),
            'matcher': 'rbx = rdi (0x5654c01); reader slot %s with rdi = rbx+0x8; tag 2 (0x56550e4), tag 3 (0x56551ef)'
                       % hex(READER_SLOT),
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
    print('box offsets', result['result_path']['setter_offsets_in_box'], 'cases', result['parent_0x2cde430']['cases'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
