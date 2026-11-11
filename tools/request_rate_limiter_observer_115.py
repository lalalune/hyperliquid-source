#!/usr/bin/env python3
"""Bind the node #115 `handle_request_rate_limiter` observer (23rd stage).

Continues #5954, which found that 0x2f19520 builds an observer named
`handle_request_rate_limiter` and moves it 8 bytes into its output. This tool
binds:

1. the cell: 0x2f19520 is the initializer of a lazy cell at 0x64f3a18 (value
   word relocated to it, state dword +0x270 = 3 at rest); it is not called
   directly. Its 0x270-byte value is a lock byte (+0x0), the observer
   (+0x8..+0x268) and a qword +0x268 (initial 1). The observer is built with
   a = 0.001 and selector 0, then +0x0 = 1, +0x8 = 2.0 (the #5865 getter
   pattern), and observer +0x1f8 = 6000;
2. the only user: GOT slot 0x64e8920 is loaded three times, all in
   0x2e3ed10, an info_server request handler; it passes the cell to
   0x15494d0 (slot 0x64e1030, one call) with an f64 built from two clock
   reads (0x5c842e0 with edi = 1, then 0x5c84210);
3. the wrapper 0x15494d0: k = 1 when N = cell +0x268 < 2000, else N / 2000;
   it records only when 0x1562120(k) returns true (thread-local random value
   modulo k == 0); it takes the lock byte, records the value with count k
   through 0x1547530, then, when the observer's rollover flag (+0x10) is 1,
   clears it and stores the rolled-over window's summed count (observer
   +0x18) as the new N. The comparisons N >= 2001 with calls < 200, and
   calls > 20000 only choose whether that store comes before or after the
   unlock;
4. the record entry 0x1547530 fills observer +0x10 = 1, +0x18 = window +0x78
   (saturating sum of counts), +0x20 = window +0x80 (saturating call count)
   when a window rolls over.

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
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-request-rate-limiter-observer-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

INIT = 0x2f19520
CELL, CELL_SLOT = 0x64f3a18, 0x64e8920
HANDLER = 0x2e3ed10
WRAPPER, WRAPPER_SLOT = 0x15494d0, 0x64e1030
SAMPLE, SAMPLE_SLOT = 0x1562120, 0x64e1028
RECORD, RECORD_SLOT = 0x1547530, 0x64e1010
CTOR, CTOR_SLOT = 0x1548bb0, 0x64e1020
NAME = (0x644408, b'handle_request_rate_limiter')
A_CONST = 0x459af0
MAGIC = 0x20c49ba5e353f7d

FIXED = {
    # initializer 0x2f19520
    0x2f19543: 'b91b000000',                    # mov ecx, 27              (name length)
    0x2f1954b: '31f6',                          # xor esi, esi             (selector 0)
    0x2f19553: '48c7042401000000',              # mov qword [rsp], 1       (observer +0x0)
    0x2f1955b: '48b80000000000000040',          # movabs rax, 2.0          (observer +0x8)
    0x2f195f1: 'c60300',                        # mov byte [rbx], 0        (lock byte)
    0x2f195f4: '488d7b01',                      # lea rdi, [rbx+1]
    0x2f195fb: 'baff010000',                    # mov edx, 0x1ff
    0x2f19603: '48c7830002000070170000',        # mov qword [rbx+0x200], 6000 (observer +0x1f8)
    0x2f1960e: '48c7836802000001000000',        # mov qword [rbx+0x268], 1    (N)
    # wrapper 0x15494d0
    0x15494e2: '4c8bbf68020000',                # mov r15, [rdi+0x268]     (N)
    0x15494e9: '41be01000000',                  # mov r14d, 1
    0x15494ef: '4981ffd0070000',                # cmp r15, 2000
    0x15494f6: '7217',                          # jb -> k = 1
    0x15494fb: '48c1e804',                      # shr rax, 4
    0x15494ff: '48b97d3f355eba490c02',          # movabs rcx, MAGIC
    0x1549509: '48f7e1',                        # mul rcx
    0x154950c: '4989d6',                        # mov r14, rdx             (k = N / 2000)
    0x154950f: '4c89f7',                        # mov rdi, r14
    0x1549518: '84c0',                          # test al, al
    0x154951a: '0f8490000000',                  # je ret                   (not sampled)
    0x1549520: 'b101',                          # mov cl, 1
    0x1549524: 'f00fb00b',                      # lock cmpxchg [rbx], cl   (lock)
    0x154952e: '488d7b08',                      # lea rdi, [rbx+8]         (observer)
    0x1549538: '4c89f6',                        # mov rsi, r14             (count = k)
    0x1549541: '488b4b18',                      # mov rcx, [rbx+0x18]      (observer +0x10)
    0x1549545: '4c8b7320',                      # mov r14, [rbx+0x20]      (observer +0x18)
    0x1549549: '488b4328',                      # mov rax, [rbx+0x28]      (observer +0x20)
    0x154954d: '48c7431800000000',              # mov qword [rbx+0x18], 0
    0x1549555: '4883f901',                      # cmp rcx, 1
    0x1549559: '7526',                          # jne unlock
    0x154955b: '4981ffd1070000',                # cmp r15, 2001
    0x1549565: '483dc8000000',                  # cmp rax, 200
    0x154956e: '483d204e0000',                  # cmp rax, 20000
    0x154957a: '4c89b368020000',                # mov [rbx+0x268], r14     (store before unlock)
    0x15495a9: '4c89b368020000',                # mov [rbx+0x268], r14     (store after unlock)
    # sampling predicate 0x1562120
    0x1562284: '48f7f3',                        # div rbx                  (random % k)
    0x156228e: 'f7f3',                          # div ebx
    0x1562290: '4885d2',                        # test rdx, rdx
    0x1562293: '0f94c0',                        # sete al
    # record entry 0x1547530: window counters and rollover output
    0x1547852: '4c037378',                      # add r14, [rbx+0x78]      (window count sum)
    0x1547870: '488b9380000000',                # mov rdx, [rbx+0x80]
    0x1547877: '48ffc2',                        # inc rdx                  (window calls)
    0x1547aa7: '488b6b78',                      # mov rbp, [rbx+0x78]
    0x1547aab: '488bb380000000',                # mov rsi, [rbx+0x80]
    0x15482b2: '4889ac24e0010000',              # mov [rsp+0x1e0], rbp
    0x15482ba: '4889b424e8010000',              # mov [rsp+0x1e8], rsi
    0x1547bc3: '4883bc24d001000002',            # cmp qword [rsp+0x1d0], 2 (None)
    0x1547bd2: '488bac24e0010000',              # mov rbp, [rsp+0x1e0]
    0x1547bda: '488bb424e8010000',              # mov rsi, [rsp+0x1e8]
    0x1547bf2: '48c7431001000000',              # mov qword [rbx+0x10], 1
    0x1547bfa: '48896b18',                      # mov [rbx+0x18], rbp
    0x1547bfe: '48897320',                      # mov [rbx+0x20], rsi
    # handler 0x2e3ed10
    0x2e3fc5e: 'bf01000000',                    # mov edi, 1               (clock id)
    0x2e3fcd2: '8b8770020000',                  # mov eax, [rdi+0x270]     (cell state)
    0x2e3fd51: '4084ed',                        # test bpl, bpl            (rax of the wrapper unused)
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x2f19531, b'\x48\x8d\x15', 7, NAME[0]),
    (0x2f1953b, b'\xf2\x0f\x10\x05', 8, A_CONST),
    (0x2f1954d, b'\xff\x15', 6, CTOR_SLOT),
    (0x1549512, b'\xff\x15', 6, SAMPLE_SLOT),
    (0x154953b, b'\xff\x15', 6, RECORD_SLOT),
    (0x2e3fc63, b'\xe8', 5, 0x5c842e0),
    (0x2e3fca2, b'\xe8', 5, 0x5c84210),
    (0x2e3fccb, b'\x48\x8b\x3d', 7, CELL_SLOT),
    (0x2e3fd2f, b'\x48\x8b\x3d', 7, CELL_SLOT),
    (0x2e3fd44, b'\x48\x8b\x3d', 7, CELL_SLOT),
    (0x2e3fd4b, b'\xff\x15', 6, WRAPPER_SLOT),
)
RELOCATIONS = {CELL: INIT, CELL_SLOT: CELL, WRAPPER_SLOT: WRAPPER, SAMPLE_SLOT: SAMPLE,
               RECORD_SLOT: RECORD, CTOR_SLOT: CTOR}


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


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def rip_sites(data, pattern, target, length):
    """Sites of `pattern` + rel32 whose RIP-relative target is `target`."""
    base, code = text(data)
    out = []
    for m in re.finditer(pattern, code):
        i = m.start()
        if i + length <= len(code) and base + i + length + struct.unpack_from('<i', code, i + length - 4)[0] == target:
            out.append(base + i)
    return out


def frame_of(fdes, va):
    for f in fdes:
        if f['start'] <= va < f['end']:
            return f['start']
    raise ValueError(f'{va:#x} has no FDE')


def stride(n):
    """Model of 0x15494e2..0x154950c: k = 1 below 2000, else ((n >> 4) * MAGIC) >> 64."""
    return 1 if n < 2000 else ((n >> 4) * MAGIC) >> 64


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
    if [k for k, v in rel.items() if v == INIT] != [CELL]:
        raise ValueError('initializer is referenced from more than the cell')
    if {k: v for k, v in rel.items() if CELL <= v < CELL + 0x278} != {CELL_SLOT: CELL}:
        raise ValueError('another relocation points into the cell')
    if read_va(data, NAME[0], len(NAME[1])) != NAME[1]:
        raise ValueError('observer name changed')
    a_value = struct.unpack('<d', read_va(data, A_CONST, 8))[0]
    state = struct.unpack('<I', read_va(data, CELL + 0x270, 4))[0]
    if a_value != 0.001 or state != 3:
        raise ValueError('cell constants changed')

    cell_loads = rip_sites(data, rb'[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', CELL_SLOT, 7)
    wrapper_calls = rip_sites(data, rb'\xff\x15', WRAPPER_SLOT, 6)
    init_calls = rip_sites(data, rb'\xe8', INIT, 5)
    name_refs = rip_sites(data, rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', NAME[0], 7)
    load_frames = sorted({frame_of(fdes, v) for v in cell_loads})
    if load_frames != [HANDLER] or wrapper_calls != [0x2e3fd4b] or init_calls or name_refs != [0x2f19531]:
        raise ValueError('census changed')
    samples = [0, 1, 1999, 2000, 2001, 3999, 4000, 123456, 10 ** 9, 2 ** 63 + 12345]
    model = {str(n): stride(n) for n in samples}
    if any(stride(n) != max(1, n // 2000) for n in samples):
        raise ValueError('stride model disagrees with N / 2000')

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'cell': {
            'cell': hex(CELL),
            'initializer': hex(INIT) + ' (R_X86_64_RELATIVE value word; no direct calls)',
            'state_dword_at_rest': '+0x270 = %d' % state,
            'layout': '+0x0 lock byte; +0x8..+0x268 observer; +0x268 N (initial 1)',
            'observer_ctor': 'slot %s -> %s, name %r, a = %r, selector 0' % (
                hex(CTOR_SLOT), hex(CTOR), NAME[1].decode(), a_value),
            'after_ctor': 'observer +0x0 = 1, +0x8 = 2.0, +0x1f8 = 6000',
        },
        'users': {
            'cell_slot': hex(CELL_SLOT) + ' (the only relocation into the cell)',
            'cell_slot_loads': [hex(v) for v in cell_loads],
            'functions': [hex(v) for v in load_frames],
            'wrapper_calls': [hex(v) for v in wrapper_calls],
            'value': 'f64 from 0x5c842e0 (edi = 1) then 0x5c84210 at 0x2e3fc63 / 0x2e3fca2',
            'wrapper_result': 'unused: 0x2e3fd51 tests bpl after the call',
        },
        'wrapper': {
            'fn': hex(WRAPPER),
            'stride': 'k = 1 if N < 2000 else N / 2000 (magic %s)' % hex(MAGIC),
            'stride_samples': model,
            'sample': 'slot %s -> %s: thread-local random value %% k == 0' % (hex(SAMPLE_SLOT), hex(SAMPLE)),
            'record': 'lock byte cmpxchg 0 -> 1; slot %s -> %s (observer, value, count = k)'
                      % (hex(RECORD_SLOT), hex(RECORD)),
            'rollover': 'if observer +0x10 == 1: clear it; N = observer +0x18; '
                        'N >= 2001 && calls < 200, or calls > 20000, only moves the store after the unlock',
        },
        'record_rollover': {
            'window_count_sum': '+0x78 (add at 0x1547852)',
            'window_calls': '+0x80 (inc at 0x1547877)',
            'outputs': 'observer +0x10 = 1, +0x18 = window +0x78, +0x20 = window +0x80 (0x1547bf2..0x1547bfe)',
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
    print(f"cell_loads={len(result['users']['cell_slot_loads'])} wrapper_calls={len(result['users']['wrapper_calls'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
