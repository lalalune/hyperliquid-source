#!/usr/bin/env python3
"""Bind the callers of the node #115 lu.rs sleep helpers and the info handler's packed fields (26th stage).

Continues the info_server packets (open #5957, #5960). The 25th stage found
that the handler 0x2e3ed10 would start the inner future 0x2d4f790 with 0.014
seconds, that 0x2d4f790 returns at once on 0.0 and otherwise calls 0x2d4f8b0,
which sleeps for its argument, and that the handler's guard flag is always 0.
This tool binds:

1. the call census: four `call rel32` sites reach 0x2d4f790 and two reach
   0x2d4f8b0; no R_X86_64_RELATIVE entry names either function;
2. the argument at each 0x2d4f790 call:
   - 0x2cf08b0 (futures unfold, unfold.rs:108:21 / lu.rs:386:64): one of two
     f64 at +0x10/+0x18, picked by a toggled byte at +0x8; a byte at +0x30
     chooses 0x2d4f8b0 (no zero check) or 0x2d4f790;
   - 0x2e071c0 and 0x2e075f0 (node/src/channel.rs:16:9): max(0, A - B)
     seconds from two (date, secs, frac) tuples, where B comes from the
     wall-clock call 0x1629690; +inf gives 0;
   - 0x2e3ed10 (info handler): the constant 0.014;
3. the handler's two packed records at +0x2d8..+0x2e9 and +0x6b8..+0x6c9:
   an Option byte (1 when [rsp+0x160] bit 0 is set), a 4-byte value, a
   12-byte value and the constant byte 2; then the zero word at +0x6da.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-lu-sleep-callers-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

OUTER, INNER = 0x2d4f790, 0x2d4f8b0
EXPECTED_OUTER_CALLS = {0x2cf09c7: 0x2cf08b0, 0x2e072c6: 0x2e071c0, 0x2e076f0: 0x2e075f0, 0x2e3fd8f: 0x2e3ed10}
EXPECTED_INNER_CALLS = {0x2cf0986: 0x2cf08b0, 0x2d4f7de: 0x2d4f790}
WALL_CLOCK_SLOT, WALL_CLOCK = 0x64e0990, 0x1629690
TIME_DIFF_SLOT, TIME_DIFF = 0x64e0fc0, 0x162a290
NANOS, INF = 0x458d50, 0x459010
SECONDS = 0x3f8cac083126e979
UNFOLD_PANIC = (0x61671d, b'Unfold must not be polled after it returned `Poll::Ready(None)`')
LOCATIONS = {
    0x644f7e8: ('/home/ubuntu/hl/code_Mainnet/z_vendor/futures-util/src/stream/unfold.rs', 108, 21),
    0x6451440: ('base/src/lu.rs', 386, 64),
    0x6451af8: ('node/src/channel.rs', 16, 9),
    0x6451b10: ('node/src/channel.rs', 20, 33),
}

FIXED = {
    # 0x2cf08b0: pick one of two intervals, then sleep with or without the zero check
    0x2cf0959: '0fb64308',              # movzx eax, byte [rbx+0x8]
    0x2cf095d: '3401',                  # xor al, 1
    0x2cf0962: 'f20f1044c310',          # movsd xmm0, [rbx+rax*8+0x10]
    0x2cf096d: 'f20f114338',            # movsd [rbx+0x38], xmm0      (sleep argument)
    0x2cf0972: '807b3000',              # cmp byte [rbx+0x30], 0
    0x2cf0976: '7441',                  # je 0x2cf09b9
    0x2cf097f: '4c8d7b38',              # lea r15, [rbx+0x38]
    0x2cf09c0: '4c8d7b38',              # lea r15, [rbx+0x38]
    0x2cf0a68: 'be3f000000',            # mov esi, 63                  (panic message length)
    # 0x2e071c0 / 0x2e075f0: seconds = max(0, secs + nanos / 1e9), +inf -> 0
    0x2e074b2: 'f20f58c8', 0x2e074ba: 'f20f5fc8', 0x2e074c6: '7404', 0x2e074cc: 'f20f114370',
    0x2e078c1: 'f20f58c8', 0x2e078c9: 'f20f5fc8', 0x2e078d5: '7404', 0x2e078db: 'f20f114370',
    0x2e072bc: '4c8d7b70', 0x2e076e6: '4c8d7b70',   # lea r15, [rbx+0x70]
    # 0x2e3ed10: constant argument
    0x2e3fd6f: '48b8' + struct.pack('<Q', SECONDS).hex(),
    0x2e3fd79: '48898370050000',        # mov [rbx+0x570], rax
    0x2e3fd68: '4c8db370050000',        # lea r14, [rbx+0x570]
    # 0x2e3ed10: Option byte and 4-byte value
    0x2e3f51f: '8bac2462010000',        # mov ebp, [rsp+0x162]
    0x2e3f526: 'f684246001000001',      # test byte [rsp+0x160], 1
    0x2e3f52e: '7472',                  # je 0x2e3f5a2                 (None -> al = 0)
    0x2e3f54c: '0fb7842466010000',      # movzx eax, word [rsp+0x166]
    0x2e3f554: '0facc510',              # shrd ebp, eax, 16
    0x2e3f558: 'b001',                  # mov al, 1
    0x2e3f5a2: '31c0',                  # xor eax, eax
    0x2e3f5e7: '890424',                # mov [rsp], eax
    # 0x2e3ed10: the two packed records
    0x2e3f77a: '8b0c24',                # mov ecx, [rsp]
    0x2e3f77d: '888bd8020000', 0x2e3f783: '89abd9020000', 0x2e3f789: '488b842490000000',
    0x2e3f791: '488983dd020000', 0x2e3f798: '8b842498000000', 0x2e3f79f: '8983e5020000',
    0x2e3f7a5: 'c683e902000002',
    0x2e3f7b3: '888bb8060000', 0x2e3f7b9: '89abb9060000', 0x2e3f7bf: '488b842480000000',
    0x2e3f7c7: '488983bd060000', 0x2e3f7ce: '8b842488000000', 0x2e3f7d5: '8983c5060000',
    0x2e3f7db: 'c683c906000002',
    0x2e3f7e2: '66c783da0600000000',    # mov word [rbx+0x6da], 0
}
REFERENCES = (
    (0x2cf0a5a, b'\x48\x8d\x3d', 7, UNFOLD_PANIC[0]),
    (0x2cf0a61, b'\x48\x8d\x15', 7, 0x644f7e8),
    (0x2cf0a73, b'\x48\x8d\x3d', 7, 0x6451440),
    (0x2cf0a80, b'\x48\x8d\x3d', 7, 0x6451440),
    (0x2e07242, b'\x48\x8d\x3d', 7, 0x6451af8),
    (0x2e0766c, b'\x48\x8d\x3d', 7, 0x6451af8),
    (0x2e07337, b'\x48\x8d\x15', 7, 0x6451b10),
    (0x2e07757, b'\x48\x8d\x15', 7, 0x6451b10),
    (0x2e07438, b'\xff\x15', 6, WALL_CLOCK_SLOT),
    (0x2e07847, b'\xff\x15', 6, WALL_CLOCK_SLOT),
    (0x2e07477, b'\xff\x15', 6, TIME_DIFF_SLOT),
    (0x2e07886, b'\xff\x15', 6, TIME_DIFF_SLOT),
    (0x2e074aa, b'\xf2\x0f\x5e\x0d', 8, NANOS),
    (0x2e078b9, b'\xf2\x0f\x5e\x0d', 8, NANOS),
    (0x2e074be, b'\x66\x0f\x2e\x0d', 8, INF),
    (0x2e078cd, b'\x66\x0f\x2e\x0d', 8, INF),
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


def slot_calls(data, slot):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xff\x15', code):
        i = m.start()
        if i + 6 <= len(code) and base + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == slot:
            out.append(base + i)
    return out


def frame_starts(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start'], ordered[i]['end']
    return frame




def rel32_calls(data, target):
    base, code = text(data)
    return [base + m.start() for m in re.finditer(rb'\xe8', code)
            if m.start() + 5 <= len(code)
            and base + m.start() + 5 + struct.unpack_from('<i', code, m.start() + 1)[0] == target]


def location(data, rel, va):
    ptr = rel.get(va)
    if ptr is None:
        raise ValueError(f'Location at {va:#x} has no relocation')
    length = struct.unpack('<Q', read_va(data, va + 8, 8))[0]
    line, col = struct.unpack('<II', read_va(data, va + 16, 8))
    return read_va(data, ptr, length).decode(), line, col


def seconds_model(secs, nanos):
    """The f64 the two channel futures store: max(0, secs + nanos / 1e9), +inf -> 0."""
    value = max(float(secs) + float(nanos) / 1e9, 0.0)
    return 0.0 if value == float('inf') else value


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in ((WALL_CLOCK_SLOT, WALL_CLOCK), (TIME_DIFF_SLOT, TIME_DIFF)):
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    if OUTER in rel.values() or INNER in rel.values():
        raise ValueError('a relocation now names a sleep helper')
    for va, expect in LOCATIONS.items():
        if location(data, rel, va) != expect:
            raise ValueError(f'Location at {va:#x} changed')
    if read_va(data, UNFOLD_PANIC[0], len(UNFOLD_PANIC[1])) != UNFOLD_PANIC[1]:
        raise ValueError('unfold panic message changed')
    nanos = struct.unpack('<d', read_va(data, NANOS, 8))[0]
    inf = struct.unpack('<d', read_va(data, INF, 8))[0]
    if nanos != 1e9 or inf != float('inf'):
        raise ValueError('conversion constants changed')

    frame = frame_starts(fdes)
    outer = {va: frame(va)[0] for va in rel32_calls(data, OUTER)}
    inner = {va: frame(va)[0] for va in rel32_calls(data, INNER)}
    if outer != EXPECTED_OUTER_CALLS or inner != EXPECTED_INNER_CALLS:
        raise ValueError('sleep call census changed')
    seconds = struct.unpack('<d', struct.pack('<Q', SECONDS))[0]
    samples = {'(1, 500000000)': (1, 500000000), '(0, 0)': (0, 0), '(-1, 0)': (-1, 0), '(2**62, 0)': (2 ** 62, 0)}

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'info-api',
        'helpers': {'outer': hex(OUTER), 'inner': hex(INNER),
                    'relocations_naming_either': 0},
        'outer_calls': [
            {'call': hex(0x2cf09c7), 'fn': hex(0x2cf08b0), 'locations': ['unfold.rs:108:21', 'lu.rs:386:64'],
             'argument': 'f64 [rbx+0x10+8*(byte [rbx+0x8] ^ 1)] copied to +0x28 and +0x38',
             'other_path': 'byte [rbx+0x30] != 0 -> %s calls %s directly (no zero check)'
                           % (hex(0x2cf0986), hex(INNER))},
            {'call': hex(0x2e072c6), 'fn': hex(0x2e071c0), 'locations': ['channel.rs:16:9', 'channel.rs:20:33'],
             'argument': 'max(0, A - B) seconds; B from slot %s -> %s; difference slot %s -> %s; +inf -> 0'
                         % (hex(WALL_CLOCK_SLOT), hex(WALL_CLOCK), hex(TIME_DIFF_SLOT), hex(TIME_DIFF))},
            {'call': hex(0x2e076f0), 'fn': hex(0x2e075f0), 'locations': ['channel.rs:16:9', 'channel.rs:20:33'],
             'argument': 'same shape as 0x2e071c0'},
            {'call': hex(0x2e3fd8f), 'fn': hex(0x2e3ed10), 'locations': [],
             'argument': 'constant %r (0x%x); guarded by the flag the 25th stage found constant 0' % (seconds, SECONDS)},
        ],
        'inner_calls': [[hex(k), hex(v)] for k, v in sorted(inner.items())],
        'seconds_model_samples': {k: seconds_model(*v) for k, v in samples.items()},
        'handler_records': {
            'option_byte': '1 when byte [rsp+0x160] bit 0 is set (%s), else 0 (%s); stored to [rsp] (%s)'
                           % (hex(0x2e3f526), hex(0x2e3f5a2), hex(0x2e3f5e7)),
            'value32': 'ebp = dword [rsp+0x162] shrd word [rsp+0x166], 16: bytes [rsp+0x164..0x168)',
            'record_1': '+0x2d8 byte, +0x2d9 dword, +0x2dd qword [rsp+0x90], +0x2e5 dword [rsp+0x98], +0x2e9 = 2',
            'record_2': '+0x6b8 byte, +0x6b9 dword, +0x6bd qword [rsp+0x80], +0x6c5 dword [rsp+0x88], +0x6c9 = 2',
            'flag_word': '+0x6da = 0 (%s)' % hex(0x2e3f7e2),
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
    print(f"outer_calls={len(result['outer_calls'])} inner_calls={len(result['inner_calls'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
