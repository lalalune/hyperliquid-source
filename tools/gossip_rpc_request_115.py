#!/usr/bin/env python3
"""Bind the node #115 gossip_rpc_request step that runs before verify_peer (30th stage).

The 29th stage (open PR #5966) found that the verify_peer future 0x2ae0920
first awaits 0x2ae0100, which writes the name `gossip_rpc_request` and 10.0,
and goes on only when that step returns tag 0x44. This tool binds:

1. 0x2ae0100: the name `gossip_rpc_request` (18 bytes) at +0x38/+0x40 and
   10.0 at +0x470; it polls the inner future 0x2b69d20 on its state +0x8e0
   (0x498 bytes); inner tag 0x46 gives outer tag 0x45 (pending), inner tag
   0x45 formats the `lu::timeout` template 0x4326d0 and gives tag 0x2f, and
   any other inner tag is returned unchanged;
2. 0x2b69d20 connect: it reads a dword through its +0x70 pointer and builds
   word 0 / that dword / port 0xfa2 (4002) at +0x80..+0x88, formats
   `rpc connect {}` (0x4422f7) with it, and stores 11 at +0x158 and 2.0 at
   +0x160 beside the message;
3. 0x2b69d20 retry exhaustion: the template `async_sleep_retry retries
   exhausted: {}` (0x444d45) and `[n_retries: {}]` (0x434a4e) with the
   count at +0x1a8;
4. 0x2b69d20 send: the name `send gossip rpc request` (23 bytes, 0x605abe),
   the request pointer from +0x78, 60.0 at +0x170, then a call to 0x2b7a290;
5. direct-call census of 0x2ae0100, 0x2b69d20 and the poll of the caller
   0x2accee0, and that 0x2accee0 never stores to its +0x1268 dword.

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
PACKET = ROOT / 'research/work-items/RE-008-gossip-rpc-request-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

GOSSIP_RPC = 0x2ae0100
INNER = 0x2b69d20
SEND_POLL = 0x2b7a290
CALLER = 0x2accee0
CALLER_DWORD = 0x1268

STRINGS = {
    0x605aac: b'gossip_rpc_request',
    0x605abe: b'send gossip rpc request',
    0x4422f7: b'\x0crpc connect \xc0\x00',
    0x444d45: b'%async_sleep_retry retries exhausted: \xc0\x00',
    0x434a4e: b'\xc0\x10 @@ [n_retries: \xc0\x01]',
    0x4326d0: b'\x0clu::timeout ',
}

FIXED = {
    # 0x2ae0100 start state: name, length, inner closure fields, 10.0
    0x2ae015a: '4c897338',                  # mov [rbx+0x38], r14            (name ptr)
    0x2ae015e: '48c7434012000000',          # mov qword [rbx+0x40], 0x12     (name len 18)
    0x2ae0175: '48b80000000000002440',      # movabs rax, 0x4024000000000000 (10.0)
    0x2ae017f: '48898370040000',            # mov [rbx+0x470], rax
    # 0x2ae0100 poll of the inner future
    0x2ae0426: '488dbbe0080000',            # lea rdi, [rbx+0x8e0]
    0x2ae0435: 'ba98040000',                # mov edx, 0x498
    0x2ae0442: '4c8db3e0080000',            # lea r14, [rbx+0x8e0]
    0x2ae0451: '4c89f6',                    # mov rsi, r14
    0x2ae0459: '0fb6ac24d0010000',          # movzx ebp, byte [rsp+0x1d0]  (inner tag)
    0x2ae0461: '4080fd46',                  # cmp bpl, 0x46
    0x2ae0465: '751c',                      # jne 0x2ae0483
    0x2ae0477: '41c6042445',                # mov byte [r12], 0x45         (outer pending)
    0x2ae04e3: '4080fd45',                  # cmp bpl, 0x45
    0x2ae04e7: '0f8556010000',              # jne 0x2ae0643                 (pass tag through)
    0x2ae05c7: '40b52f',                    # mov bpl, 0x2f                 (timeout tag)
    0x2ae0796: '41882c24',                  # mov [r12], bpl                (store tag)
    # 0x2b69d20 connect address and retry fields
    0x2b69da8: '488b4370',                  # mov rax, [rbx+0x70]
    0x2b69dac: '8b00',                      # mov eax, [rax]
    0x2b69db5: '898382000000',              # mov [rbx+0x82], eax
    0x2b69dbb: '66c78386000000a20f',        # mov word [rbx+0x86], 0xfa2    (4002)
    0x2b69dc4: '66c783800000000000',        # mov word [rbx+0x80], 0
    0x2b69e4d: '48c783580100000b000000',    # mov qword [rbx+0x158], 11
    0x2b69e58: '48b80000000000000040',      # movabs rax, 0x4000000000000000 (2.0)
    0x2b69e62: '48898360010000',            # mov [rbx+0x160], rax
    0x2b6a093: '488d83a8010000',            # lea rax, [rbx+0x1a8]          (n_retries)
    # 0x2b69d20 send step
    0x2b6a60b: '488b7378',                  # mov rsi, [rbx+0x78]           (request)
    0x2b6a61d: '48898b40010000',            # mov [rbx+0x140], rcx          (name ptr)
    0x2b6a624: '48c7834801000017000000',    # mov qword [rbx+0x148], 23
    0x2b6a676: '48b80000000000004e40',      # movabs rax, 0x404e000000000000 (60.0)
    0x2b6a680: '48898370010000',            # mov [rbx+0x170], rax
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x2ae0153, b'\x4c\x8d\x35', 7, 0x605aac),
    (0x2ae0454, b'\xe8', 5, INNER),
    (0x2ae0525, b'\x48\x8d\x3d', 7, 0x4326d0),
    (0x2b69de4, b'\x48\x8d\x35', 7, 0x4422f7),
    (0x2b6a074, b'\x48\x8d\x05', 7, 0x444d45),
    (0x2b6a0d4, b'\x48\x8d\x35', 7, 0x434a4e),
    (0x2b6a616, b'\x48\x8d\x0d', 7, 0x605abe),
    (0x2b6a6a6, b'\xe8', 5, SEND_POLL),
)
EXPECTED_CALLS = {
    GOSSIP_RPC: [0x2adacc4, 0x2adee64, 0x2ae097f],
    INNER: [0x2ae0454, 0x2cb2101],
    CALLER: [0x2b1db89, 0x2b26b09],
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


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def direct_calls(data, target):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code) and base + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == target:
            out.append(base + i)
    return out


def frame(fdes, va):
    ordered = sorted(fdes, key=lambda f: f['start'])
    i = bisect.bisect_right([f['start'] for f in ordered], va) - 1
    if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
        raise ValueError(f'{va:#x} has no FDE')
    return ordered[i]['start'], ordered[i]['end']


def disp_uses(data, lo, hi, disp):
    """Opcode bytes of [reg+disp32] operands (no SIB) in [lo, hi), by kind."""
    raw = read_va(data, lo, hi - lo)
    pat = struct.pack('<i', disp)
    kinds = {'load': [], 'store': [], 'other': []}
    for m in re.finditer(re.escape(pat), raw):
        k = m.start()
        if k < 2:
            continue
        modrm, op = raw[k - 1], raw[k - 2]
        if modrm >> 6 != 2 or modrm & 7 == 4:
            continue
        kind = 'load' if op in (0x8b, 0xb6) else 'store' if op in (0x89, 0x88, 0xc7, 0xc6) else 'other'
        kinds[kind].append(lo + k - 2)
    return kinds


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, text_bytes in STRINGS.items():
        if read_va(data, va, len(text_bytes)) != text_bytes:
            raise ValueError(f'string at {va:#x} changed')
    calls = {}
    for target, expect in EXPECTED_CALLS.items():
        found = direct_calls(data, target)
        if found != expect:
            raise ValueError(f'call census of {target:#x} changed')
        calls[hex(target)] = [hex(v) for v in found]
    lo, hi = frame(fdes, CALLER)
    if lo != CALLER:
        raise ValueError('caller FDE changed')
    uses = disp_uses(data, lo, hi, CALLER_DWORD)
    if uses['store'] or len(uses['load']) != 8:
        raise ValueError('caller +0x1268 census changed')
    gossip = frame(fdes, GOSSIP_RPC)
    inner = frame(fdes, INNER)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'transport',
        'gossip_rpc_request': {
            'fde': [hex(v) for v in gossip],
            'name': '+0x38/+0x40 -> 0x605aac gossip_rpc_request (18 bytes)',
            'limit': '+0x470 = 10.0 (0x4024000000000000)',
            'inner': 'state +0x8e0 (0x498 bytes) polled by direct call 0x2ae0454 -> 0x2b69d20',
            'inner_tag_0x46': 'outer tag 0x45 (pending)',
            'inner_tag_0x45': 'lu::timeout template 0x4326d0, outer tag 0x2f',
            'other_inner_tags': 'returned unchanged (0x2ae0796 mov [r12], bpl)',
        },
        'inner_future': {
            'fde': [hex(v) for v in inner],
            'connect_address': '+0x80 word 0, +0x82 dword read through +0x70, +0x86 port 0xfa2 (4002)',
            'connect_message': '0x4422f7 "rpc connect {}" formatted with &+0x80',
            'retry_fields': '+0x158 = 11, +0x160 = 2.0',
            'retry_exhausted': '0x444d45 "async_sleep_retry retries exhausted: {}" and 0x434a4e '
                               '"[n_retries: {}]" with +0x1a8',
            'send': '0x605abe "send gossip rpc request" (23 bytes) at +0x140/+0x148, request from +0x78, '
                    '+0x170 = 60.0, then direct call 0x2b7a290',
        },
        'direct_calls': calls,
        'caller_plus_0x1268': {
            'fde': [hex(lo), hex(hi)],
            'loads': [hex(v) for v in uses['load']],
            'stores': [hex(v) for v in uses['store']],
            'other': [hex(v) for v in uses['other']],
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
    print(f"caller_loads={len(result['caller_plus_0x1268']['loads'])} "
          f"gossip_calls={len(result['direct_calls'][hex(GOSSIP_RPC)])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
