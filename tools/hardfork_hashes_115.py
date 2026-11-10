#!/usr/bin/env python3
"""Bind the node #115 `hardfork_hashes` read at the start of the slow abci driver (55th stage).

Continues #6016 (the slow driver closure 0x5a34440 reads `hardfork_hashes`
before its receive loop and, when the closure's first byte is 0, sends the
result once on a second channel). This tool binds:

1. the driver head: `lea rdx, "hardfork_hashes"` (0x93b070, 15 bytes) and
   `call 0x5647720` with rsi = [closure+0x78]+0x10 (the slow runner);
2. the read wrapper 0x5647720 (one direct call): a blocking call
   (0x4e46b50, edx = 1) plus a once-per-minute counter in the runner block at
   +0xb50 (lock byte +0xb50, divisor +0xb58, last minute +0xb60, count +0xb68)
   that records `slow_abci_engine_read_increment` with (0.01, 0.05);
3. the body 0x4fc3490: a read lock on runner +0x6a8 (add 0x10), a check of
   runner +0x128 == 1000000000, and the worker 0x5484670 with runner +0xb00;
4. the worker 0x5484670: height = box +0x28; a 0x38-byte value from
   0x4e48ee0 (ecx = 1), whose closure 0x4e4b860 serialises the box through
   0x5480950 with config dword 0x01000400 and references
   "serialized abci state"; the abci digest through 0x4e46090 and slot
   0x64e7820 (-> 0x41c5140, #6024); a 32-byte value from 0x452aab0
   (edx = 1); output +0x38 height, +0x40..+0x60 that value, +0x60..+0x80 the
   digest;
5. the send: the driver copies result +0x38 and +0x40..+0x60 into a
   0x28-byte message, increments [closure+0x30]+0x10 and pushes it with
   0x581a4f0 onto the channel at [closure+0x28], only when the closure's
   first byte is 0.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, fixed, read_va, relative_relocations, rip_target

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-hardfork-hashes-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

DRIVER = 0x5a34440
READ = 0x5647720
BODY = 0x4fc3490
WORKER = 0x5484670
SERIAL_WRAP = 0x4e48ee0
SERIAL_CLOSURE = 0x4e4b860
SERIALISER = 0x5480950
DIGEST_INPUT = 0x4e46090
DIGEST_SLOT, DIGEST_ROOT = 0x64e7820, 0x41c5140
VALUE = 0x452aab0
PUSH = 0x581a4f0

STRINGS = {
    0x93b070: b'hardfork_hashes',
    0x92a7f5: b'slow_abci_engine_read_increment',
    0x91875b: b'serialized abci state',
}

FIXED = {
    # driver head
    0x5a3446d: 'b90f000000',              # mov ecx, 15 (len "hardfork_hashes")
    0x5a34456: '488b7778',                # mov rsi, [rdi+0x78]
    0x5a3445a: '4883c610',                # add rsi, 0x10
    0x5a34517: '803800',                  # cmp byte [rax], 0
    0x5a3451a: '0f85d8000000',            # jne 0x5a345f8 (skip the send)
    0x5a34520: '488b442478',              # mov rax, [rsp+0x78]   (result +0x38)
    0x5a34547: '48898424b8020000',        # mov [rsp+0x2b8], rax  (message +0x0)
    0x5a34554: '488b4830',                # mov rcx, [rax+0x30]
    0x5a34558: 'f048ff4110',              # lock inc qword [rcx+0x10]
    0x5a3455d: '488b5828',                # mov rbx, [rax+0x28]   (channel)
    # read wrapper: per-minute block at runner +0xb50
    0x5647762: 'ba01000000',              # mov edx, 1
    0x564776c: '498d9d500b0000',          # lea rbx, [r13+0xb50]
    0x564783c: '498b8d580b0000',          # mov rcx, [r13+0xb58]
    0x5647854: '493b85600b0000',          # cmp rax, [r13+0xb60]
    0x5647873: '498985600b0000',          # mov [r13+0xb60], rax
    0x5647886: '48c74424781f000000',      # mov qword [rsp+0x78], 31
    # body: read lock, 1e9 check, worker argument
    0x4fc34ea: '498dac24a8060000',        # lea rbp, [r12+0x6a8]
    0x4fc351f: '488d4810',                # lea rcx, [rax+0x10]  (one reader)
    0x4fc35a9: '4181bc2428010000' + '00ca9a3b',  # cmp dword [r12+0x128], 1e9
    0x4fc3754: '498db424000b0000',        # lea rsi, [r12+0xb00]
    # worker
    0x5484684: '488b1e',                  # mov rbx, [rsi]
    0x5484687: '4c8b7b28',                # mov r15, [rbx+0x28]   (height)
    0x548469e: 'b901000000',              # mov ecx, 1
    0x54846e0: 'ba01000000',              # mov edx, 1
    0x54847a5: 'ba01000000',              # mov edx, 1
    0x54847da: '4d897d38',                # mov [r13+0x38], r15
    0x54847ee: '410f114540',              # movups [r13+0x40], xmm0
    0x54847f3: '410f114d50',              # movups [r13+0x50], xmm1
    0x5484808: '410f114560',              # movups [r13+0x60], xmm0
    0x548480d: '410f114d70',              # movups [r13+0x70], xmm1
    # serialiser closure config
    0x4e4b8c1: 'c744240800040001',        # mov dword [rsp+8], 0x01000400
    0x4e4b8c9: 'c644240c00',              # mov byte [rsp+0xc], 0
}
CALLS = {
    # site: target (rel32 call)
    0x5a34472: READ,
    0x5a3459c: PUSH,
    0x5647767: 0x4e46b50,
    0x4fc3764: WORKER,
    0x54846a3: SERIAL_WRAP,
    0x54846e5: DIGEST_INPUT,
    0x54847aa: VALUE,
    0x4e48f7e: 0x4e36140,
    0x4e361fb: SERIAL_CLOSURE,
    0x4e4b8de: SERIALISER,
}
REFERENCES = (
    (0x5a3445e, b'\x48\x8d\x15', 7, 0x93b070),
    (0x564787a, b'\x48\x8d\x05', 7, 0x92a7f5),
    (0x564788f, b'\x66\x0f\x28\x05', 8, 0x453530),
    (0x4e4ba2f, b'\x48\x8d\x05', 7, 0x91875b),
    (0x54846f7, b'\xff\x15', 6, DIGEST_SLOT),
)


def call_target(data, va):
    raw = read_va(data, va, 5)
    if raw[0] != 0xe8:
        raise ValueError(f'call at {va:#x} changed')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS.items():
        if call_target(data, va) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, text in STRINGS.items():
        if read_va(data, va, len(text)) != text:
            raise ValueError(f'string at {va:#x} changed')
    if relative_relocations(data).get(DIGEST_SLOT) != DIGEST_ROOT:
        raise ValueError('digest slot changed')
    low, high = struct.unpack('<dd', read_va(data, 0x453530, 16))
    if (low, high) != (0.01, 0.05):
        raise ValueError('read increment constants changed')
    census = {hex(t): [hex(v) for v in direct_calls(data, t)]
              for t in (READ, WORKER, SERIAL_WRAP, SERIAL_CLOSURE, VALUE, PUSH)}
    if census[hex(READ)] != ['0x5a34472']:
        raise ValueError('read wrapper census changed')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'driver_head': {
            'name': '0x93b070 hardfork_hashes (15 bytes)',
            'call': '0x5a34472 -> 0x5647720 with rsi = [closure+0x78]+0x10',
            'send_gate': 'byte [closure] == 0 (0x5a34517)',
            'message': '0x28 bytes: result +0x38 (height), result +0x40..+0x60 (32-byte value)',
            'channel': '[closure+0x28], push 0x581a4f0 at 0x5a3459c; counter [closure+0x30]+0x10 lock inc',
        },
        'read_wrapper': {
            'fn': hex(READ),
            'blocking': '0x4e46b50 (edx = 1) -> 0x4f21a90 -> body 0x4fc3490',
            'per_minute_block': 'runner +0xb50 lock byte, +0xb58 divisor, +0xb60 last minute, +0xb68 count',
            'record': 'slow_abci_engine_read_increment (31 bytes) with (0.01, 0.05) when the minute changes',
        },
        'body': {
            'fn': hex(BODY),
            'read_lock': 'runner +0x6a8, add 0x10 per reader (0x4fc351f)',
            'check': 'dword runner +0x128 == 1000000000 (0x4fc35a9)',
            'worker_call': '0x4fc3764 -> 0x5484670 with rsi = runner +0xb00',
        },
        'worker': {
            'fn': hex(WORKER),
            'height': 'box +0x28 -> output +0x38',
            'serialised_state': '0x4e48ee0 (ecx = 1) -> 0x4e36140 -> closure 0x4e4b860 -> 0x5480950 '
                                'cfg 0x01000400; references "serialized abci state"; output +0x0..+0x38',
            'abci_digest': '0x4e46090 (edx = 1) then slot 0x64e7820 -> 0x41c5140; output +0x60..+0x80',
            'value': '0x452aab0 (edx = 1) -> 32 bytes at output +0x40..+0x60',
        },
        'direct_call_census': census,
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
    print('read_callers=%d worker_callers=%d' % (
        len(result['direct_call_census'][hex(READ)]), len(result['direct_call_census'][hex(WORKER)])))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
