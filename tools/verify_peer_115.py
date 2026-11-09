#!/usr/bin/env python3
"""Bind the node #115 verify_peer future 0x2ae0920 and how its caller handles the result (29th stage).

The 28th stage found that each 10-second tick of the lu.rs unfold stream makes
the caller in 0x2accee0 poll 0x2ae0920, which writes a request named
verify_peer with a dword at +0x22 and 4001 at +0x26. This tool binds:

1. the future's resume table 0x604058 (five states) and its start state: it
   copies the dword at +0x1 (written by the caller from state +0x1268) and
   awaits 0x2ae0100 first;
2. 0x2ae0100 writes the name gossip_rpc_request (18 bytes) and 10.0 at +0x470;
3. only when that result tag is 0x44 does 0x2ae0920 write the verify_peer
   request: +0x10 name (11 bytes), +0x20 word 0, +0x22 the dword, +0x26 word
   0xfa1 (4001), +0x110 the f64 5.0;
4. a 5-second deadline: CLOCK_MONOTONIC now plus 5.0 converted by 0x15ed960,
   a Tokio sleep (timer-disabled panic text, 0x73 bytes), the inner future
   polled by 0x2b782e0, and the sleep polled through slot 0x64e1358; on
   expiry the name is formatted with the lu::timeout template and the result
   tag is 0x34; an inner result 2 also gives 0x34; other results give 0x44;
5. the caller 0x2accee0: on 0x44 with a zero success counter (+0x1250) it
   calls 0x4fac470 ("marking node_ip as verified", 27 bytes) with the dword,
   then increments the counter (saturating); any other non-pending tag
   formats "peer verification failed: {}", records "dropping connection"
   (19 bytes) with the dword, the counter and 12 bytes at +0x126c, and
   releases the unfold seed at +0x1248.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
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
PACKET = ROOT / 'research/work-items/RE-008-verify-peer-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

VERIFY = 0x2ae0920
GOSSIP_RPC = 0x2ae0100
MARK_VERIFIED = 0x4fac470
RESUME_TABLE = 0x604058
RESUME_TARGETS = (0x2ae094d, 0x2ae11ae, 0x2ae11bb, 0x2ae096d, 0x2ae099d)
FIVE = 0x4593d0

STRINGS = {
    0x605ad5: b'verify_peer',
    0x605aac: b'gossip_rpc_request',
    0x919921: b'marking node_ip as verified',
    0x6056de: b'dropping connection',
    0x44900c: b'\x1apeer verification failed: \xc0\x00',
    0x4326d0: b'\x0clu::timeout ',
    0x94ca6b: b'A Tokio 1.x context was found, but timers are disabled.',
}
SLOTS = {
    0x64e0f70: 0x15ed960,   # seconds conversion (#5861)
    0x64e0848: 0x5cf2b50,   # runtime handle
    0x64e1358: 0x5ce94c0,   # sleep poll
    0x64e7340: MARK_VERIFIED,
}

FIXED = {
    # resume dispatch on the state byte
    0x2ae093a: '0fb606',                      # movzx eax, byte [rsi]
    # start state: copy the caller's dword, await 0x2ae0100
    0x2ae094d: '8b4301',                      # mov eax, [rbx+1]
    0x2ae0950: '894305',                      # mov [rbx+5], eax
    0x2ae0957: '894309',                      # mov [rbx+9], eax
    0x2ae095a: '48c7431001000000',            # mov qword [rbx+0x10], 1
    0x2ae0962: '48894b28',                    # mov [rbx+0x28], rcx (&+9)
    0x2ae098c: '4080fd45',                    # cmp bpl, 0x45 (pending)
    0x2ae0b0e: '4080fd44',                    # cmp bpl, 0x44
    0x2ae0b12: '0f85d1050000',                # jne 0x2ae10e9 (pass the tag on)
    # verify_peer request
    0x2ae0b4c: '8b4305',                      # mov eax, [rbx+5]
    0x2ae0b56: '4c896310',                    # mov [rbx+0x10], r12 (name)
    0x2ae0b5a: '48c743180b000000',            # mov qword [rbx+0x18], 11
    0x2ae0b62: '66c743200000',                # mov word [rbx+0x20], 0
    0x2ae0b68: '894322',                      # mov [rbx+0x22], eax
    0x2ae0b6b: '66c74326a10f',                # mov word [rbx+0x26], 0xfa1
    0x2ae0b78: '48b80000000000001440',        # movabs rax, 5.0
    0x2ae0b82: '488983' '10010000',           # mov [rbx+0x110], rax
    # deadline
    0x2ae0c6c: 'bf01000000',                  # mov edi, 1 (CLOCK_MONOTONIC)
    0x2ae0c88: 'f20f1083a0030000',            # movsd xmm0, [rbx+0x3a0] (5.0)
    0x2ae0d39: '81b990000000' '00ca9a3b',       # cmp dword [rcx+0x90], 1e9 (timers disabled)
    # inner poll and sleep poll
    0x2ae0e82: '4983fe03',                    # cmp r14, 3 (inner pending)
    0x2ae0ea4: '84c0',                        # test al, al (sleep pending)
    0x2ae1003: '4183fe02',                    # cmp r14d, 2
    0x2ae1012: '40b534',                      # mov bpl, 0x34
    0x2ae10c7: '40b544',                      # mov bpl, 0x44
    0x2ae11a1: 'be73000000',                  # mov esi, 0x73 (panic text length)
    # 0x2ae0100 head
    0x2ae015e: '48c7434012000000',            # mov qword [rbx+0x40], 18
    0x2ae0175: '48b80000000000002440',        # movabs rax, 10.0
    0x2ae017f: '4889837004' '0000',           # mov [rbx+0x470], rax
    # caller 0x2accee0: build and poll the future
    0x2ad0260: '8b8368120000',                # mov eax, [rbx+0x1268]
    0x2ad0266: 'c6838812000000',              # mov byte [rbx+0x1288], 0
    0x2ad026d: '898389120000',                # mov [rbx+0x1289], eax
    0x2ad0298: '4080fd45',                    # cmp bpl, 0x45
    # caller: success
    0x2ad0302: '4080fd44',                    # cmp bpl, 0x44
    0x2ad0306: '0f8513020000',                # jne 0x2ad051f (failure)
    0x2ad030c: '488b8350120000',              # mov rax, [rbx+0x1250]
    0x2ad0313: '4885c0',                      # test rax, rax
    0x2ad0316: '7521',                        # jne 0x2ad0339 (skip marking)
    0x2ad031f: '8bb368120000',                # mov esi, [rbx+0x1268]
    0x2ad0339: '48ffc0',                      # inc rax
    0x2ad033c: '48c7c1ffffffff',              # mov rcx, -1
    0x2ad0343: '480f45c8',                    # cmovne rcx, rax (saturate)
    0x2ad0347: '48898b50120000',              # mov [rbx+0x1250], rcx
    # caller: failure
    0x2ad0605: '8b8368120000',                # mov eax, [rbx+0x1268]
    0x2ad0623: '488b8b50120000',              # mov rcx, [rbx+0x1250]
    0x2ad062a: '488b936c120000',              # mov rdx, [rbx+0x126c]
    0x2ad0631: '8bb374120000',                # mov esi, [rbx+0x1274]
    0x2ad0655: '48c78424f00200' '0013000000', # mov qword [rsp+0x2f0], 19
    0x2ad06e4: '4c8bb348120000',              # mov r14, [rbx+0x1248] (seed)
    # 0x4fac470: log text with the dword
    0x4fac47a: '89f5',                        # mov ebp, esi
    0x4fac4a9: '48c74424181b000000',          # mov qword [rsp+0x18], 27
    0x4fac4b2: '896c2420',                    # mov [rsp+0x20], ebp
}
RIP_REFS = (
    # (instruction va, prefix, length, target)
    (0x2ae093d, b'\x48\x8d\x0d', 7, RESUME_TABLE),
    (0x2ae0b4f, b'\x4c\x8d\x25', 7, 0x605ad5),
    (0x2ae0c90, b'\xff\x15', 6, 0x64e0f70),
    (0x2ae0d0e, b'\x48\x8d\x3d', 7, 0x6447128),
    (0x2ae0d15, b'\xff\x15', 6, 0x64e0848),
    (0x2ae0e9e, b'\xff\x15', 6, 0x64e1358),
    (0x2ae0f2e, b'\x48\x8d\x3d', 7, 0x4326d0),
    (0x2ae1193, b'\x48\x8d\x3d', 7, 0x94ca6b),
    (0x2ae119a, b'\x48\x8d\x15', 7, 0x6447128),
    (0x2ae0153, b'\x4c\x8d\x35', 7, 0x605aac),
    (0x2ad0590, b'\x48\x8d\x35', 7, 0x44900c),
    (0x2ad0646, b'\x48\x8d\x15', 7, 0x6056de),
    (0x2ad032c, b'\xff\x15', 6, 0x64e7340),
    (0x4fac49d, b'\x48\x8d\x05', 7, 0x919921),
)
DIRECT_CALLS = (
    (0x2ae097f, GOSSIP_RPC),
    (0x2ae0c71, 0x5c842e0),     # clock_gettime wrapper
    (0x2ae0e75, 0x2b782e0),     # inner poll
    (0x2ae0f3d, 0x2b41590),     # format
    (0x2ad028b, VERIFY),
    (0x2ad0683, 0x2d4e730),     # event record
)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


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


def direct_calls(data, target):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    code = data[sec['offset']:sec['offset'] + sec['size']]
    out = []
    for m in re.finditer(rb'\xe8', code):
        i = m.start()
        if i + 5 <= len(code) and sec['address'] + i + 5 + struct.unpack_from('<i', code, i + 1)[0] == target:
            out.append(sec['address'] + i)
    return out


def bind(data):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, prefix, length, target in RIP_REFS:
        raw = read_va(data, va, length)
        if raw[:len(prefix)] != prefix or va + length + struct.unpack_from('<i', raw, len(prefix))[0] != target:
            raise ValueError(f'reference at {va:#x} changed')
    for va, target in DIRECT_CALLS:
        raw = read_va(data, va, 5)
        if raw[0] != 0xe8 or va + 5 + struct.unpack_from('<i', raw, 1)[0] != target:
            raise ValueError(f'call at {va:#x} changed')
    rel = relative_relocations(data)
    for slot, target in SLOTS.items():
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    for va, text in STRINGS.items():
        if read_va(data, va, len(text)) != text:
            raise ValueError(f'string at {va:#x} changed')
    table = read_va(data, RESUME_TABLE, 4 * len(RESUME_TARGETS))
    targets = tuple(RESUME_TABLE + struct.unpack_from('<i', table, 4 * i)[0] for i in range(len(RESUME_TARGETS)))
    if targets != RESUME_TARGETS:
        raise ValueError('resume table changed')
    five = struct.unpack('<d', read_va(data, FIVE, 8))[0]
    if five != 5.0:
        raise ValueError('timeout constant changed')
    verify_calls = direct_calls(data, VERIFY)
    gossip_calls = direct_calls(data, GOSSIP_RPC)
    mark_calls = direct_calls(data, MARK_VERIFIED)

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'transport',
        'resume_table': {'table': hex(RESUME_TABLE), 'targets': [hex(t) for t in targets]},
        'start_state': {
            'copies': '+0x1 dword -> +0x5 and +0x9; +0x10 = 1; +0x28 = &+0x9',
            'awaits': hex(GOSSIP_RPC) + ' (name gossip_rpc_request, 18 bytes; 10.0 at +0x470)',
            'pending_tag': '0x45',
            'continue_tag': '0x44; any other tag is returned as is',
        },
        'request': {
            'name': 'verify_peer (11 bytes) at +0x10/+0x18',
            'address': '+0x20 word 0, +0x22 dword from +0x5, +0x26 word 0xfa1 (4001)',
            'timeout_seconds': five,
        },
        'deadline': {
            'clock': 'clock id 1 via 0x5c842e0, stored at +0x378',
            'conversion': 'slot 0x64e0f70 -> 0x15ed960',
            'timer_check': 'runtime field +0x90 == 1e9 -> panic text 0x94ca6b (0x73 bytes), Location 0x6447128',
            'inner_poll': '0x2b782e0 on +0x188; 3 = pending',
            'sleep_poll': 'slot 0x64e1358 -> 0x5ce94c0; 0 = expired',
            'on_expiry': 'format lu::timeout template 0x4326d0 with the name; result tag 0x34',
            'inner_result_2': 'result tag 0x34',
            'inner_result_other': 'result tag 0x44',
        },
        'caller': {
            'fn': '0x2accee0',
            'argument': '+0x1268 dword -> future +0x1289 (future at +0x1288)',
            'on_0x44': 'if +0x1250 == 0: slot 0x64e7340 -> 0x4fac470 ("marking node_ip as verified", the dword); '
                       'then +0x1250 += 1 saturating',
            'on_other': '"peer verification failed: {}" (0x44900c); event "dropping connection" (19 bytes) '
                        'with the dword, +0x1250 and +0x126c..+0x1278 via 0x2d4e730; seed +0x1248 released',
        },
        'census': {
            'direct_calls_to_verify': [hex(v) for v in verify_calls],
            'direct_calls_to_gossip_rpc': [hex(v) for v in gossip_calls],
            'direct_calls_to_mark_verified': [hex(v) for v in mark_calls],
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
    c = result['census']
    print(f"verify_calls={len(c['direct_calls_to_verify'])} gossip_calls={len(c['direct_calls_to_gossip_rpc'])}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
