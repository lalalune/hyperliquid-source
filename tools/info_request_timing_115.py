#!/usr/bin/env python3
"""Bind what the node #115 info_server handler times, and its user_ip.rs:28:48 future (24th stage).

Continues open PR #5956, which found that the info_server request handler
0x2e3ed10 passes the handle_request_rate_limiter cell and an f64 from two
clock calls to the wrapper 0x15494d0. This tool binds:

1. the two clock reads: 0x5c842e0 (clock_gettime through GLOB_DAT slot
   0x64e1248) with edi = 1 at 0x2e3fb25 and at 0x2e3fc63; the first result is
   kept in r14 / r12d across one call through slot 0x64e8918 -> 0x2ecf9d0 with
   the request copied to state +0x428, the conversion 0x273bf30 and the
   response store at state +0x468..+0x4b0;
2. the difference 0x5c84210 (now, start): Ok tag 0 with (secs, nanos) when
   now >= start, else tag 1; the handler turns Ok into secs + nanos / 1e9 and
   passes 0.0 for the Err tag and for +inf;
3. the user_ip.rs:28:48 Location: its only two references are the
   `async fn` resumed-after-completion and resumed-after-panicking panics of
   an inner future at state +0x570 whose state byte is +0x608 (jump table
   0x6164a8, five arms); arm 0 stores the f64 0.014 at +0x570 and polls the
   future through 0x2d4f790 after the timing call, only when bpl is set.

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
PACKET = ROOT / 'research/work-items/RE-008-info-request-timing-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

CLOCK, DIFF, POLL_INNER = 0x5c842e0, 0x5c84210, 0x2d4f790
DISPATCH_SLOT, DISPATCH = 0x64e8918, 0x2ecf9d0
CELL_SLOT, CELL = 0x64e8920, 0x64f3a18
WRAPPER_SLOT = 0x64e1030
CLOCK_GOT = 0x64e1248
PANIC_DONE_SLOT, PANIC_DONE = 0x64e1368, 0x1681e60
PANIC_PANICKED_SLOT, PANIC_PANICKED = 0x64e1360, 0x1681e80
LOC_USER_IP, LOC_ROUTER = 0x6450438, 0x6450408
STATE_TABLE = 0x6164a8
INF, BILLION = 0x459010, 0x458d50

FIXED = {
    # first clock read, kept in callee-saved r14 / r12d
    0x2e3fb20: 'bf01000000',                # mov edi, 1
    0x2e3fb2a: '4989c6',                    # mov r14, rax          (secs)
    0x2e3fb2d: '4189d4',                    # mov r12d, edx         (nanos)
    0x2e3fb30: '4c8dab28040000',            # lea r13, [rbx+0x428]  (request)
    0x2e3fb3f: '4c89ee',                    # mov rsi, r13
    # second clock read and the difference
    0x2e3fc5e: 'bf01000000',                # mov edi, 1
    0x2e3fc68: '48898424b80a0000',          # mov [rsp+0xab8], rax  (now)
    0x2e3fc77: '4c89b424d80b0000',          # mov [rsp+0xbd8], r14  (start secs)
    0x2e3fc7f: '4489a424e00b0000',          # mov [rsp+0xbe0], r12d (start nanos)
    0x2e3fc87: '488dbc2400010000',          # lea rdi, [rsp+0x100]  (result)
    0x2e3fc8f: '488db424b80a0000',          # lea rsi, [rsp+0xab8]  (now)
    0x2e3fc9f: '4c89f2',                    # mov rdx, r14 (= &start)
    0x2e3fca7: '80bc240001000000',          # cmp byte [rsp+0x100], 0 (Ok tag)
    0x2e3fcaf: '660f57c0',                  # xorpd xmm0, xmm0
    0x2e3fcb3: '660f57db',                  # xorpd xmm3, xmm3
    0x2e3fced: 'f20f2a9c2410010000',        # cvtsi2sd xmm3, [rsp+0x110] (nanos)
    0x2e3fd19: 'f20f58da',                  # addsd xmm3, xmm2       (secs + nanos/1e9)
    0x2e3fd29: '74a0',                      # je 0x2e3fccb           (== inf -> keep 0.0)
    0x2e3fd2b: '660f28c3',                  # movapd xmm0, xmm3
    # difference: Ok when now >= start
    0x5c8422f: '4139f8',                    # cmp r8d, edi           (nanos)
    0x5c84232: '410f93c1',                  # setae r9b
    0x5c84239: '4839ce',                    # cmp rsi, rcx           (secs)
    0x5c8423c: '410f9dc2',                  # setge r10b
    0x5c84285: '48c70300000000',            # mov qword [rbx], 0     (Ok)
    0x5c842ac: '0f5705',                    # xorps xmm0, [rip+...]  (flip tag -> Err)
    # inner future: state byte +0x608, arm 0 init, poll after timing
    0x2e3fd51: '4084ed',                    # test bpl, bpl
    0x2e3fd61: 'c6830806000000',            # mov byte [rbx+0x608], 0
    0x2e3fd6f: '48b879e9263108ac8c3f',      # movabs rax, 0.014
    0x2e3fd79: '48898370050000',            # mov [rbx+0x570], rax
    0x2e3fd8a: '488b742430',                # mov rsi, [rsp+0x30]
    0x2e3fd98: '41c6042403',                # mov byte [r12], 3      (pending)
    0x2e3fe47: '0fb68308060000',          # movzx eax, byte [rbx+0x608]
    0x2e3ff01: '41c6042401',                # mov byte [r12], 1      (completed)
}
CALLS = (
    # (va, target) for E8 rel32
    (0x2e3fb25, CLOCK), (0x2e3fc63, CLOCK), (0x2e3fca2, DIFF), (0x2e3fd8f, POLL_INNER),
)
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x2e3fb42, b'\xff\x15', 6, DISPATCH_SLOT),
    (0x2e3fd44, b'\x48\x8b\x3d', 7, CELL_SLOT),
    (0x2e3fd4b, b'\xff\x15', 6, WRAPPER_SLOT),
    (0x5c842ed, b'\xff\x15', 6, CLOCK_GOT),
    (0x2e3fe55, b'\x48\x8d\x0d', 7, STATE_TABLE),
    (0x2e3fe69, b'\x48\x8d\x3d', 7, LOC_USER_IP),
    (0x2e3fe70, b'\xff\x15', 6, PANIC_DONE_SLOT),
    (0x2e40f43, b'\x48\x8d\x3d', 7, LOC_USER_IP),
    (0x2e40f4a, b'\xff\x15', 6, PANIC_PANICKED_SLOT),
    (0x2e3fd11, b'\xf2\x0f\x5e\x1d', 8, BILLION),
    (0x2e3fd1d, b'\x66\x0f\x2e\x1d', 8, INF),
    (0x1681e67, b'\x48\x8d\x3d', 7, 0x46f2ed),
    (0x1681e87, b'\x48\x8d\x3d', 7, 0x46f310),
)
# straight-line spans between the two clock reads, hashed; the README states the
# hand check that neither writes r14 or r12
SPANS = ((0x2e3fb2a, 0x2e3fb82), (0x2e3fbbe, 0x2e3fca7))


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


def relocations(data):
    rel, glob = {}, {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
            elif info & 0xffffffff == 6:
                glob[va] = info >> 32
    return rel, glob


def dynamic_symbol_name(data, index):
    secs = sections(data)
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    name_off = struct.unpack_from('<I', data, dynsym['offset'] + 24 * index)[0]
    start = dynstr['offset'] + name_off
    return data[start:data.index(b'\0', start)].decode()


def location(data, rel, va):
    path_ptr = rel[va]
    length, line, column = struct.unpack('<QII', read_va(data, va + 8, 16))
    return read_va(data, path_ptr, length).decode(), line, column


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def lea_refs(data, target):
    base, code = text(data)
    out = []
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if i + 7 <= len(code) and base + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == target:
            out.append(base + i)
    return out


def bind(data):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, target in CALLS:
        if rip_target(data, va, b'\xe8', 5) != target:
            raise ValueError(f'call at {va:#x} changed')
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')

    rel, glob = relocations(data)
    for slot, target in ((DISPATCH_SLOT, DISPATCH), (CELL_SLOT, CELL),
                         (PANIC_DONE_SLOT, PANIC_DONE), (PANIC_PANICKED_SLOT, PANIC_PANICKED)):
        if rel.get(slot) != target:
            raise ValueError(f'relocation at {slot:#x} changed')
    clock_symbol = dynamic_symbol_name(data, glob[CLOCK_GOT])
    if clock_symbol != 'clock_gettime':
        raise ValueError('clock symbol changed')

    inf, billion = (struct.unpack('<d', read_va(data, va, 8))[0] for va in (INF, BILLION))
    if inf != float('inf') or billion != 1e9:
        raise ValueError('constants changed')
    initial = struct.unpack('<d', bytes.fromhex(FIXED[0x2e3fd6f][4:]))[0]

    done = read_va(data, 0x46f2ed, 35)
    panicked = read_va(data, 0x46f310, 34)
    if done != b'`async fn` resumed after completion' or panicked != b'`async fn` resumed after panicking':
        raise ValueError('panic messages changed')
    user_ip = location(data, rel, LOC_USER_IP)
    if user_ip != ('info_server/src/user_ip.rs', 28, 48):
        raise ValueError('user_ip Location changed')
    user_ip_refs = lea_refs(data, LOC_USER_IP)
    if user_ip_refs != [0x2e3fe69, 0x2e40f43]:
        raise ValueError('user_ip Location reference census changed')

    arms = [STATE_TABLE + struct.unpack('<i', read_va(data, STATE_TABLE + 4 * i, 4))[0] for i in range(5)]
    if arms[:4] != [0x2e3fd6f, 0x2e3fe65, 0x2e40f3f, 0x2e3fd87]:
        raise ValueError('inner future state table changed')

    spans = {'%#x-%#x' % span: hashlib.sha256(read_va(data, span[0], span[1] - span[0])).hexdigest()
             for span in SPANS}

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'info-api',
        'handler': hex(0x2e3ed10),
        'clock': {
            'fn': hex(CLOCK),
            'symbol': '%s via GLOB_DAT %s' % (clock_symbol, hex(CLOCK_GOT)),
            'clock_id': 1,
            'reads': [hex(0x2e3fb25) + ' start -> r14 (secs), r12d (nanos)',
                      hex(0x2e3fc63) + ' now -> [rsp+0xab8]'],
        },
        'between_reads': {
            'dispatch': 'request copied to state +0x428; call slot %s -> %s (rdi = rsp+0x100, rsi = state+0x428) at %s'
                        % (hex(DISPATCH_SLOT), hex(DISPATCH), hex(0x2e3fb42)),
            'conversion': hex(0x273bf30) + ' (rsp+0x100 -> rsp+0x908), drop ' + hex(0x26b1890),
            'response_store': 'state +0x468..+0x4b0 from rsp+0x908..+0x948 (main path)',
            'span_sha256': spans,
        },
        'difference': {
            'fn': hex(DIFF),
            'args': 'rdi = rsp+0x100 (result), rsi = &now, rdx = &start',
            'ok': 'now >= start (secs signed, then nanos): tag qword 0, secs +0x8, nanos +0x10',
            'err': 'otherwise: recursive start - now, tag flipped by xorps with ' + hex(0x453aa0),
        },
        'recorded_value': {
            'ok': 'secs (u64 -> f64 via %s / %s) + nanos / %s' % (hex(0x451210), hex(0x450170), billion),
            'err_tag': 0.0,
            'equal_to_inf': 0.0,
            'call': 'cell %s through slot %s at %s' % (hex(CELL), hex(WRAPPER_SLOT), hex(0x2e3fd4b)),
        },
        'user_ip_future': {
            'location': '%s:%d:%d' % user_ip,
            'location_refs': [hex(v) for v in user_ip_refs],
            'state': 'byte state +0x608, future at state +0x570, table %s' % hex(STATE_TABLE),
            'arms': {'0': hex(arms[0]) + ' store %r at +0x570, state +0x600 = 0, then poll' % initial,
                     '1': hex(arms[1]) + ' ' + done.decode() + ' (slot %s)' % hex(PANIC_DONE_SLOT),
                     '2': hex(arms[2]) + ' ' + panicked.decode() + ' (slot %s)' % hex(PANIC_PANICKED_SLOT),
                     '3': hex(arms[3]) + ' poll again'},
            'poll': '%s (rdi = state+0x570, rsi = [rsp+0x30]) at %s; pending -> state 3; ready -> state 1 at %s'
                    % (hex(POLL_INNER), hex(0x2e3fd8f), hex(0x2e3ff01)),
            'entered_when': 'bpl != 0 at %s, after the wrapper call' % hex(0x2e3fd51),
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
    print('clock=%s user_ip=%s' % (result['clock']['symbol'], result['user_ip_future']['location']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
