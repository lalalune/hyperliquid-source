#!/usr/bin/env python3
"""RE-001: bound two downstream callees reached from node #94 0x1455c00.

0x1455c00 reaches 0x13460a0 (direct call), and 0x157b480 (RELATIVE slot). This
tool records the next hop from each: 0x1346100 (called by 0x13460a0) and
0x157b810 (called through slot 0x576e098 by 0x157b480). For each target it
re-derives the FDE extent, body digest, pinned instruction bytes, byte-pattern
E8 candidates, and every observed RIP-relative `.got` operand with its
resolved RELATIVE addend.

No high-level name, Rust implementation, complete decode or call-graph closure
beyond these two entries is claimed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bincode_varint as bv  # noqa: E402

TARGETS = (
    (0x1346100, 0x1346182, (
        (0x1346100, '554889e54157415653', 'push rbp; mov rbp,rsp; push r15; push r14; push rbx'),
        (0x1346109, '50', 'push rax'),
        (0x134610A, '4889fb', 'mov rbx,rdi: keeps the first argument'),
        (0x134610D, '41bf01000000', 'mov r15d,1'),
        (0x1346113, '4885c9', 'test rcx,rcx'),
        (0x1346116, '790a', 'jns +0xa'),
        (0x1346118, 'b808000000', 'mov eax,8'),
        (0x134611D, '4531f6', 'xor r14d,r14d'),
    ), (
        (0x1346130, 'ff15', 6, 'slot', 0x576E030, 0x54C5620),
        (0x1346145, 'ff15', 6, 'slot', 0x576DFD8, 0x54C06B0),
    )),
    (0x157B810, 0x157B83C, (
        (0x157B810, '554889e54883ec30', 'push rbp; mov rbp,rsp; sub rsp,0x30'),
        (0x157B818, '48897df0', 'mov [rbp-0x10],rdi'),
        (0x157B81C, '488975f8', 'mov [rbp-8],rsi'),
        (0x157B820, '488d45f0', 'lea rax,[rbp-0x10]'),
        (0x157B824, '488945d8', 'mov [rbp-0x28],rax'),
        (0x157B828, '488955e0', 'mov [rbp-0x20],rdx'),
        (0x157B82C, '66c745e80100', 'mov word [rbp-0x18],1'),
    ), (
        (0x157B836, 'ff15', 6, 'slot', 0x57706E0, 0x4ECDCF0),
    )),
)

LIMITATIONS = (
    'Two downstream callees only. E8 rows are byte-pattern candidates, not a '
    'decoded call census. No native decode, semantic name, callee closure of '
    '0x54c5620/0x54c06b0/0x4ecdcf0, Rust implementation, runtime reachability or '
    'gate is claimed. FDE extents are unwind-described ranges.'
)


def scan(data, expected_sha256=bv.SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise bv.EvidenceError(f'input SHA-256 {digest} is not node #94 {bv.SHA256}')
    secs = bv.sections(data)
    fdes = bv.fde_extents(data, secs)
    relocs = bv.relative_relocs(data, secs)
    rows = []
    for start, expected_end, anchors, operands in TARGETS:
        end = fdes.get(start)
        if end != expected_end:
            raise bv.EvidenceError(f'0x{start:x}: FDE extent is not 0x{start:x}..0x{expected_end:x}')
        offset = bv.va_to_off(secs, start)
        body = data[offset:offset + (end - start)]
        pinned = []
        for va, hexbytes, meaning in anchors:
            want = bytes.fromhex(hexbytes)
            index = va - start
            if not 0 <= index <= len(body) - len(want) or body[index:index + len(want)] != want:
                raise bv.EvidenceError(f'0x{start:x}: bytes at {va:#x} are not {hexbytes}')
            pinned.append({'va': f'{va:#x}', 'bytes': hexbytes, 'meaning': meaning})
        resolved = []
        for site, prefix_hex, length, kind, slot, addend in operands:
            prefix = bytes.fromhex(prefix_hex)
            index = site - start
            if not 0 <= index <= len(body) - length or body[index:index + len(prefix)] != prefix:
                raise bv.EvidenceError(f'0x{start:x}: operand at {site:#x} is not {prefix_hex}')
            disp = struct.unpack_from('<i', body, index + length - 4)[0]
            value = site + length + disp
            if value != slot:
                raise bv.EvidenceError(f'{site:#x}: rip operand {value:#x} != slot {slot:#x}')
            if relocs.get(value) != addend:
                raise bv.EvidenceError(f'{slot:#x}: RELATIVE addend is not {addend:#x}')
            resolved.append({'site_va': f'{site:#x}', 'instruction_bytes': body[index:index + length].hex(),
                             'slot_va': f'{slot:#x}',
                             'relocation': {'kind': 'relative', 'type': 8, 'addend': f'{addend:#x}',
                                            'target_va': f'{addend:#x}'},
                             'target_is_fde_start': addend in fdes})
        e8 = []
        for index in range(len(body) - 4):
            if body[index] == 0xE8:
                target = start + index + 5 + struct.unpack_from('<i', body, index + 1)[0]
                e8.append({'site_va': f'{start + index:#x}', 'target_va': f'{target:#x}'})
        rows.append({'start_va': f'{start:#x}', 'end_va': f'{end:#x}', 'size': end - start,
                     'file_offset': f'{offset:#x}', 'body_sha256': hashlib.sha256(body).hexdigest(),
                     'anchors': pinned, 'operands': resolved, 'e8_byte_candidates': e8})
    return {'schema': 're001-consumer-downstream/1',
            'target': {'release': 94, 'sha256': digest, 'size': len(data)},
            'coordinates': 'linked VAs; file_offset = va - 0x1000 inside .text',
            'functions': rows, 'function_count': len(rows), 'limitations': LIMITATIONS}


def render(result):
    return json.dumps(result, indent=1, sort_keys=True) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=bv.TARGET)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', type=Path)
    args = parser.parse_args(argv)
    try:
        text = render(scan(args.input.read_bytes())).encode()
        if args.check is not None:
            if args.check.read_bytes() != text:
                raise bv.EvidenceError(f'{args.check}: downstream record differs')
            sys.stdout.buffer.write(b'Consumer downstream extents reproduce exactly.\n')
            return 0
        if args.output is not None:
            args.output.write_bytes(text)
        else:
            sys.stdout.buffer.write(text)
        return 0
    except (bv.EvidenceError, OSError, struct.error, ValueError) as error:
        print(f'consumer_downstream: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
