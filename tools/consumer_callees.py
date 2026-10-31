#!/usr/bin/env python3
"""RE-001: bound the five callee targets reached from node #94 0x1455c00.

Static, offline, read-only. PR #634 recorded eleven RIP-relative operands in
0x1455c00; five of them are RELATIVE-bound ``.text`` addends (the rest are the
two GOT ``memcpy`` imports and repeated slots). This tool re-derives, per
addend: the FDE extent, body digest, pinned instruction bytes, every byte
``E8 rel32`` candidate inside the body, and each pinned RIP-relative operand
with its resolved target or RELATIVE slot addend.

No high-level name, Rust implementation, complete instruction decode, callee
closure beyond these five entries, or runtime behaviour is claimed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bincode_varint as bv  # noqa: E402
import elf_index  # noqa: E402

# (start, expected end, anchors, operands)
# anchor: (va, exact bytes, meaning)
# operand: (site, prefix, instruction length, kind, expected, addend)
#   kind 'target' -> expected absolute VA of a rip-relative lea
#   kind 'slot'   -> expected GOT/data slot VA plus its RELATIVE addend
#   kind 'direct' -> expected E8 rel32 target
TARGETS = (
    (0x54C8CB0, 0x54C8D55, (
        (0x54C8CB0, 'f30f1efa', 'endbr64'),
        (0x54C8CB4, '4881fe00100000', 'cmp rsi,0x1000: size threshold'),
        (0x54C8CBB, '0f878f000000', 'ja slow tail when size > 0x1000'),
        (0x54C8CC1, '85d2', 'test edx,edx: alignment argument'),
        (0x54C8CC3, '0f8587000000', 'jne slow tail for a nonzero alignment'),
        (0x54C8CC9, 'f7c7ff0f0000', 'test edi,0xfff: low pointer bits'),
    ), (
        (0x54C8CD1, '488d0d', 7, 'target', 0x59AFD00, None),
        (0x54C8CE7, '4c8d15', 7, 'target', 0x59AFF40, None),
    )),
    (0x1346068, 0x134607D, (
        (0x1346068, '554889e5', 'push rbp; mov rbp,rsp'),
        (0x134606C, '4885ff', 'test rdi,rdi'),
        (0x134606F, '7506', 'jne +6: selects the second indirect call'),
    ), (
        (0x1346071, 'ff15', 6, 'slot', 0x576E0C0, 0x1346080),
        (0x1346077, 'ff15', 6, 'slot', 0x576E020, 0x1345E2A),
    )),
    (0x54C06B0, 0x54C0772, (
        (0x54C06B0, 'f30f1efa', 'endbr64'),
        (0x54C06B4, '4881ff00100000', 'cmp rdi,0x1000: size threshold'),
        (0x54C06BB, '0f877f000000', 'ja slow tail when size > 0x1000'),
    ), (
        (0x54C06C1, '488d15', 7, 'target', 0x59AFD00, None),
        (0x54C06D7, '488d35', 7, 'target', 0x59AFF40, None),
    )),
    (0x13460A0, 0x13460FB, (
        (0x13460A0, '554889e5415653', 'push rbp; mov rbp,rsp; push r14; push rbx'),
        (0x13460AB, '4889fb', 'mov rbx,rdi: keeps the argument pointer'),
        (0x13460B5, '4883f809', 'cmp rax,9: minimum before cmovae'),
    ), (
        (0x13460CE, 'e8', 5, 'direct', 0x1346100, None),
    )),
    (0x157B480, 0x157B499, (
        (0x157B480, '554889e54889fa', 'push rbp; mov rbp,rsp; mov rdx,rdi'),
        (0x157B48E, 'be39000000', 'mov esi,0x39'),
    ), (
        (0x157B487, '488d3d', 7, 'target', 0x252CF8, None),
        (0x157B493, 'ff15', 6, 'slot', 0x576E098, 0x157B810),
    )),
)

LIMITATIONS = (
    'Five RELATIVE addends of 0x1455c00 only. E8 rows are byte-pattern candidates, '
    'not a decoded call census. No native decode, callee closure of the recorded '
    'targets, Rust implementation, semantic name, runtime reachability or gate is '
    'claimed. FDE extents are unwind-described ranges, not validated boundaries.'
)


def scan(data, expected_sha256=bv.SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise bv.EvidenceError(f'input SHA-256 {digest} is not node #94 {bv.SHA256}')
    secs = bv.sections(data)
    all_sections = elf_index.sections(data)

    def describe(va):
        for section in all_sections:
            if section['address'] <= va < section['address'] + section['size']:
                return {'name': section['name'], 'type': section['type'],
                        'file_backed': section['type'] != 8 and
                        section['offset'] + (va - section['address']) < len(data)}
        return None

    text = secs['.text']
    text_bytes = data[text['offset']:text['offset'] + text['size']]
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
        for site, prefix_hex, length, kind, expected, addend in operands:
            prefix = bytes.fromhex(prefix_hex)
            index = site - start
            if not 0 <= index <= len(body) - length or body[index:index + len(prefix)] != prefix:
                raise bv.EvidenceError(f'0x{start:x}: operand at {site:#x} is not {prefix_hex}')
            disp = struct.unpack_from('<i', body, index + length - 4)[0]
            value = site + length + disp
            row = {'site_va': f'{site:#x}', 'instruction_bytes': body[index:index + length].hex(),
                   'kind': kind}
            if kind == 'direct':
                if value != expected:
                    raise bv.EvidenceError(f'{site:#x}: call target {value:#x} != {expected:#x}')
                row['target_va'] = f'{value:#x}'
                row['target_section'] = describe(value)
            elif kind == 'target':
                if value != expected:
                    raise bv.EvidenceError(f'{site:#x}: rip target {value:#x} != {expected:#x}')
                row['target_va'] = f'{value:#x}'
                row['target_section'] = describe(value)
            else:
                if value != expected:
                    raise bv.EvidenceError(f'{site:#x}: rip operand {value:#x} != slot {expected:#x}')
                if relocs.get(value) != addend:
                    raise bv.EvidenceError(f'{value:#x}: RELATIVE addend is not {addend:#x}')
                row['slot_va'] = f'{value:#x}'
                row['slot_section'] = describe(value)
                row['relocation'] = {'kind': 'relative', 'type': 8, 'addend': f'{addend:#x}',
                                     'target_va': f'{addend:#x}'}
                row['target_section'] = describe(addend)
            row['target_is_fde_start'] = value in fdes or (addend is not None and addend in fdes)
            resolved.append(row)
        e8 = []
        for index in range(len(body) - 4):
            if body[index] == 0xE8:
                target = start + index + 5 + struct.unpack_from('<i', body, index + 1)[0]
                e8.append({'site_va': f'{start + index:#x}', 'target_va': f'{target:#x}'})
        rows.append({
            'start_va': f'{start:#x}', 'end_va': f'{end:#x}', 'size': end - start,
            'file_offset': f'{offset:#x}', 'body_sha256': hashlib.sha256(body).hexdigest(),
            'anchors': pinned, 'operands': resolved, 'e8_byte_candidates': e8,
        })
    return {
        'schema': 're001-consumer-callees/1',
        'target': {'release': 94, 'sha256': digest, 'size': len(data)},
        'coordinates': 'linked VAs; file_offset = va - 0x1000 inside .text',
        'functions': rows,
        'function_count': len(rows),
        'limitations': LIMITATIONS,
    }


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
                raise bv.EvidenceError(f'{args.check}: consumer callee record differs')
            sys.stdout.buffer.write(b'Consumer callee extents reproduce exactly.\n')
            return 0
        if args.output is not None:
            args.output.write_bytes(text)
        else:
            sys.stdout.buffer.write(text)
        return 0
    except (bv.EvidenceError, OSError, struct.error, ValueError) as error:
        print(f'consumer_callees: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
