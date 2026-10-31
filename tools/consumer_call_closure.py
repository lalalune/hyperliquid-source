#!/usr/bin/env python3
"""RE-001: close the call/relocation targets of node #94 function 0x1455c00.

Static, offline, read-only. The function is the opaque consumer that the
periodic-slice packet (RE-001-periodic-slice-consumer-94) called but left
unresolved. This tool re-derives, from the pinned artifact bytes only:

* the unwind-described extent of 0x1455c00 and the digest of its body;
* every byte-pattern direct ``E8 rel32`` caller in ``.text`` and the FDE that
  contains each site;
* the absence of any ``R_X86_64_RELATIVE`` pointer slot to the target;
* every RIP-relative ``.got`` operand of the four observed encodings, with its
  resolved relocation (RELATIVE addend or GLOB_DAT symbol name);
* the single ``Location`` record reached from the in-function ``lea``;
* the single ``0x20`` immediate store between the two copy ranges;
* the overflow branch that reaches the panic helper.

No high-level name, Rust implementation, caller census beyond the stated
encodings or runtime behaviour is claimed. Output is canonical JSON (sorted
keys, fixed separators, trailing newline) written as bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bincode_varint as bv  # noqa: E402

TARGET = 0x1455C00
EXPECTED_END = 0x1455F8D
LOCATION_LEA = 0x1455F31
LOCATION_SLOT = 0x566AD18
LOCATION_PATH = b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/src/iter/traits/accum.rs'
LOCATION_LINE, LOCATION_COLUMN = 204, 1
SEPARATOR_SITE, SEPARATOR_BYTES, SEPARATOR_IMMEDIATE = 0x1455E47, '42c6043820', 0x20
OVERFLOW_SITE, OVERFLOW_BYTES, OVERFLOW_TARGET = 0x1455D13, '0f82', 0x1455F31

# (site, encoded prefix, instruction length, expected slot, expected binding)
# binding is ('relative', addend) or ('glob_dat', symbol-name).
INDIRECT = (
    (0x1455C73, '4c8b2d', 7, 0x576E010, ('relative', 0x54C8CB0)),
    (0x1455D33, 'ff15', 6, 0x576DFB8, ('relative', 0x1346068)),
    (0x1455D55, 'ff15', 6, 0x576E010, ('relative', 0x54C8CB0)),
    (0x1455DA8, 'ff15', 6, 0x576E010, ('relative', 0x54C8CB0)),
    (0x1455DBA, 'ff15', 6, 0x576DFD8, ('relative', 0x54C06B0)),
    (0x1455E10, 'ff15', 6, 0x576DFE0, ('glob_dat', 'memcpy')),
    (0x1455E3C, 'ff15', 6, 0x576E0C8, ('relative', 0x13460A0)),
    (0x1455E79, 'ff15', 6, 0x576DFE0, ('glob_dat', 'memcpy')),
    (0x1455ED7, '4c8b3d', 7, 0x576E010, ('relative', 0x54C8CB0)),
    (0x1455F38, 'ff15', 6, 0x576E118, ('relative', 0x157B480)),
    (0x1455F60, 'ff15', 6, 0x576E010, ('relative', 0x54C8CB0)),
)

LIMITATIONS = (
    'The caller set is a byte-pattern E8 rel32 scan over .text, not a decoded '
    'control-flow or indirect-call census; the companion native export rejects '
    'candidates that are not instruction starts. The indirect operand set covers '
    'only the ff15, ff25, 488d3d, 4c8b3d and 4c8b2d encodings observed here. '
    'FDE extents are unwind-described ranges, not validated function boundaries. '
    'No high-level name, Rust implementation, runtime reachability, complete '
    'callee closure or component gate is claimed.'
)


def relocations(data, secs):
    """Return every .rela.dyn entry keyed by slot VA."""
    r = secs['.rela.dyn']
    if r['size'] % 24:
        raise bv.EvidenceError('.rela.dyn size is not a multiple of 24')
    out = {}
    for offset in range(r['offset'], r['offset'] + r['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        out[slot] = {'type': info & 0xFFFFFFFF, 'symbol_index': info >> 32, 'addend': addend}
    return out


def dynamic_symbol(data, secs, index):
    if index == 0:
        raise bv.EvidenceError('relocation carries symbol index 0')
    entry = secs['.dynsym']['offset'] + index * 24
    if entry + 24 > secs['.dynsym']['offset'] + secs['.dynsym']['size']:
        raise bv.EvidenceError(f'symbol index {index} outside .dynsym')
    name_offset = struct.unpack_from('<I', data, entry)[0]
    start = secs['.dynstr']['offset'] + name_offset
    end = data.index(b'\0', start)
    if end >= secs['.dynstr']['offset'] + secs['.dynstr']['size']:
        raise bv.EvidenceError(f'symbol {index} name runs past .dynstr')
    return data[start:end].decode('ascii')


def operand_target(body, index, length):
    """Resolve a RIP-relative disp32 immediately before the instruction end."""
    disp = struct.unpack_from('<i', body, index + length - 4)[0]
    return TARGET + index + length + disp


def scan(data, expected_sha256=bv.SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise bv.EvidenceError(f'input SHA-256 {digest} is not node #94 {bv.SHA256}')
    secs = bv.sections(data)
    text = secs['.text']
    text_bytes = data[text['offset']:text['offset'] + text['size']]
    fdes = bv.fde_extents(data, secs)
    if fdes.get(TARGET) != EXPECTED_END:
        raise bv.EvidenceError(f'0x{TARGET:x}: FDE extent is not 0x{TARGET:x}..0x{EXPECTED_END:x}')
    offset = bv.va_to_off(secs, TARGET)
    body = data[offset:offset + (EXPECTED_END - TARGET)]
    starts = sorted(fdes)

    callers = bv.direct_calls(text_bytes, text['addr'], TARGET)
    if not callers:
        raise bv.EvidenceError('no byte-pattern caller reaches 0x%x' % TARGET)
    caller_rows = []
    for site in callers:
        index = __import__('bisect').bisect_right(starts, site) - 1
        if index < 0 or not starts[index] <= site < fdes[starts[index]]:
            raise bv.EvidenceError(f'caller {site:#x} is outside every FDE')
        caller_rows.append({'site_va': f'{site:#x}', 'site_offset': f'{site - text["addr"]:#x}',
                            'fde_start_va': f'{starts[index]:#x}',
                            'fde_end_va': f'{fdes[starts[index]]:#x}'})

    relocs = relocations(data, secs)
    pointer_slots = sorted(slot for slot, row in relocs.items()
                           if row['type'] == 8 and row['addend'] == TARGET)
    if pointer_slots:
        raise bv.EvidenceError('RELATIVE pointer slot reaches the target: %s'
                               % ', '.join(hex(s) for s in pointer_slots))

    rows, seen = [], set()
    for site, prefix_hex, length, slot, binding in INDIRECT:
        prefix = bytes.fromhex(prefix_hex)
        index = site - TARGET
        if not 0 <= index <= len(body) - length or body[index:index + len(prefix)] != prefix:
            raise bv.EvidenceError(f'indirect operand at {site:#x} is not {prefix_hex}')
        got = operand_target(body, index, length)
        if got != slot:
            raise bv.EvidenceError(f'indirect operand at {site:#x} resolves to {got:#x}, not {slot:#x}')
        seen.add(site)
        row = relocs.get(slot)
        if row is None:
            raise bv.EvidenceError(f'{slot:#x}: no relocation')
        record = {'site_va': f'{site:#x}', 'instruction_bytes': body[index:index + length].hex(),
                  'instruction_length': length, 'slot_va': f'{slot:#x}'}
        kind, expected = binding
        if kind == 'relative':
            if row['type'] != 8 or row['addend'] != expected:
                raise bv.EvidenceError(f'{slot:#x}: expected R_X86_64_RELATIVE addend {expected:#x}')
            record['relocation'] = {'kind': 'relative', 'type': 8, 'addend': f'{expected:#x}',
                                    'target_va': f'{expected:#x}'}
        else:
            if row['type'] != 6:
                raise bv.EvidenceError(f'{slot:#x}: expected GLOB_DAT relocation, got type {row["type"]}')
            symbol = dynamic_symbol(data, secs, row['symbol_index'])
            if symbol != expected or row['addend'] != 0:
                raise bv.EvidenceError(f'{slot:#x}: expected GLOB_DAT {expected}, got {symbol}@0x{row["addend"]:x}')
            record['relocation'] = {'kind': 'glob_dat', 'type': 6, 'symbol': symbol, 'addend': '0x0'}
        rows.append(record)

    # Bound the operand set to the observed encodings: any additional hit at a
    # different site would silently escape the pinned rows.
    patterns = {bytes.fromhex(prefix): length for _, prefix, length, _, _ in INDIRECT}
    for prefix, length in patterns.items():
        index = body.find(prefix)
        while index >= 0:
            site = TARGET + index
            target_va = operand_target(body, index, length)
            if site not in seen and target_va >= 0x5760000 and target_va < 0x5770000:
                raise bv.EvidenceError(f'unpinned {prefix.hex()} operand at {site:#x} -> {target_va:#x}')
            index = body.find(prefix, index + 1)

    location = bv.panic_location(data, secs, bv.relative_relocs(data, secs), LOCATION_LEA)
    if location['location'] != f'{LOCATION_SLOT:#x}':
        raise bv.EvidenceError(f'{LOCATION_LEA:#x}: lea does not name Location {LOCATION_SLOT:#x}')
    if location['path'].encode() != LOCATION_PATH or location['line'] != LOCATION_LINE \
            or location['column'] != LOCATION_COLUMN:
        raise bv.EvidenceError(f'{LOCATION_SLOT:#x}: Location record changed')

    index = SEPARATOR_SITE - TARGET
    if body[index:index + len(SEPARATOR_BYTES) // 2] != bytes.fromhex(SEPARATOR_BYTES):
        raise bv.EvidenceError(f'{SEPARATOR_SITE:#x}: separator store changed')
    separator_hits = body.count(bytes.fromhex(SEPARATOR_BYTES))
    if separator_hits != 1:
        raise bv.EvidenceError(f'{SEPARATOR_SITE:#x}: expected one separator store, got {separator_hits}')

    index = OVERFLOW_SITE - TARGET
    if body[index:index + len(OVERFLOW_BYTES) // 2] != bytes.fromhex(OVERFLOW_BYTES):
        raise bv.EvidenceError(f'{OVERFLOW_SITE:#x}: overflow branch changed')
    rel = struct.unpack_from('<i', body, index + 2)[0]
    if OVERFLOW_SITE + 6 + rel != OVERFLOW_TARGET:
        raise bv.EvidenceError(f'{OVERFLOW_SITE:#x}: overflow branch target changed')

    return {
        'schema': 're001-consumer-call-closure/1',
        'target': {'release': 94, 'sha256': digest, 'size': len(data)},
        'coordinates': 'linked VAs; site_offset = va - .text address',
        'function': {'start_va': f'{TARGET:#x}', 'end_va': f'{EXPECTED_END:#x}',
                     'size': EXPECTED_END - TARGET, 'file_offset': f'{offset:#x}',
                     'body_sha256': hashlib.sha256(body).hexdigest()},
        'direct_callers': caller_rows,
        'direct_caller_count': len(caller_rows),
        'relative_pointer_slots_to_target': [],
        'indirect_operands': rows,
        'indirect_operand_count': len(rows),
        'location': {'lea_site_va': f'{LOCATION_LEA:#x}', 'slot_va': f'{LOCATION_SLOT:#x}',
                     'path': location['path'], 'line': location['line'],
                     'column': location['column']},
        'separator_store': {'site_va': f'{SEPARATOR_SITE:#x}', 'bytes': SEPARATOR_BYTES,
                            'immediate': f'{SEPARATOR_IMMEDIATE:#x}', 'occurrences': separator_hits},
        'overflow_branch': {'site_va': f'{OVERFLOW_SITE:#x}', 'bytes': OVERFLOW_BYTES,
                            'target_va': f'{OVERFLOW_TARGET:#x}'},
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
                raise bv.EvidenceError(f'{args.check}: consumer call closure differs')
            sys.stdout.buffer.write(b'Consumer call closure reproduces exactly.\n')
            return 0
        if args.output is not None:
            args.output.write_bytes(text)
        else:
            sys.stdout.buffer.write(text)
        return 0
    except (bv.EvidenceError, OSError, struct.error, ValueError) as error:
        print(f'consumer_call_closure: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
