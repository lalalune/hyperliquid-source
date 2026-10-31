#!/usr/bin/env python3
"""Inventory the global_constants component of one captured hl-node release.

The scan is static: it reads the ELF section table and `.rela.dyn`, never the
loader and never the running binary. Every output is bound to the artifact
SHA-256 recorded in provenance/artifacts.json.

It answers three bounded questions:

1. Where are the two observed path seeds (`/cham`, `/static_config`) and what
   exactly does the code reference: the text or a length-prefixed pool entry?
2. Is there a materialized 76-entry `&str` table for `AwsName`, in which order,
   and does it agree with the pinned reference list?
3. Which code sites reference the pool entries and the table, and inside which
   unwind-index window does each site fall?

Unwind windows are bounded by the next `.eh_frame_hdr` start. They are index
bounds, not decoded FDE extents, and are labelled that way in the output.

Usage:
    python3 tools/constants_scan.py --release 94 --out research/work-items/constants
    python3 tools/constants_scan.py --release 94 --check research/work-items/constants

Exit status is non-zero on any failed invariant; the tool does not guess.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index  # noqa: E402

REFERENCE = ROOT / 'references/can1357-hl/global_constants/aws_name.rs'
REFERENCE_CONFIG = ROOT / 'references/can1357-hl/global_constants/static_config.rs'
EXPECTED_VARIANTS = 76
POOL_MARKER = 0xC0


class ScanError(ValueError):
    pass


def artifact(release):
    path = ROOT / f'artifacts/node/{release}/hl-node'
    data = path.read_bytes()
    record = json.loads((ROOT / 'provenance/artifacts.json').read_text())
    expected = next((f['sha256'] for f in record['files']
                     if f['path'] == f'artifacts/node/{release}/hl-node'), None)
    if expected is None:
        raise ScanError(f'no provenance record for node #{release}')
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ScanError(f'digest mismatch: {actual} != {expected}')
    return data, expected


def section(data, name):
    for row in sections(data):
        if row['name'] == name:
            if row['type'] == 8:
                raise ScanError(f'{name} is NOBITS')
            return row
    raise ScanError(f'missing section {name}')


def va_to_offset(sec, va):
    if not sec['address'] <= va < sec['address'] + sec['size']:
        raise ScanError(f'{va:#x} outside {sec["name"]}')
    return sec['offset'] + va - sec['address']


def entries_size(data, name):
    """Read sh_entsize for `name` from the raw section table."""
    if data[:6] != b'\x7fELF\x02\x01':
        raise ScanError('expected ELF64 little-endian input')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, _ = struct.unpack_from('<HHH', data, 58)
    if entsize < 64 or shoff + entsize * count > len(data):
        raise ScanError('invalid section table')
    for index in range(count):
        row = struct.unpack_from('<IIQQQQIIQQ', data, shoff + index * entsize)
        if row[0] == 0 and index != 0:
            continue
        if section_name(data, index, entsize, count) == name:
            return row[9]
    raise ScanError(f'missing section {name}')


def section_name(data, index, entsize, count):
    shoff = struct.unpack_from('<Q', data, 40)[0]
    names_index = struct.unpack_from('<H', data, 62)[0]
    if names_index >= count:
        raise ScanError('invalid section name table')
    name_off, _, _, _, offset, size = struct.unpack_from('<IIQQQQ', data, shoff + names_index * entsize)
    table = data[offset:offset + size]
    start = struct.unpack_from('<I', data, shoff + index * entsize)[0]
    end = table.find(b'\0', start)
    if end < 0:
        raise ScanError('unterminated section name')
    try:
        return table[start:end].decode('utf-8')
    except UnicodeDecodeError:
        raise ScanError('section name is not valid UTF-8')


def relocations(data):
    """Return {slot_va: addend} for every R_X86_64_RELATIVE in .rela.dyn."""
    sec = section(data, '.rela.dyn')
    if entries_size(data, '.rela.dyn') != 24:
        raise ScanError('unsupported .rela.dyn entsize')
    out = {}
    for index in range(sec['size'] // 24):
        offset, info, addend = struct.unpack_from('<QQq', data, sec['offset'] + index * 24)
        if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
            out[offset] = addend
    return out


def expected_names():
    text = REFERENCE.read_text()
    match = re.search(r'AWS_NAME_STRINGS: \[&str; 76\] = \[(.*?)\];', text, re.S)
    if not match:
        raise ScanError('reference AWS_NAME_STRINGS array not found')
    names = re.findall(r'"([^"]+)"', match.group(1))
    if len(names) != EXPECTED_VARIANTS or len(set(names)) != EXPECTED_VARIANTS:
        raise ScanError('reference array is not 76 distinct names')
    return names


def pool_entry(data, rodata, needle, require_marker=False):
    """Locate `needle` as a `[c0] <len> <text> 00` pool entry in .rodata.

    The 0xc0 byte is an optional alignment marker emitted before a literal; when
    present it is the byte the code points at. Entries without it are prefixed
    by the length byte alone. Exactly one candidate must exist.
    """
    encoded = needle.encode()
    starts = []
    pos = rodata['offset']
    end = pos + rodata['size']
    while True:
        found = data.find(encoded, pos, end)
        if found < 0:
            break
        starts.append(found)
        pos = found + 1
    hits = []
    for offset in starts:
        length = len(encoded)
        if data[offset + length] not in (0, POOL_MARKER):
            continue
        if offset - 2 >= rodata['offset'] and data[offset - 2] == POOL_MARKER and data[offset - 1] == length:
            hits.append((offset - 2, True))
        elif offset - 1 >= rodata['offset'] and data[offset - 1] == length:
            hits.append((offset - 1, False))
    if require_marker:
        hits = [hit for hit in hits if hit[1]]
    if len(hits) != 1:
        raise ScanError(f'{needle!r}: expected one length-prefixed entry, got {len(hits)}')
    entry, prefixed = hits[0]
    text = rodata['address'] + offset - rodata['offset'] if False else rodata['address'] + (entry - rodata['offset']) + (2 if prefixed else 1)
    return rodata['address'] + entry - rodata['offset'], text, prefixed


def string_table(data, rodata, relro, names, count=EXPECTED_VARIANTS):
    """Find the longest 16-byte-stride (pointer, length) run into .rodata."""
    relocs = relocations(data)
    hits = {}
    for offset in range(0, relro['size'] - 16, 8):
        slot = relro['address'] + offset
        pointer = relocs.get(slot)
        if pointer is None:
            continue
        length = struct.unpack_from('<Q', data, relro['offset'] + offset + 8)[0]
        if not rodata['address'] <= pointer < rodata['address'] + rodata['size']:
            continue
        if not 2 <= length <= 16:
            continue
        text = data[va_to_offset(rodata, pointer):va_to_offset(rodata, pointer) + length]
        if not text.isascii() or not all(32 < byte < 127 for byte in text):
            continue
        if text.decode() not in names:
            continue
        hits[slot] = (pointer, length, text.decode())
    best, current = [], []
    previous = None
    for slot in sorted(hits):
        if previous is not None and slot - previous == 16:
            current.append(slot)
        else:
            if len(current) > len(best):
                best = current
            current = [slot]
        previous = slot
    if len(current) > len(best):
        best = current
    if len(best) != count:
        raise ScanError(f'expected a {count}-entry table, longest run is {len(best)}')
    return best[0], [(slot, *hits[slot]) for slot in best]


def xrefs(data, text, targets):
    """RIP-relative operands whose resolved address is one of `targets`."""
    base = text['address'] - text['offset']
    wanted = {target: [] for target in targets}
    for offset in range(text['offset'] + 1, text['offset'] + text['size'] - 7):
        rex, opcode = data[offset - 1], data[offset]
        if rex not in (0x48, 0x49, 0x4C, 0x4D):
            continue
        if opcode not in (0x8D, 0x8B, 0x89, 0x3B, 0x39, 0x03, 0x0B, 0x2B, 0x29):
            continue
        if data[offset + 1] & 0xC7 != 0x05:
            continue
        end = base + offset + 6
        target = end + struct.unpack_from('<i', data, offset + 2)[0]
        if target in wanted:
            wanted[target].append((base + offset, data[offset - 1:offset + 6].hex()))
    return wanted


def window(starts, site):
    """Nearest index start at or before `site`, and the following start."""
    import bisect
    index = bisect.bisect_right(starts, site) - 1
    if index < 0:
        raise ScanError(f'{site:#x} precedes every unwind start')
    return starts[index], starts[index + 1] if index + 1 < len(starts) else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', default='94')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--check', type=Path,
                        help='compare against files previously written to this directory')
    args = parser.parse_args()

    data, digest = artifact(args.release)
    rodata = section(data, '.rodata')
    relro = section(data, '.data.rel.ro')
    text = section(data, '.text')

    names = expected_names()
    config_text = REFERENCE_CONFIG.read_text()
    if 'DEFAULT_AWS_NAME: AwsName = AwsName::NvTestnet' not in config_text:
        raise ScanError('reference default is not NvTestnet')

    seeds = {name: pool_entry(data, rodata, name, require_marker=True)
             for name in ('/cham', '/static_config')}
    table_va, table = string_table(data, rodata, relro, set(names))

    observed = [entry[3] for entry in table]
    if observed != names:
        for index, (got, want) in enumerate(zip(observed, names)):
            if got != want:
                raise ScanError(f'table entry {index}: {got!r} != reference {want!r}')
        raise ScanError('table and reference differ in length')

    default_index = names.index('NvTestnet')
    if default_index != 32:
        raise ScanError('NvTestnet is not discriminant 32 in the reference order')

    # The pool entry for the two panic texts proves the argument order the
    # default occupies; they are not seeds of the component but of its errors.
    messages = {name: pool_entry(data, rodata, name)
                for name in ('/hl', '/code', 'cham_dir does not exist: ',
                             'could not create ')}

    starts = [row['start'] for row in unwind_index(data)[1]]

    targets = {**{k: v[0] for k, v in seeds.items()},
               **{k: v[0] for k, v in messages.items()}, 'aws_name_table': table_va}
    found = xrefs(data, text, targets.values())

    # The canonical names are emitted as one contiguous alphanumeric blob;
    # names the compiler also needed elsewhere are deduplicated to earlier
    # .rodata copies. Pick the run that carries the most table pointers.
    pointers = [entry[1] for entry in table]
    runs, start = [], None
    for offset in range(rodata['offset'], rodata['offset'] + rodata['size'] + 1):
        alnum = offset < rodata['offset'] + rodata['size'] and (
            chr(data[offset]).isalnum() and data[offset] < 0x80)
        if alnum and start is None:
            start = offset
        elif not alnum and start is not None:
            runs.append((start, offset))
            start = None
    best = max(runs, key=lambda run: sum(
        rodata['address'] + run[0] - rodata['offset'] <= pointer < rodata['address'] + run[1] - rodata['offset']
        for pointer in pointers))
    blob_start = rodata['address'] + best[0] - rodata['offset']
    blob_end = rodata['address'] + best[1] - rodata['offset']
    rows = []
    for index, (slot, pointer, length, value) in enumerate(table):
        site = 'blob' if blob_start <= pointer and pointer + length <= blob_end else 'dedup'
        rows.append({'discriminant': index, 'table_va': slot, 'text_va': pointer,
                     'length': length, 'origin': site, 'text': value,
                     'xrefs': found.get(pointer, [])})

    xref_rows = []
    for kind, target in targets.items():
        for site, instruction in found.get(target, []):
            start, end = window(starts, site)
            xref_rows.append({'target': kind, 'target_va': target, 'site_va': site,
                              'window_start': start, 'window_end': end,
                              'instruction': instruction})
    if not xref_rows:
        raise ScanError('no code reference found for any target')

    document = {
        'schema_version': 1,
        'artifact': f'artifacts/node/{args.release}/hl-node',
        'sha256': digest,
        'coordinates': 'linked virtual addresses (VA); file offsets are section-relative',
        'sections': {name: {'address': sec['address'], 'offset': sec['offset'], 'size': sec['size']}
                     for name, sec in (('.rodata', rodata), ('.data.rel.ro', relro), ('.text', text))},
        'pool_marker': f'0x{POOL_MARKER:02x}',
        'seeds': {k: {'entry_va': v[0], 'text_va': v[1]} for k, v in seeds.items()},
        'messages': {k: {'entry_va': v[0], 'text_va': v[1]} for k, v in messages.items()},
        'table': {'va': table_va, 'entries': len(table), 'default_index': default_index,
                  'blob_start': blob_start, 'blob_end': blob_end},
        'table_rows': rows,
        'xrefs': sorted(xref_rows, key=lambda row: (row['target_va'], row['site_va'])),
        'window_basis': 'nearest .eh_frame_hdr start <= site, next start; not decoded FDE extents',
    }

    strings = ['kind\tindex\tentry_va\ttext_va\tfile_offset\tlength\torigin\tbytes\ttext\txrefs']
    for name, (entry, text_va, prefixed) in sorted(seeds.items()):
        offset = va_to_offset(rodata, entry)
        width = len(name) + (2 if prefixed else 1)
        strings.append(f'seed\t\t{entry:#x}\t{text_va:#x}\t{offset:#x}\t{width}\tpool\t'
                       f'{data[offset:offset + width].hex()}\t{name}\t{len(found.get(entry, []))}')
    for row in rows:
        offset = va_to_offset(rodata, row['text_va'])
        strings.append(f'variant\t{row["discriminant"]}\t{row["table_va"]:#x}\t{row["text_va"]:#x}\t'
                       f'{offset:#x}\t{row["length"]}\t{row["origin"]}\t'
                       f'{data[offset:offset + row["length"]].hex()}\t{row["text"]}\t{len(row["xrefs"])}')

    xrefs_tsv = ['target\ttarget_va\tsite_va\tsite_file_offset\twindow_start\twindow_end\tinstruction']
    for row in document['xrefs']:
        xrefs_tsv.append(f'{row["target"]}\t{row["target_va"]:#x}\t{row["site_va"]:#x}\t'
                         f'{va_to_offset(text, row["site_va"]):#x}\t{row["window_start"]:#x}\t'
                         f'{row["window_end"]:#x}\t{row["instruction"]}')

    outputs = {
        'constants.json': json.dumps(document, indent=1) + '\n',
        'strings.tsv': '\n'.join(strings) + '\n',
        'xrefs.tsv': '\n'.join(xrefs_tsv) + '\n',
    }
    if args.check:
        for name, content in outputs.items():
            if (args.check / name).read_text() != content:
                raise SystemExit(f'stale output: {name}')
        print(f'{args.check}: outputs match')
        return
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for name, content in outputs.items():
            (args.out / name).write_text(content)
    print(f'#94 {digest}')
    print('seeds: ' + ', '.join(f'{k}={v[1]:#x}' for k, v in seeds.items()))
    print(f'table: {table_va:#x}, {len(table)} entries, default NvTestnet={default_index}')
    print(f'xrefs: {len(xref_rows)} sites over {len({row["target_va"] for row in xref_rows})} targets')


if __name__ == '__main__':
    try:
        main()
    except ScanError as error:
        raise SystemExit(f'constants_scan: {error}')
