#!/usr/bin/env python3
"""Verify pinned call and result-tag evidence for the 92 node #115 action handlers."""
import argparse
import csv
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from action_prior_key_wrapper_115 import COPIES as MODELLED_CLONES  # noqa: E402
from action_router_115 import HANDLERS, TARGET  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

TASK = ROOT / 'research/work-items/action-dispatch-shared-admission-115'
TABLE = TASK / 'handlers.tsv'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
FIRST_CALLS = (0x2a8ab70, 0x4717440, 0x3ed25b0)
GATES = (0x2c202b0, 0x2c206b0)


class EvidenceError(ValueError):
    pass


def parse_site_values(value, fields):
    if value == '-':
        return []
    result = []
    for item in value.split(','):
        parts = item.split(':')
        if len(parts) != fields:
            raise EvidenceError(f'malformed evidence item: {item!r}')
        result.append(parts)
    return result


def verify_call(data, text, site, kind, expected):
    offset = site - text['address'] + text['offset']
    if not text['address'] <= site < text['address'] + text['size']:
        raise EvidenceError(f'call outside .text: {site:#x}')
    if kind == 'direct':
        raw = data[offset:offset + 5]
        if len(raw) != 5 or raw[0] != 0xe8:
            raise EvidenceError(f'expected direct call at {site:#x}')
        actual = site + 5 + struct.unpack_from('<i', raw, 1)[0]
    elif kind == 'got':
        raw = data[offset:offset + 6]
        if len(raw) != 6 or raw[:2] != b'\xff\x15':
            raise EvidenceError(f'expected RIP-relative indirect call at {site:#x}')
        actual = site + 6 + struct.unpack_from('<i', raw, 2)[0]
    else:
        raise EvidenceError(f'unknown call kind {kind!r}')
    if actual != expected:
        raise EvidenceError(f'call target mismatch at {site:#x}: {actual:#x} != {expected:#x}')


def verify_marker(data, text, site, expected, marker):
    offset = site - text['address'] + text['offset']
    if not text['address'] <= site < text['address'] + text['size']:
        raise EvidenceError(f'marker outside .text: {site:#x}')
    if data[offset:offset + len(expected)] != expected:
        raise EvidenceError(f'{marker} marker bytes differ at {site:#x}')
    if marker == '0x120 store':
        opcodes = expected[1:] if expected[0] & 0xf0 == 0x40 else expected
        if not opcodes.startswith(bytes.fromhex('66c7')) or b'\x20\x01' not in opcodes:
            raise EvidenceError(f'not a pinned 16-bit 0x120 immediate at {site:#x}')
    elif marker == '0x0f tag':
        opcodes = expected[1:] if expected[0] & 0xf0 == 0x40 else expected
        if not opcodes.startswith(bytes.fromhex('c6')) or not opcodes.endswith(b'\x0f'):
            raise EvidenceError(f'not a pinned byte 0x0f immediate at {site:#x}')
    else:
        raise EvidenceError(f'unknown marker kind {marker!r}')


def verify_records(data, rows):
    digest = hashlib.sha256(data).hexdigest()
    if digest != DIGEST:
        raise EvidenceError(f'node #115 digest mismatch: {digest}')
    text = next((s for s in sections(data) if s['name'] == '.text'), None)
    if text is None:
        raise EvidenceError('missing .text section')
    _, fdes, _ = fde_extents(data)
    fde_by_start = {f['start']: f for f in fdes}
    if len(rows) != len(HANDLERS):
        raise EvidenceError(f'expected {len(HANDLERS)} handlers, got {len(rows)}')
    if not set(MODELLED_CLONES).issubset(set(HANDLERS)):
        raise EvidenceError('the ten modeled clone entries no longer map to router arms')

    code_count = tag_count = 0
    call_count = 0
    code_exceptions = []
    for index, row in enumerate(rows):
        va = HANDLERS[index]
        if int(row['index']) != index or int(row['tag'], 16) != 0x86 + index:
            raise EvidenceError(f'bad router index/tag at row {index}')
        if int(row['handler_va'], 16) != va:
            raise EvidenceError(f'handler differs from router arm {index}')
        fde = fde_by_start.get(va)
        if fde is None or int(row['fde_end'], 16) != fde['end']:
            raise EvidenceError(f'FDE end differs for handler {va:#x}')

        calls = parse_site_values(row['calls_to_second_gate'], 3)
        targets = []
        previous = va - 1
        for site_s, kind, target_s in calls:
            site, target = int(site_s, 16), int(target_s, 16)
            if site <= previous or not va <= site < fde['end']:
                raise EvidenceError(f'call sites are unordered or outside FDE at {va:#x}')
            verify_call(data, text, site, kind, target)
            targets.append(target)
            previous = site
            call_count += 1
        if tuple(targets[:3]) != FIRST_CALLS:
            raise EvidenceError(f'common first call sequence differs at {va:#x}')
        if not all(target in targets for target in GATES):
            raise EvidenceError(f'missing one of the two check calls at {va:#x}')
        if targets[-1] != GATES[1]:
            raise EvidenceError(f'call inventory does not end at the second check at {va:#x}')

        code_sites = parse_site_values(row['code120_sites'], 2)
        tag_sites = parse_site_values(row['tag0f_sites'], 2)
        for site_s, expected_hex in code_sites:
            site, expected = int(site_s, 16), bytes.fromhex(expected_hex)
            if not va <= site < fde['end']:
                raise EvidenceError(f'0x120 marker outside FDE at {site:#x}')
            verify_marker(data, text, site, expected, '0x120 store')
        for site_s, expected_hex in tag_sites:
            site, expected = int(site_s, 16), bytes.fromhex(expected_hex)
            if not va <= site < fde['end']:
                raise EvidenceError(f'0x0f tag marker outside FDE at {site:#x}')
            verify_marker(data, text, site, expected, '0x0f tag')
        if code_sites:
            code_count += 1
        else:
            code_exceptions.append(va)
        if tag_sites:
            tag_count += 1

    return {
        'handlers': len(rows),
        'common_first_calls': len(rows),
        'both_check_calls': len(rows),
        'pinned_calls': call_count,
        'handlers_with_literal_0x120_store': code_count,
        'handlers_without_literal_0x120_store': [f'{va:#x}' for va in code_exceptions],
        'handlers_with_literal_0x0f_tag_store': tag_count,
        'exact_clone_model_indices': [HANDLERS.index(va) for va in MODELLED_CLONES],
        'target_sha256': digest,
    }


def load_rows(path=TABLE):
    with path.open(newline='') as handle:
        rows = list(csv.DictReader(handle, delimiter='\t'))
    required = {'index', 'tag', 'handler_va', 'fde_end', 'calls_to_second_gate', 'code120_sites', 'tag0f_sites'}
    if not rows or set(rows[0]) != required:
        raise EvidenceError('handler table has an unexpected schema')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--table', type=Path, default=TABLE)
    args = parser.parse_args()
    print(verify_records(args.binary.read_bytes(), load_rows(args.table)))


if __name__ == '__main__':
    main()
