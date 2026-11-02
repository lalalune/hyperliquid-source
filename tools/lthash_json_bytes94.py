#!/usr/bin/env python3
"""Bounded static evidence for the lattice checkpoint JSON byte-value helpers."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = (0x302ae70, 0x30596e0, 0x4ebfd80)
# Complete selected blocks, hand delimited after instruction-boundary inspection.
WINDOWS = {
    'scanner_dispatch': (0x4ebfd97, '488b56084c8b76104939d60f8388010000488b2df9728b00488b0d2ae28a00498b374c01f64531edeb266666666666662e0f1f8400000000004b8d042e48ffc04989471049ffc54839d00f8346010000420fb6042e807c05000074dd83f8220f84ac00000083f85c75cf'),
    'scanner_escape': (0x4ebfe34, '4b8d042e48ffc0498947104c89ff31f64c89e2e824f1ffff4885c00f8576010000498b57084d8b77104939d64889d9488b1c240f8249ffffffe9be000000'),
    'scanner_quote_return': (0x4ebfea8, '498b7c24104b8d042e4885ff74524c39f00f8225010000498b04244829f84939c50f872801000049037c24084c89eaff1503e18a004b8d042e48ffc04d036c24104d896c241049894710498b44240848c70301000000488943084c896b10eb5c4c39f00f82120100004b8d042e48ffc04989471048c70300000000488973084c896b10eb374d01ee'),
    'array_punctuation': (0x302ae7b, '488b364c8b4620488b4e284c39c1734f488b561848ffc14d89c149f7d948bf002600000100000066666666662e0f1f840000000000440fb6540aff4983fa2c0f87920000004c0fa3d7733248894e284d8d140949ffc248ffc14983fa0175d648c744240802000000488d4424084889f74889c6e8dd83fbffe9960000004983fa2c75548078080075684885c90f84c300000048894e284c39c1733148ffc1b8010000004c29c0440fb6440aff4983f82077454c0fa3c7733f48894e284c8d040849ffc048ffc14983f80275da48c744240805000000eb914183fa5d750e66c70300004889d84883c4205bc3807808007448c6400800eb064183f85d744a'),
    'array_value_result': (0x302af78, '488d7c2408e85ee70200807c2408007415488b44241048894308c603014889d84883c4205bc30fb644240988430266c70300014889d84883c4205bc348c744240807000000e921ffffff48c744240815000000e913ffffff'),
    'number_entry': (0x30596ed, '488b4e20488b46284839c8733b498b561848ffc048f7d948be002600000100000066900fb67c02ff4883ff2d7751480fa3fe732c49894628488d3c0148ffc748ffc04883ff0175db48c744241005000000488d7424104c89f7e8859bf8ffeb4b4883ff2d75194885c00f84cf00000049894628488d7c24284c89f631d2eb174080c7d04080ff0a7331488d7c24284c89f6ba01000000e848a5f8ff'),
    'number_range': (0x3059788, '488b4c24284883f903753b488b44243048894308c603014883c4385b415ec3488d157afa6702488d74240f4c89f7e885abf8ff4889c74c89f6e8ea6c2b0048894308b001eb30488b44243083f901741983f902752b483d0001000072144889442418c644241002eb51483d00010000733f88430131c088034883c4385b415ec3'),
    # Context only: existing packet owns the caller and its fixed-length decision.
    'context_string_call': (0x3094849, '4883f8ff0f84a802000048ffc04989462849c7461000000000488d7c24404c89f2ff15980c6e02837c244002488b7424480f85d800000048897308c60301'),
    'context_length_and_copy': (0x3094958, '488b7c24504881ff000800000f855b0100008b068b4e03894c2413894424104c8b7e074883c60f488dbc2440080000baf1070000ff154e966d02eb7a'),
    'context_array_call': (0x30948f0, '4c89e74c89eee87565f9ff'),
}


def identity(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 SHA-256 mismatch')


def read_va(data, secs, va, size):
    if size < 0:
        raise ValueError('negative size')
    rows = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size']]
    if len(rows) != 1:
        raise ValueError('VA not uniquely backed by file bytes')
    row = rows[0]
    off = row['offset'] + va - row['address']
    if off + size > len(data):
        raise ValueError('truncated file range')
    return data[off:off + size]


def relative_relocations(data, secs, wanted):
    rows = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(rows) != 1:
        raise ValueError('ambiguous relocation section')
    section = rows[0]
    if section['size'] % 24:
        raise ValueError('truncated RELA section')
    result = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', data, off)
        if address in wanted:
            if address in result or info != 8:
                raise ValueError('duplicate or non-relative selected relocation')
            result[address] = addend
    if set(result) != set(wanted):
        raise ValueError('selected relocation missing')
    return result


def check_relocations(data, secs):
    rel = relative_relocations(data, secs, {0x5775508, 0x57770a8})
    if rel[0x5775508] != 0x4ebfd80 or rel[0x57770a8] != 0x7caac8:
        raise ValueError('relocation destination mismatch')
    return rel


def classify_byte(table, value):
    if len(table) != 256 or not 0 <= value <= 255:
        raise ValueError('invalid byte class input')
    if not table[value]:
        return 'copy'
    if value == 0x22:
        return 'quote'
    if value == 0x5c:
        return 'escape'
    return 'copy'


def scan_plain(table, data):
    """Model the byte scanner up to its first closing quote, escape or exhaustion."""
    for index, value in enumerate(data):
        path = classify_byte(table, value)
        if path == 'quote':
            return 'quote', data[:index]
        if path == 'escape':
            return 'escape', data[:index]
    return 'exhausted', data


def admit_number(tag, value):
    """Model only post-parser result dispatch, not textual JSON number syntax."""
    if tag in (1, 2) and 0 <= value < 256:
        return value
    return None


def check_windows(data, secs):
    pins = []
    for name, (va, expected) in sorted(WINDOWS.items()):
        raw = read_va(data, secs, va, len(bytes.fromhex(expected)))
        if raw.hex() != expected:
            raise ValueError('instruction window mismatch: ' + name)
        pins.append({'name': name, 'va': hex(va), 'bytes': raw.hex()})
    return pins


def check_table(table):
    if table != bytes([1 if x < 32 or x in (34, 92) else 0 for x in range(256)]):
        raise ValueError('scanner classification table mismatch')
    return table


def collect(data):
    identity(data)
    secs = sections(data)
    _, extents, _ = fde_extents(data)
    by_start = {x['start']: x for x in extents}
    if len(by_start) != len(extents):
        raise ValueError('duplicate FDE starts')
    result_fdes = []
    for start in FUNCTIONS:
        row = by_start[start]
        raw = read_va(data, secs, start, row['end'] - start)
        result_fdes.append({'start': hex(start), 'end_exclusive': hex(row['end']),
                            'fde': hex(row['fde']), 'body_sha256': hashlib.sha256(raw).hexdigest()})
    pins = check_windows(data, secs)
    rel = check_relocations(data, secs)
    table = check_table(read_va(data, secs, rel[0x57770a8], 256))
    # Check the contextual slot call and the selected direct call from array helper.
    def direct_call(site, expected):
        raw = read_va(data, secs, site, 5)
        if raw[0] != 0xe8 or site + 5 + struct.unpack_from('<i', raw, 1)[0] != expected:
            raise ValueError('call target mismatch')
    direct_call(0x30948f6, 0x302ae70)
    direct_call(0x302af7d, 0x30596e0)
    call = read_va(data, secs, 0x309486a, 6)
    if call[:2] != b'\xff\x15' or 0x3094870 + struct.unpack_from('<i', call, 2)[0] != 0x5775508:
        raise ValueError('contextual slot call mismatch')
    def branch(site):
        raw = read_va(data, secs, site, 6)
        if 0x70 <= raw[0] <= 0x7f:
            length, delta = 2, struct.unpack_from('<b', raw, 1)[0]
        elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            length, delta = 6, struct.unpack_from('<i', raw, 2)[0]
        else:
            raise ValueError('unexpected branch opcode')
        return {'site': hex(site), 'bytes': raw[:length].hex(), 'target': hex(site + length + delta)}
    branch_sites = (0x4ebfdf1, 0x4ebfdf6, 0x4ebfdff, 0x302ae89, 0x302aefc,
                    0x302af02, 0x302af56, 0x302af6a, 0x302af76,
                    0x30597e3, 0x30597f7, 0x3094964)
    # Both constants are extracted from the pinned instruction operands.
    mask = struct.unpack('<Q', read_va(data, secs, 0x302ae9a, 8))[0]
    limit = struct.unpack('<I', read_va(data, secs, 0x3094960, 4))[0]
    cases = [{'byte': x, 'table': table[x], 'path': classify_byte(table, x)} for x in range(256)]
    return {'target_sha256': DIGEST, 'coordinate_system': 'linked ELF VA; end exclusive',
            'function_extents': result_fdes, 'windows': pins,
            'selected_relocations': [{'slot': hex(x), 'addend': hex(rel[x])} for x in sorted(rel)],
            'class_table_va': hex(rel[0x57770a8]), 'class_table_hex': table.hex(),
            'selected_branches': [branch(x) for x in branch_sites],
            'whitespace_mask': hex(mask), 'whitespace_bytes': [x for x in range(64) if mask & (1 << x)],
            'string_byte_length': limit,
            'byte_dispatch': cases,
            'number_result_boundary': [{'tag': t, 'value': v, 'accepted_byte': admit_number(t, v)}
                                       for t in range(4) for v in (0, 1, 255, 256)],
            'limitations': ['FDE extents do not alone establish function boundaries',
                            'Selected context windows are owned by prior work',
                            'Escape and numeric parser callees are not modelled',
                            'Static decisions are not target execution']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = BINARY.read_bytes()
    record = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, struct.error) as error:
        print('lthash_json_bytes94: ' + str(error), file=sys.stderr)
        sys.exit(1)
