#!/usr/bin/env python3
"""Attribute node94's version maxima to ELF requirement and import records.

Static ELF64-LE parsing only. The public producer authenticates one byte snapshot;
the lower-level parser is also exposed for local counterfactual tests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'artifacts/node/94/hl-node'
OUT = ROOT / 'work/version-requirements-94.json'
NAMESPACES = re.compile(r'(GLIBC|GLIBCXX|CXXABI|GCC|OPENSSL)_([0-9.]+)\Z')


def elf_hash(name):
    """The ELF version-name hash, as stored in Elf64_Vernaux.vna_hash."""
    value = 0
    for byte in name.encode('ascii'):
        value = (value << 4) + byte
        high = value & 0xf0000000
        value ^= high >> 24
        value &= ~high
    return value


def analyze(data):
    """Parse a byte vector; authentication is the caller's separate obligation."""
    raw_sections = sections(data)
    if struct.unpack_from('<H', data, 18)[0] != 0x3e:
        raise ValueError('Expected x86-64 ELF')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    shentsize = struct.unpack_from('<H', data, 58)[0]
    rows = []
    for index, sec in enumerate(raw_sections):
        header_offset = shoff + index * shentsize
        header = struct.unpack_from('<IIQQQQIIQQ', data, header_offset)
        rows.append(dict(sec, index=index, header_file_offset=header_offset,
                         link=header[6], info=header[7], entry_size=header[9]))
    selected = {}
    for name, typ in (('.dynsym', 11), ('.dynstr', 3), ('.gnu.version', 0x6fffffff),
                      ('.gnu.version_r', 0x6ffffffe), ('.dynamic', 6)):
        matches = [s for s in rows if s['name'] == name]
        if len(matches) != 1 or matches[0]['type'] != typ:
            raise ValueError(f'Expected one file-backed {name} section of type {typ}')
        selected[name] = matches[0]
    dynsym, dynstr, versym, verneed, dynamic = (selected[n] for n in
        ('.dynsym', '.dynstr', '.gnu.version', '.gnu.version_r', '.dynamic'))
    for section, linked in ((dynsym, dynstr), (versym, dynsym), (verneed, dynstr),
                            (dynamic, dynstr)):
        if section['link'] != linked['index']:
            raise ValueError(f'Unexpected linked section for {section["name"]}')
    if dynsym['entry_size'] != 24 or dynsym['size'] % 24 or \
            versym['entry_size'] != 2 or versym['size'] != 2 * (dynsym['size'] // 24):
        raise ValueError('Dynamic symbol/version table sizes disagree')

    def string(index):
        if not 0 <= index < dynstr['size']:
            raise ValueError('String offset outside .dynstr')
        offset = dynstr['offset'] + index
        end = data.find(b'\0', offset, dynstr['offset'] + dynstr['size'])
        if end < 0:
            raise ValueError('Unterminated .dynstr string')
        try:
            return data[offset:end].decode('ascii')
        except UnicodeDecodeError as exc:
            raise ValueError('Expected ASCII version/import metadata') from exc

    if dynamic['entry_size'] != 16 or dynamic['size'] % 16:
        raise ValueError('Unsupported dynamic entry size')
    tags = {}
    dynamic_entries = []
    for off in range(dynamic['offset'], dynamic['offset'] + dynamic['size'], 16):
        tag, value = struct.unpack_from('<qQ', data, off)
        if tag == 0:
            break
        tags.setdefault(tag, []).append(value)
        dynamic_entries.append({'tag': tag, 'value': value, 'file_offset': off})
    else:
        raise ValueError('Dynamic array has no DT_NULL')
    expected_tags = {5: dynstr['address'], 6: dynsym['address'], 10: dynstr['size'],
                     11: 24, 0x6ffffff0: versym['address'],
                     0x6ffffffe: verneed['address'], 0x6fffffff: verneed['info']}
    for tag, value in expected_tags.items():
        if tags.get(tag) != [value]:
            raise ValueError(f'Dynamic tag {tag:#x} disagrees with section metadata')
    needed = [string(v) for v in tags.get(1, [])]

    def record(offset, size, kind):
        if not verneed['offset'] <= offset or offset + size > verneed['offset'] + verneed['size']:
            raise ValueError(f'{kind} record outside .gnu.version_r')
        interval = (offset, offset + size)
        if any(a < interval[1] and interval[0] < b for a, b in occupied):
            raise ValueError('Overlapping version requirement records')
        occupied.append(interval)

    requirements, providers, occupied = [], [], []
    off = verneed['offset']
    if not 0 < verneed['info'] <= verneed['size'] // 16:
        raise ValueError('Invalid version provider count')
    for provider_index in range(verneed['info']):
        record(off, 16, 'Verneed')
        version, count, file_name, aux, nxt = struct.unpack_from('<HHIII', data, off)
        provider = string(file_name)
        if version != 1 or not count or count > verneed['size'] // 16 or provider not in needed:
            raise ValueError('Invalid version provider header')
        providers.append({'name': provider, 'verneed_file_offset': off,
                          'name_file_offset': dynstr['offset'] + file_name,
                          'aux_count': count})
        auxoff = off + aux
        for aux_index in range(count):
            record(auxoff, 16, 'Vernaux')
            name_hash, flags, other, name_index, aux_next = struct.unpack_from('<IHHII', data, auxoff)
            name = string(name_index)
            if (other & 0x7fff) < 2 or name_hash != elf_hash(name):
                raise ValueError('Invalid version requirement index/name hash')
            requirements.append({'provider': provider, 'name': name, 'index': other & 0x7fff,
                'version_other_raw': other,
                'version_flags': flags, 'name_hash': name_hash,
                'verneed_file_offset': off, 'vernaux_file_offset': auxoff,
                'name_file_offset': dynstr['offset'] + name_index, 'symbols': []})
            if aux_index + 1 < count:
                if aux_next < 16:
                    raise ValueError('Incomplete Vernaux chain')
                auxoff += aux_next
            elif aux_next:
                raise ValueError('Vernaux count does not end its chain')
        if provider_index + 1 < verneed['info']:
            if nxt < 16:
                raise ValueError('Incomplete Verneed chain')
            off += nxt
        elif nxt:
            raise ValueError('Verneed count does not end its chain')
    by_index = {r['index']: r for r in requirements}
    if len(by_index) != len(requirements):
        raise ValueError('Duplicate version requirement index')

    unversioned, defined_count = [], 0
    for index in range(dynsym['size'] // 24):
        off = dynsym['offset'] + index * 24
        name_index, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, off)
        version_offset = versym['offset'] + 2 * index
        version_raw = struct.unpack_from('<H', data, version_offset)[0]
        version_index = version_raw & 0x7fff
        if index == 0:
            if data[off:off + 24] != b'\0' * 24 or version_raw:
                raise ValueError('Invalid reserved null symbol/version entry')
            continue
        if shndx != 0:
            defined_count += 1
            continue
        symbol = {'index': index, 'name': string(name_index), 'binding': info >> 4,
                  'type': info & 15, 'visibility': other & 3,
                  'section_index': shndx, 'value': value, 'size': size,
                  'symbol_file_offset': off,
                  'name_file_offset': dynstr['offset'] + name_index,
                  'versym_file_offset': version_offset, 'versym_raw': version_raw}
        if version_index < 2:
            unversioned.append(symbol)
        elif version_index not in by_index:
            raise ValueError('Undefined symbol references an absent version requirement')
        else:
            by_index[version_index]['symbols'].append(symbol)

    maximum_versions = {}
    for row in requirements:
        match = NAMESPACES.fullmatch(row['name'])
        if match:
            namespace, version = match.groups()
            numbers = tuple(map(int, version.split('.')))
            maximum_versions[namespace] = max(numbers, maximum_versions.get(namespace, numbers))
    maxima = {namespace: [r for r in requirements if NAMESPACES.fullmatch(r['name']) and
        r['name'] == namespace + '_' + '.'.join(map(str, version))]
        for namespace, version in sorted(maximum_versions.items())}
    return {'sections': selected, 'dynamic_entries': dynamic_entries,
            'needed': needed, 'providers': providers, 'requirements': requirements,
            'dynsym_count': dynsym['size'] // 24,
            'defined_symbol_count': defined_count, 'reserved_null_symbol_count': 1,
            'unversioned_undefined_symbols': unversioned, 'maxima': maxima}


def generate(root=ROOT):
    root = Path(root)
    manifest = json.loads((root / 'provenance/artifacts.json').read_text())
    identity = next(i for i in manifest['files'] if i['path'] == TARGET)
    data = (root / TARGET).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if len(data) != identity['size'] or actual != identity['sha256']:
        raise ValueError('Node94 artifact size/SHA-256 mismatch')
    facts = analyze(data)
    return {'target': TARGET, 'sha256': actual, 'size': len(data),
            'tool': 'tools/node94_version_requirements.py', 'facts': facts,
            'captured_executable_executed': False,
            'limits': 'ELF version metadata only; no import call reachability, loader execution, '
                      'minimum runtime or build-host identity, source reconstruction or component equivalence.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUT)
    args = parser.parse_args()
    result = generate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as handle:
        handle.write((json.dumps(result, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    print(json.dumps({'target_sha256': result['sha256'],
                      'provider_count': len(result['facts']['providers']),
                      'requirement_count': len(result['facts']['requirements']),
                      'maxima': {n: [{'provider': r['provider'], 'name': r['name'],
                                 'symbol_count': len(r['symbols'])} for r in rows]
                                 for n, rows in result['facts']['maxima'].items()}}, indent=2))


if __name__ == '__main__':
    main()
