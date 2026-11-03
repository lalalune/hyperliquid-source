#!/usr/bin/env python3
'''Re-derive the node #115 RE-015 hl-node literal inventory from pinned bytes.

The pinned target artifacts/node/115/hl-node is read in place. It is never
executed, copied or modified. Every value saved under
research/work-items/RE-015-node115-literal-inventory is derived again from
those bytes and compared field by field. Corruption controls alter a derived
record in memory and assert that the comparator rejects it.
'''
import argparse
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET_REL = 'artifacts/node/115/hl-node'
TARGET = ROOT / TARGET_REL
PACKET = ROOT / 'research/work-items/RE-015-node115-literal-inventory'
EVIDENCE = PACKET / 'evidence.json'
EXPECTED_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
LITERAL = b'hl-node'
SCAN_SECTIONS = ('.rodata', '.data.rel.ro', '.data')
PRINTED_HITS = 3
R_X86_64_RELATIVE = 8


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_at(handle, offset, size):
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise AssertionError('short read at file offset 0x%x' % offset)
    return data


def parse_sections(handle):
    ident = read_at(handle, 0, 16)
    assert ident[:4] == b'\x7fELF', 'not an ELF file'
    assert ident[4] == 2, 'expected ELFCLASS64'
    assert ident[5] == 1, 'expected little-endian ELF'
    shoff = struct.unpack_from('<Q', read_at(handle, 0x28, 8))[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', read_at(handle, 0x3a, 6))
    assert shoff > 0 and shentsize >= 64, 'malformed section table'
    assert shnum > 0, 'no section headers'
    table = read_at(handle, shoff, shentsize * shnum)
    headers = []
    for index in range(shnum):
        fields = struct.unpack_from('<IIQQQQIIQQ', table, index * shentsize)
        headers.append({'name_off': fields[0], 'type': fields[1], 'addr': fields[3],
                        'offset': fields[4], 'size': fields[5], 'link': fields[6]})
    if shstrndx == 0xffff or shstrndx >= shnum:
        strtab_index = headers[0]['link']
    else:
        strtab_index = shstrndx
    strtab = headers[strtab_index]
    names = read_at(handle, strtab['offset'], strtab['size'])
    out = {}
    for header in headers:
        stop = names.find(b'\x00', header['name_off'])
        assert stop >= 0, 'malformed section name offset'
        name = names[header['name_off']:stop].decode('ascii', 'replace')
        if name not in out:
            out[name] = header
    return out


def derive():
    '''Derive every recorded packet value from the pinned target bytes.'''
    assert TARGET.is_file(), 'missing pinned target %s' % TARGET
    size_bytes = TARGET.stat().st_size
    before = sha256_file(TARGET)
    assert before == EXPECTED_SHA256, 'target digest mismatch before read: %s' % before
    hits = []
    entries = 0
    addend_counts = {}
    with open(TARGET, 'rb') as handle:
        sections = parse_sections(handle)
        for name in SCAN_SECTIONS:
            assert name in sections, 'missing section %s' % name
        for name in SCAN_SECTIONS:
            section = sections[name]
            assert section['size'] > 0, 'empty section %s' % name
            blob = read_at(handle, section['offset'], section['size'])
            start = 0
            while True:
                found = blob.find(LITERAL, start)
                if found < 0:
                    break
                hits.append({'va': '0x%x' % (section['addr'] + found),
                             'file_offset': '0x%x' % (section['offset'] + found),
                             'section': name,
                             'bytes_hex': blob[found:found + len(LITERAL)].hex()})
                start = found + 1
        rela = sections.get('.rela.dyn')
        if rela is not None and rela['size']:
            blob = read_at(handle, rela['offset'], rela['size'])
            entries = len(blob) // 24
            for index in range(entries):
                fields = struct.unpack_from('<QQq', blob, index * 24)
                if (fields[1] & 0xffffffff) != R_X86_64_RELATIVE:
                    continue
                addend_counts[fields[2]] = addend_counts.get(fields[2], 0) + 1
    after = sha256_file(TARGET)
    assert after == EXPECTED_SHA256, 'target digest changed during read: %s' % after
    printed = []
    for hit in hits[:PRINTED_HITS]:
        record = dict(hit)
        record['relative_slots'] = addend_counts.get(int(hit['va'], 16), 0)
        printed.append(record)
    return {
        'target': {'path': TARGET_REL, 'sha256': before, 'size_bytes': size_bytes},
        'captured_code_executed': False,
        'sections': dict([(name, {'va_start': '0x%x' % sections[name]['addr'],
                                  'va_end': '0x%x' % (sections[name]['addr'] + sections[name]['size']),
                                  'file_offset': '0x%x' % sections[name]['offset'],
                                  'size': sections[name]['size']})
                          for name in SCAN_SECTIONS]),
        'rela_dyn': {'entries': entries,
                     'relative_relocations': sum(addend_counts.values())},
        'literal': {'token': LITERAL.decode('ascii'),
                    'token_hex': LITERAL.hex(),
                    'length': len(LITERAL),
                    'occurrences': len(hits),
                    'printed_occurrences': printed},
    }


def load_evidence():
    assert EVIDENCE.is_file(), 'missing packet evidence file %s' % EVIDENCE
    return json.loads(EVIDENCE.read_text(encoding='utf-8'))


def compare(recorded, derived):
    '''Return the list of fields whose saved value differs from the bytes.'''
    problems = []
    if recorded.get('target') != derived['target']:
        problems.append('target identity')
    if recorded.get('captured_code_executed') is not False:
        problems.append('captured_code_executed')
    if recorded.get('sections') != derived['sections']:
        problems.append('section bounds')
    if recorded.get('rela_dyn') != derived['rela_dyn']:
        problems.append('rela.dyn counts')
    if recorded.get('literal') != derived['literal']:
        problems.append('literal record')
    return problems


def _flip_literal_byte(record):
    record['literal']['printed_occurrences'][0]['bytes_hex'] = '686c2d6e6f6466'


def _shift_second_va(record):
    record['literal']['printed_occurrences'][1]['va'] = '0x440f37'


def _claim_relative_slot(record):
    record['literal']['printed_occurrences'][2]['relative_slots'] = 1


def _drop_one_occurrence(record):
    record['literal']['occurrences'] = 4


def _add_relative_relocation(record):
    record['rela_dyn']['relative_relocations'] = record['rela_dyn']['relative_relocations'] + 1


def _shorten_rodata(record):
    record['sections']['.rodata']['va_end'] = '0xb9ea3f'


def _replace_digest(record):
    record['target']['sha256'] = '0' * 64


def _mark_executed(record):
    record['captured_code_executed'] = True


CONTROLS = (('literal bytes', _flip_literal_byte),
            ('occurrence address', _shift_second_va),
            ('relative slot', _claim_relative_slot),
            ('occurrence count', _drop_one_occurrence),
            ('rela count', _add_relative_relocation),
            ('section bound', _shorten_rodata),
            ('target digest', _replace_digest),
            ('execution flag', _mark_executed))


def run_controls(derived):
    '''In-memory corruption controls: each altered copy must be rejected.'''
    for label, mutate in CONTROLS:
        altered = copy.deepcopy(derived)
        mutate(altered)
        assert compare(altered, derived), 'corruption control was accepted: %s' % label
    return len(CONTROLS)


def main(argv=None):
    parser = argparse.ArgumentParser(description='node #115 RE-015 literal inventory')
    parser.add_argument('--output', default='', help='directory for a derived report')
    args = parser.parse_args(argv)
    derived = derive()
    recorded = load_evidence()
    problems = compare(recorded, derived)
    controls = run_controls(derived)
    literal = derived['literal']
    print('target_sha256: %s' % derived['target']['sha256'])
    print('size_bytes: %d' % derived['target']['size_bytes'])
    for name in SCAN_SECTIONS:
        section = derived['sections'][name]
        print('section %s: va=%s..%s file_offset=%s size=%d' % (
            name, section['va_start'], section['va_end'],
            section['file_offset'], section['size']))
    print('rela_dyn_entries: %d relative_relocations: %d' % (
        derived['rela_dyn']['entries'], derived['rela_dyn']['relative_relocations']))
    print('literal %s: occurrences=%d' % (literal['token'], literal['occurrences']))
    for record in literal['printed_occurrences']:
        print('  va=%s file_offset=%s section=%s bytes=%s relative_slots=%d' % (
            record['va'], record['file_offset'], record['section'],
            record['bytes_hex'], record['relative_slots']))
    print('corruption_controls: %d' % controls)
    if problems:
        for problem in problems:
            print('mismatch: %s' % problem)
        return 1
    print('evidence_matches_pinned_bytes: True')
    if args.output:
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        report = out / 'derived.json'
        report.write_text(json.dumps(derived, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        print('wrote: %s' % report)
    return 0


if __name__ == '__main__':
    sys.exit(main())
