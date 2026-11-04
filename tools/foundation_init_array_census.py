#!/usr/bin/env python3
"""RE-001 node #115 static-initializer census checker.

Re-derives the .init_array/.fini_array constructor census recorded in
research/work-items/RE-001-node115-init-array-census from the pinned node #115
target bytes. The target is read in place; it is never executed and never
copied. Exit status is nonzero when the packet is missing or incomplete, when
the target identity differs, or when a recorded value disagrees with the value
re-derived from those bytes.
"""

import hashlib
import json
import struct
from pathlib import Path

TARGET_SHA256 = (
    'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
)
TARGET_SIZE = 105896032
TARGET_PATH = Path('artifacts') / 'node' / '115' / 'hl-node'
PACKET_DIR = Path('research') / 'work-items' / 'RE-001-node115-init-array-census'
PACKET_FILES = ('README.md', 'evidence.json', 'init-array.txt', 'frames.txt')
R_X86_64_RELATIVE = 8
ELF64_SECTION = 64
ELF64_RELA = 24
EM_X86_64 = 62
SHT_RELA = 4
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15


def hx(value):
    return '0x' + format(value & 0xffffffffffffffff, 'x')


def load_sections(data):
    assert data[:4] == b'\x7fELF' and data[4:7] == b'\x02\x01\x01', 'not ELFCLASS64 little-endian'
    assert struct.unpack_from('<H', data, 0x12)[0] == EM_X86_64, 'not EM_X86_64'
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    assert shentsize == ELF64_SECTION and shnum > 0 and shstrndx < shnum, 'unexpected section table'
    assert shoff + shnum * shentsize <= len(data), 'section table past end of file'
    entries = []
    for index in range(shnum):
        fields = struct.unpack_from('<IIQQQQIIQQ', data, shoff + index * shentsize)
        entries.append({
            'index': index,
            'name_off': fields[0],
            'type': fields[1],
            'flags': fields[2],
            'addr': fields[3],
            'offset': fields[4],
            'size': fields[5],
            'entsize': fields[9],
        })
    table = entries[shstrndx]
    assert table['offset'] + table['size'] <= len(data), 'section name table past end of file'
    names = data[table['offset']:table['offset'] + table['size']]
    for entry in entries:
        stop = names.find(b'\x00', entry['name_off'])
        assert stop >= 0, 'unterminated section name'
        entry['name'] = names[entry['name_off']:stop].decode('utf-8', 'replace')
    return entries


def section_table(entries):
    table = {}
    for entry in entries:
        name = entry['name']
        if not name:
            continue
        assert name not in table, 'duplicate section name ' + name
        table[name] = entry
    return table


def relative_relocations(data, section):
    assert section['type'] == SHT_RELA and section['entsize'] == ELF64_RELA
    assert section['size'] % ELF64_RELA == 0, '.rela.dyn is not whole records'
    assert section['offset'] + section['size'] <= len(data), '.rela.dyn past end of file'
    found = {}
    count = section['size'] // ELF64_RELA
    for index in range(count):
        offset = section['offset'] + index * ELF64_RELA
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, offset)
        if (r_info & 0xffffffff) == R_X86_64_RELATIVE:
            found.setdefault(r_offset, []).append(r_addend & 0xffffffffffffffff)
    return found, count


def slot_records(data, section, expected_type, relocations):
    assert section['type'] == expected_type, section['name'] + ' has an unexpected section type'
    assert section['size'] % 8 == 0, section['name'] + ' size is not whole 8-byte slots'
    assert section['entsize'] in (0, 8), section['name'] + ' entry size is not 0 or 8'
    assert section['offset'] + section['size'] <= len(data), section['name'] + ' past end of file'
    count = section['size'] // 8
    words = struct.unpack_from('<%dQ' % count, data, section['offset'])
    records = []
    for index in range(count):
        va = section['addr'] + index * 8
        records.append({'index': index, 'va': va, 'word': words[index],
                        'relative': relocations.get(va, [])})
    return records


def slot_lines(section_name, records):
    lines = []
    for record in records:
        targets = record['relative']
        rendered = ','.join(hx(value) for value in targets) if targets else 'none'
        lines.append('slot %s[%d] va=%s word=%s relative=%s' % (
            section_name, record['index'], hx(record['va']),
            hx(record['word']), rendered))
    return lines


def digest_lines(lines):
    return hashlib.sha256(('\n'.join(lines) + '\n').encode('utf-8')).hexdigest()


def _leb(data, offset, end, signed):
    value = 0
    shift = 0
    while True:
        assert offset < end, 'truncated LEB128'
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            if signed and byte & 0x40:
                value -= 1 << shift
            return value, offset
        assert shift <= 70, 'overlong LEB128'


def _read_encoded(data, offset, encoding, field_va, end):
    fmt = encoding & 0x0f
    if fmt in (0x01, 0x09):
        value, offset = _leb(data, offset, end, fmt == 0x09)
    else:
        sizes = {0x00: 8, 0x02: 2, 0x03: 4, 0x04: 8, 0x0a: 2, 0x0b: 4, 0x0c: 8}
        assert fmt in sizes, 'unsupported DW_EH_PE format 0x%x' % fmt
        size = sizes[fmt]
        assert offset + size <= end, 'truncated encoded pointer'
        if fmt in (0x0a, 0x0b, 0x0c):
            code = ('h', 'i', 'q')[size // 4]
        else:
            code = ('H', 'I', 'Q')[size // 4]
        value = struct.unpack_from('<' + code, data, offset)[0]
        offset += size
    application = encoding & 0x70
    if application == 0x10:
        value += field_va
    elif application:
        raise AssertionError('unsupported DW_EH_PE application 0x%x' % application)
    return value & 0xffffffffffffffff, offset


def _parse_cie(data, offset, end, va):
    assert offset < end, 'truncated CIE'
    version = data[offset]
    assert version in (1, 3, 4), 'unsupported CIE version %d' % version
    stop = data.find(b'\x00', offset + 1, end)
    assert stop >= 0, 'unterminated CIE augmentation string'
    augmentation = data[offset + 1:stop].decode('latin-1')
    offset = stop + 1
    _, offset = _leb(data, offset, end, False)
    _, offset = _leb(data, offset, end, True)
    if version == 1:
        assert offset < end, 'truncated CIE return register'
        offset += 1
    else:
        _, offset = _leb(data, offset, end, False)
    encoding = 0x00
    if augmentation.startswith('z'):
        length, offset = _leb(data, offset, end, False)
        aug_end = offset + length
        assert aug_end <= end, 'CIE augmentation data past record end'
        position = offset
        for char in augmentation[1:]:
            if char == 'R':
                assert position < aug_end, 'truncated CIE FDE encoding'
                encoding = data[position]
                position += 1
            elif char == 'P':
                assert position < aug_end, 'truncated CIE personality encoding'
                pointer_encoding = data[position]
                position += 1
                _, position = _read_encoded(data, position, pointer_encoding, 0, aug_end)
            elif char == 'L':
                position += 1
            elif char not in ('S', 'B', 'G'):
                raise AssertionError('unsupported CIE augmentation %r' % char)
        assert position == aug_end, 'CIE augmentation length does not match its fields'
        offset = aug_end
    return {'va': va, 'encoding': encoding}


def parse_eh_frame(data, section):
    base = section['offset']
    stop = base + section['size']
    assert stop <= len(data), '.eh_frame past end of file'
    offset = base
    cies = {}
    frames = []
    while offset + 4 <= stop:
        va = section['addr'] + (offset - base)
        length = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if length == 0:
            break
        if length == 0xffffffff:
            assert offset + 8 <= stop, 'truncated extended .eh_frame length'
            length = struct.unpack_from('<Q', data, offset)[0]
            offset += 8
        body = offset
        record_end = body + length
        assert length >= 4 and record_end <= stop, '.eh_frame record past section end'
        (first,) = struct.unpack_from('<I', data, body)
        if first == 0:
            cies[va] = _parse_cie(data, body + 4, record_end, va)
        else:
            cie_va = section['addr'] + (body - base) - first
            cie = cies.get(cie_va)
            assert cie is not None, 'FDE references an unknown CIE'
            field_va = section['addr'] + (body + 4 - base)
            start, position = _read_encoded(data, body + 4, cie['encoding'], field_va, record_end)
            size, position = _read_encoded(data, position, cie['encoding'] & 0x0f, 0, record_end)
            assert size > 0, 'FDE reports an empty address range'
            frames.append({'start': start, 'end': start + size, 'cie': cie_va})
        offset = record_end
    frames.sort(key=lambda frame: (frame['start'], frame['end']))
    for index in range(1, len(frames)):
        assert frames[index - 1]['start'] != frames[index]['start'], 'duplicate FDE start address'
    return cies, frames


def fde_for(va, frames):
    low = 0
    high = len(frames)
    while low < high:
        middle = (low + high) // 2
        if frames[middle]['start'] <= va:
            low = middle + 1
        else:
            high = middle
    index = low - 1
    steps = 0
    while index >= 0 and steps < 32:
        frame = frames[index]
        if frame['start'] <= va < frame['end']:
            return frame
        index -= 1
        steps += 1
    return None


def frame_lines(section_name, records, frames):
    lines = []
    covered = 0
    for record in records:
        frame = fde_for(record['va'], frames)
        if frame is None:
            lines.append('frame %s[%d] va=%s fde=none' % (
                section_name, record['index'], hx(record['va'])))
            continue
        covered += 1
        lines.append('frame %s[%d] va=%s fde=%s..%s bytes=%d' % (
            section_name, record['index'], hx(record['va']),
            hx(frame['start']), hx(frame['end']), frame['end'] - frame['start']))
    return lines, covered


def _array_summary(section, records, slot_text, frame_text, covered):
    return {
        'va': hx(section['addr']),
        'offset': hx(section['offset']),
        'size': section['size'],
        'count': len(records),
        'covered_by_relative': sum(1 for record in records if record['relative']),
        'slots_sha256': digest_lines(slot_text),
        'frames_sha256': digest_lines(frame_text),
        'fde_covered': covered,
        'fde_missing': len(records) - covered,
    }


def derive(root):
    binary = root / TARGET_PATH
    assert binary.is_file(), 'missing pinned target ' + str(binary)
    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == TARGET_SHA256, 'target digest mismatch: ' + digest
    assert len(data) == TARGET_SIZE, 'target size mismatch: %d' % len(data)
    sections = section_table(load_sections(data))
    names = ('.init_array', '.fini_array', '.rela.dyn', '.eh_frame')
    for name in names:
        assert name in sections, 'required section missing: ' + name
    relocations, rela_records = relative_relocations(data, sections['.rela.dyn'])
    init = slot_records(data, sections['.init_array'], SHT_INIT_ARRAY, relocations)
    fini = slot_records(data, sections['.fini_array'], SHT_FINI_ARRAY, relocations)
    cies, frames = parse_eh_frame(data, sections['.eh_frame'])
    lines = {
        'init_lines': slot_lines('.init_array', init),
        'fini_lines': slot_lines('.fini_array', fini),
    }
    lines['init_frames'], init_covered = frame_lines('.init_array', init, frames)
    lines['fini_frames'], fini_covered = frame_lines('.fini_array', fini, frames)
    derived = {
        'target_sha256': digest,
        'target_size': len(data),
        'sections': {},
        'rela_dyn': {'records': rela_records, 'relative_targets': len(relocations)},
        'eh_frame': {'cie_records': len(cies), 'fde_records': len(frames)},
        'init_array': _array_summary(sections['.init_array'], init,
                                     lines['init_lines'], lines['init_frames'], init_covered),
        'fini_array': _array_summary(sections['.fini_array'], fini,
                                     lines['fini_lines'], lines['fini_frames'], fini_covered),
    }
    for name in names:
        entry = sections[name]
        derived['sections'][name] = {
            'index': entry['index'],
            'type': entry['type'],
            'flags': hx(entry['flags']),
            'addr': hx(entry['addr']),
            'offset': hx(entry['offset']),
            'size': entry['size'],
            'entsize': entry['entsize'],
        }
    return derived, lines


def compare(path, recorded, derived, mismatches):
    if isinstance(derived, dict):
        if not isinstance(recorded, dict):
            mismatches.append((path, recorded, derived))
            return
        for key in sorted(derived):
            compare(path + '.' + key, recorded.get(key, '<missing>'), derived[key], mismatches)
        return
    if recorded != derived:
        mismatches.append((path, recorded, derived))


def comparator_controls():
    probe = []
    compare('control', {'value': 1}, {'value': 2}, probe)
    assert len(probe) == 1, 'comparator did not report a changed scalar'
    probe = []
    compare('control', {'value': 1}, {'value': 1}, probe)
    assert not probe, 'comparator reported an identical scalar'
    probe = []
    compare('control', {}, {'value': 1}, probe)
    assert len(probe) == 1, 'comparator did not report a missing record'


def digest_controls(lines):
    for key in sorted(lines):
        body = lines[key]
        mutated = list(body)
        mutated[0] = mutated[0] + 'x'
        assert digest_lines(mutated) != digest_lines(body), 'record digest does not bind ' + key


def _line_slot(line):
    head = line.partition('] ')[0]
    section, _, index = head.rpartition('[')
    assert section, 'excerpt line has no slot index: ' + line
    assert index.isdigit(), 'excerpt line index is not numeric: ' + line
    return section, int(index)


def check_excerpts(packet, lines, recorded, mismatches):
    allowed = {
        'init-array.txt': set(lines['init_lines']),
        'frames.txt': set(lines['init_frames'] + lines['fini_frames']),
    }
    for name in ('init-array.txt', 'frames.txt'):
        text = (packet / name).read_text(encoding='utf-8')
        body = [line.rstrip() for line in text.splitlines() if line.strip()]
        assert body, name + ' records no observed line'
        assert len(body) <= 64, name + ' is longer than the bounded excerpt'
        last = {}
        for line in body:
            assert line in allowed[name], name + ' line is not derived from the target: ' + line
            section, index = _line_slot(line)
            assert last.get(section, -1) < index, name + ' lines are not in increasing order: ' + line
            last[section] = index
        entry = recorded.get('excerpts')
        assert isinstance(entry, dict) and name in entry, 'evidence.json lacks excerpts.' + name
        if entry[name] != len(body):
            mismatches.append(('excerpts.' + name, entry[name], len(body)))


def main():
    root = Path(__file__).resolve().parents[1]
    derived, lines = derive(root)
    print('target path ' + str(TARGET_PATH))
    print('target sha256 ' + derived['target_sha256'])
    print('target size %d' % derived['target_size'])
    for name in ('.init_array', '.fini_array', '.rela.dyn', '.eh_frame'):
        entry = derived['sections'][name]
        print('section %s index=%d type=%d flags=%s addr=%s offset=%s size=%d entsize=%d' % (
            name, entry['index'], entry['type'], entry['flags'], entry['addr'],
            entry['offset'], entry['size'], entry['entsize']))
    print('rela.dyn records %d relative targets %d' % (
        derived['rela_dyn']['records'], derived['rela_dyn']['relative_targets']))
    print('.eh_frame cie_records %d fde_records %d' % (
        derived['eh_frame']['cie_records'], derived['eh_frame']['fde_records']))
    for name in ('init_array', 'fini_array'):
        entry = derived[name]
        print('%s count=%d size=%d covered_by_relative=%d fde_covered=%d fde_missing=%d' % (
            name, entry['count'], entry['size'], entry['covered_by_relative'],
            entry['fde_covered'], entry['fde_missing']))
        print(name + ' slots_sha256 ' + entry['slots_sha256'])
        print(name + ' frames_sha256 ' + entry['frames_sha256'])
    for line in lines['init_lines'][:8]:
        print(line)
    for line in lines['init_lines'][-4:]:
        print(line)
    for line in lines['init_frames'][:6]:
        print(line)
    for line in lines['fini_lines']:
        print(line)
    for line in lines['fini_frames']:
        print(line)
    packet = root / PACKET_DIR
    for name in PACKET_FILES:
        print('packet file ' + name + ' present=' + str((packet / name).is_file()))
    missing = [name for name in PACKET_FILES if not (packet / name).is_file()]
    assert not missing, 'evidence packet is incomplete, missing: ' + ', '.join(missing)
    try:
        recorded = json.loads((packet / 'evidence.json').read_text(encoding='utf-8'))
    except ValueError as error:
        raise AssertionError('evidence.json is not valid JSON: ' + str(error))
    assert isinstance(recorded, dict), 'evidence.json must hold an object'
    mismatches = []
    compare('evidence', recorded, derived, mismatches)
    check_excerpts(packet, lines, recorded, mismatches)
    comparator_controls()
    digest_controls(lines)
    for path, was, now in mismatches:
        print('MISMATCH %s recorded=%r derived=%r' % (path, was, now))
    assert not mismatches, '%d recorded value(s) disagree with the target bytes' % len(mismatches)
    print('packet verified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
