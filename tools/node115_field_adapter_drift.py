#!/usr/bin/env python3
"""RE-014: source-bound node115 field caller and strict adapter extent drift.

Static bytes and metadata only. No captured/native/compiler/evaluator execution.
The explicit official artifact is a compatibility provider, not an original-build claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import elf_index
from build_provenance import program_headers

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
ARCHIVE_SHA256 = 'ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256'
ARCHIVE_SIZE = 2917630
MEMBER = 'core-e60dd2ab51fbc7de.core.61a85662de008515-cgu.0.rcgu.o'
MEMBER_SHA256 = '57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13'
PARENT_START, PARENT_END = 0x167d950, 0x167dad6
ADAPTER_START, ADAPTER_END = 0x1686bd0, 0x1686e46
PARENT_SECTION = '.text._ZN4core3fmt8builders11DebugStruct5field17h1d514c80a2f1f809E'
ADAPTER_SECTION = '.text._ZN68_$LT$core..fmt..builders..PadAdapter$u20$as$u20$core..fmt..Write$GT$9write_str17h26b230683c3cc8feE'
FIELD_ROLES = {93: (2, 'literal', b', '), 100: (2, 'literal', b' { '),
               154: (2, 'literal', b': '), 207: (2, 'literal', b' {\n'),
               284: (2, 'vtable', None), 294: (9, 'adapter', None),
               309: (2, 'literal', b': '), 324: (9, 'adapter', None),
               370: (2, 'literal', b',\n')}


class EvidenceError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise EvidenceError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def authenticate_target(data):
    need(type(data) is bytes and len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
         'expected immutable authenticated node115 size/SHA-256')


def authenticate_archive(data):
    need(type(data) is bytes and len(data) == ARCHIVE_SIZE and sha(data) == ARCHIVE_SHA256,
         'expected immutable authenticated official libcore archive size/SHA-256')


def archive_member(data):
    need(type(data) is bytes and data[:8] == b'!<arch>\n', 'expected GNU ar archive')
    cursor, names, found = 8, b'', []
    while cursor < len(data):
        header = data[cursor:cursor + 60]
        need(len(header) == 60 and header[58:60] == b'`\n', 'invalid ar member header')
        try:
            size = int(header[48:58]); name = header[:16].decode('ascii').rstrip()
        except (ValueError, UnicodeDecodeError) as error:
            raise EvidenceError('invalid ar name/size') from error
        offset = cursor + 60
        need(size >= 0 and offset + size <= len(data), 'truncated ar member')
        body = data[offset:offset + size]
        if name == '//':
            names = body
        elif name.startswith('/') and name[1:].isdigit():
            index = int(name[1:]); end = names.find(b'/\n', index)
            need(0 <= index < len(names) and end >= index, 'invalid ar long name')
            name = names[index:end].decode('ascii')
        else:
            name = name.rstrip('/')
        if name == MEMBER:
            found.append((body, offset))
        cursor = offset + size + size % 2
    need(cursor == len(data) and len(found) == 1, 'expected one exact core object member')
    return found[0]


class Image:
    """Existing main section/program readers, with bounded symbol/RELA access."""
    def __init__(self, data, kind):
        need(type(data) is bytes and len(data) >= 64, 'expected immutable ELF bytes')
        need(data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] == 62,
             'expected AMD64 ELF64 little-endian')
        need(struct.unpack_from('<H', data, 16)[0] == kind, 'unexpected ELF object type')
        self.data = data
        self.sections = elf_index.sections(data)
        self.programs = program_headers(data)
        self.shoff = struct.unpack_from('<Q', data, 40)[0]
        need(struct.unpack_from('<H', data, 58)[0] == 64, 'unsupported section header size')
        for index, section in enumerate(self.sections):
            raw = struct.unpack_from('<IIQQQQIIQQ', data, self.shoff + 64 * index)
            section.update(index=index, link=raw[6], info=raw[7], entry_size=raw[9],
                           header_file_offset=self.shoff + 64 * index)

    def named(self, name):
        rows = [s for s in self.sections if s['name'] == name]
        need(len(rows) == 1, 'expected one section: ' + name)
        return rows[0]

    def content(self, section):
        need(section['type'] != 8, 'NOBITS has no file bytes')
        return self.data[section['offset']:section['offset'] + section['size']]

    def virtual(self, address, size, code=False):
        need(isinstance(address, int) and size > 0, 'invalid virtual read')
        segments = [p for p in self.programs if p[0] == 1 and p[3] <= address
                    and address + size <= p[3] + p[5] and (not code or p[1] & 1)]
        sections = [s for s in self.sections if s['type'] != 8 and s['size']
                    and s['address'] <= address and address + size <= s['address'] + s['size']
                    and (not code or s['flags'] & 4)]
        need(len(segments) == len(sections) == 1, 'read lacks unique file-backed section/PT_LOAD')
        segment, section = segments[0], sections[0]
        offset = segment[2] + address - segment[3]
        need(offset == section['offset'] + address - section['address'], 'section/PT_LOAD disagreement')
        return self.data[offset:offset + size], offset, section

    def symbol(self, table_index, index):
        need(0 <= table_index < len(self.sections), 'invalid symbol table index')
        table = self.sections[table_index]
        need(table['type'] in (2, 11) and table['entry_size'] == 24
             and table['size'] % 24 == 0 and 0 <= index < table['size'] // 24,
             'invalid symbol entry')
        offset = table['offset'] + index * 24
        name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', self.data, offset)
        need(table['link'] < len(self.sections), 'invalid symbol string table')
        strings = self.content(self.sections[table['link']]); end = strings.find(b'\0', name)
        need(0 <= name < len(strings) and end >= name, 'invalid symbol name')
        try:
            decoded = strings[name:end].decode('utf-8')
        except UnicodeDecodeError as error:
            raise EvidenceError('invalid symbol name encoding') from error
        return {'name': decoded, 'info': info, 'other': other,
                'section_index': section, 'value': value, 'size': size,
                'file_offset': offset, 'symbol_index': index, 'symbol_table_index': table_index}

    def rela_rows(self, section):
        need(section['type'] == 4 and section['entry_size'] == 24 and section['size'] % 24 == 0,
             'invalid RELA section')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', self.data, offset)
            yield {'offset': address, 'type': info & 0xffffffff, 'symbol_index': info >> 32,
                   'addend': addend, 'record_file_offset': offset,
                   'relocation_section': section['name'], 'target_section_index': section['info'],
                   'symbol_table_index': section['link']}

    def object_relocations(self, destination):
        sections = [s for s in self.sections if s['type'] == 4 and s['info'] == destination['index']]
        need(len(sections) == 1, 'expected one object RELA section')
        rows = list(self.rela_rows(sections[0]))
        for row in rows:
            row['symbol'] = self.symbol(row['symbol_table_index'], row['symbol_index'])
        return rows


def selected_frame(image, expected_start, expected_size):
    """Only logarithmic index probes and this FDE/CIE; no global FDE census."""
    header, frames = image.named('.eh_frame_hdr'), image.named('.eh_frame')
    raw = image.content(header)
    need(len(raw) >= 12 and raw[:4] == bytes([1, 0x1b, 0x03, 0x3b]), 'unsupported unwind header')
    count = struct.unpack_from('<I', raw, 8)[0]
    need(12 + count * 8 <= len(raw), 'truncated unwind index')
    low, high, probes = 0, count, []
    while low < high:
        index = (low + high) // 2
        value = header['address'] + struct.unpack_from('<i', raw, 12 + index * 8)[0]
        probes.append(index)
        if value < expected_start:
            low = index + 1
        else:
            high = index
    need(low < count, 'selected FDE start absent')
    entry = 12 + low * 8; start_delta, frame_delta = struct.unpack_from('<ii', raw, entry)
    need(header['address'] + start_delta == expected_start, 'selected FDE start absent')
    # Local neighbors are checked; the full digest, not an invented global census,
    # binds the rest of the established index.
    for neighbor in (low - 1, low + 1):
        if 0 <= neighbor < count:
            value = header['address'] + struct.unpack_from('<i', raw, 12 + neighbor * 8)[0]
            need(value < expected_start if neighbor < low else value > expected_start,
                 'selected unwind index neighborhood is not strict')
    fde_va = header['address'] + frame_delta
    fde_offset = frames['offset'] + fde_va - frames['address']
    need(frames['offset'] <= fde_offset and fde_offset + 4 <= frames['offset'] + frames['size'],
         'selected FDE outside .eh_frame')
    length = struct.unpack_from('<I', image.data, fde_offset)[0]
    # The supported zR record needs4B CIE displacement,4B begin,4B range,
    # and its one-byte zero augmentation length INSIDE the declared record.
    need(13 <= length < 0xffffffff and fde_offset + length + 4 <= frames['offset'] + frames['size'],
         'invalid selected FDE length')
    cie_delta, begin_delta, size = struct.unpack_from('<IiI', image.data, fde_offset + 4)
    need(image.data[fde_offset + 16] == 0, 'unsupported selected FDE augmentation length')
    need(fde_va + 8 + begin_delta == expected_start and size == expected_size,
         'selected FDE extent disagreement')
    cie_offset = fde_offset + 4 - cie_delta
    need(frames['offset'] <= cie_offset and cie_offset + 8 <= fde_offset, 'invalid selected CIE binding')
    cie_length, cie_id = struct.unpack_from('<II', image.data, cie_offset)
    need(cie_id == 0 and cie_length > 0 and cie_offset + cie_length + 4 <= fde_offset,
         'invalid selected CIE')
    cie = image.data[cie_offset:cie_offset + cie_length + 4]
    # Both selected FDEs use this observed zR CIE. Do not reinterpret arbitrary encodings.
    need(cie == bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'),
         'selected CIE encoding/record changed')
    body, body_offset, section = image.virtual(expected_start, expected_size, code=True)
    return {'start': expected_start, 'end': expected_start + expected_size, 'bytes': expected_size,
            'body_file_offset': body_offset, 'body_sha256': sha(body), 'section': section['name'],
            'FDE_VA': fde_va, 'FDE_file_offset': fde_offset,
            'FDE_raw_sha256': sha(image.data[fde_offset:fde_offset + length + 4]),
            'FDE_raw_length_bytes': length + 4, 'FDE_range_file_offset': fde_offset + 12,
            'FDE_CIE_pointer_file_offset': fde_offset + 4,
            'FDE_augmentation_length_file_offset': fde_offset + 16,
            'FDE_declared_length_bytes': length, 'FDE_used_header_bytes': 17,
            'CIE_file_offset': cie_offset, 'CIE_raw_sha256': sha(cie),
            'CIE_encoding_file_offset': cie_offset + 16, 'CIE_raw_hex': cie.hex(),
            'index_entry_file_offset': header['offset'] + entry,
            'index_entries_consulted': len(probes) + 3, 'global_index_census_claimed': False}


def derive(target, archive):
    """Unqualified below-identity seam. Full identity admission is analyze's job."""
    member, member_offset = archive_member(archive)
    source, image = Image(member, 1), Image(target, 3)
    parent, adapter = source.named(PARENT_SECTION), source.named(ADAPTER_SECTION)
    need(parent['size'] == 390 and adapter['size'] == 622, 'source function extents changed')
    need(parent['flags'] & 4 and adapter['flags'] & 4, 'source definitions are not executable')
    symbol_table = source.named('.symtab')
    definitions = []
    for section, size in ((parent, 390), (adapter, 622)):
        matches = []
        for index in range(symbol_table['size'] // 24):
            symbol = source.symbol(symbol_table['index'], index)
            if symbol['section_index'] == section['index'] and symbol['info'] & 15 == 2:
                matches.append(symbol)
        need(len(matches) == 1 and matches[0]['value'] == 0 and matches[0]['size'] == size
             and matches[0]['name'] == section['name'][len('.text.'):],
             'source function symbol/section definition changed')
        definitions.append(matches[0])
    source_parent = source.content(parent)
    frame = selected_frame(image, PARENT_START, PARENT_END - PARENT_START)
    adapter_frame = selected_frame(image, ADAPTER_START, ADAPTER_END - ADAPTER_START)
    target_parent, parent_offset, _ = image.virtual(PARENT_START, 390, code=True)
    rows = source.object_relocations(parent)
    need(len(rows) == len(FIELD_ROLES) and {r['offset'] for r in rows} == set(FIELD_ROLES),
         'source parent RELA field domain changed')
    literals, fields, got_slots, excluded = [], [], [], set()
    vtable_section = None
    for row in sorted(rows, key=lambda r: r['offset']):
        offset = row['offset']; kind, role, expected_literal = FIELD_ROLES[offset]
        need(row['type'] == kind and row['addend'] == -4, 'source parent RELA kind/addend changed')
        symbol = row['symbol']; index = symbol['section_index']
        need(0 < index < len(source.sections), 'source symbol is not a defined section')
        section = source.sections[index]
        need(not excluded.intersection(range(offset, offset + 4)), 'source RELA fields overlap')
        excluded.update(range(offset, offset + 4))
        destination = PARENT_START + offset + 4 + struct.unpack_from('<i', target_parent, offset)[0]
        field = {**row, 'role': role, 'field_width': 4,
                 'archive_record_file_offset': member_offset + row['record_file_offset'],
                 'target_field_file_offset': parent_offset + offset,
                 'target_field_VA': PARENT_START + offset, 'target_RIP_destination': destination,
                 'source_field_hex': source_parent[offset:offset + 4].hex(),
                 'target_field_hex': target_parent[offset:offset + 4].hex()}
        fields.append(field)
        if role == 'adapter':
            need(symbol['info'] & 15 == 2 and symbol['section_index'] == adapter['index']
                 and symbol['value'] == 0 and symbol['size'] == 622,
                 'source GOT symbol is not the selected adapter definition')
            got_slots.append(destination)
            continue
        need(symbol['info'] & 15 == 3 and symbol['value'] == 0 and section['type'] == 1,
             'source data symbol is not a section definition')
        expected = source.content(section)
        if role == 'literal':
            need(expected == expected_literal, 'source literal bytes changed')
        else:
            need(len(expected) == 48, 'source vtable byte extent changed')
            need(vtable_section is None, 'duplicate source vtable reference')
            vtable_section = section
        actual, file_offset, data_section = image.virtual(destination, len(expected))
        need(actual == expected, 'target literal/vtable raw data disagreement')
        data_row = {'parent_field_offset': offset, 'source_section_index': section['index'],
                    'source_section_name': section['name'], 'target_VA': destination,
                    'target_file_offset': file_offset, 'target_section': data_section['name'],
                    'bytes': len(actual), 'raw_hex': actual.hex(), 'sha256': sha(actual), 'raw_equal': True}
        if role == 'literal':
            literals.append(data_row)
        else:
            vtable = data_row
    need(len(excluded) == 36 and len(literals) == 6 and len(set(got_slots)) == 1,
         'selected parent comparison domains changed')
    need(all(source_parent[i] == target_parent[i] for i in range(390) if i not in excluded),
         'parent nonRELA code disagreement')
    source_pointers = source.object_relocations(vtable_section)
    need(len(source_pointers) == 3 and {r['offset'] for r in source_pointers} == {24, 32, 40},
         'source vtable RELA field domain changed')
    selected_source = []
    for row in source_pointers:
        symbol = row['symbol']; index = symbol['section_index']
        expected_kind = {24: 2, 32: 2, 40: 3}[row['offset']]
        need(row['type'] == 1 and row['addend'] == 0 and symbol['info'] & 15 == expected_kind
             and 0 < index < len(source.sections) and source.sections[index]['flags'] & 4
             and symbol['value'] == 0, 'source vtable pointer kind/symbol/addend changed')
        if row['offset'] == 24:
            need(index == adapter['index'] and symbol['size'] == 622,
                 'source selected vtable method is not the adapter')
            selected_source.append(row)
    need(len(selected_source) == 1, 'source selected adapter pointer is ambiguous')
    needed = {got_slots[0]} | {vtable['target_VA'] + r['offset'] for r in source_pointers}
    dynamic = {slot: [] for slot in needed}
    for row in image.rela_rows(image.named('.rela.dyn')):
        if row['offset'] in needed:
            dynamic[row['offset']].append(row)
    for slot, records in dynamic.items():
        need(len(records) == 1 and records[0]['type'] == 8 and records[0]['symbol_index'] == 0,
             'target pointer lacks one symbol-free RELATIVE record')
        raw_slot, slot_offset, slot_section = image.virtual(slot, 8)
        records[0].update(slot_file_offset=slot_offset, slot_section=slot_section['name'],
                          raw_slot_hex=raw_slot.hex())
        image.virtual(records[0]['addend'], 1, code=True)
    got = dynamic[got_slots[0]][0]
    need(got['addend'] == ADAPTER_START, 'selected GOT target is not the observed adapter')
    bindings = []
    for row in sorted(source_pointers, key=lambda r: r['offset']):
        slot = vtable['target_VA'] + row['offset']; actual = dynamic[slot][0]
        selected = row['offset'] == 24
        if selected:
            need(actual['addend'] == got['addend'], 'selected vtable/GOT adapter disagreement')
        bindings.append({'slot_VA': slot, 'source_RELA': row,
                         'archive_record_file_offset': member_offset + row['record_file_offset'],
                         'target_RELATIVE': actual, 'selected_630_adapter': selected,
                         'runtime_pointer_observed': False, 'further_behavior_qualified': False})
    vtable['pointer_bindings'] = bindings
    adapter_raw, _, _ = image.virtual(ADAPTER_START, 630, code=True)
    return {'schema': 'node115-field-adapter-drift-v1', 'identity_admitted': False,
            'target': {'bytes': len(target), 'sha256': sha(target), 'release': 115},
            'source_archive': {'bytes': len(archive), 'sha256': sha(archive), 'member': MEMBER,
                               'member_data_offset': member_offset, 'member_bytes': len(member),
                               'member_sha256': sha(member), 'function_definitions': definitions},
            'parent390': {'frame': frame, 'source_section': PARENT_SECTION,
                          'source_bytes': 390, 'target_bytes': 390, 'relocations': fields,
                          'actual_RELA_bytes': 36, 'nonRELA_bytes': 354,
                          'all_nonRELA_equal': True, 'raw_target_hex': target_parent.hex(),
                          'raw_source_sha256': sha(source_parent)},
            'parent_literal_references': literals, 'parent48B_vtable': vtable,
            'parent_GOT_to_adapter': {'slot_VA': got_slots[0], 'RELATIVE': got,
                                     'parent_field_offsets': [r['offset'] for r in fields if r['role'] == 'adapter']},
            'adapter630': {'frame': adapter_frame, 'source_bytes': 622, 'target_bytes': 630,
                           'extent_drift_bytes': 8, 'mask_transferred': False, 'compared_bytes': 0,
                           'behavior_transferred': False, 'raw_target_hex': adapter_raw.hex(),
                           'raw_target_sha256': sha(adapter_raw),
                           'source_section': ADAPTER_SECTION,
                           'source_sha256': sha(source.content(adapter))},
            'limits': ['Source-bound parent code/data correspondence only; no unique original compiler/source/type/ABI identity.',
                       'Adapter extent630 differs from source622: no mask, normalized byte-count or behavior transfer.',
                       'Other vtable callees and drifted adapter internal data/calls/behavior remain opaque.',
                       'RELATIVE addends are static loader inputs, not observed runtime pointer contents.',
                       'Selected indexed FDE lookups only; no global function census.',
                       'No captured execution/emulator/compiler/sourcebuild/new implementation/gate claim.']}


def analyze(target, archive):
    authenticate_target(target); authenticate_archive(archive)
    member, _ = archive_member(archive)
    need(sha(member) == MEMBER_SHA256, 'authenticated archive member differs')
    result = derive(target, archive)
    result['identity_admitted'] = True
    return result


def generate(binary, libcore, output):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError('output already exists; preserve previous evidence')
    target, archive = Path(binary).read_bytes(), Path(libcore).read_bytes()
    result = analyze(target, archive)
    payload = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('utf-8')
    output.mkdir(parents=True, exist_ok=False)
    with (output / 'records.json').open('xb') as handle:
        handle.write(payload)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--libcore', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate(args.binary, args.libcore, args.output)


if __name__ == '__main__':
    main()
