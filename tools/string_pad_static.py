#!/usr/bin/env python3
"""Static code/data/helper closure for node94's Unicode precision/string padding request.

Parse one admitted target snapshot and one admitted published ar snapshot.
GNU objdump only disassembles owned small raw spans. No target or instruction
evaluator executes. Published-artifact correspondence is not a source build.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

import libcore_fmt_correspondence as elf

ROOT = Path(__file__).resolve().parents[1]
SHA = elf.TARGET_SHA256
CORE_SHA = elf.CORE_SHA256
MAIN = '_ZN4core3fmt9Formatter3pad17hd951768bb544c519E'
COUNT = '_ZN4core3str5count14do_count_chars17h04852a97bf01ca2eE'
SPECS = [('main', 0x1573450, 1081, 300, MAIN),
         ('count', 0x15796C0, 1483, 365, COUNT)]
DATA = {0x2086A0: bytes.fromhex('bfbf0000000000000000000000000000'),
        0x2088F0: bytes.fromhex('01000000000000000100000000000000'),
        0x203E60: bytes([1]) * 16}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(body, base):
    with tempfile.TemporaryDirectory(prefix='string-pad-native-') as directory:
        p = Path(directory) / 'span.bin'
        p.write_bytes(body)
        argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                '--insn-width=16', '--adjust-vma=' + hex(base), str(p)]
        result = subprocess.run(argv, check=True, capture_output=True)
        need(p.read_bytes() == body, 'Owned native span changed')
    rows, cursor = [], base
    for line in result.stdout.decode().splitlines():
        fields = line.split('\t')
        if len(fields) < 3 or not re.fullmatch(r'\s*[0-9a-f]+:', fields[0]):
            continue
        address = int(fields[0].strip()[:-1], 16)
        raw = bytes.fromhex(fields[1])
        need(raw and address == cursor and '(bad)' not in fields[2], 'Incomplete native instruction tiling')
        need(body[address-base:address-base+len(raw)] == raw, 'Native row bytes changed')
        rows.append({'va': address, 'raw': raw.hex(), 'assembly': fields[2]})
        cursor += len(raw)
    need(cursor == base + len(body), 'Native body extent differs')
    return rows, result.stdout.decode().replace(str(p), '<owned-string-pad-span>'), {
        'argv': argv[:-1] + ['<owned-string-pad-span>'], 'stderr_hex': result.stderr.hex(),
        'version': subprocess.run(['objdump', '--version'], check=True, capture_output=True).stdout.decode().splitlines()[0]}


def native_edges(rows):
    result = []
    for row in rows:
        raw, va = bytes.fromhex(row['raw']), row['va']
        if raw[:1] == b'\xe8':
            result.append({'va': va, 'kind': 'direct-call', 'target': va+5+int.from_bytes(raw[1:5], 'little', signed=True)})
        elif raw[:2] == b'\xff\x15':
            result.append({'va': va, 'kind': 'RIP-call', 'slot': va+6+int.from_bytes(raw[2:6], 'little', signed=True)})
        elif raw[:1] == b'\xff' and raw[1] & 0x38 in (0x10, 0x20):
            kind = 'local-alignment-jump' if va == 0x15737BB else 'dynamic-call-or-tail'
            result.append({'va': va, 'kind': kind, 'raw': raw.hex()})
        elif raw[:1] in (b'\x41', b'\x42', b'\x43') and raw[1:2] == b'\xff' and raw[2] & 0x38 in (0x10, 0x20):
            result.append({'va': va, 'kind': 'dynamic-call-or-tail', 'raw': raw.hex()})
    return result


def audit_loader_writes(target):
    """Census actual ELF relocation writes; this does not apply a loader."""
    need(not any(s['type'] in (9, 19) and s['size'] for s in target.sections),
         'Unhandled non-RELA relocation table')
    immutable = [(base, base + size, role) for role, base, size, _, _ in SPECS]
    immutable += [(address, address + len(raw), 'constant-' + hex(address)) for address, raw in DATA.items()]
    immutable.append((0x251B74, 0x251B84, 'alignment-table'))
    slot, end_slot = 0x5770628, 0x5770630
    counts, tables, selected = {}, [], []
    for section in target.sections:
        if section['type'] != 4:
            continue
        need(section['entsize'] == 24 and section['size'] % 24 == 0,
             'Malformed actual RELA record domain')
        table_count = 0
        for position in range(section['offset'], section['offset'] + section['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', target.data, position)
            kind, symbol = info & 0xffffffff, info >> 32
            # These are the complete observed kinds in this authenticated ELF;
            # every one writes an eight-byte x86-64 field. Unknowns fail closed.
            need(kind in (1, 6, 7, 8, 18), 'Unhandled actual relocation write kind')
            need(address <= (1 << 64) - 8, 'Wrapping loader write interval')
            end = address + 8
            for start, stop, role in immutable:
                need(not (address < stop and start < end), 'Loader write overlaps immutable ' + role)
            if address < end_slot and slot < end:
                selected.append({'slot': address, 'end': end, 'kind': kind, 'symbol': symbol,
                                 'addend': addend, 'record_file_offset': position,
                                 'section_index': section['index'], 'section_name': section['name']})
            counts[kind] = counts.get(kind, 0) + 1
            table_count += 1
        tables.append({'section_index': section['index'], 'section_name': section['name'],
                       'record_count': table_count})
    need(counts == {8: 78833, 6: 263, 1: 924, 18: 2, 7: 278}, 'Actual full RELA census differs')
    need(len(selected) == 1 and selected[0]['slot'] == slot and selected[0]['end'] == end_slot
         and selected[0]['kind'] == 8 and selected[0]['symbol'] == 0
         and selected[0]['addend'] == 0x15796C0, 'Competing or partial count-slot loader writer')
    return {'records': sum(counts.values()), 'kind_counts': counts, 'record_tables': tables,
            'all_observed_write_widths': 8, 'protected_intervals': immutable,
            'immutable_overlap_count': 0, 'selected_slot_writers': selected,
            'no_nonempty_REL_or_RELR_sections': True}


def derive(target_bytes, archive_bytes):
    """Inner structural producer also permits owned corruption controls."""
    members = elf.ar_members(archive_bytes)
    need(elf.MEMBER in members and sha(members[elf.MEMBER]) == elf.MEMBER_SHA256,
         'Selected official member identity differs')
    source, target = elf.Elf(members[elf.MEMBER], 1), elf.Elf(target_bytes, 3)
    loader_writes = audit_loader_writes(target)
    cies, fdes = elf.eh_frame_records(target_bytes, target.sections)
    symbols, records, exports = {}, {}, {}
    for role, base, size, count, name in SPECS:
        section = source.by_name('.text.' + name)
        symbol = source.function(section['index'], name)
        official = source.section_bytes(section['index'])
        need(len(official) == size, 'Complete published function size differs')
        body, mapping = target.va_bytes(base, size, executable=True)
        matching = [f for f in fdes if f['start'] == base]
        need(len(matching) == 1 and matching[0]['end'] == base+size, 'Exact complete FDE binding is not unique')
        fde = matching[0]
        cie = cies[fde['cie']]
        fields, excluded = [], set()
        for row in source.relocations(section['index']):
            offset = row['offset']
            need(row['kind'] in (2, 4, 9) and row['addend'] == -4 and 0 <= offset <= size-4,
                 'Actual code relocation kind/addend/extent changed')
            slots = set(range(offset, offset+4))
            need(not excluded & slots, 'Overlapping code relocation fields')
            excluded |= slots
            destination = base+offset+4+int.from_bytes(body[offset:offset+4], 'little', signed=True)
            fields.append({**row, 'width': 4, 'target_reference_va': destination})
        differences = [i for i, (a, b) in enumerate(zip(body, official)) if a != b]
        need(not [i for i in differences if i not in excluded], role + ' has changed non-relocation code/dataflow bytes')
        expected_offsets = {'main': [190, 268, 294, 853], 'count': [115, 123, 261, 269, 606]}[role]
        need([f['offset'] for f in fields] == expected_offsets, 'Exact source relocation field domain changed')
        rows, listing, native = decode(body, base)
        need(len(rows) == count, 'Complete native row denominator changed')
        frame, _ = target.va_bytes(fde['fde'], 8)
        flen = struct.unpack_from('<I', frame)[0]+4
        cie_head, _ = target.va_bytes(fde['cie'], 4)
        clen = struct.unpack('<I', cie_head)[0]+4
        records[role] = {'role': role, 'range': [hex(base), hex(base+size)], 'bytes': size,
                         'rows': count, 'body_sha256': sha(body), 'source_symbol': symbol,
                         'source_section': section, 'source_body_sha256': sha(official),
                         'target_mapping': mapping, 'FDE': fde, 'CIE': cie,
                         'fde_raw': target.va_bytes(fde['fde'], flen)[0].hex(),
                         'cie_raw': target.va_bytes(fde['cie'], clen)[0].hex(),
                         'raw_equal_positions': size-len(differences), 'code_relocation_bytes': len(excluded),
                         'nonfield_equal_positions': size-len(excluded), 'relocations': fields,
                         'native_rows': rows, 'edges': native_edges(rows), 'native_tool': native}
        symbols[role] = symbol
        exports[role + '.objdump.txt'] = listing.encode()
        exports['official-' + role + '.bin'] = official
        exports['captured-' + role + '.bin'] = body
    references = []
    for role, record in records.items():
        for field in record['relocations']:
            symbol, destination = field['symbol'], field['target_reference_va']
            item = {'role': role, 'field_offset': field['offset'], 'kind': field['kind'], 'target_va': hex(destination)}
            if field['kind'] == 9:
                need(role == 'main' and symbol == symbols['count'], 'Official count helper symbol differs')
                relative = target.relative(destination)
                need(destination == 0x5770628 and relative['addend'] == SPECS[1][1]
                     and target.va_bytes(destination, 8)[0] == bytes(8), 'Actual fixed count RELATIVE binding differs')
                item['target_relative'] = relative
            elif role == 'main' and field['offset'] == 853:
                section = source.section(symbol['section'])
                table = source.section_bytes(section['index'])
                relas = source.relocations(section['index'])
                raw, _ = target.va_bytes(destination, 16)
                need(destination == 0x251B74 and len(table) == 16 and [r['offset'] for r in relas] == [0, 4, 8, 12],
                     'Actual alignment table domain differs')
                expected = []
                for r in relas:
                    need(r['kind'] == 2 and r['symbol']['section'] == symbols['main']['section'], 'Alignment source target differs')
                    expected.append(SPECS[0][1] + r['symbol']['value'] + r['addend'] - r['offset'])
                actual = [destination + v for v in struct.unpack('<iiii', raw)]
                need(actual == expected == [0x15737BD, 0x15737E2, 0x15737E6, 0x15737BD], 'Actual alignment destinations differ')
                starts = {r['va'] for r in records['main']['native_rows']}
                need(all(v in starts for v in actual), 'Alignment target is not an actual native instruction start')
                item.update({'raw': raw.hex(), 'source_table_relocations': relas, 'target_destinations': [hex(v) for v in actual]})
            else:
                need(destination in DATA, 'Unexpected actual constant reference')
                section = source.section_bytes(symbol['section'])
                raw = section[symbol['value']:symbol['value']+16]
                observed, _ = target.va_bytes(destination, 16)
                need(raw == observed == DATA[destination], 'Actual count classifier/reduction constant differs')
                item.update({'source_raw': raw.hex(), 'target_raw': observed.hex()})
            references.append(item)
    need(len(records['main']['edges']) == 6
         and sum(e['kind'] == 'local-alignment-jump' for e in records['main']['edges']) == 1
         and not records['count']['edges'],
         'Actual complete CALL/tail-dispatch closure changed')
    def operand(role, offset, size, expected):
        observed = int.from_bytes(exports['captured-' + role + '.bin'][offset:offset+size], 'little')
        need(observed == expected, 'Actual proved scalar operand differs')
        return observed
    parameters = {'option_mask': operand('main', 0x1B, 4, 0x18000000),
                  'precision_mask': operand('main', 0x28, 4, 0x10000000),
                  'count_threshold': operand('main', 0x31, 1, 32),
                  'fill_mask': operand('main', 0x39E, 4, 0x1FFFFF),
                  'alignment_shift': operand('main', 0x34E, 1, 29), 'width_bits': 16, 'precision_bits': 16,
                  'count_batch_words': operand('count', 0x2B6, 4, 192),
                  'count_batch_cmov_operand': operand('count', 0x2BC, 4, 192),
                  'pair_mask': operand('count', 0x244, 8, 0x00FF00FF00FF00FF),
                  'pair_multiplier': operand('count', 0x24E, 8, 0x0001000100010001)}
    parameters.update({'byte_lane_bound': parameters['count_batch_words'],
                       'pair_bound': 2*parameters['count_batch_words'],
                       'reduction_bound': 8*parameters['count_batch_words']})
    need(parameters['byte_lane_bound'] < 256 and parameters['reduction_bound'] < 65536,
         'Actual packed-byte/pair arithmetic bounds fail')
    return {'schema': 'node94-string-pad-static/1', 'target_sha256': sha(target_bytes),
            'target_bytes': len(target_bytes), 'archive_sha256': sha(archive_bytes),
            'member_sha256': elf.MEMBER_SHA256, 'functions': records, 'references': references,
            'actual_loader_write_audit': loader_writes,
            'proof_parameters': parameters,
            'claimed_projection': 'normal callback requests/header effects/lowAL under explicit safe token/Cell domain',
            'source_artifact_is_not_rebuilt_Rust': True, 'captured_execution_or_instruction_evaluator': False,
            'component_gates_requested': False}, exports


def analyze(target_bytes, archive_bytes):
    need(type(target_bytes) is bytes and len(target_bytes) == 91774280 and sha(target_bytes) == SHA,
         'Target is not one authenticated immutable node94 snapshot')
    need(type(archive_bytes) is bytes and sha(archive_bytes) == CORE_SHA, 'Published core archive identity differs')
    return derive(target_bytes, archive_bytes)


def generate(target, core, output):
    output = Path(output)
    need(not output.exists(), 'Preserve existing output')
    report, exports = analyze(Path(target).read_bytes(), Path(core).read_bytes())
    output.mkdir(parents=True)
    for name, raw in exports.items():
        (output / name).write_bytes(raw)
    (output / 'REPORT.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--core-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = generate(args.target, args.core_archive, args.output)
    print(json.dumps({'primary_bytes': 1081, 'primary_rows': 300, 'credited_helper_bytes': 1483,
                      'credited_helper_rows': 365, 'target_sha256': report['target_sha256']}, sort_keys=True))
