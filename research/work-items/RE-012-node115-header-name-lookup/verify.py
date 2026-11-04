"""Reproduce selected Node115 code/data observations; never execute the target."""
import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
LEAF = bytes.fromhex('400fb6c7c1e003488d0d029f7afd488b1408488d0def345e03488b0408c3')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def contract(data, record, headers):
    require(record['targetSHA256'] == TARGET_SHA256 and record['targetSize'] == len(data), 'record target identity mismatch')
    secs = sections(data)

    def read(address, size):
        candidates = [s for s in secs if s['type'] != 8
                      and s['address'] <= address
                      and address + size <= s['address'] + s['size']]
        require(len(candidates) == 1, 'ambiguous or unmapped ELF VA')
        section = candidates[0]
        offset = section['offset'] + address - section['address']
        return data[offset:offset + size]

    relocations = {}
    for section in secs:
        if section['type'] != 4:
            continue
        require(section['size'] % 24 == 0, 'invalid RELA extent')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            cell, info, addend = struct.unpack_from('<QQq', data, offset)
            if info & 0xffffffff == 8:
                relocations[cell] = addend

    require(len(headers) == 81, 'selected table has exactly81 header rows')
    for ordinal, row in enumerate(headers):
        require(int(row['ordinal']) == ordinal, 'ordinal order mismatch')
        name = row['name'].encode('ascii')
        require(re.fullmatch(b'[a-z0-9-]+', name), 'not a standard header literal')
        cell, target, length_cell = (int(row[k], 16) for k in
                                     ['pointer_cell_elf_va', 'name_elf_va', 'length_cell_elf_va'])
        require(cell == int(record['pointerTableELFVA'], 16) + ordinal * 8,
                'pointer cell mismatch')
        require(length_cell == int(record['lengthTableELFVA'], 16) + ordinal * 8,
                'length cell mismatch')
        require(relocations.get(cell) == target, 'name relocation mismatch')
        require(read(cell, 8) == bytes(8), 'pointer cell pre-relocation bytes differ')
        require(struct.unpack('<Q', read(length_cell, 8))[0] == int(row['length']) == len(name),
                'observed length mismatch')
        require(read(target, len(name)) == name, 'header literal mismatch')

    leaf_start = int(record['observedLeaf']['extent'][0], 16)
    require(int(record['observedLeaf']['extent'][1], 16) - leaf_start == len(LEAF), 'lookup extent differs')
    require(read(leaf_start, len(LEAF)) == LEAF, 'lookup instructions differ')
    require(leaf_start + 14 + struct.unpack('<i', LEAF[10:14])[0]
            == int(record['lengthTableELFVA'], 16), 'length RIP target mismatch')
    require(leaf_start + 25 + struct.unpack('<i', LEAF[21:25])[0]
            == int(record['pointerTableELFVA'], 16), 'pointer RIP target mismatch')
    for address, expected in [
            (0x2e774ae, '488d0d43295e03'), (0x2e77654, '488d0d9d275e03'),
            (0x2e77368, '807c246400'), (0x2e775b3, '6642c704383a20'),
            (0x2e77625, '66c704300d0a'), (0x2e77693, '4420f540c0e5054430ed')]:
        expected = bytes.fromhex(expected)
        require(read(address, len(expected)) == expected, 'writer instruction predicate differs')

    for location in record['writerSourceLocationCandidates']:
        address = int(location['locationELFVA'], 16)
        site = int(location['instructionELFVA'], 16)
        instruction = read(site, 7)
        require(instruction[:3] == bytes.fromhex('488d15') and site + 7 + struct.unpack('<i', instruction[3:])[0] == address, 'source-location code reference differs')
        target = relocations.get(address)
        require(target == int(location['fileStringELFVA'], 16), 'source-path relocation mismatch')
        size, line, column = struct.unpack('<QII', read(address + 8, 16))
        literal = read(target, size)
        require(hashlib.sha256(literal).hexdigest() == location['sourcePathByteSHA256'],
                'compiled source-path digest mismatch')
        require(literal.decode('utf-8').endswith(location['sourcePathSuffix'])
                and (line, column) == (location['line'], location['column']),
                'vendored source coordinate mismatch')

    foreign = record['excludedAdjacentPanicLocation']
    address = int(foreign['ELFVA'], 16)
    target = relocations.get(address)
    size, line, column = struct.unpack('<QII', read(address + 8, 16))
    require(read(target, size).decode('utf-8') == foreign['file']
            and (line, column) == (foreign['line'], foreign['column']),
            'unrelated panic descriptor differs')
    require('/library/core/src/time.rs' in foreign['file'] and not foreign['headerLookupRole'],
            'adjacent descriptor is not a header name')
    _, fdes, _ = fde_extents(data)
    for span in record['disassembly']:
        lo, hi = int(span['startELFVA'], 16), int(span['endELFVA'], 16)
        require(any(f['start'] == lo and f['end'] == hi for f in fdes),
                'selected unwind extent differs')
    return {'header_rows': len(headers), 'selected_unwind_ranges': len(record['disassembly']),
            'lookup_bytes': len(LEAF), 'bounds_check_in_leaf': False}


def structural_controls(data, record, headers):
    cases = []
    altered = copy.deepcopy(headers)
    altered[0]['length'] = str(int(altered[0]['length']) + 1)
    cases.append(('wrong_length_claim', data, record, altered))
    altered = copy.deepcopy(headers)
    altered.append(dict(altered[-1], ordinal='81'))
    cases.append(('adjacent_descriptor_as_82nd_header', data, record, altered))
    altered_record = copy.deepcopy(record)
    altered_record['observedLeaf']['extent'][0] = '0x2e758f0'
    cases.append(('file_offset_misreported_as_elf_va', data, altered_record, headers))
    for name, candidate, rec, table in cases:
        try:
            contract(candidate, rec, table)
        except ValueError:
            continue
        raise ValueError('structural negative accepted: ' + name)
    # Mutation is in memory after identity authentication, to exercise the
    # instruction contract rather than merely re-testing the whole-file hash.
    changed = bytearray(data)
    text = next(s for s in sections(data) if s['name'] == '.text')
    offset = text['offset'] + 0x2e768f0 - text['address']
    changed[offset] ^= 1
    try:
        contract(changed, record, headers)
    except ValueError:
        return [case[0] for case in cases] + ['changed_lookup_instruction']
    raise ValueError('changed instruction accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--objdump', required=True)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    data = args.target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == TARGET_SHA256, 'wrong target identity')
    tool = Path(shutil.which(args.objdump) or args.objdump).resolve()
    captured = {TARGET_SHA256, '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}
    require(hashlib.sha256(tool.read_bytes()).hexdigest() not in captured,
            'captured node/visor cannot be selected as an analysis tool')
    version = subprocess.check_output([str(tool), '--version'], stderr=subprocess.PIPE).decode('utf-8').splitlines()[0]
    require('GNU objdump' in version, 'select the declared GNU analysis tool')
    record = json.loads((HERE / 'observed/records.json').read_text(encoding='utf-8'))
    with (HERE / 'observed/headers.tsv').open(encoding='utf-8', newline='') as handle:
        headers = list(csv.DictReader(handle, delimiter='\t'))
    result = contract(data, record, headers)
    native = []
    for span in record['disassembly']:
        retained = HERE / 'observed' / (span['name'] + '.objdump.txt')
        require(hashlib.sha256(retained.read_bytes()).hexdigest() == span['outputSHA256'], 'retained raw disassembly changed')
        command = [str(tool), '-d', '-M', 'intel',
                   '--start-address=' + span['startELFVA'], '--stop-address=' + span['endELFVA'],
                   str(args.target)]
        output = subprocess.check_output(command, cwd=ROOT, stderr=subprocess.PIPE).decode('utf-8')
        for expected in {'lookup': ['2e76902'], 'writer': ['2e774ae', '2e77654'],
                         'adjacent-negative': ['2e7dad9']}[span['name']]:
            require(re.search(r'^\s*' + expected + r':\s', output, re.M),
                    'native decoded instruction boundary missing')
        native.append({'span': span['name'], 'command': command, 'decoded_boundaries_confirmed': True})
    result.update(target_sha256=TARGET_SHA256, analysis_tool_version=version, native_disassembly=native,
                  captured_target_executed=False, implementation_or_gate_claim=False)
    if args.self_test:
        result['post_identity_structural_negatives_rejected'] = structural_controls(data, record, headers)
    rendered = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(rendered.encode('utf-8'))
    print(rendered)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print('header lookup evidence: ' + str(error), file=sys.stderr)
        raise SystemExit(1)