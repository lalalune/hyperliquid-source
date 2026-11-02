#!/usr/bin/env python3
"""Verify static evidence and corruption controls; never execute captured code."""
import argparse
import copy
import hashlib
import gzip
import json
from pathlib import Path
import tempfile

import collect as c

HERE = Path(__file__).resolve().parent


def offset(secs, va):
    matches = [s['offset'] + va - s['address'] for s in secs
               if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']]
    c.demand(len(matches) == 1, 'mutation address unmapped')
    return matches[0]


def verify_native(text, data, secs, start, end):
    rows = c.parse_disassembly(text, start, end)
    # Separate concatenation check: no instruction evaluator, output masks or SHA gate.
    actual = bytes.fromhex(''.join(row['hex'] for row in rows))
    c.demand(actual == c.read_va(data, secs, start, end - start), 'native bytes disagree with target')
    return rows


def compare_tree(first, second):
    a = {p.name: p.read_bytes() for p in first.iterdir() if p.is_file()}
    b = {p.name: p.read_bytes() for p in second.iterdir() if p.is_file()}
    c.demand(a == b, 'retained/regenerated evidence differs')


def main(gnu, llvm):
    data = (c.ROOT / c.REL).read_bytes()
    c.demand(hashlib.sha256(data).hexdigest() == c.DIGEST, 'wrong baseline digest')
    secs, _, relocs = c.selected_checks(data)
    fdes = c.fde_checks(data, secs)
    retained = json.loads((HERE / 'observed/records.json').read_text())
    negatives = []

    def rejects(label, operation, reason):
        try:
            operation()
        except (ValueError, FileExistsError) as error:
            c.demand(reason in str(error), label + ': wrong rejection: ' + str(error))
            negatives.append({'control': label, 'rejection': reason})
        else:
            raise ValueError(label + ': corruption accepted')

    mutable = bytearray(data)

    def flip_at(file_offset, operation):
        mutable[file_offset] ^= 1
        try:
            operation(mutable)
        finally:
            mutable[file_offset] ^= 1

    # These run below the whole-image digest gate; exact bytes, data roles and
    # relocation bindings must reject for their own reasons.
    for name, (va, _) in c.ANCHORS.items():
        rejects('anchor/' + name,
                lambda va=va: flip_at(offset(secs, va), c.selected_checks), 'anchor ' + name)
    for va in c.TABLES:
        rejects('table/' + hex(va),
                lambda va=va: flip_at(offset(secs, va), c.selected_checks), 'dispatch table')
    for row in relocs:
        rejects('relocation/' + row['slot'],
                lambda row=row: flip_at(row['record_file_offset'] + 16, c.selected_checks),
                'selected relocation binding')
        rejects('relocation-symbol-index/' + row['slot'],
                lambda row=row: flip_at(row['record_file_offset'] + 12, c.selected_checks),
                'selected relocation binding')
    contract = json.loads((HERE / 'contract.json').read_text())
    checked = set()
    for case in contract['cases']:
        if case['construction'] == 'direct-name':
            va = int(case['output_stores'],16)
            if va not in checked:
                rejects('direct-output/' + hex(va),
                        lambda va=va: flip_at(offset(secs,va), lambda d: c.contract_checks(d,secs)),
                        'direct output stores')
                checked.add(va)
        for field in case.get('fields_in_order', []):
            for key in ('call','input_setup','key_lea','key_length_at','key_va'):
                va = int(field[key],16)
                if va not in checked:
                    rejects('field-operand/' + key + '/' + hex(va),
                            lambda va=va,key=key: flip_at(offset(secs,va), lambda d: c.contract_checks(d,secs)),
                            'field witness ' + key)
                    checked.add(va)
    for witness in contract['additional_witnesses']:
        rejects('additional/' + witness['role'],
                lambda witness=witness: flip_at(offset(secs,int(witness['va'],16)), lambda d: c.contract_checks(d,secs)),
                'additional witness ' + witness['role'])
    # Metadata must agree with decoded operands rather than merely accompany an
    # unchanged instruction. Each field offset is independently perturbed.
    for i, case in enumerate(contract['cases']):
        for k, field in enumerate(case.get('fields_in_order', [])):
            altered = copy.deepcopy(contract)
            altered['cases'][i]['fields_in_order'][k]['input_offset'] = hex(int(field['input_offset'],16) ^ 1)
            rejects('claimed-input-offset/' + field['call'],
                    lambda altered=altered: c.contract_checks(data,secs,altered), 'field input operand')

    for name, fde in fdes.items():
        rejects('FDE-range/' + name,
                lambda fde=fde: flip_at(offset(secs, fde['fde']) + 12,
                                       lambda d: c.fde_checks(d, secs)), 'FDE extent')
    hdr = next(s for s in secs if s['name'] == '.eh_frame_hdr')
    rejects('unwind-header-encoding',
            lambda: flip_at(hdr['offset'] + 3, lambda d: c.fde_checks(d, secs)),
            'unsupported unwind index encoding')
    for name, fde in fdes.items():
        if fde['lsda'] is None:
            continue
        expected = retained['ranges'][name]['lsda_call_sites']
        size = len(bytes.fromhex(expected['header_and_callsite_hex']))
        def compare_lsda(d, fde=fde, expected=expected):
            c.demand(c.lsda_calls(d, secs, fde) == expected, 'LSDA retained facts differ')
        rejects('LSDA-callsite/' + name,
                lambda fde=fde, size=size: flip_at(offset(secs, fde['lsda']) + size - 1,
                                                  compare_lsda), 'LSDA retained facts differ')

    normalized_rows = 0
    for name, (start, end) in c.RANGES.items():
        exports = {}
        for label in ('gnu', 'llvm'):
            path = HERE / 'observed' / (name + '.' + label + '.txt')
            stored = path.read_bytes() if label == 'gnu' else path.with_suffix('.txt.gz').read_bytes()
            raw = stored if label == 'gnu' else gzip.decompress(stored)
            meta = retained['ranges'][name]['native_exports'][label]
            c.demand(hashlib.sha256(stored).hexdigest() == meta['stored_sha256'], 'stored export digest')
            c.demand(hashlib.sha256(raw).hexdigest() == meta['raw_sha256'], 'raw export digest')
            text = raw.decode()
            exports[label] = c.instruction_partition(verify_native(text, data, secs, start, end))
        c.demand([(r['va'], r['hex']) for r in exports['gnu']] ==
                 [(r['va'], r['hex']) for r in exports['llvm']], 'native partition mismatch')
        normalized_rows += len(exports['gnu'])

    first, end = c.RANGES['constructor']
    native = (HERE / 'observed/constructor.gnu.txt').read_text()
    lines = native.splitlines()
    index = next(i for i, line in enumerate(lines) if line.lstrip().startswith('4752890:'))
    truncated = '\n'.join(lines[:index] + lines[index + 1:])
    rejects('native-missing-first-row', lambda: verify_native(truncated, data, secs, first, end),
            'non-contiguous native decode')
    wrong = native.replace('4752890:\t41 57', '4752890:\t40 57', 1)
    c.demand(wrong != native, 'native byte mutation not applied')
    rejects('native-wrong-byte', lambda: verify_native(wrong, data, secs, first, end),
            'native bytes disagree with target')
    rejects('native-dangling-lock', lambda: c.instruction_partition([
        {'va': '0x4752890', 'hex': 'f0', 'asm': 'lock'}]), 'dangling LOCK prefix')

    # A byte outside hand-selected anchors must pass that subset check and still
    # fail complete native-to-target comparison. This makes the subset limit visible.
    def altered_unselected(d):
        c.selected_checks(d)
        rejects('native-versus-unselected-target-byte',
                lambda: verify_native(native, d, secs, first, end), 'native bytes disagree with target')
    flip_at(offset(secs, first), altered_unselected)

    with tempfile.TemporaryDirectory(prefix='consensus-construction-static-') as temp:
        temp = Path(temp)
        for name in ('one', 'two'):
            c.collect(c.ROOT / c.REL, temp / name, gnu, llvm)
            compare_tree(HERE / 'observed', temp / name)
        compare_tree(temp / 'one', temp / 'two')
        wrong_input = temp / 'wrong-target'
        wrong_input.write_bytes(b'not the captured target')
        rejects('wrong-digest-before-output',
                lambda: c.collect(wrong_input, temp / 'must-not-exist', gnu, llvm), 'wrong target digest')
        c.demand(not (temp / 'must-not-exist').exists(), 'wrong digest created output')
        rejects('existing-output-preserved',
                lambda: c.collect(c.ROOT / c.REL, temp / 'one', gnu, llvm), 'File exists')
        compare_tree(HERE / 'observed', temp / 'one')

    return {'target_sha256': c.DIGEST, 'full_FDE_ranges': len(c.RANGES),
            'compared_bytes': sum(b - a for a, b in c.RANGES.values()),
            'normalized_instruction_rows': normalized_rows,
            'fresh_regenerations_equal_retained': 2,
            'negative_controls': negatives, 'negative_control_count': len(negatives),
            'positive_sensitivity': 'A mutated unselected constructor byte passes anchor/table/relocation checks but fails full native byte comparison.',
            'scope': 'Static parsing and native disassembly only; no captured execution, instruction interpreter, ABI equivalence, timing or liveness test.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gnu', default='/opt/homebrew/opt/binutils/bin/objdump')
    parser.add_argument('--llvm', default='/usr/bin/objdump')
    args = parser.parse_args()
    print(json.dumps(main(args.gnu, args.llvm), indent=2))
