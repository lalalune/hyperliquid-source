#!/usr/bin/env python3
"""Verify static evidence and corruption controls; never execute captured code."""
import argparse
import hashlib
import gzip
import json
from pathlib import Path
import tempfile
import struct

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
    dependencies = json.loads((HERE / 'dependencies.json').read_text())
    for path, digest in dependencies['files'].items():
        c.demand(hashlib.sha256((c.ROOT / path).read_bytes()).hexdigest() == digest,
                 'credited dependency changed: ' + path)
    data = (c.ROOT / c.REL).read_bytes()
    c.demand(hashlib.sha256(data).hexdigest() == c.DIGEST, 'wrong baseline digest')
    secs, relocs = c.selected_checks(data)
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
    sensitivity = []

    def flip_at(file_offset, operation):
        mutable[file_offset] ^= 1
        try:
            operation(mutable)
        finally:
            mutable[file_offset] ^= 1

    # These run below the whole-image digest gate; exact bytes, data roles and
    # relocation bindings must reject for their own reasons.
    def check_one_anchor(d, name):
        va, expected = c.ANCHORS[name]
        c.demand(c.read_va(d, c.sections(d), va, len(bytes.fromhex(expected))).hex() == expected,
                 'anchor ' + name)

    for name, (va, _) in c.ANCHORS.items():
        rejects('anchor/' + name,
                lambda va=va, name=name: flip_at(offset(secs, va),
                                               lambda d: check_one_anchor(d, name)), 'anchor ' + name)
    for name, (va, _) in c.LITERALS.items():
        rejects('literal/' + name,
                lambda va=va: flip_at(offset(secs, va), c.selected_checks), 'literal ' + name)
    for row in relocs:
        rejects('relocation/' + row['slot'],
                lambda row=row: flip_at(row['record_file_offset'] + 16, c.selected_checks),
                'selected relocation binding')
        rejects('relocation-kind/' + row['slot'],
                lambda row=row: flip_at(row['record_file_offset'] + 8, c.selected_checks),
                'selected relocation binding')
        rejects('relocation-symbol-index/' + row['slot'],
                lambda row=row: flip_at(row['record_file_offset'] + 12, c.selected_checks),
                'selected relocation binding')
    for name, fde in fdes.items():
        rejects('FDE-range/' + name,
                lambda fde=fde: flip_at(offset(secs, fde['fde']) + 12,
                                       lambda d: c.fde_checks(d, secs)), 'FDE extent')
    hdr = next(s for s in secs if s['name'] == '.eh_frame_hdr')
    rejects('unwind-header-encoding',
            lambda: flip_at(hdr['offset'] + 3, lambda d: c.fde_checks(d, secs)),
            'unsupported unwind index encoding')
    # Alter a selected index address while leaving its FDE intact.
    index_offset = next(hdr['offset'] + 12 + i * 8
                        for i in range(struct.unpack_from('<I', data, hdr['offset'] + 8)[0])
                        if hdr['address'] + struct.unpack_from('<i', data, hdr['offset'] + 12 + i * 8)[0]
                        == c.RANGES['provider'][0])
    rejects('unwind-index-link',
            lambda: flip_at(index_offset + 4, lambda d: c.fde_checks(d, secs)),
            'FDE/index disagreement')
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

    first, end = c.RANGES['provider']
    native = (HERE / 'observed/provider.gnu.txt').read_text()
    lines = native.splitlines()
    index = next(i for i, line in enumerate(lines) if line.lstrip().startswith('1e29f50:'))
    truncated = '\n'.join(lines[:index] + lines[index + 1:])
    rejects('native-missing-first-row', lambda: verify_native(truncated, data, secs, first, end),
            'non-contiguous native decode')
    wrong = native.replace('1e29f50:\t55', '1e29f50:\t54', 1)
    c.demand(wrong != native, 'native byte mutation not applied')
    rejects('native-wrong-byte', lambda: verify_native(wrong, data, secs, first, end),
            'native bytes disagree with target')
    rejects('native-dangling-lock', lambda: c.instruction_partition([
        {'va': '0x1e29f50', 'hex': 'f0', 'asm': 'lock'}]), 'dangling LOCK prefix')

    # A byte outside hand-selected anchors must pass that subset check and still
    # fail complete native-to-target comparison. This makes the subset limit visible.
    def altered_unselected(d):
        c.selected_checks(d)
        rejects('native-versus-unselected-target-byte',
                lambda: verify_native(native, d, secs, first, end), 'native bytes disagree with target')
    flip_at(offset(secs, first), altered_unselected)

    # Actual operative fields change below the full digest gate. Read the changed
    # value first, then require the certificate to reject, and decode the changed
    # entire FDE with both native providers. No captured instruction is evaluated.
    mutations = [
        ('opening-byte', 0x1e29fd1, b'{', 'opening_byte', 'provider-opening'),
        ('closing-byte', 0x1dbe780, b'}', 'closing_byte', 'sequence-close-first'),
        ('comma-byte', 0x1dbe79c, b';', 'comma_byte', 'sequence-comma'),
        ('depth-increment-for-decrement', 0x1e29fed, b'\xc1', 'depth_decrement_opcode', 'provider-opening'),
        ('accepted-tag-one-to-zero', 0x1d773c4, b'\0', 'accepted_first_tag', 'element-tag-sign'),
        ('accepted-tag-two-to-three', 0x1d773c9, b'\3', 'accepted_second_tag', 'element-tag-sign'),
        ('decimal-threshold', 0x1d763f4, b'\x99', 'decimal_safe_quotient_minus_one', 'integer-first-digit'),
        ('decimal-last-digit-six', 0x1d76462, b'\6', 'decimal_last_digit_bound', 'integer-overflow-bound'),
        ('growth-minimum-three', 0x43bbce7, b'\3', 'growth_minimum', 'reserve-capacity'),
        ('element-width-four', 0x43bbcfe, b'\4', 'element_width', 'reserve-arguments'),
        ('alignment-four', 0x43bbcf8, b'\4', 'element_alignment', 'reserve-arguments'),
        ('allocation-range-high-bit', 0x43bd576, b'\x40', 'allocation_half_range', 'allocation-size-bound'),
        ('negative-integer-tag-one', 0x1d76009, b'\1', 'negative_integer_output_tag', 'number-negative-integer-tag'),
        ('ordering-first-JBE', 0x2923e80, b'\x76', 'ordering_first_condition', 'ordering-first-JB'),
        ('ordering-second-JL', 0x2923ea2, b'\x7c', 'ordering_second_condition', 'ordering-second-JB'),
    ]
    baseline_facts = c.operand_facts(data, secs)
    with tempfile.TemporaryDirectory(prefix='nonce-native-controls-') as temp:
        snapshot = Path(temp) / 'hl-node'
        for name, va, replacement, fact, anchor in mutations:
            off = offset(secs, va)
            saved = mutable[off:off + len(replacement)]
            mutable[off:off + len(replacement)] = replacement
            try:
                changed = c.operand_facts(mutable, secs)
                c.demand(changed[fact] != baseline_facts[fact], 'operative field did not change')
                rejects('operative/' + name, lambda: c.selected_checks(mutable), 'anchor ' + anchor)
                snapshot.write_bytes(mutable)
                bounds = next(bounds for bounds in c.RANGES.values() if bounds[0] <= va < bounds[1])
                parts = []
                for label, tool in [('gnu', gnu), ('llvm', llvm)]:
                    _, rows = c.decode(mutable, secs, tool, label, bounds, snapshot)
                    parts.append([(r['va'], r['hex']) for r in c.instruction_partition(rows)])
                c.demand(parts[0] == parts[1], 'mutated native partition mismatch')
                sensitivity.append({'control': name, 'address': hex(va), 'field': fact,
                                    'before': baseline_facts[fact], 'after': changed[fact],
                                    'native_partition_agreement': True})
            finally:
                mutable[off:off + len(replacement)] = saved
        c.demand(mutable == data, 'control input not restored')

    with tempfile.TemporaryDirectory(prefix='nonce-static-') as temp:
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
                lambda: c.collect(c.ROOT / c.REL, temp / 'one', gnu, llvm), 'existing output refused')
        compare_tree(HERE / 'observed', temp / 'one')

    return {'target_sha256': c.DIGEST, 'full_FDE_ranges': len(c.RANGES),
            'compared_bytes': sum(b - a for a, b in c.RANGES.values()),
            'normalized_instruction_rows': normalized_rows,
            'fresh_regenerations_equal_retained': 2,
            'negative_controls': negatives, 'negative_control_count': len(negatives),
            'operative_native_controls': sensitivity,
            'positive_sensitivity': 'A mutated unselected provider byte passes anchor/table/relocation checks but fails full native byte comparison.',
            'scope': 'Static parsing and native disassembly only; no captured execution, instruction interpreter, ABI equivalence, timing or liveness test.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gnu', default='/opt/homebrew/opt/binutils/bin/objdump')
    parser.add_argument('--llvm', default='/usr/bin/objdump')
    args = parser.parse_args()
    print(json.dumps(main(args.gnu, args.llvm), indent=2))
