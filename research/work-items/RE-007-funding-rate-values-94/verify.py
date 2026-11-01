#!/usr/bin/env python3
"""Verify static evidence and corruption controls; never execute captured code."""
import argparse
import hashlib
import gzip
import json
from pathlib import Path
import tempfile
import struct
import os
import subprocess
import sys

import collect as c

HERE = Path(__file__).resolve().parent


def load_bytes(data, va, size):
    """Independent ELF64 PT_LOAD mapper; does not use shared section parsing."""
    c.demand(data[:6] == b'\x7fELF\x02\x01', 'PT_LOAD ELF identity')
    first = struct.unpack_from('<Q', data, 32)[0]
    stride, count = struct.unpack_from('<HH', data, 54)
    c.demand(stride == 56 and first + stride * count <= len(data), 'PT_LOAD table bounds')
    candidates = []
    for i in range(count):
        typ, flags, off, address, physical, filesz, memsz, align = struct.unpack_from(
            '<IIQQQQQQ', data, first + i * stride)
        if typ == 1 and address <= va and va + size <= address + filesz:
            c.demand(off + filesz <= len(data), 'PT_LOAD file bounds')
            candidates.append(off + va - address)
    c.demand(len(candidates) == 1, 'PT_LOAD ambiguous or unmapped address')
    return data[candidates[0]:candidates[0] + size]


def verify_load_mapping(data):
    secs = c.sections(data)
    spans = list(c.RANGES.values()) + [(a, a + len(bytes.fromhex(h)))
                                     for a, h in c.LITERALS.values()]
    for start, end in spans:
        c.demand(load_bytes(data, start, end - start) == c.read_va(data, secs, start, end - start),
                 'section/PT_LOAD disagreement')
    c.demand(load_bytes(data, 0x37506d2, 8).hex() == 'f8ffffffffffff0f', 'raw vector bulk mask')
    c.demand(load_bytes(data, 0x275eef8, 2).hex() == 'a801', 'raw caller presence bit')


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
    secs, relocs = c.selected_checks(data)
    verify_load_mapping(data)
    fdes = c.fde_checks(data, secs)
    c.opaque_callee_checks(data, secs)
    retained = json.loads((HERE / 'native/records.json').read_text())
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
                lambda va=va, name=name: flip_at(offset(secs, va),
                    lambda d: c.demand(c.read_va(d, secs, va, len(bytes.fromhex(c.LITERALS[name][1]))).hex()
                                       == c.LITERALS[name][1], 'literal ' + name)), 'literal ' + name)
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
    for slot, expected in c.SPEC['imports'].items():
        binding = c.selected_slot_bindings(data, secs, {int(slot, 16)})[slot]
        rejects('import-relocation/' + slot,
                lambda binding=binding: flip_at(binding['record_file_offset'] + 16, c.selected_checks),
                'import relocation binding')
        symtab = next(s for s in secs if s['name'] == '.dynsym')
        symbol_offset = symtab['offset'] + expected['symbol_index'] * 24
        rejects('import-symbol/' + slot,
                lambda symbol_offset=symbol_offset: flip_at(symbol_offset + 4, c.selected_checks),
                'import symbol binding')
        strtab = next(s for s in secs if s['name'] == '.dynstr')
        name_offset = strtab['offset'] + struct.unpack_from('<I', data, symbol_offset)[0]
        rejects('import-name/' + slot,
                lambda name_offset=name_offset: flip_at(name_offset, c.selected_checks),
                'import symbol binding')
    checked_cies = set()
    for name, fde in fdes.items():
        row = retained['ranges'][name]
        for field in ('fde', 'cie'):
            address = fde[field]
            raw = row[field + '_hex']
            c.demand(c.read_va(data, secs, address, len(bytes.fromhex(raw))).hex() == raw,
                     'retained unwind bytes differ')
            if field == 'cie' and address in checked_cies:
                continue
            if field == 'cie':
                checked_cies.add(address)
            rejects(field.upper() + '-raw/' + name,
                    lambda address=address, raw=raw: flip_at(offset(secs, address) + len(bytes.fromhex(raw)) - 1,
                        lambda d: c.demand(c.read_va(d, secs, address, len(bytes.fromhex(raw))).hex() == raw,
                                           'retained unwind bytes differ')),
                    'retained unwind bytes differ')
    hdr = next(s for s in secs if s['name'] == '.eh_frame_hdr')
    rejects('unwind-header-encoding',
            lambda: flip_at(hdr['offset'] + 3, lambda d: c.fde_checks(d, secs)),
            'unsupported unwind index encoding')
    # Alter a selected index address while leaving its FDE intact.
    index_offset = next(hdr['offset'] + 12 + i * 8
                        for i in range(struct.unpack_from('<I', data, hdr['offset'] + 8)[0])
                        if hdr['address'] + struct.unpack_from('<i', data, hdr['offset'] + 12 + i * 8)[0]
                        == c.RANGES['rate'][0])
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

    for address in c.SPEC['opaque_callees']:
        rejects('opaque-callee-identity/' + address,
                lambda address=address: flip_at(offset(secs, int(address, 16)),
                                               lambda d: c.opaque_callee_checks(d, secs)),
                'opaque callee identity')

    text_section = next(s for s in secs if s['name'] == '.text')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    stride, count = struct.unpack_from('<HH', data, 58)
    header = next(shoff + i * stride for i in range(count)
                  if struct.unpack_from('<Q', data, shoff + i * stride + 16)[0]
                  == text_section['address'])
    rejects('independent-section-mapping-shift',
            lambda: flip_at(header + 24, verify_load_mapping), 'section/PT_LOAD disagreement')
    rejects('independent-vector-bound',
            lambda: flip_at(offset(secs, 0x37506d2), verify_load_mapping), 'raw vector bulk mask')
    rejects('independent-presence-bit',
            lambda: flip_at(offset(secs, 0x275eef9), verify_load_mapping), 'raw caller presence bit')

    normalized_rows = 0
    for name, (start, end) in c.RANGES.items():
        exports = {}
        for label in ('gnu', 'llvm'):
            path = HERE / 'native' / (name + '.' + label + '.txt')
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

    first, end = c.RANGES['rate']
    native = (HERE / 'native/rate.gnu.txt').read_text()
    lines = native.splitlines()
    index = next(i for i, line in enumerate(lines) if line.lstrip().startswith('3750610:'))
    truncated = '\n'.join(lines[:index] + lines[index + 1:])
    rejects('native-missing-first-row', lambda: verify_native(truncated, data, secs, first, end),
            'non-contiguous native decode')
    wrong = native.replace('3750610:\t41 57', '3750610:\t41 56', 1)
    c.demand(wrong != native, 'native byte mutation not applied')
    rejects('native-wrong-byte', lambda: verify_native(wrong, data, secs, first, end),
            'native bytes disagree with target')
    rejects('native-dangling-lock', lambda: c.instruction_partition([
        {'va': '0x3750610', 'hex': 'f0', 'asm': 'lock'}]), 'dangling LOCK prefix')

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
    mutations = c.SPEC['mutations']
    baseline_facts = c.operand_facts(data, secs)
    with tempfile.TemporaryDirectory(prefix='funding-native-controls-') as temp:
        snapshot = Path(temp) / 'hl-node'
        for mutation in mutations:
            name = fact = mutation['name']
            va = int(mutation['va'], 16)
            replacement = mutation['after'].to_bytes(mutation['size'], 'little')
            off = offset(secs, va)
            saved = mutable[off:off + len(replacement)]
            mutable[off:off + len(replacement)] = replacement
            try:
                changed = c.operand_facts(mutable, secs)
                c.demand(changed[fact] != baseline_facts[fact], 'operative field did not change')
                rejects('operative/' + name, lambda: c.selected_checks(mutable), 'anchor ')
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

    with tempfile.TemporaryDirectory(prefix='funding-static-') as temp:
        temp = Path(temp)
        for name, optimized, seed, timezone in [('one', False, '13', 'UTC'), ('two', True, '97', 'Pacific/Honolulu')]:
            env = dict(os.environ, PYTHONHASHSEED=seed, TZ=timezone)
            command = [sys.executable, '-B'] + (['-O'] if optimized else []) + [str(HERE / 'collect.py'), '--out', str(temp / name), '--gnu', gnu, '--llvm', llvm]
            subprocess.run(command, env=env, check=True, capture_output=True, text=True)
            compare_tree(HERE / 'native', temp / name)
        compare_tree(temp / 'one', temp / 'two')
        wrong_input = temp / 'wrong-target'
        wrong_input.write_bytes(b'not the captured target')
        rejects('wrong-digest-before-output',
                lambda: c.collect(wrong_input, temp / 'must-not-exist', gnu, llvm), 'wrong target digest')
        c.demand(not (temp / 'must-not-exist').exists(), 'wrong digest created output')
        rejects('existing-output-preserved',
                lambda: c.collect(c.ROOT / c.REL, temp / 'one', gnu, llvm), 'existing output refused')
        compare_tree(HERE / 'native', temp / 'one')

    return {'target_sha256': c.DIGEST, 'full_FDE_ranges': len(c.RANGES),
            'compared_bytes': sum(b - a for a, b in c.RANGES.values()),
            'normalized_instruction_rows': normalized_rows,
            'fresh_regenerations_equal_retained': 2,
            'negative_control_count': len(negatives),
            'negative_control_classes': {kind: sum(x['control'].split('/')[0] == kind for x in negatives) for kind in sorted({x['control'].split('/')[0] for x in negatives})},
            'operative_native_controls': sensitivity,
            'independent_PT_LOAD_mapping': 'All three complete bodies and selected literals match section mapping; vector bound and caller presence mask read independently.',
            'positive_sensitivity': 'A mutated rate prologue byte passes selected anchor/table/relocation checks but fails complete native byte comparison.',
            'scope': 'Static parsing and native disassembly only; no captured execution, instruction interpreter, ABI equivalence, timing or liveness test.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gnu', default='/opt/homebrew/opt/binutils/bin/objdump')
    parser.add_argument('--llvm', default='/usr/bin/objdump')
    args = parser.parse_args()
    print(json.dumps(main(args.gnu, args.llvm), indent=2))
