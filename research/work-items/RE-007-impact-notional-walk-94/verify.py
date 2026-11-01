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
    # These independent raw operands are the two main arithmetic bounds.
    c.demand(int.from_bytes(load_bytes(data, 0x3c02801, 8), 'little') == (1 << 63) - 2,
             'raw full-product cap')
    c.demand(load_bytes(data, 0x3c02ccb, 13).hex() == '488d51ff4839c20f8363ffffff',
             'raw final-average guard')


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
    verify_load_mapping(data)
    fdes = c.fde_checks(data, secs)
    c.opaque_callee_checks(data, secs)
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
    hdr = next(s for s in secs if s['name'] == '.eh_frame_hdr')
    rejects('unwind-header-encoding',
            lambda: flip_at(hdr['offset'] + 3, lambda d: c.fde_checks(d, secs)),
            'unsupported unwind index encoding')
    # Alter a selected index address while leaving its FDE intact.
    index_offset = next(hdr['offset'] + 12 + i * 8
                        for i in range(struct.unpack_from('<I', data, hdr['offset'] + 8)[0])
                        if hdr['address'] + struct.unpack_from('<i', data, hdr['offset'] + 12 + i * 8)[0]
                        == c.RANGES['impact'][0])
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
    rejects('independent-raw-product-cap',
            lambda: flip_at(offset(secs, 0x3c02801), verify_load_mapping), 'raw full-product cap')
    rejects('independent-raw-final-guard',
            lambda: flip_at(offset(secs, 0x3c02cd3), verify_load_mapping), 'raw final-average guard')

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

    first, end = c.RANGES['impact']
    native = (HERE / 'observed/impact.gnu.txt').read_text()
    lines = native.splitlines()
    index = next(i for i, line in enumerate(lines) if line.lstrip().startswith('3c027d0:'))
    truncated = '\n'.join(lines[:index] + lines[index + 1:])
    rejects('native-missing-first-row', lambda: verify_native(truncated, data, secs, first, end),
            'non-contiguous native decode')
    wrong = native.replace('3c027d0:\t55', '3c027d0:\t54', 1)
    c.demand(wrong != native, 'native byte mutation not applied')
    rejects('native-wrong-byte', lambda: verify_native(wrong, data, secs, first, end),
            'native bytes disagree with target')
    rejects('native-dangling-lock', lambda: c.instruction_partition([
        {'va': '0x3c027d0', 'hex': 'f0', 'asm': 'lock'}]), 'dangling LOCK prefix')

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
        ('product-cap-minus-one', 0x3c02801, b'\xfd', 'product_cap', 'product-limit'),
        ('slab-stride-240', 0x3c02a33, b'\xf0', 'slab_stride', 'slab-tag-link-quantity'),
        ('slab-stop-tag-three', 0x3c02a3a, b'\3', 'slab_tag', 'slab-tag-link-quantity'),
        ('quantity-offset-192', 0x3c02a4f, b'\xc0', 'quantity_offset', 'slab-tag-link-quantity'),
        ('full-cap-setae', 0x3c02afb, b'\x93', 'full_product_condition', 'full-product-before-partial'),
        ('threshold-strict-JA', 0x3c02b19, b'\x87', 'threshold_condition', 'candidate-and-threshold'),
        ('partial-divisor-r13', 0x3c02c8b, b'\xf5', 'partial_division_modrm', 'partial-divide'),
        ('final-guard-JA', 0x3c02cd3, b'\x87', 'final_guard_condition', 'final-guard'),
        ('average-divisor-rbx', 0x3c02ce8, b'\xf3', 'average_division_modrm', 'average-divide'),
        ('level-flag-bit-two', 0x3c02a05, b'\2', 'level_flag_mask', 'level-head-admission'),
        ('parent-offset-360', 0x3c028f3, b'\x68', 'parent_offset', 'parent-climb'),
        ('first-tree-offset-136', 0x3750eb4, b'\x88', 'first_tree_offset', 'caller-two-impact-calls'),
        ('second-tree-offset-160', 0x3750ecf, b'\xa0', 'second_tree_offset', 'caller-two-impact-calls'),
        ('zero-combiner-different-source', 0x3750eeb, b'\xc2', 'caller_zero_combiner', 'caller-both-zero-tests'),
        ('zero-sentinel-output-16', 0x3750eef, b'\x10', 'caller_sentinel_offset', 'caller-both-zero-tests'),
        ('slab-add-no-carry-JAE', 0x3c02a59, b'\x73', 'slab_sum_carry_condition', 'slab-add-and-link'),
        ('remaining-count-increment', 0x3c02a25, b'\xc1', 'level_count_decrement', 'slab-quantity-setup'),
    ]
    baseline_facts = c.operand_facts(data, secs)
    with tempfile.TemporaryDirectory(prefix='impact-native-controls-') as temp:
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

    with tempfile.TemporaryDirectory(prefix='impact-static-') as temp:
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
            'independent_PT_LOAD_mapping': 'Both complete bodies and selected literals match section mapping; raw cap and final guard checked separately.',
            'positive_sensitivity': 'A mutated unselected impact byte passes anchor/table/relocation checks but fails full native byte comparison.',
            'scope': 'Static parsing and native disassembly only; no captured execution, instruction interpreter, ABI equivalence, timing or liveness test.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gnu', default='/opt/homebrew/opt/binutils/bin/objdump')
    parser.add_argument('--llvm', default='/usr/bin/objdump')
    args = parser.parse_args()
    print(json.dumps(main(args.gnu, args.llvm), indent=2))
