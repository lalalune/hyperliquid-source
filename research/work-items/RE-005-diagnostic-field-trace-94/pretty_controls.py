"""Actual copied-byte controls for the conditional pretty/adapter proof."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_diagnostic_field_static as field
import bincode_diagnostic_adapter_static as adapter

PARENT_MUTANTS = [
    ('pretty-H-polarity', 0x1572013, b'\x74'),
    ('opening-error-polarity', 0x1572040, b'\x84'),
    ('opening-length', 0x1572027, b'\x02'),
    ('pretty-flag-initial', 0x1572048, b'\x00'),
    ('pretty-flags-source-offset', 0x157205C, b'\x08'),
    ('pretty-local-formatter-value-arg', 0x15720A3, b'\x90'),
    ('pretty-uncached-suffix-destination', 0x15720BA, b'\x90'),
    ('pretty-suffix-length', 0x15720C7, b'\x01'),
    ('pretty-status-reset', 0x157203C, b'\x02'),
    ('pretty-value-error-polarity', 0x15720B2, b'\x84'),
    ('pretty-suffix-result-source', 0x15720D0, b'\xd4'),
    ('pretty-value-error-direct-ret', 0x15720B3, struct.pack('<i', 0x1571F86 - (0x15720B1 + 6))),
]

ADAPTER_MUTANTS = [
    ('adapter-scalar-LF', 0x157D103, b'\x0d'),
    ('adapter-alignment-LF', 0x157D193, b'\x0d'),
    ('adapter-tail-LF', 0x157D1C3, b'\x0d'),
    ('adapter-piece-flag-LF', 0x157D065, b'\x0d'),
    ('adapter-recheck-LF', 0x157D1E6, b'\x0d'),
    ('adapter-wide-threshold', 0x157D0E9, b'\x0e'),
    ('adapter-wide-stride', 0x157D172, b'\x20'),
    ('adapter-wide-first-load', 0x157D144, b'\xf9'),
    ('adapter-LFWORD', 0x157D01D, b'\x0d' * 8),
    ('adapter-C-borrow', 0x157D028, b'\x00'),
    ('adapter-HI-low-bit', 0x157D013, b'\x08' * 8),
    ('adapter-restored-LFWORD', 0x157D092, b'\x0d' * 8),
    ('adapter-flag-pointer-offset', 0x157D032, b'\x08'),
    ('adapter-vtable-offset', 0x157D041, b'\x10'),
    ('adapter-indent-length', 0x157D223, b'\x03'),
    ('adapter-indent-error-polarity', 0x157D247, b'\x74'),
    ('adapter-payload-error-polarity', 0x157D09E, b'\x84'),
    ('adapter-flag-store-target', 0x157D075, b'\x02'),
    ('adapter-flag-store-source', 0x157D075, b'\x09'),
    ('adapter-failure-AL', 0x157D25E, b'\x00'),
    ('adapter-continuation-mask', 0x157D0A4, b'\x00'),
    ('adapter-final-tail-bit', 0x157D207, b'\x00'),
    ('adapter-empty-tail-polarity', 0x157D214, b'\x75'),
    ('adapter-selected-piece-store-skipped', 0x157D24E, struct.pack('<i', 0x157D076 - (0x157D24C + 6))),
    ('adapter-payload-flag-chain', 0x157D09A, b'\x03'),
    ('adapter-success-result-register', 0x157D25A, b'\xc9'),
]


def shape(rows, graph):
    branches = graph['branches']
    return {'native_rows': len(rows), 'calls': len(graph['calls']), 'returns': len(graph['returns']),
            'conditional_branches': sum(b.get('kind') == 'conditional' if 'kind' in b else b['opcode'] != 'jmp'
                                        for b in branches.values()),
            'jumps': sum(b.get('kind') == 'jump' if 'kind' in b else b['opcode'] == 'jmp'
                         for b in branches.values())}


def context(data):
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != field.SHA256:
        raise ValueError('Pretty controls require authenticated node94')
    secs = field.bv.sections(data)

    def read(va, n):
        pos = field.bv.va_to_off(secs, va)
        return data[pos:pos + n]

    return read


def mathematical_witness(name, facts):
    """Word/interval counterexamples; no instruction/register interpreter."""
    if name in ['adapter-LFWORD', 'adapter-C-borrow', 'adapter-HI-low-bit']:
        value = (b'\x00\x0a' + b'\xff' * 6) if name == 'adapter-C-borrow' else (b'\x0a' + b'\xff' * 7)
        words = [int.from_bytes(value, 'little'), (1 << 64) - 1]
        skip = adapter.wide_predicate(*words, facts['C'], facts['LFWORD'], facts['HI'])
        if not skip:
            raise ValueError(name + ' lacks the claimed false-negative arithmetic witness')
        return {'kind': 'wide-skip false negative', 'input16_hex': (value + b'\xff' * 8).hex(),
                'contains_LF': True, 'changed_word_equation_says_skip': skip,
                'captured_or_emulated_execution': False}
    if name == 'adapter-wide-threshold':
        return {'kind': 'admitted read exceeds remaining input', 'remaining': 15, 'pointer_mod8': 0,
                'input_hex': (b'\xff' * 15).hex(),
                'changed_wide_guard': 15 > facts['small_threshold'], 'read_interval': [0, 16], 'overread_bytes': 1}
    if name == 'adapter-wide-stride':
        return {'kind': 'unchecked skipped interval', 'checked_interval': [0, 16],
                'remaining': 64, 'pointer_mod8': 0, 'input_hex': (b'\xff' * 20 + b'\x0a' + b'\xff' * 43).hex(),
                'changed_next_offset': facts['wide_skip_stride'], 'LF_index': 20,
                'gap': [16, facts['wide_skip_stride']]}
    if name == 'adapter-wide-first-load':
        return {'kind': 'first skipped byte not loaded', 'first_word_interval':
                [8 + facts['first_word_displacement'], 16 + facts['first_word_displacement']],
                'second_word_interval': [8, 16], 'unread_LF_index': 0,
                'remaining': 16, 'pointer_mod8': 0, 'input_hex': (b'\x0a' + b'\xff' * 15).hex()}
    if name == 'adapter-scalar-LF':
        return {'kind': 'changed first-delimiter association', 'input_hex': '0a0d',
                'expected_first_LF_index': 0, 'changed_compare_value': facts['delimiters']['0x157d100']}
    return None


def run(data, archive=None):
    read = context(data)
    parent_body = read(field.BASE, field.END - field.BASE)
    adapter_body = read(adapter.BASE, adapter.END - adapter.BASE)
    rows, _, _, _ = field.native_rows(parent_body)
    parent_graph = field.cfg(rows)
    parent_shape = shape(rows, parent_graph)
    parent_flat = field.operand_facts(parent_body, read)
    parent_pretty = field.pretty_operand_facts(parent_body, rows, read)
    field.check_pretty(parent_pretty, field.flat_paths(parent_graph, parent_flat, mode='pretty', pretty=parent_pretty))
    arows, _, _, _ = adapter.native(adapter_body)
    agraph = adapter.edges(arows)
    adapter_shape = shape(arows, agraph)
    adapter.check(adapter.operand_facts(adapter_body, arows, read), agraph)
    mutants = list(PARENT_MUTANTS)
    for name, va in [('pretty-suffix-pointer', 0x15720C2), ('pretty-adapter-direct-slot', 0x1572076)]:
        displacement = struct.unpack_from('<i', parent_body, va - field.BASE)[0]
        mutants.append((name, va, struct.pack('<i', displacement + 1)))
    records = []
    for span, body, base, source_mutants, expected_shape in [
        ('field', parent_body, field.BASE, mutants, parent_shape),
        ('adapter', adapter_body, adapter.BASE, ADAPTER_MUTANTS, adapter_shape)]:
        for name, va, replacement in source_mutants:
            changed = bytearray(body)
            pos = va - base
            before = bytes(changed[pos:pos + len(replacement)])
            changed[pos:pos + len(replacement)] = replacement
            if span == 'field':
                native_rows, listing, _, _ = field.native_rows(bytes(changed))
                graph = field.cfg(native_rows)
            else:
                native_rows, listing, _, _ = adapter.native(bytes(changed))
                graph = adapter.edges(native_rows)
            actual_shape = shape(native_rows, graph)
            if actual_shape != expected_shape:
                raise ValueError(name + ' did not retain its declared native shape')
            row = {'name': name, 'span': span, 'va': hex(va), 'before': before.hex(), 'after': replacement.hex(),
                   'span_sha256': hashlib.sha256(changed).hexdigest(), 'shape': actual_shape,
                   'shape_equal_to_original': True, 'native_sha256': hashlib.sha256(listing.encode()).hexdigest()}
            try:
                if span == 'field':
                    flat = field.operand_facts(changed, read)
                    facts = field.pretty_operand_facts(changed, native_rows, read)
                    paths = field.flat_paths(graph, flat, mode='pretty', pretty=facts)
                    if name == 'pretty-value-error-direct-ret':
                        bad = next(p for p in paths if any(g['value'] == 'pretty_value_AL' and not g['zero']
                                                          for g in p['guards']))
                        row['actual_skipped_outputs'] = {'stores': bad['ordered_state_stores'], 'return': bad['return']}
                    field.check_pretty(facts, paths)
                else:
                    facts = adapter.operand_facts(changed, native_rows, read)
                    witness = mathematical_witness(name, facts)
                    if witness is not None:
                        row['mathematical_counterexample'] = witness
                    adapter.check(facts, graph)
            except (field.ContractError, adapter.ContractError) as error:
                row['rejected_by_relation'] = str(error)
            else:
                raise ValueError(name + ' unexpectedly satisfies the contract')
            if archive is not None:
                (archive / (name + '.objdump.txt')).write_text(listing)
            records.append(row)
    return {'authenticated_parent_image_sha256': field.SHA256,
            'baseline_native_shapes': {'field': parent_shape, 'adapter': adapter_shape},
            'counterfactuals': records,
            'method': 'Actual copied byte mutations and GNU decoding; static CFG/dataflow, interval and byte-borrow certificates. No instruction interpreter, callbacks or captured execution.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Existing pretty evidence is preserved')
    args.output.mkdir(parents=True)
    result = run(field.TARGET.read_bytes(), args.output)
    (args.output / 'pretty-counterfactuals.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'counterfactuals': len(result['counterfactuals']), 'same_shape': True,
                      'captured_or_emulated_execution': False}))


if __name__ == '__main__':
    main()
