"""Real390-byte counterfactuals: static decoding/contracts, never execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_diagnostic_field_static as field

# All edits preserve native instruction widths and call/branch/return counts.
MUTANTS = (
    ('entry-status-offset', 0x1571F69, b'\x09'),
    ('entry-branch-polarity', 0x1571F6B, b'\x75'),
    ('prefix-error-polarity', 0x1571FCA, b'\x74'),
    ('prefix-error-continues', 0x1571FCB, b'\x00'),
    ('prefix-error-skips-common-outputs', 0x1571FCB, b'\xba'),
    ('prefix-length-xor', 0x1571FA9, b'\x02'),
    ('prefix-selection-polarity', 0x1571FBC, b'\x44'),
    ('prefix-condition-register', 0x1571FB9, b'\xc9'),
    ('name-argument-source', 0x1571FD5, b'\xfe'),
    ('colon-length', 0x1571FEF, b'\x01'),
    ('value-method-slot', 0x157200B, b'\x10'),
    ('value-formatter-argument', 0x1572004, b'\xf6'),
    ('error-store-offset', 0x1571F70, b'\x09'),
    ('field-present-store', 0x1571F74, b'\x00'),
    ('value-result-source', 0x15720D0, b'\xd4'),
    ('formatter-mode-mask', 0x1571F96, b'\x40'),
    ('value-saved-data-slot', 0x1572001, b'\xc8'),
)


def shape(rows, graph):
    return {'rows': len(rows), 'calls': len(graph['calls']), 'returns': len(graph['returns']),
            'conditional_branches': sum(v['opcode'] != 'jmp' for v in graph['branches'].values()),
            'unconditional_jumps': sum(v['opcode'] == 'jmp' for v in graph['branches'].values())}


def context(data):
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != field.SHA256:
        raise ValueError('Controls require authenticated node94')
    secs = field.bv.sections(data)

    def read(va, size):
        pos = field.bv.va_to_off(secs, va)
        return data[pos:pos + size]

    return read(field.BASE, field.END - field.BASE), read


def run(data, archive=None):
    body, read = context(data)
    base, _ = field.prove_span(body, read)
    base_shape = {'rows': base['native_instruction_rows'], 'calls': len(base['cfg']['calls']),
                  'returns': len(base['cfg']['returns']),
                  'conditional_branches': sum(x['opcode'] != 'jmp' for x in base['cfg']['branches'].values()),
                  'unconditional_jumps': sum(x['opcode'] == 'jmp' for x in base['cfg']['branches'].values())}
    controls = list(MUTANTS)
    disp = struct.unpack_from('<i', body, 0x1571FEA - field.BASE)[0]
    controls.append(('colon-pointer', 0x1571FEA, struct.pack('<i', disp + 1)))
    ledger = []
    for name, va, replacement in controls:
        changed = bytearray(body)
        pos = va - field.BASE
        before = bytes(changed[pos:pos + len(replacement)])
        changed[pos:pos + len(replacement)] = replacement
        rows, listing, version, argv = field.native_rows(bytes(changed))
        graph = field.cfg(rows)
        actual_shape = shape(rows, graph)
        if actual_shape != base_shape:
            raise ValueError(name + ' did not preserve the claimed shape')
        record = {'name': name, 'va': hex(va), 'before': before.hex(), 'after': replacement.hex(),
                  'span_sha256': field.sha(changed), 'shape': actual_shape,
                  'shape_equal_to_original': True, 'native_sha256': field.sha(listing.encode())}
        try:
            facts = field.operand_facts(changed, read)
            paths = field.flat_paths(graph, facts)
            record['changed_operand_facts'] = {k: v for k, v in facts.items() if v != base['operand_facts'][k]}
            record['derived_call_sequences'] = [[hex(c) for c in path['calls']] for path in paths]
            record['derived_output_witnesses'] = [
                {'sites': [hex(pc) for pc in path.get('output_witness_pcs', [])],
                 'stores': path.get('ordered_state_stores'), 'return': path.get('return')}
                for path in paths]
            record['changed_branch_edges'] = {hex(k): v for k, v in graph['branches'].items()
                                              if v != base['cfg']['branches'][k]}
            field.check_contract(facts, paths)
        except field.ContractError as error:
            record['rejected_by_relation'] = str(error)
        else:
            raise ValueError(name + ' unexpectedly satisfied the contract')
        if archive is not None:
            with (archive / (name + '.objdump.txt')).open('x') as stream:
                stream.write(listing)
        ledger.append(record)
    return {'authenticated_parent_image_sha256': field.SHA256, 'original_span_sha256': field.sha(body),
            'baseline_shape': base_shape, 'counterfactuals': ledger,
            'method': 'Actual copied raw bytes, native decode/static extraction, relation rejection. No instruction interpreter or target execution.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Existing control evidence is preserved')
    args.output.mkdir(parents=True)
    result = run(field.TARGET.read_bytes(), args.output)
    (args.output / 'counterfactuals.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'counterfactuals': len(result['counterfactuals']), 'same_shape': True,
                      'target_executed': False, 'instruction_interpreter': False}))


if __name__ == '__main__':
    main()
