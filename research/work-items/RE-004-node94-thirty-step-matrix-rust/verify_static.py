"""Downstream corruption controls for the complete fixed-step numeric core."""
import json
import struct
import oracle


def check():
    original = oracle.TARGET.read_bytes()
    facts = oracle.admit()
    oracle.require(facts == json.loads((oracle.PACKET / 'frozen/ORACLE-FREEZE.json').read_text())['static_facts'],
                   'Frozen static facts changed')
    secs, offset = oracle.mapping(original)
    rel = next(s for s in secs if s['name'] == '.rela.dyn')['address']
    cases = {
        'first_identity_row': (0x565f2e6, None), 'second_identity_row': (0x565f2f0, None),
        'packed_bias': (0x565f2fb, None), 'iteration_count': (0x565f2fd, None),
        'swap_accumulator_and': (0x565f306, None), 'swap_accumulator_shift': (0x565f309, None),
        'unsigned_compare': (0x565f30c, None), 'old_pair_snapshot': (0x565f30f, None),
        'old_matrix_snapshot': (0x565f319, None), 'old_accumulator_snapshot': (0x565f31f, None),
        'conditional_swap': (0x565f322, None), 'matrix_swap': (0x565f32e, None),
        'row_subtraction': (0x565f339, None), 'bias_restoration': (0x565f33c, None),
        'original_parity_gate': (0x565f340, None), 'even_accumulator_restore': (0x565f356, None),
        'second_plus_two': (0x565f35b, None), 'first_halving': (0x565f35e, None),
        'increment_quarter': (0x565f362, None), 'row_doubling': (0x565f365, None),
        'loop_back_edge': (0x565f371, None), 'return_bias_shift': (0x565f375, None),
        'low_field_zero_extend': (0x565f377, None), 'high_field_shift': (0x565f37b, None),
        'coefficient_unbias': (0x565f38d, None), 'return': (0x565f38f, None),
        'padding': (oracle.END, None), 'caller_tail_target': (0x565f2d6, None),
        'unexpected_naming_relocation': (rel + 16, struct.pack('<q', oracle.START)),
        'unexpected_code_relocation': (rel, struct.pack('<Q', oracle.START)),
    }
    for i, body in enumerate(facts['bodies']):
        cases[f'fde_extent_{i}'] = body['frames']['fde']['va'] + 12, None
    cases['cie'] = facts['bodies'][0]['frames']['cie']['va'] + 17, None
    controls = {}
    for label, (address, replacement) in cases.items():
        changed = bytearray(original)
        if replacement is None:
            changed[offset(address, 1)] ^= 1
        else:
            begin = offset(address, len(replacement))
            changed[begin:begin + len(replacement)] = replacement
        try:
            oracle.structure(changed)
        except ValueError as error:
            controls[label] = {'va': hex(address), 'rejected': str(error)}
        else:
            raise ValueError('Structural corruption accepted: ' + label)
    return {'target_sha256': oracle.TARGET_SHA,
            'body_instruction_counts': [len(x['instructions']) for x in facts['bodies']],
            'structural_controls': controls, 'captured_execution': False}


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
