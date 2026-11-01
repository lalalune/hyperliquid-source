"""Downstream corruption controls for the complete all-i32 calendar constructor."""
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
        'save_rax': (0x151f6f0, None), 'clear_rax': (0x151f6f1, None),
        'epoch_offset': (0x151f6f5, None), 'overflow_branch': (0x151f6fb, None),
        'signed_reciprocal': (0x151f705, None), 'reciprocal_sign_fix': (0x151f717, None),
        'cycle_length': (0x151f71b, None), 'euclidean_correction': (0x151f72a, None),
        'year_reciprocal': (0x151f733, None), 'year_scale': (0x151f74b, None),
        'leap_table_reference': (0x151f758, None), 'year_correction_condition': (0x151f767, None),
        'correction_panic_gate': (0x151f76b, None), 'table_bounds_gate': (0x151f77b, None),
        'ordinal_correction': (0x151f7a9, None), 'ordinal_gate': (0x151f7b7, None),
        'restore_rcx_early': (0x151f7bd, None), 'noncorrection_gate': (0x151f7c1, None),
        'year_lower': (0x151f7ed, None), 'year_interval': (0x151f7f3, None),
        'flags_table_reference': (0x151f7fe, None), 'year_pack_shift': (0x151f808, None),
        'final_gate': (0x151f81f, None), 'restore_rcx_late': (0x151f827, None),
        'panic_call': (0x151f832, None), 'padding': (oracle.END, None),
        'leap_century': (0x250354 + 100, None), 'flag_century': (0x2504e5 + 100, None),
        'caller_slot': (0x13c8e99, None), 'source_location_line': (0x5672140 + 16, None),
        'unexpected_naming_relocation': (rel + 16, struct.pack('<q', oracle.START)),
        'unexpected_code_relocation': (rel, struct.pack('<Q', oracle.START)),
        'unexpected_table_writer': (rel, struct.pack('<Q', 0x250354)),
        'partial_overlap_slot_writer': (rel, struct.pack('<Q', 0x576e890 - 3)),
    }
    for address, item in facts['relocations'].items():
        cases['relocation_' + hex(int(address))] = item['record_va'] + 16, None
        cases['slot_' + hex(int(address))] = int(address), None
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
