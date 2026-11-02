"""Static identity, complete-body, dependency and corruption qualification."""
import json
import struct
import oracle


def check():
    original = oracle.TARGET.read_bytes()
    facts = oracle.admit()
    frozen = json.loads((oracle.PACKET / 'frozen/ORACLE-FREEZE.json').read_text())
    oracle.require(facts == frozen['static_facts'], 'Frozen static facts changed')
    _, offset = oracle.mapping(original)
    cases = {
        'ordinal_width': (0x151f87a, None), 'fast_overflow_flag': (0x151f884, None),
        'fast_positive_gate': (0x151f889, None), 'leap_bit': (0x151f894, None),
        'fast_upper_gate': (0x151f8a1, None), 'signed_year_shift': (0x151f8a8, None),
        'year_reciprocal': (0x151f8af, None), 'year_euclidean_fix': (0x151f8d5, None),
        'leap_table_edge': (0x151f8e6, None), 'slow_add_overflow': (0x151f900, None),
        'cycle_reciprocal': (0x151f90b, None), 'day_euclidean_fix': (0x151f933, None),
        '365_reciprocal': (0x151f93c, None), 'year_correction_borrow': (0x151f967, None),
        'ordinal_interval': (0x151f9b5, None), 'year_interval': (0x151fa01, None),
        'flag_table_edge': (0x151fa0c, None), 'packed_ordinal_mask': (0x151fa25, None),
        'fast_preservation_mask': (0x151fa3e, None), 'padding': (oracle.END, None),
        'leap_table_data': (0x250355, None), 'flag_table_data': (0x2504e5, None),
        'first_location_line': (0x5672150, None), 'last_location_path': (0x1f88a6, None),
    }
    for index, body in enumerate(facts['bodies']):
        cases[f'fde_extent_{index}'] = body['frames']['fde']['va'] + 12, None
        for site in body['sites']:
            cases[f'caller_{site:x}'] = site + 2, None
    cases['cie'] = facts['bodies'][0]['frames']['cie']['va'] + 17, None
    for address, rel in facts['relocations'].items():
        cases[f'relocation_{int(address):x}'] = rel['record_va'] + 16, struct.pack('<q', rel['addend'] + 1)
        cases[f'slot_{int(address):x}'] = int(address), None
    for site in (0x151fa55, 0x151fa62, 0x151fa74, 0x151fa89, 0x151fa96):
        cases[f'panic_call_{site:x}'] = site + 2, None
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
            'structural_controls': controls, 'arithmetic_certificates': oracle.certificates(),
            'captured_execution': False}


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
