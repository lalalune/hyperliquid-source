"""Downstream structural corruption controls, without target execution."""
import json
import struct
import oracle


def check():
    original = oracle.TARGET.read_bytes()
    facts = oracle.admit()
    frozen = json.loads((oracle.PACKET / 'frozen/ORACLE-FREEZE.json').read_text())
    oracle.require(facts == frozen['static_facts'], 'Frozen static facts changed')
    secs, offset = oracle.mapping(original)
    rel = next(s for s in secs if s['name'] == '.rela.dyn')['address']
    cases = {
        'first_top_load': (0x565f019, None), 'coefficient_sign': (0x565f021, None),
        'negation_carry': (0x565f045, None), 'first_sign_high': (0x565f059, None),
        'first_multiply': (0x565f05f, None), 'first_high_carry': (0x565f0b4, None),
        'second_source_advance': (0x565f0b8, None), 'first_store': (0x565f0bc, None),
        'last_intermediate_store': (0x565f0d2, None), 'second_load_order': (0x565f0d3, None),
        'second_sign_high': (0x565f128, None), 'raw_last_multiply': (0x565f17d, None),
        'source_restore': (0x565f187, None), 'sum_carry': (0x565f18d, None),
        'seventh_sum_word': (0x565f1a1, None), 'first_shift': (0x565f1a6, None),
        'sixth_shift': (0x565f1bf, None), 'sum_sign': (0x565f1c3, None),
        'rbx_sign_result': (0x565f1c9, None), 'final_negation': (0x565f1cc, None),
        'final_carry': (0x565f1f2, None), 'final_store': (0x565f209, None),
        'return': (0x565f20b, None), 'padding': (oracle.END, None),
        'unexpected_naming_relocation': (rel + 16, struct.pack('<q', oracle.START)),
        'unexpected_code_relocation': (rel, struct.pack('<Q', oracle.START)),
    }
    for index, body in enumerate(facts['bodies']):
        cases[f'fde_extent_{index}'] = body['frames']['fde']['va'] + 12, None
        for site in body['sites']:
            cases[f'caller_{site:x}'] = site + 1, None
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
