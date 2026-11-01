"""Downstream corruption controls for the complete mask/store function."""
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
        'endbr': (0x5521d10, None), 'default_all_ones': (0x5521d17, None),
        'full_width_sentinel': (0x5521d1e, None), 'sentinel_branch': (0x5521d20, None),
        'one_base': (0x5521d22, None), 'ecx_zero_extension': (0x5521d26, None),
        'shift_width': (0x5521d28, None), 'subtract_one': (0x5521d2e, None),
        'store_width': (0x5521d2f, None), 'store_displacement': (0x5521d32, None),
        'return': (0x5521d36, None), 'padding': (oracle.END, None),
        'initial_global': (oracle.STORE, None), 'caller_edge': (0x54b9c40, None),
        'unexpected_naming_relocation': (rel + 16, struct.pack('<q', oracle.START)),
        'unexpected_code_relocation': (rel, struct.pack('<Q', oracle.START)),
        'unexpected_global_writer': (rel, struct.pack('<Q', oracle.STORE)),
        'partial_overlap_global_writer': (rel, struct.pack('<Q', oracle.STORE - 3)),
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
