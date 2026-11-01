"""Downstream corruption controls for the four-round arithmetic leaf."""
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
        'endbr': (0x565d8a0, None), 'input_low_load': (0x565d8a4, None),
        'input_high_load': (0x565d8af, None),
        'round0_coefficient': (0x565d8b6, None), 'round1_coefficient': (0x565d8e8, None),
        'round2_coefficient': (0x565d943, None), 'round3_coefficient': (0x565d99e, None),
        'fold0': (0x565d8c6, None), 'fold1': (0x565d921, None),
        'fold2': (0x565d97c, None), 'fold3': (0x565d9d7, None),
        'high_operand_load': (0x565d900, None), 'carry0': (0x565d8da, None),
        'carry1': (0x565d935, None), 'carry2': (0x565d990, None),
        'carry3': (0x565da1b, None), 'final_rax': (0x565da11, None),
        'final_r9': (0x565da1f, None), 'return': (0x565da22, None),
        'padding': (oracle.END, None), 'caller1_edge': (0x565d786, None),
        'caller2_edge': (0x565d826, None),
        'unexpected_naming_relocation': (rel + 16, struct.pack('<q', oracle.START)),
        'unexpected_code_relocation': (rel, struct.pack('<Q', oracle.START)),
        'partial_overlap_code_writer': (rel, struct.pack('<Q', oracle.START - 3)),
        'caller_writer': (rel, struct.pack('<Q', 0x565d780)),
        'padding_writer': (rel, struct.pack('<Q', oracle.END)),
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
