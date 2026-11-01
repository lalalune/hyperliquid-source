"""Downstream corruption controls for the complete four-entry correction family."""
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
    cases = {}
    gates = [0x565da86, 0x565dd37, 0x565de26, 0x565deb7]
    stores = [0x565da92, 0x565dd4c, 0x565de32, 0x565decc]
    returns = [0x565da60, 0x565dd3a, 0x565de59, 0x565def1]
    for i, body in enumerate(facts['bodies']):
        for label, address in [('entry', body['start']), ('gate', gates[i]),
                               ('store', stores[i]), ('raw_return', returns[i]),
                               ('return_opcode', body['end'] - 2), ('padding', body['end']),
                               ('fde', body['frames']['fde']['va'] + 12)]:
            cases[f'{label}_{i}'] = address, None
        cases[f'naming_relocation_{i}'] = rel + 16, struct.pack('<q', body['start'])
        cases[f'partial_body_writer_{i}'] = rel, struct.pack('<Q', body['start'] - 3)
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
