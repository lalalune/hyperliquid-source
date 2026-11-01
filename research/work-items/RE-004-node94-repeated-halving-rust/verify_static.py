"""Downstream corruption controls for the complete repeated-halving loop."""
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
        'entry':(0x565dbc0,None), 'initial_low_load':(0x565dbca,None),
        'odd_mask':(0x565dbdc,None), 'correction_low_read':(0x565dbe0,None),
        'correction_high_read':(0x565dbf7,None), 'low_add':(0x565dbfb,None),
        'high_adc':(0x565dc04,None), 'overflow_mask':(0x565dc07,None),
        'low_shift':(0x565dc0a,None), 'high_shift':(0x565dc1c,None),
        'middle_carry':(0x565dc2a,None), 'overflow_carry':(0x565dc31,None),
        'count_low32':(0x565dc3b,None), 'loop_edge':(0x565dc3e,None),
        'first_store':(0x565dc3f,None), 'final_store':(0x565dc4a,None),
        'return':(0x565dc5d,None), 'padding':(0x565dc5f,None),
        'naming_relocation':(rel+16,struct.pack('<q',0x565dbc0)),
        'code_writer':(rel,struct.pack('<Q',0x565dbc0)),
        'partial_code_writer':(rel,struct.pack('<Q',0x565dbbd)),
        'padding_writer':(rel,struct.pack('<Q',0x565dc5f)),
    }
    body=facts['bodies'][0]
    cases['fde']=body['frames']['fde']['va']+12,None
    cases['cie']=body['frames']['cie']['va']+17,None
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
