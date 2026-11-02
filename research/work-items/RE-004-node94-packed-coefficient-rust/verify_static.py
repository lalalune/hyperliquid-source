"""Downstream corruption controls for the normalizer and packed-coefficient loop closure."""
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
    addresses = {'normalizer_entry':0x565ec20,'second_high_read':0x565ec28,
      'first_rank_gate':0x565ec42,'second_rank_gate':0x565ec5f,'bsr':0x565ec75,
      'undefined_value_kill':0x565ec85,'masked_shift':0x565ec8c,'low31_mask':0x565ec94,
      'normalizer_tail':0x565ecaf,'unreachable_ret':0x565ecb0,
      'loop_entry':0x565ecc0,'initial_u':0x565ecc4,'initial_v':0x565ecce,
      'bias':0x565ecd8,'unsigned_compare':0x565ece2,'saved_u':0x565eceb,
      'saved_v':0x565ecee,'u_correction':0x565ed04,'parity':0x565ed0a,
      'x_shift':0x565ed20,'v_scale':0x565ed23,'v_bias':0x565ed26,
      'count32':0x565ed29,'backedge':0x565ed2d,'u_low32':0x565ed32,
      'v_low32':0x565ed34,'u_high32':0x565ed37,'v_high32':0x565ed3b,
      'decoded_bias':0x565ed3f,'return':0x565ed4b}
    cases={label:(address,None) for label,address in addresses.items()}
    for i,body in enumerate(facts['bodies']):
        cases[f'fde_{i}']=body['frames']['fde']['va']+12,None
        for j,(site,target) in enumerate(body['sites']):cases[f'edge_{i}_{j}']=site+1,None
    for i,start in enumerate(oracle.STARTS):
        cases[f'naming_{i}']=rel+16,struct.pack('<q',start)
        cases[f'partial_writer_{i}']=rel,struct.pack('<Q',start-3)
    for i,pad in enumerate(json.loads((oracle.PACKET/'static-lock.json').read_text())['padding']):cases[f'padding_{i}']=pad['start'],None
    cases['cie']=facts['bodies'][0]['frames']['cie']['va']+17,None
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
