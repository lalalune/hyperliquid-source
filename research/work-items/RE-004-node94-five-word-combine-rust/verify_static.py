"""Corrupt full-body, caller, frame and relocation facts without executing target code."""
import json
import struct
import oracle


def check():
    original = oracle.TARGET.read_bytes()
    facts = oracle.admit()
    oracle.require(facts == json.loads((oracle.PACKET/'frozen/ORACLE-FREEZE.json').read_text())['static_facts'], 'Frozen static facts changed')
    secs, offset = oracle.mapping(original)
    rel = next(s for s in secs if s['name'] == '.rela.dyn')['address']
    addresses = {
        'entry':0x565e960, 'first_top_read':0x565e973,
        'first_sign':0x565e97d, 'first_magnitude':0x565e987,
        'first_negation':0x565e999, 'first_top_carry':0x565e9a8,
        'first_mul':0x565e9ac, 'first_product_carry':0x565e9c1,
        'first_top_and':0x565e9d8, 'first_top_neg':0x565e9db,
        'first_last_mul':0x565e9de, 'first_top_adc':0x565e9e4,
        'second_coefficient':0x565e9e7, 'second_read':0x565e9ea,
        'second_top_read':0x565e9fa, 'second_sign':0x565ea01,
        'second_negation':0x565ea20, 'second_top_carry':0x565ea2f,
        'second_first_mul':0x565ea33, 'second_carry':0x565ea48,
        'second_top_and':0x565ea5f, 'second_top_neg':0x565ea62,
        'second_last_mul':0x565ea65, 'second_top_adc':0x565ea6b,
        'sum_low':0x565ea6e, 'sum_high':0x565ea7a,
        'store_low':0x565ea7d, 'store_high':0x565ea8c,
        'return':0x565ea90, 'padding':0x565ea92,
    }
    cases = {name:(address,None) for name,address in addresses.items()}
    for i, body in enumerate(facts['bodies']):
        cases[f'fde_{i}'] = body['frames']['fde']['va']+12,None
        for j,(site,target) in enumerate(body['sites']):
            cases[f'call_{i}_{j}'] = site+1,None
    cases['cie'] = facts['bodies'][0]['frames']['cie']['va']+17,None
    cases['naming_relocation'] = rel+16,struct.pack('<q',0x565e960)
    cases['partial_code_writer'] = rel,struct.pack('<Q',0x565e95d)
    controls = {}
    for label,(address,replacement) in cases.items():
        changed = bytearray(original)
        if replacement is None:
            changed[offset(address,1)] ^= 1
        else:
            begin = offset(address,len(replacement))
            changed[begin:begin+len(replacement)] = replacement
        try:
            oracle.structure(changed)
        except ValueError as error:
            controls[label] = {'va':hex(address),'rejected':str(error)}
        else:
            raise ValueError('Accepted corruption '+label)
    return {'target_sha256':oracle.TARGET_SHA,'structural_controls':controls,
            'instruction_counts':[len(x['instructions']) for x in facts['bodies']],
            'captured_execution':False}


if __name__ == '__main__':
    print(json.dumps(check(),indent=2))
