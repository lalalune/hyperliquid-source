"""Reauthenticate all complete bodies and reject independent structural damage."""
import json
import struct
import oracle


def check():
    original = oracle.TARGET.read_bytes()
    facts = oracle.admit()
    oracle.require(facts == json.loads((oracle.PACKET/'frozen/ORACLE-FREEZE.json').read_text())['static_facts'], 'Frozen static facts changed')
    secs,offset = oracle.mapping(original)
    rel = next(s for s in secs if s['name'] == '.rela.dyn')['address']
    cases = {}
    for i,body in enumerate(facts['bodies']):
        cases[f'fde_{i}'] = body['frames']['fde']['va']+12,None
        cases[f'body_end_{i}'] = body['end']-1,None
        if body['start'] in oracle.STARTS:
            for instruction in body['instructions']:
                address = int(instruction['va'],16)
                cases[f'instruction_{address:x}'] = address,None
        for j,(site,target) in enumerate(body['sites']):
            cases[f'call_{i}_{j}'] = site+1,None
    lock = json.loads((oracle.PACKET/'static-lock.json').read_text())
    for i,pad in enumerate(lock['padding']):
        cases[f'padding_{i}'] = pad['start'],None
    for i,start in enumerate(oracle.SCAN_TARGETS):
        cases[f'naming_relocation_{i}'] = rel+16,struct.pack('<q',start)
        cases[f'partial_code_writer_{i}'] = rel,struct.pack('<Q',start-3)
    for i,record in enumerate({body['frames']['cie']['va'] for body in facts['bodies']}):
        cases[f'cie_{i}'] = record+17,None
    controls = {}
    for label,(address,replacement) in cases.items():
        changed = bytearray(original)
        if replacement is None:
            changed[offset(address,1)] ^= 1
        else:
            start = offset(address,len(replacement))
            changed[start:start+len(replacement)] = replacement
        try:
            oracle.structure(changed)
        except ValueError as error:
            controls[label] = {'va':hex(address),'rejected':str(error)}
        else:
            raise ValueError('Accepted corruption '+label)
    return {'target_sha256':oracle.TARGET_SHA,'structural_controls':controls,
            'instruction_counts':[len(b['instructions']) for b in facts['bodies']],
            'captured_execution':False}


if __name__ == '__main__':
    print(json.dumps(check(),indent=2))
