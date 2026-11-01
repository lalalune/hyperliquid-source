"""Reject corruptions of the full fused multiply/fold closure and caller facts."""
import json
import struct
import oracle


def check():
    original = oracle.TARGET.read_bytes()
    facts = oracle.admit()
    oracle.require(facts == json.loads((oracle.PACKET/'frozen/ORACLE-FREEZE.json').read_text())['static_facts'], 'Frozen static facts changed')
    secs,offset = oracle.mapping(original)
    rel = next(s for s in secs if s['name'] == '.rela.dyn')['address']
    # Each product/fold block, all width-defining terminal effects and stores.
    addresses = [0x565d440,0x565d444,0x565d447,0x565d44a,0x565d454,
                 0x565d464,0x565d46a,0x565d478,0x565d47b,0x565d482,
                 0x565d4c2,0x565d4d3,0x565d4d9,0x565d4dc,0x565d4e2,
                 0x565d515,0x565d532,0x565d539,0x565d540,0x565d580,
                 0x565d591,0x565d597,0x565d5a0,0x565d5d3,0x565d5f0,
                 0x565d5f7,0x565d5fe,0x565d63e,0x565d64f,0x565d655,
                 0x565d65e,0x565d691,0x565d6ad,0x565d6b1,0x565d6b5,
                 0x565d6bd,0x565d6c6,0x565d6f9,0x565d6fd,0x565d70a,
                 0x565d711,0x565d714,0x565d718,0x565d71b,0x565d726,
                 0x565d72d,0x565d731,0x565d73d,0x565d740,0x565d74c,
                 0x565d750,0x565d752]
    cases = {f'semantic_{address:x}':(address,None) for address in addresses}
    for i,body in enumerate(facts['bodies']):
        cases[f'fde_{i}'] = body['frames']['fde']['va']+12,None
        for j,(site,target) in enumerate(body['sites']):
            cases[f'call_{i}_{j}'] = site+1,None
    cases['cie'] = facts['bodies'][0]['frames']['cie']['va']+17,None
    cases['naming_relocation'] = rel+16,struct.pack('<q',0x565d440)
    cases['partial_code_writer'] = rel,struct.pack('<Q',0x565d43d)
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
