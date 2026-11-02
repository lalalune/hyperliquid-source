#!/usr/bin/env python3
"""Prove boundary relations from authenticated operands, without capture execution."""
import argparse
import itertools
import verify


def parameters(data):
    image = verify.Image(data)
    u = lambda a, n=1: int.from_bytes(image.get(a, n), 'little')
    return {'minimum_length': u(0x4ec8003), 'prefix_word': u(0x4ec800d, 2),
            'prefix_cut': u(0x4ec802e, 4), 'first_prefix_condition': u(0x4ec8036),
            'suffix_distance': 256 - u(0x4ec8077), 'first_suffix_condition': u(0x4ec8072),
            'release_condition': u(0x4ec8120)}


def signed(byte):
    return byte if byte < 128 else byte - 256


def boundary(byte):
    return signed(byte) > -65


def selected(raw, p):
    """Local branch relation; valid UTF-8 and length/prefix premises are explicit."""
    if len(raw) < p['minimum_length'] or int.from_bytes(raw[:2], 'little') != p['prefix_word']:
        return {'route': 'transfer', 'bytes': len(raw)}
    prefix = p['prefix_cut']
    # Only two branch conditions are used, the measured opcode and a deliberate
    # counterfactual. Later candidates keep their measured signed comparisons.
    first = boundary(raw[6]) if p['first_prefix_condition'] == 0x7f else raw[6] > 0xbf
    if not first:
        prefix = next((i for i in range(5, 1, -1) if boundary(raw[i])), int(signed(raw[1]) >= -64))
    suffix = len(raw) - p['suffix_distance']
    continuation = not boundary(raw[-4]) if p['first_suffix_condition'] == 0x7e else raw[-4] < 0xbf
    if continuation:
        suffix = next((len(raw) - d for d in (3, 2, 1) if boundary(raw[-d])), len(raw))
    return {'route': 'format_request', 'prefix_end': prefix, 'suffix_start': suffix,
            'prefix_hex': raw[:prefix].hex(), 'suffix_hex': raw[suffix:].hex()}


def reference(text):
    raw = text.encode('utf-8')
    if len(raw) < 21 or not text.startswith('0x'):
        return {'route': 'transfer', 'bytes': len(raw)}
    cuts = [0]
    for char in text:
        cuts.append(cuts[-1] + len(char.encode('utf-8')))
    a, b = max(i for i in cuts if i <= 6), min(i for i in cuts if i >= len(raw) - 4)
    return {'route': 'format_request', 'prefix_end': a, 'suffix_start': b,
            'prefix_hex': raw[:a].hex(), 'suffix_hex': raw[b:].hex()}


def release_requested(capacity, p):
    return capacity != 0 if p['release_condition'] == 0x74 else capacity == 0


def deductions(data):
    p = parameters(data)
    verify.require(p == {'minimum_length': 21, 'prefix_word': 0x7830, 'prefix_cut': 6,
                         'first_prefix_condition': 0x7f, 'suffix_distance': 4,
                         'first_suffix_condition': 0x7e, 'release_condition': 0x74}, 'changed operands')
    for b in range(256):
        verify.require(boundary(b) == (b & 0xc0 != 0x80), 'signed boundary predicate')
    examples = ['0x' + 'a'*18, '0x' + 'a'*19, '0X'+'a'*25, 'validator-'+'a'*25,
                '0x'+'z'*25, '0xabc'+'é'+'a'*18, '0xabc'+'€'+'a'*18,
                '0xabc'+'😀'+'a'*18, '0x'+'a'*18+'€x', '0x'+'a'*18+'😀x',
                '0x'+'a'*18+'😀', '0x'+'\0'*25]
    rows=[]
    for text in examples:
        actual=selected(text.encode(),p)
        verify.require(actual==reference(text), 'example boundary')
        rows.append({'input':text,'byte_length':len(text.encode()),**actual})
    # Every code-point width combination in four adjacent characters, with
    # independent prefix and suffix placements. Unicode scalar endpoints below
    # exercise values at the encoding transitions and around surrogate space.
    chars=['a','é','€','😀']; count=0
    for left in itertools.product(chars,repeat=4):
        for right in itertools.product(chars,repeat=3):
            text='0x'+''.join(left)+'padding'*3+''.join(right)
            actual=selected(text.encode(),p)
            verify.require(actual==reference(text), 'width-composition boundary')
            a,b=actual['prefix_end'],actual['suffix_start']
            verify.require(3 <= a <= 6 and 1 <= len(text.encode())-b <= 4, 'valid UTF-8 retained bounds')
            count+=1
    scalars=[0,0x7f,0x80,0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff]
    scalar_cases=0
    for value in scalars:
        for prefix_padding in range(7):
            for suffix_padding in range(6):
                text='0x'+'a'*prefix_padding+chr(value)+'middle'*4+chr(value)+'b'*suffix_padding
                verify.require(selected(text.encode(),p)==reference(text), 'scalar endpoint boundary')
                scalar_cases+=1
    thresholds=0
    for prefix in ('0x','0X','xx','00'):
        for n in range(2,41):
            text=prefix+'q'*(n-2)
            verify.require(selected(text.encode(),p)==reference(text), 'admission boundary')
            thresholds+=1
    return {'schema':1,'target_sha256':verify.DIGEST,'parameters':p,
            'scope':'Static branch algebra and independent Unicode boundary reference, not native execution or full formatting equivalence.',
            'byte_predicates':256,'width_compositions':count,'scalar_endpoint_cases':scalar_cases,
            'admission_cases':thresholds,'examples':rows}


def counterfacts(data):
    image=verify.Image(data)
    trials=[('minimum length',0x4ec8003,20,lambda p:selected(b'0x'+b'a'*18,p)),
            ('lowercase prefix',0x4ec800e,ord('X'),lambda p:selected(b'0x'+b'a'*25,p)),
            ('six-byte prefix budget',0x4ec802e,5,lambda p:selected(b'0x'+b'a'*25,p)),
            ('signed prefix boundary',0x4ec8036,0x77,lambda p:selected(b'0x'+b'a'*25,p)),
            ('four-byte suffix budget',0x4ec8077,0xfb,lambda p:selected(b'0x'+b'a'*25,p)),
            ('signed suffix boundary',0x4ec8072,0x72,lambda p:selected(b'0x'+b'a'*25,p)),
            ('nonzero capacity release',0x4ec8120,0x75,lambda p:release_requested(32,p))]
    rows=[]
    for name,va,byte,predict in trials:
        changed=bytearray(data);changed[image.off(va)]=byte
        before,after=predict(parameters(data)),predict(parameters(changed))
        verify.require(before!=after,'inert byte counterfactual: '+name)
        try:verify.observe(changed,body_hashes=False,exports=False)
        except ValueError as error:rows.append({'name':name,'va':hex(va),'original_byte':image.get(va,1).hex(),'replacement_byte':f'{byte:02x}','before':before,'after':after,'rejection':str(error)})
        else:raise ValueError('counterfactual survived: '+name)
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong artifact')
    report=deductions(data);report['actual_byte_counterfacts']=counterfacts(data)
    text=verify.encoded(report);path=verify.PACKET/'relations.json'
    if args.write:path.write_text(text)
    else:verify.require(path.read_text()==text,'relation regeneration differs')
    print('PASS: 256 byte predicates, 16384 width compositions, 420 scalar cases, 156 admission cases, 7 actual-byte counterfacts')


if __name__=='__main__':main()
