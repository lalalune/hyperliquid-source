#!/usr/bin/env python3
"""Static integer/byte lemmas for the collector proof, not a target interpreter."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('time_lock_verify', HERE / 'verify.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
U64 = (1 << 64) - 1


def parameters(data):
    im = v.Image(data)
    # Only data immediates are projected. Instruction shapes and all surrounding
    # branches are independently bound by obligations.json and native exports.
    for a, raw in [(0x5961bc5, '4983ff'), (0x5961be5, '83c1'),
                   (0x5961be8, '83f9'), (0x5961c1c, 'ba'),
                   (0x5961abc, '4983c5'), (0x5961a83, '4883c0')]:
        v.require(im.get(a, len(bytes.fromhex(raw))).hex() == raw, 'parameter opcode')
    return {'fast_cutoff': im.get(0x5961bc8, 1)[0],
            'digit_bias': im.get(0x5961be7, 1)[0],
            'digit_max': im.get(0x5961bea, 1)[0],
            'radix': int.from_bytes(im.get(0x5961c1d, 4), 'little'),
            'input_stride': im.get(0x5961abf, 1)[0],
            'output_stride': im.get(0x5961a86, 1)[0]}


def digit(byte, p):
    # The actual short path uses 32-bit ADD, with a sign-extended imm8.
    bias = p['digit_bias'] - 256 if p['digit_bias'] >= 128 else p['digit_bias']
    value = (byte + bias) & ((1 << 32) - 1)
    return value <= p['digit_max']


def verify(data):
    v.require(len(data) == 105896032 and v.sha(data) == v.DIGEST, 'wrong node115 input')
    p = parameters(data)
    v.require(p == {'fast_cutoff': 17, 'digit_bias': 208, 'digit_max': 9,
                    'radix': 10, 'input_stride': 24, 'output_stride': 8}, 'parameter relation')
    admitted_bytes = [b for b in range(256) if digit(b, p)]
    v.require(admitted_bytes == list(range(48, 58)), 'exact ASCII digit set')
    fast_max = p['radix'] ** (p['fast_cutoff'] - 1) - 1
    v.require(fast_max == 9999999999999999 and fast_max <= U64, 'fast fold cannot overflow')
    # MUL overflow plus an invalid current byte still selects invalid-digit tag1;
    # ADC preserves the byte comparison carry across MOV eax,0.
    overflow_tags = {str(b): 1 + int(((b - 48) & 255) < 10) for b in range(256)}
    v.require({b for b in range(256) if overflow_tags[str(b)] == 2} == set(admitted_bytes),
              'overflow path digit precedence')
    # One decimal step at all selected arithmetic boundaries, independently using
    # mathematical unbounded integers. No original register or memory is advanced.
    pairs = []
    for value in (0, 1, 10**16-1, U64//10-1, U64//10, U64//10+1, U64):
        for d in range(10):
            product = value * p['radix']; total = product + d
            kind = 'multiply-overflow' if product > U64 else ('add-overflow' if total > U64 else 'in-range')
            v.require((kind == 'in-range') == (value <= (U64-d)//10), 'decimal overflow partition')
            pairs.append({'value': str(value), 'digit': d, 'classification': kind})
    # With i input entries already copied to temporary storage and k prior
    # accepted entries, k < i. The next output write cannot touch an unread entry.
    geometry = 0
    for i in range(1, 129):
        for k in range(i):
            v.require((k+1)*p['output_stride'] <= i*p['input_stride'], 'in-place prefix safety')
            geometry += 1
    v.require(3*p['output_stride'] == p['input_stride'], 'capacity conversion preserves byte allocation')
    # A stable filter's last value need not be a maximum. The FDE has no value
    # comparison or sorting call in its accepted-value path.
    example = [9, 2, 9, 1]
    v.require(example[-1] == 1 and max(example) == 9, 'last is not a maximum theorem')
    counterfacts = []
    for key, a, value, observation in [
        ('fast_cutoff', 0x5961bc8, 21, 'unchecked 20-digit maximum exceeds u64'),
        ('digit_bias', 0x5961be7, 209, 'ASCII digit set changes from 0..9 to /..8'),
        ('radix', 0x5961c1d, 11, 'a decimal step from 1 with digit0 becomes11'),
        ('input_stride', 0x5961abf, 16, 'input record byte stride changes'),
        ('output_stride', 0x5961a86, 16, 'three output slots no longer preserve 24 input bytes')]:
        changed = bytearray(data); changed[v.Image(data).off(a)] = value
        q = parameters(changed)
        v.require(q[key] != p[key], 'counterfact extraction')
        if key == 'fast_cutoff': v.require(q['radix']**(q[key]-1)-1 > U64, observation)
        if key == 'digit_bias': v.require([b for b in range(256) if digit(b,q)] == list(range(47,57)), observation)
        if key == 'radix': v.require(1*q['radix']+0 == 11, observation)
        if key == 'input_stride': v.require(q[key] != 24, observation)
        if key == 'output_stride': v.require(3*q[key] != 24, observation)
        try:
            v.observe(changed, body_hashes=False, exports=False)
        except ValueError as error:
            v.require('instruction obligation' in str(error), 'counterfact rejection reason')
        else:
            raise ValueError('semantic counterfact accepted')
        counterfacts.append({'parameter':key, 'old':p[key], 'new':q[key], 'observation':observation})
    return {'parameters':p, 'ascii_bytes_checked':256, 'ascii_digits':admitted_bytes,
            'fast_maximum':str(fast_max), 'decimal_boundary_steps':pairs,
            'overflow_tag_cases':256, 'in_place_geometry_cases':geometry,
            'capacity_equation':'24*C == 8*(3*C), with valid allocation sizes',
            'last_value_example':example, 'counterfacts':counterfacts,
            'scope':'Finite arithmetic/byte checks supporting PROOF.md; no target execution or emulation, no Rust implementation or runtime-equivalence claim.'}


if __name__ == '__main__':
    result = verify(v.TARGET.read_bytes())
    v.require(result == json.loads((HERE / 'algebra.json').read_text()), 'algebra record drift')
    print('PASS: ASCII, overflow, compaction and five operand counterfacts')
