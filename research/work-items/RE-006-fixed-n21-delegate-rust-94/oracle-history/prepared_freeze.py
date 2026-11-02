"""Pre-Rust immutable rank oracle for one qualified n21 native continuation.

No captured code is evaluated. This sorts mathematical labeled input words;
native candidate/cursor correspondence requires the separate induction proof.
"""
from pathlib import Path
from bisect import bisect_right
from collections import Counter
import hashlib
import json
import random
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MASK = (1 << 64) - 1
HIGH = 1 << 63


def sha(data):
    return hashlib.sha256(data).hexdigest()


def oracle(left, seed, incoming, name, ordinal, refusal=0):
    assert len(left) == 10 and len(seed) == 8 and len(incoming) == 3
    source = [((0xd00d000000000000 + ordinal * 37 + i) & MASK) for i in range(18)] + incoming
    scratch = left + seed + [MASK - ordinal - i for i in range(3)]
    scratch += [((0xa55a000000000000 + ordinal * 101 + i) & MASK) for i in range(16)]
    before = dict(name=name, native_domain=not refusal, id=ordinal, source21=source, scratch37=scratch)
    if refusal:
        before.update(status=refusal, expected_source21=source, expected_scratch37=scratch,
                      insertion_positions=[0] * 3, center_side=0, final_cursors=[0] * 4,
                      pairs=[[0] * 3 for _ in range(10)], writes=[])
        return before
    assert left == sorted(left) and seed == sorted(seed)
    writes, positions = [], []
    prefix = list(seed)
    for value in incoming:
        j = len(prefix)
        insertion = bisect_right(prefix, value)
        positions.append(insertion)
        writes.append([0, 10 + j, value])  # target's initial append always happens
        writes.extend([0, 10 + index, prefix[index - 1]] for index in range(j, insertion, -1))
        if insertion < j:
            writes.append([0, 10 + insertion, value])
        prefix = prefix[:insertion] + [value] + prefix[insertion:]
    # Completely independent final sequence: immutable unsigned stable ranks.
    prepared = left + prefix
    ranks = sorted([(value, side, index) for side, words in enumerate((left, prefix))
                    for index, value in enumerate(words)])
    pairs = []
    for t in range(10):
        front = ranks[:t]
        back = ranks[21 - t:] if t else []
        lf = sum(side == 0 for _, side, _ in front)
        rf = 10 + sum(side == 1 for _, side, _ in front)
        lb = 9 - sum(side == 0 for _, side, _ in back)
        rb = 20 - sum(side == 1 for _, side, _ in back)
        assert 0 <= lf <= 9 and 10 <= rf <= 19 and 0 <= lb <= 9 and 11 <= rb <= 20
        # These assertions test the mathematical induction's candidate lemma;
        # they do not run native instructions or establish the proof alone.
        front_side = 1 if prepared[rf] < prepared[lf] else 0
        back_value_side = 1 if prepared[rb] > prepared[lb] else 0
        back_retire_side = 1 if prepared[rb] >= prepared[lb] else 0
        assert front_side == ranks[t][1]
        assert back_retire_side == ranks[20 - t][1]
        assert min(prepared[rf], prepared[lf]) == ranks[t][0]
        assert max(prepared[rb], prepared[lb]) == ranks[20 - t][0]
        pairs.append([front_side, back_value_side, back_retire_side])
        writes.extend(([1, t, ranks[t][0]], [1, 20 - t, ranks[20 - t][0]]))
    front, back = ranks[:10], ranks[11:]
    lf = sum(side == 0 for _, side, _ in front)
    rf = 10 + sum(side == 1 for _, side, _ in front)
    lex = 10 - sum(side == 0 for _, side, _ in back)
    rex = 21 - sum(side == 1 for _, side, _ in back)
    center_side = ranks[10][1]
    assert center_side == (0 if lf < lex else 1)
    lf += center_side == 0
    rf += center_side == 1
    assert lf == lex and rf == rex
    writes.append([1, 10, ranks[10][0]])
    assert 24 <= len(writes) <= 54
    before.update(status=0, expected_source21=[value for value, _, _ in ranks],
                  expected_scratch37=prepared + scratch[21:], insertion_positions=positions,
                  center_side=center_side, final_cursors=[lf, lex, rf, rex],
                  pairs=pairs, writes=writes)
    return before


def encode(rows, expected):
    result = bytearray(b'N21OUT01' if expected else b'N21IN001')
    result += struct.pack('<I', len(rows))
    for row in rows:
        if not expected:
            result += struct.pack('<I58Q', row['id'], *row['source21'], *row['scratch37'])
        else:
            result += struct.pack('<II58Q', row['id'], row['status'], *row['expected_source21'], *row['expected_scratch37'])
            result += struct.pack('<8I', *row['insertion_positions'], row['center_side'], *row['final_cursors'])
            result += struct.pack('<30I', *[v for pair in row['pairs'] for v in pair])
            result += struct.pack('<I', len(row['writes']))
            result += b''.join(struct.pack('<IIQ', *event) for event in row['writes'])
            result += bytes((54 - len(row['writes'])) * 16)
    return bytes(result)


def main():
    # Native domain: fixed n21 entry, sorted prepared left10 and right seed8.
    named = [
        ('left-below-right', list(range(10)), list(range(100,108)), [108,109,110]),
        ('right-below-left', list(range(100,110)), list(range(8)), [8,9,10]),
        ('alternating-center-left', list(range(0,20,2)), list(range(1,17,2)), [17,19,21]),
        ('alternating-center-right', list(range(1,21,2)), list(range(0,16,2)), [16,18,20]),
        ('all-equal-dual-provenance', [42]*10, [42]*8, [42]*3),
        ('left-exhausted-after-five-pairs', list(range(5))+list(range(100,105)), list(range(50,58)), [58,59,60]),
        ('right-exhausted-early', list(range(50,60)), [0,1,2,3,100,101,102,103], [4,104,105]),
        ('high-bit-crossing', [0,1,2,HIGH-2,HIGH-1,HIGH,HIGH+1,HIGH+2,MASK-1,MASK], list(range(HIGH-4,HIGH+4)), [HIGH+4,0,MASK]),
        ('all-twenty-seven-right-shifts', list(range(10)), list(range(HIGH,HIGH+8)), [9,8,7]),
        ('equal-front-distinct-back', [0,0,2,3,4,5,6,7,8,31], [0,1,9,10,11,12,13,14], [15,16,40]),
        ('equal-back-distinct-front', [0,2,3,4,5,6,7,8,9,MASK], [1,10,11,12,13,14,15,MASK], [MASK,16,17]),
        ('mixed-equal-extremes', [0,0,2,3,3,7,8,9,9,MASK], [0,1,2,3,7,9,MASK,MASK], [MASK,0,7]),
        ('append-ties', list(range(10)), [0,1,2,3,4,5,6,6], [6,6,6]),
        ('middle-and-front-ties', [0,1,1,2,2,3,3,4,4,5], [0,1,1,2,3,3,4,5], [1,3,0]),
        ('max-seed-low-incoming', [0,1,2,3,4,5,6,HIGH,MASK,MASK], [MASK]*8, [0,1,MASK]),
        ('zero-seed-high-incoming', [0]*5+[MASK]*5, [0]*8, [HIGH,MASK,1]),
    ]
    rows = [oracle(l,s,x,name,i) for i,(name,l,s,x) in enumerate(named)]
    rng = random.Random(0x4918F4D)
    grid = [0,1,2,(1<<32)-1,1<<32,HIGH-1,HIGH,HIGH+1,MASK-1,MASK]
    for i in range(64):
        l=sorted(rng.choice(grid) for _ in range(10));s=sorted(rng.choice(grid) for _ in range(8));x=[rng.choice(grid) for _ in range(3)]
        rows.append(oracle(l,s,x,f'grid-{i:02}',len(rows)))
    for name,l,s,status in [
        ('policy-left-inversion',[1,0]+list(range(2,10)),list(range(8)),1),
        ('policy-right-seed-inversion',list(range(10)),[1,0]+list(range(2,8)),2),
        ('policy-both-inversions',[1,0]+list(range(2,10)),[1,0]+list(range(2,8)),1),
        ('policy-high-bit-left-inversion',[HIGH,0]+[MASK]*8,list(range(8)),1),
    ]:
        rows.append(oracle(l,s,[1,2,3],name,len(rows),status))
    stimulus,expected=encode(rows,False),encode(rows,True)
    assert len(stimulus)==12+84*468 and len(expected)==12+84*1492
    assert not (ROOT/'src/node94-orderbook/src/n21_right_merge.rs').exists()
    record=dict(stage='pre-Rust frozen conditional n21 full-array/state expectations',
                target_sha256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
                source_base='56c0ec672bd8fdcfaa80f2db700a61e6240b3663',native_cases=80,policy_cases=4,
                rust_source_present=False,captured_execution=False,instruction_evaluation=False,
                admission='At4918f4d exactn21/R12=10/RCX=8/RDX=11/RBX=21; stable disjoint A21/S37, preparedS[0..10) sortedunsigned, S[10..18) sortedunsigned, validcallee frame. Seed/left reachability notproved.',
                oracle='Immutable stable ranks(value,side,index), not an x86 evaluator. Independent bisect_right prefix splice gives complete right preparation; rank induction separately proves native candidate/cursor correspondence.',
                observations='Chosen logical source-level stores and cursor/provenance metadata, not original ABI returns or compiled physical store trace.',
                input_sha256=sha(stimulus),expected_sha256=sha(expected),input_bytes=len(stimulus),expected_bytes=len(expected),
                generator_sha256=sha(Path(__file__).read_bytes()),cases=rows,
                summary=dict(center_sides=dict(Counter(r['center_side'] for r in rows if r['native_domain'])),minimum_writes=min(len(r['writes']) for r in rows if r['native_domain']),maximum_writes=max(len(r['writes']) for r in rows)))
    for name,raw in [('PRE-SOURCE-FULL-ARRAY-FREEZE.json',(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()),('input.bin',stimulus),('expected.bin',expected)]:
        path=HERE/name
        assert not path.exists()
        path.write_bytes(raw)
        print(name,len(raw),sha(raw))


if __name__=='__main__':
    main()
