"""Pre-Rust original delegate-entry A21 to scratch/composition expectations.

Only immutable unsigned sorting and bisect splices are used. No target code is
executed or evaluated. Final-A composition remains subject to native review.
"""
from pathlib import Path
from bisect import bisect_right
from collections import Counter
import hashlib
import itertools
import json
import random
import struct

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
MAX=(1<<64)-1
HIGH=1<<63


def sha(raw):return hashlib.sha256(raw).hexdigest()


def case(name,source,ordinal):
    assert len(source)==21 and all(0<=x<=MAX for x in source)
    initial=[((0xa55a000000000000+ordinal*101+i)&MAX) for i in range(37)]
    scratch=list(initial);writes=[];partitions=[]
    for offset,temp in [(0,21),(10,29)]:
        words=source[offset:offset+8]
        temporary=sorted(words[:4])+sorted(words[4:])
        destination=sorted(words)
        for relative in range(0,8,4):
            a,b,c,d=words[relative:relative+4]
            low1,high1=min(a,b),max(a,b);low2,high2=min(c,d),max(c,d)
            partitions.append([int(low2<low1),int(high2<high1)])
        for j,value in enumerate(temporary):writes.append([0,temp+j,value]);scratch[temp+j]=value
        for j in [0,7,1,6,2,5,3,4]:writes.append([0,offset+j,destination[j]]);scratch[offset+j]=destination[j]
    after_seeds=list(scratch)
    left=list(scratch[:8])
    insertion_indices=[]
    for value in source[8:10]:
        j=len(left);k=bisect_right(left,value);insertion_indices.append(k)
        writes.append([0,j,value]);writes.extend([0,d,left[d-1]] for d in range(j,k,-1))
        if k<j:writes.append([0,k,value])
        left=left[:k]+[value]+left[k:]
    scratch[:10]=left
    prepared=list(scratch)
    right=list(scratch[10:18])
    for value in source[18:21]:
        j=len(right);k=bisect_right(right,value);insertion_indices.append(k)
        writes.append([0,10+j,value]);writes.extend([0,10+d,right[d-1]] for d in range(j,k,-1))
        if k<j:writes.append([0,10+k,value])
        right=right[:k]+[value]+right[k:]
    scratch[10:21]=right
    final=sorted(source)
    for t in range(10):writes.extend(([1,t,final[t]],[1,20-t,final[20-t]]))
    writes.append([1,10,final[10]])
    assert scratch[:10]==sorted(source[:10]) and scratch[10:21]==sorted(source[10:21])
    assert sorted(prepared[:18]+source[18:21])==final
    assert 58<=len(writes)<=107
    return dict(id=ordinal,name=name,source21=source,initial_scratch37=initial,
                source_after_seeds21=list(source),scratch_after_seeds37=after_seeds,
                prepared_scratch37=prepared,final_source21=final,final_scratch37=scratch,
                insertion_indices=insertion_indices,logical_writes=writes,network_partitions=partitions)


def main():
    assert not (ROOT/'src/node94-orderbook/src/n21_seed_prepare.rs').exists()
    named=[
        ('ascending',list(range(21))),('descending',list(range(20,-1,-1))),
        ('all-equal',[42]*21),('alternating-low-high',[i//2 if i%2==0 else MAX-i//2 for i in range(21)]),
        ('unsigned-crossing',[HIGH,0,MAX,1,HIGH-1,HIGH+1,2,MAX-1,3,HIGH-2,4,HIGH+2,5,MAX-2,6,HIGH-3,7,HIGH+3,8,9,10]),
        ('pair-duplicates',[0,0,MAX,MAX,1,1,HIGH,HIGH,0,MAX,HIGH,HIGH,2,2,3,3,0,0,HIGH,MAX,0]),
        ('all-first-half-above',list(range(100,110))+list(range(11))),
        ('all-second-half-above',list(range(10))+list(range(100,111))),
        ('left-extremes-right-middle',[0,1,2,3,4,100,101,102,103,104]+list(range(50,61))),
        ('right-extremes-left-middle',list(range(50,60))+[0,1,2,3,100,101,102,103,4,104,105]),
        ('all-max',[MAX]*21),('all-zero',[0]*21),
        ('word32-boundaries',[(1<<32)+(i%3)-1 for i in range(21)]),
        ('network-p0q0',[0,2,1,3]*5+[4]),('network-p1q0',[1,2,0,3]*5+[4]),
        ('network-p0q1',[0,3,1,2]*5+[4]),('network-p1q1',[2,3,0,1]*5+[4]),
    ]
    rows=[case(name,words,index) for index,(name,words) in enumerate(named)]
    rng=random.Random(0x4912A50);grid=[0,1,2,(1<<32)-1,1<<32,HIGH-1,HIGH,HIGH+1,MAX-1,MAX]
    for i in range(63):rows.append(case(f'grid-{i:02}',[rng.choice(grid) for _ in range(21)],len(rows)))
    assert len(rows)==80
    counts=Counter(tuple(p) for row in rows for p in row['network_partitions']);assert len(counts)==4
    stimulus=b'S21IN001'+struct.pack('<I',len(rows))+b''.join(struct.pack('<I58Q',r['id'],*r['source21'],*r['initial_scratch37']) for r in rows)
    expected=b'S21OUT01'+struct.pack('<I',len(rows))+b''.join(struct.pack('<I153Q',r['id'],*r['source_after_seeds21'],*r['scratch_after_seeds37'],*r['prepared_scratch37'],*r['final_source21'],*r['final_scratch37']) for r in rows)
    record=dict(stage='pre-Rust static-derived seed/preparation plus proposed full n21 composition freeze',
                target_sha256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
                base='56c0ec672bd8fdcfaa80f2db700a61e6240b3663',rust_source_present=False,
                captured_execution=False,instruction_evaluation=False,original_A_definition='A at entry of delegate4918d30 with n21/cap>=37; no outer-core/collector reachability claim',
                expected_roles='afterseedAunchanged;afterseedS;afterleftj8/j9preparedS;composedfinalA;composedfinalS. Full composition is a static proof candidate, not yet reviewed/compiled/runtime validated.',
                input_sha256=sha(stimulus),expected_sha256=sha(expected),input_bytes=len(stimulus),expected_bytes=len(expected),generator_sha256=sha(Path(__file__).read_bytes()),
                cases=rows,network_partition_counts={str(k):v for k,v in sorted(counts.items())},
                all_twenty_four_distinct_four_word_permutations=[dict(input=list(x),expected=sorted(x)) for x in itertools.permutations([0,1,HIGH,MAX])],
                all_eighty_one_three_value_four_word_cases=[dict(input=list(x),expected=sorted(x)) for x in itertools.product([0,HIGH,MAX],repeat=4)],
                minimum_logical_writes=min(len(r['logical_writes']) for r in rows),maximum_logical_writes=max(len(r['logical_writes']) for r in rows))
    for name,raw in [('SEED-PRE-SOURCE-FREEZE.json',(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()),('input.bin',stimulus),('expected.bin',expected)]:
        p=HERE/name;assert not p.exists();p.write_bytes(raw);print(name,len(raw),sha(raw))


if __name__=='__main__':main()
