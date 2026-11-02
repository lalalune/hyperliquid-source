#!/usr/bin/env python3
"""Static proof replay for one admitted monotone path; no instruction evaluator."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE.parent / 'RE-006-large-sort-scratch-contract-94/verify.py'
SOURCE_SHA = 'deb2cff39e7ab8c1a0e36b6c7339db25f97cb9acd3c20171b3a16ca730710be2'
FROZEN = {'fixtures.json':'086d75c7e15d84bd83c9575640b02286fd53b291d390badab30f0054af34b542',
          'mutations.json':'e9e6463d91c93b48cf1cde206f2a79ab08418f78f11b1d016331ba1c26169548'}
if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA:
    raise ValueError('scratch verifier dependency changed')
spec = importlib.util.spec_from_file_location('scratch_static_dependency', SOURCE)
scratch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scratch)
require, sha, render = scratch.require, scratch.sha, scratch.render

BOUNDS = (0x4dbd490,0x4dbdb5e)
EXTRA_PINS = (
    ('full-width first qwords and comparison',0x4dbd647,'488b4424084c8b00488b50084c39c2'),
    ('ascending full-width next comparison',0x4dbd6a0,'4889f7488b742408488b34c64839fe'),
    ('descending full-width next comparison',0x4dbd6d0,'4889f7488b742408488b34c64839fe'),
    ('qword pair shuffles',0x4dbd766,'660f70db4e660f70d24e'),
    ('qword pair shuffle left zero',0x4dbd779,'660f70c04e'),
    ('qword pair shuffle left one',0x4dbd784,'660f70c14e'),
    ('normal terminal frame restoration',0x4dbdb4c,'4881c4e80200005b415c415d415e415f5dc3'),
)


def frozen(name):
    raw = (HERE/name).read_bytes()
    require(sha(raw)==FROZEN[name], 'pre-model fixture changed: '+name)
    return json.loads(raw)


def operand_obligations(image):
    for row in frozen('mutations.json')['controls']:
        expected=bytes.fromhex(row['original_hex'])
        require(image.read(int(row['va'],16),len(expected))==expected,'frozen operand mismatch: '+row['name'])
    for name,va,expected in EXTRA_PINS:
        require(image.read(va,len(bytes.fromhex(expected)))==bytes.fromhex(expected),'operand mismatch: '+name)


def words_for(case):
    n,family=case['count'],case['family']; maximum=2**64-1
    if family=='constant': return [2**63]*n
    if family=='nondecreasing_ties': return [(i//3)*maximum//((n-1)//3) for i in range(n)]
    if family=='descending_tie':
        words=[(n-i)*maximum//n for i in range(n)]
        words[case['tie_index']]=words[case['tie_index']-1]
        return words
    words=[i*maximum//(n-1) for i in range(n)]
    if family=='decreasing': words.reverse()
    return words


def packed(words):
    return b''.join(struct.pack('<Q',x) for x in words)


def first_run_model(words):
    """Independent scalar projection, derived after freezing fixture expectations."""
    n=len(words)
    require(21<=n<=4096 and all(type(x) is int and 0<=x<2**64 for x in words),'model domain')
    descending=words[1]<words[0]
    end=2
    while end<n:
        if descending:
            if words[end]>=words[end-1]: break
        elif words[end]<words[end-1]: break
        end+=1
    threshold=min(n-(n//2),64)
    accepted=end>=threshold
    output=list(words); written=set(); vector_blocks=tail_pairs=0
    if descending and accepted:
        half=end//2; vector_pairs=half-(half%4)
        for index in range(0,vector_pairs,4):
            left=output[index:index+4]
            right=output[end-index-4:end-index]
            output[index:index+4]=[right[3],right[2],right[1],right[0]]
            output[end-index-4:end-index]=[left[3],left[2],left[1],left[0]]
            written.update(range(index,index+4)); written.update(range(end-index-4,end-index))
            vector_blocks+=1
        for index in range(vector_pairs,half):
            opposite=end-index-1
            output[index],output[opposite]=output[opposite],output[index]
            written.update((index,opposite)); tail_pairs+=1
    return output,dict(run=end,descending=descending,accepted=accepted,
        input_qwords_written=len(written),vector_blocks=vector_blocks,tail_pairs=tail_pairs,
        encoded_run=2*end+1 if accepted else None,
        whole_array_return_without_helpers=end==n and accepted)


def vector_controls():
    results=[]
    for case in frozen('fixtures.json')['cases']:
        words=words_for(case)
        require(sha(packed(words))==case['input_sha256'],'frozen input recipe mismatch')
        output,result=first_run_model(words)
        require(result['run']==case['expected_first_run'],'run extent mismatch: '+case['name'])
        if 'expected_reverse' in case:
            require(sha(packed(output))==case['expected_output_sha256'],'frozen ordering mismatch: '+case['name'])
            require(result['descending']==case['expected_reverse'],'direction mismatch')
            require(result['whole_array_return_without_helpers'],'complete monotone run not admitted')
            require(result['input_qwords_written']==case['expected_input_qwords_written'],'input write count mismatch')
        else:
            require(result['accepted']==case['expected_accept_first_run'],'tie threshold mismatch')
            prefix=sorted(words[:result['run']]) if result['accepted'] else words[:result['run']]
            require(output==prefix+words[result['run']:],'prefix normalization or suffix changed')
        results.append(dict(name=case['name'],output_sha256=sha(packed(output)),**result))
    # Freeze-time complete-output hashes already supply the independent unsigned
    # ordering oracle. These variants demonstrate material equality/sign gaps.
    signed_case=words_for(next(c for c in frozen('fixtures.json')['cases'] if c['name']=='increasing-21'))
    signed=lambda x:x if x<2**63 else x-2**64
    require(any(signed(signed_case[i])<signed(signed_case[i-1]) for i in range(1,len(signed_case))), 'signed alternative not distinguished')
    ties=words_for(next(c for c in frozen('fixtures.json')['cases'] if c['name']=='descending-tie-21-2'))
    require(ties[2]==ties[1] and first_run_model(ties)[1]['run']==2,'descending strictness alternative not distinguished')
    threshold_checks=[]
    for n in range(21,4097):
        q=(2**62+n-1)//n
        c=min((n+1)//2,64)
        require(2<=c<=n and 2*n+1<2**64 and 0<n*q<2**63,'selected path arithmetic not admitted')
        threshold_checks.append([n,c,q,n*q])
    return dict(cases=results,complete_monotone_cases=76,tie_boundary_cases=20,
                arithmetic_count_domain=4076,arithmetic_transcript_sha256=sha(render(threshold_checks).encode()),
                scope='Independent source-level consequence controls only; no captured instruction evaluation or runtime equivalence.')


def selected_graph(nodes,calls,direction):
    # Every filtered edge is justified by the addressed inequalities in README.
    # Loop/end choices and the two first/sentinel phases are retained together;
    # this graph is conditional on those mathematical invariants.
    edges={0x4dbd4b4:[0x4dbd4ba],0x4dbd4eb:[0x4dbd4ed],
           0x4dbd58d:[0x4dbd620],0x4dbd624:[0x4dbd647],
           0x4dbd6f1:[0x4dbd6f7],0x4dbd847:[0x4dbdae6],
           0x4dbd60c:[0x4dbd612],0x4dbdb15:[0x4dbdb4c]}
    if direction=='nondecreasing':
        edges.update({0x4dbd656:[0x4dbd67d],0x4dbd686:[0x4dbd68c],
                      0x4dbd6af:[0x4dbd6b1],0x4dbd6fa:[0x4dbd7f7]})
    else:
        edges.update({0x4dbd656:[0x4dbd658],0x4dbd65c:[0x4dbd6bb],
                      0x4dbd6df:[0x4dbd6e1],0x4dbd6fa:[0x4dbd700],
                      0x4dbd709:[0x4dbd70f],0x4dbd71c:[0x4dbd722]})
    by_site={int(n['site'],16):n for n in nodes}
    for site,targets in edges.items():
        require(site in by_site and set(map(hex,targets))<=set(by_site[site]['successors']),'selected edge not native')
    visited=set(); todo=[BOUNDS[0]]
    while todo:
        site=todo.pop()
        if site in visited: continue
        require(site in by_site,'selected path leaves complete native graph')
        visited.add(site)
        next_sites=edges.get(site,[int(v,16) for v in by_site[site]['successors']])
        todo.extend(next_sites)
    require(0x4dbdb5d in visited,'vacuous selected path: RET not reachable')
    reached_calls=[c for c in calls if int(c['site'],16) in visited]
    require(not reached_calls,'selected monotone path reaches unresolved call')
    input_writes=[]; stack_writes=[]
    for site in sorted(visited):
        text=by_site[site]['native']
        match=re.match(r'^mov\w*\s+([^,]+),',text)
        if match and '[' in match[1]:
            (stack_writes if 'rsp' in match[1] else input_writes).append(hex(site))
    expected=[] if direction=='nondecreasing' else list(map(hex,[0x4dbd770,0x4dbd775,0x4dbd77e,0x4dbd789,0x4dbd7d7,0x4dbd7da]))
    require(input_writes==expected,'unexpected selected input write sites')
    return dict(direction=direction,conditional_edge_filters={hex(k):list(map(hex,v)) for k,v in edges.items()},
                reachable_instruction_sites=list(map(hex,sorted(visited))),reachable_calls=reached_calls,
                input_write_sites=input_writes,explicit_stack_write_sites=stack_writes,
                ret_reachable=True,
                premise='n21..4096; entire array nondecreasing or strictly descending; valid stable disjoint buffers; addressed register/loop invariants, no abnormal control transfer.')


def collect(llvm):
    data=scratch.TARGET.read_bytes()
    require(len(data)==91774280 and sha(data)==scratch.SHA,'target identity mismatch')
    image=scratch.Image(data); operand_obligations(image); scratch.local_obligations(image)
    _,extents,_=scratch.fde_extents(data)
    fde=scratch.qualify(extents,*BOUNDS)
    streams,rows=scratch.native(image,*BOUNDS,llvm)
    nodes,calls=scratch.graph(rows)
    for mutation in frozen('mutations.json')['controls']:
        require(int(mutation['va'],16) in {r[0] for r in rows},'mutation not at native boundary')
    controls=[]
    for mutation in frozen('mutations.json')['controls']:
        va=int(mutation['va'],16); raw=bytes.fromhex(mutation['mutation_hex'])
        require(len(raw)==len(bytes.fromhex(mutation['original_hex'])),'mutation width changed')
        changed=bytearray(data); pos=image.offset(va,len(raw)); changed[pos:pos+len(raw)]=raw
        try: operand_obligations(scratch.Image(changed))
        except ValueError as error: controls.append(dict(name=mutation['name'],outcome='rejected below SHA admission',reason=str(error)))
        else: raise ValueError('frozen operand mutation survived')
    helpers=[]
    wanted={int(c['slot'],16) for c in calls}
    for sec in image.sections:
        if sec['type']==4:
            require(sec['size']%24==0,'partial relocation')
            for pos in range(sec['offset'],sec['offset']+sec['size'],24):
                slot,info,addend=struct.unpack_from('<QQq',data,pos)
                if slot in wanted: helpers.append(dict(slot=hex(slot),info=hex(info),target=hex(addend),raw_hex=data[pos:pos+24].hex()))
    require(len(helpers)==len(wanted),'missing/duplicate uncalled helper relocation')
    paths=[selected_graph(nodes,calls,direction) for direction in ['nondecreasing','strictly-decreasing']]
    files={f'raw/inner-complete-{provider}.txt':stream for provider,stream in zip(['gnu','llvm'],streams)}
    files['records.json']=render(dict(task='RE-006',component='orderbook',target_sha256=scratch.SHA,target_bytes=len(data),
        base='56c0ec672bd8fdcfaa80f2db700a61e6240b3663',coordinates='linked ELF VAs and exact section-derived file offsets',
        complete_inner_body=image.window(*BOUNDS),fde={k:hex(v) if isinstance(v,int) else v for k,v in fde.items()},
        fde_record=image.record(fde['fde']),cie_record=image.record(fde['cie']),instructions=len(rows),normal_cfg=nodes,
        all_calls=calls,uncalled_helpers=helpers,admitted_monotone_graphs=paths,
        prior_scratch_verifier={'path':str(SOURCE.relative_to(ROOT)),'sha256':SOURCE_SHA},
        frozen_before_model=FROZEN,normalization_masks=[],
        limits='Conditional manual-path invariants and native local CFG; arbitrary arrays, other lengths, lower sort/merge helper semantics and runtime reachability unproved.'))
    files['controls.json']=render(dict(local_corruptions=controls,synthetic=vector_controls()))
    return files


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    parser.add_argument('--llvm',default=os.environ.get('LLVM_OBJDUMP','llvm-objdump'))
    args=parser.parse_args(); files=collect(args.llvm)
    for name,value in files.items():
        if args.write:
            (HERE/name).parent.mkdir(parents=True,exist_ok=True); (HERE/name).write_text(value)
        else: require((HERE/name).read_text()==value,'stale evidence: '+name)
    print('Static monotone proof replay passed: 4 exports, 17 frozen operand controls, 96 frozen vectors, 4076 count admissions. No target execution/evaluation.')


if __name__=='__main__': main()
