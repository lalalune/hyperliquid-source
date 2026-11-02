#!/usr/bin/env python3
"""Bind addressed proof data and check abstract request policy, never CPU state."""
import argparse
import copy
import itertools
import json
from pathlib import Path
import struct
from survey import Image, DATA, InvalidEvidence, json_bytes, require, sha

HERE=Path(__file__).resolve().parent
ANCHORS={int(va,16):bytes.fromhex(raw) for va,raw in json.loads((HERE/'anchors.json').read_bytes()).items()}

def bind(image):
    for va,raw in ANCHORS.items():
        require(image.at(va,len(raw))==raw,'Manual proof anchor differs: '+hex(va))
    for name,(va,raw) in DATA.items():
        require(image.at(va,len(raw))==raw,'Manual proof data differs: '+name)
    image.relocations()
    # Resolve data table coordinates, without evaluating a captured instruction.
    for value,target in [(2,0x68b5f9),(17,0x68b5f0)]:
        rel=struct.unpack('<i',image.at(0xbd89c+(value-1)*4,4))[0]
        require(0xbd89c+rel==target,'Selected error-classification data edge differs')
    for va,targets in [(0xbd100,[0x67a1e6,0x67a20f,0x67a1ed,0x67a1fb]),
                       (0xbd110,[0x67a415,0x67a43e,0x67a41c,0x67a42a]),
                       (0xbd120,[0x67a85f,0x67a888,0x67a866,0x67a874])]:
        require([va+x for x in struct.unpack('<iiii',image.at(va,16))]==targets,
                'Error representation table differs')

def first(failed,kind,tag_two,directory_mode):
    if not failed:return 'READY'
    if kind==0:return 'PARENT'
    if kind==12 and not tag_two and directory_mode:return 'READY'
    return 'ERROR'

def reverse(failed,kind,tag_two,directory_mode):
    if not failed:return 'READY'
    if kind==12 and not tag_two and directory_mode:return 'READY'
    return 'ERROR'

def abstract_trace(prefixes,first_results,reverse_results):
    # Prefixes are caller-supplied abstract slice identifiers. No host path
    # library, captured iterator, syscall, C callback or machine code is run.
    requests=[]
    for index,state in enumerate(first_results):
        requests.append(prefixes[index])
        if state=='ERROR':return requests,'ERROR'
        if state=='PARENT':continue
        require(state=='READY','Bad abstract state')
        for label,state in zip(reversed(prefixes[:index]),reverse_results):
            requests.append(label)
            if state=='ERROR':return requests,'ERROR'
            require(state=='READY','Bad reverse state')
        require(len(reverse_results)>=index,'Incomplete abstract fixture')
        return requests,'ZERO'
    raise InvalidEvidence('Fixture needs an explicit first-phase stopping event')

def run(binary):
    image=Image(binary.read_bytes());bind(image)
    rows=list(itertools.product((False,True),(0,12,20),(False,True),(False,True)))
    expected_first=['READY']*12+['PARENT']*4+['ERROR','READY','ERROR','ERROR']+['ERROR']*4
    expected_reverse=['READY']*12+['ERROR']*4+['ERROR','READY','ERROR','ERROR']+['ERROR']*4
    require([first(*x) for x in rows]==expected_first,'First-phase table differs')
    require([reverse(*x) for x in rows]==expected_reverse,'Reverse-phase table differs')
    mutants={
        'first-not-found-is-ready':lambda f,k,t,d:'READY' if f and k==0 else first(f,k,t,d),
        'exists-ignores-mode':lambda f,k,t,d:'READY' if f and k==12 and not t else first(f,k,t,d),
        'reverse-not-found-retries-parent':lambda f,k,t,d:'PARENT' if f and k==0 else reverse(f,k,t,d),
    }
    witnesses={}
    for name,mutant in mutants.items():
        expected=expected_reverse if name.startswith('reverse') else expected_first
        bad=[i for i,x in enumerate(rows) if mutant(*x)!=expected[i]]
        require(bad,'Abstract mutant survived: '+name);i=bad[0]
        witnesses[name]={'input':list(rows[i]),'expected':expected[i],'mutant':mutant(*rows[i])}
    fixtures=[
        (['S0','S1','S2'],['PARENT','PARENT','READY'],['READY','READY'],['S0','S1','S2','S1','S0'],'ZERO'),
        (['S0','S1'],['PARENT','ERROR'],[],['S0','S1'],'ERROR'),
        (['S0','S1','S2'],['PARENT','PARENT','READY'],['ERROR'],['S0','S1','S2','S1'],'ERROR'),
        (['S0'],['READY'],[],['S0'],'ZERO'),
    ]
    for prefixes,initial,back,order,status in fixtures:
        require(abstract_trace(prefixes,initial,back)==(order,status),'Abstract request-order fixture differs')
    encoding=[(0,2),(17,0x1100000002),(0xffffffff,0xffffffff00000002)]
    require([((n&0xffffffff)<<32)|2 for n,_ in encoding]==[x for _,x in encoding],
            'Raw errno packing arithmetic differs')
    guards=[]
    for name,va in [('recursive-dispatch',0x679bbe),('empty-recursive-return',0x679bc7),
                   ('first-mkdir-sentinel',0x67a18a),('first-zero-kind',0x67a216),
                   ('first-exists-kind',0x67a444),('first-metadata-mode',0x67a495),
                   ('reverse-exists-kind',0x67a88e),('reverse-copy-order',0x67a6c0),
                   ('long-callback',0x6639a2),('callback-return-sentinel',0x66bbf7),
                   ('notfound-table-entry',0xbd89c+4),('exists-table-entry',0xbd89c+16*4),
                   ('reverse-error-table',0xbd120),('static-invalid-input-kind',0x7dbba0)]:
        offsets=[o+va-a for o,a,n in image.loads if a<=va<a+n]
        require(len(offsets)==1,'Mutation mapping ambiguous')
        changed=bytearray(image.data);changed[offsets[0]]^=1
        lower=copy.copy(image);lower.data=bytes(changed)
        try:bind(lower)
        except InvalidEvidence:guards.append({'case':name,'result':'below-identity corruption refused'})
        else:raise InvalidEvidence('Corrupted policy binding accepted: '+name)
    return {'targetSha256':sha(image.data),'anchors':len(ANCHORS),'firstPhaseRows':len(rows),
            'reversePhaseRows':len(rows),'abstractMutantWitnesses':witnesses,
            'abstractRequestFixtures':len(fixtures),'encodingFixtures':len(encoding),
            'bindingControls':guards,'capturedExecution':False,'instructionEvaluation':False,
            'scope':'Data binding and abstract policy arithmetic support a manual proof. '
                    'No machine-instruction evaluator, host path/errno/filesystem query or iterator simulation. '
                    'No helper/storage/lifetime/concurrency theorem.'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--receipt',type=Path)
    args=p.parse_args()
    try:
        require(not args.receipt or not args.receipt.exists(),'Preserve receipt')
        result=run(args.binary)
        if args.receipt:args.receipt.write_bytes(json_bytes(result))
        print(json.dumps(result))
    except (InvalidEvidence,OSError,UnicodeError) as error:p.exit(1,str(error)+'\n')

if __name__=='__main__':main()
