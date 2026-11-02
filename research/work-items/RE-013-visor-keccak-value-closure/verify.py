#!/usr/bin/env python3
"""Replay static bindings and pure mathematical expectations, never target code."""
import argparse
import copy
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

import collect
import corpus

HERE=Path(__file__).resolve().parent
require=collect.require
sha=collect.sha


def expect_rejection(label, function, result, category, coordinate=None):
    try:
        function()
    except ValueError as e:
        result.append(dict(name=label,category=category,rejected=True,reason=str(e),coordinate=coordinate))
        return
    raise ValueError('negative control accepted: '+label)


def compare_stream(actual, expected):
    require(actual==expected,'exact stream mismatch')


def static_controls(image,pins,frames):
    out=[]
    for name,data in [('truncated',image.data[:-1]),('same-size-header-change',bytes([0])+image.data[1:])]:
        expect_rejection(name,lambda d=data:collect.admit_image(d,pins),out,'whole-image integrity only')
    def changed_at(va,byte=0):
        off=image.offset(va,1);b=bytearray(image.data);b[off]^=1<<byte
        require(b[off]!=image.at(va,1)[0],'neutral byte mutation')
        return collect.Image(bytes(b)),dict(va=hex(va),file_offset=off)
    # Operands and round constants are compared without admitting image/body hashes.
    for f in pins['layout']['fields']:
        changed,coordinate=changed_at(int(f['va'],16))
        expect_rejection('field-'+f['name'],lambda c=changed:collect.admit_fields(c,pins),out,
                         'below-hash operand/data binding only',coordinate)
    def projected(records):
        result=copy.deepcopy(records)
        for body in result['bodies']:
            del body['sha256']
        return result
    expected=projected(pins['bindings'])
    def admit_binding(changed):
        require(projected(collect.bindings(changed,pins['layout'],frames))==expected,'derived binding mismatch')
    coordinates=[]
    for c in pins['layout']['calls']:
        a=int(c['producer'],16)+3 if c['kind']=='rbx-from-slot' else int(c['site'],16)+(1 if c['kind']=='direct' else 2)
        coordinates.append(('call-'+c['site'],a))
    for b in pins['layout']['branches']:
        coordinates.append(('branch-target-'+b['site'],int(b['site'],16)+b['bytes']-1))
    for d in pins['layout']['data_edges']:
        coordinates.append(('data-edge-'+d['site'],int(d['site'],16)+3))
    seen=set()
    for body in pins['bindings']['bodies']:
        f=body['frame']
        for name,a in [('fde-start',int(f['fde_va'],16)+8),('fde-extent',int(f['fde_va'],16)+12),
                       ('cie-encoding',int(f['cie_va'],16)+16),('index',int(f['index_va'],16))]:
            if (name,a) not in seen:
                seen.add((name,a));coordinates.append((name+'-'+hex(a),a))
        if 'lsda_va' in f:coordinates.append(('lsda-header',int(f['lsda_va'],16)))
    for name,a in coordinates:
        changed,coordinate=changed_at(a)
        expect_rejection(name,lambda c=changed:admit_binding(c),out,'below-hash structural binding only',coordinate)
    unique={c['binding']['rela']['file_offset']:c['binding']['rela'] for c in pins['bindings']['calls'] if 'binding' in c}
    for off,r in sorted(unique.items()):
        # Mutation is in the relocation record's addend, not its destination VA.
        raw=bytearray(image.data);raw[off+16]^=1;changed=collect.Image(bytes(raw))
        expect_rejection('rela-addend-'+hex(r['destination']),lambda c=changed:admit_binding(c),out,
                         'below-hash RELA binding only',dict(file_offset=off+16,slot=hex(r['destination'])))
    return out


def wrong_padding(message,first=1,last=128,omit_empty=False):
    padded=bytearray(message)
    if not(omit_empty and len(padded)%136==0):
        padded.append(first);padded.extend(b'\0'*((-len(padded))%136));padded[-1]^=last
    a=[0]*64
    for start in range(0,len(padded),136):
        for i,b in enumerate(padded[start:start+136]):
            lane,z=divmod(i,8)
            for bit in range(8):a[8*z+bit]^=((b>>bit)&1)<<lane
        a=corpus.permutation(a)
    return bytes(sum(((a[8*(i%8)+bit]>>(i//8))&1)<<bit for bit in range(8)) for i in range(32))


def mathematical_controls():
    inputs=gzip.decompress((HERE/'corpus/inputs.tsv.gz').read_bytes()).decode().splitlines()
    answers=gzip.decompress((HERE/'corpus/expected.tsv.gz').read_bytes()).decode().splitlines()
    expected={bytes.fromhex(x.split('\t')[1]) if x.split('\t')[1]!='-' else b'':bytes.fromhex(y.split('\t')[1])
              for x,y in zip(inputs,answers,strict=True)}
    witnesses=[]
    def witness(name,message,actual):
        require(actual!=expected[message],'mathematical wrong rule survived: '+name)
        witnesses.append(dict(name=name,input_hex=message.hex(),wrong=actual.hex(),expected=expected[message].hex(),
                              scope='pure mathematical rule mutation; no compiled/native execution'))
    witness('SHA3-delimiter-6',b'',wrong_padding(b'',first=6))
    witness('omit-first-padding-bit',b'abc',wrong_padding(b'abc',first=0))
    witness('omit-final-padding-bit',b'abc',wrong_padding(b'abc',last=0))
    witness('omit-empty-final-block',b'',wrong_padding(b'',omit_empty=True))
    witness('omit-exact-rate-final-block',bytes(136),wrong_padding(bytes(136),omit_empty=True))
    witness('reverse-output-lane-endianness',b'',b''.join(expected[b''][i:i+8][::-1] for i in range(0,32,8)))
    rc=corpus.RC;coords=corpus.COORDS
    try:
        corpus.RC=rc[:-1];witness('23-rounds',b'abc',corpus.digest(b'abc'))
        corpus.RC=[rc[0]^2,*rc[1:]];witness('wrong-round-constant',b'abc',corpus.digest(b'abc'))
        corpus.RC=rc
        corpus.COORDS=[(s,d,(r+1)%64 if s==1 else r) for s,d,r in coords]
        witness('wrong-rho-offset',b'abc',corpus.digest(b'abc'))
        corpus.COORDS=[(s,(d+1)%25,r) for s,d,r in coords]
        witness('wrong-pi-destination',b'abc',corpus.digest(b'abc'))
    finally:
        corpus.RC=rc;corpus.COORDS=coords
    return witnesses


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--repo',type=Path,default=HERE.parents[2]);ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args();require(not args.out.exists(),'fresh verification receipt')
    pins=json.loads((HERE/'BASIS-PINS.json').read_text())
    image=collect.authenticate(args.repo,pins)
    frames=collect.native(['/opt/homebrew/opt/binutils/bin/readelf','--debug-dump=frames',pins['target']['path']],args.repo)
    require(collect.bindings(image,pins['layout'],frames)==pins['bindings'],'positive raw evidence graph')
    certificate=corpus.finite_certificate()
    require([int.from_bytes(image.at(0xc11c0+8*i,8),'little') for i in range(24)]==corpus.constants(),'generated constants/native bytes')
    rotations=[(1,0x6bcc88),(2,0x6bcaf8),(3,0x6bcb98),(4,0x6bcc43),(5,0x6bcc35),(6,0x6bcb05),
               (7,0x6bcc8b),(8,0x6bcad9),(9,0x6bcbb3),(10,0x6bcb8f),(11,0x6bcc25),(12,0x6bcaf1),
               (13,0x6bcc9d),(14,0x6bcafc),(15,0x6bcae8),(16,0x6bcba6),(17,0x6bcc2e),(18,0x6bcad0),
               (19,0x6bcc94),(20,0x6bcca6),(21,0x6bcae0),(22,0x6bcbaf),(23,0x6bcc51),(24,0x6bcae4)]
    by_source={s:r for s,d,r in corpus.coordinates()}
    for source,address in rotations:
        raw=image.at(address,4)
        actual=1 if raw[1]==0xd1 else raw[3]
        require(raw[1] in (0xd1,0xc1) and actual==by_source[source],'native rho immediate')
    controls=static_controls(image,pins,frames)
    expected=gzip.decompress((HERE/'corpus/expected.tsv.gz').read_bytes());lines=expected.splitlines(keepends=True)
    corruptions={'missing':b''.join(lines[:-1]),'extra':expected+lines[0],'reorder':b''.join([lines[1],lines[0],*lines[2:]]),
                 'duplicate':b''.join([lines[0],lines[0],*lines[2:]]),'changed-byte':bytes([expected[0]^1])+expected[1:],
                 'missing-LF':expected[:-1],'CRLF':expected.replace(b'\n',b'\r\n'),'empty':b''}
    for name,data in corruptions.items():
        expect_rejection('comparator-'+name,lambda d=data:compare_stream(d,expected),controls,'exact byte comparator')
    witnesses=mathematical_controls()
    expected_files={str(p.relative_to(HERE)):sha(p.read_bytes()) for directory in ['corpus','observed'] for p in sorted((HERE/directory).iterdir())}
    commands=[]
    with tempfile.TemporaryDirectory(prefix='visor-keccak-precode-') as tmp:
        jobs=[]
        for label,seed,tz in [('one','19','UTC'),('two','991','Asia/Seoul')]:
            for script,directory in [('collect.py','observed'),('corpus.py','corpus')]:
                out=Path(tmp)/label/directory;out.parent.mkdir(exist_ok=True)
                argv=[sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),str(HERE/script),'--out',str(out)]
                if script=='collect.py':argv += ['--repo',str(args.repo)]
                jobs.append((label,directory,argv,out,dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED=seed,TZ=tz)))
        def run(job):
            label,directory,argv,out,env=job
            p=subprocess.run(argv,capture_output=True,env=env,timeout=300)
            require(p.returncode==0 and not p.stderr,'regeneration failed '+label+'/'+directory+': '+p.stderr.decode())
            actual={directory+'/'+x.name:sha(x.read_bytes()) for x in sorted(out.iterdir())}
            require(actual=={k:v for k,v in expected_files.items() if k.startswith(directory+'/')},'regenerated files differ')
            return dict(tree=label,kind=directory,argv=[x.replace(tmp,'<SCRATCH>').replace(str(HERE),'<PACKET>').replace(str(args.repo),'<REPO>') for x in argv],
                        exit=0,stdout=p.stdout.decode(),stderr='',files=actual)
        with ThreadPoolExecutor(max_workers=4) as pool:
            commands=list(pool.map(run,jobs))
    # The baseline crate already exists. This checks chronology only for NEW client/source.
    require(not (HERE/'rust-validation').exists() and not list(HERE.rglob('*.rs')),'new client exists before pre-code freeze')
    result=dict(status='PASS static and mathematical only',target=pins['target'],bodies=4,body_bytes=3612,rows=877,
                calls=35,branches=71,prior_files=len(pins['prior_files']),controls=controls,
                controls_count=len(controls),mathematical_wrong_rules=witnesses,finite_certificate=certificate,
                generated_files=expected_files,regenerations=commands,new_client_absent=True,
                existing_provider_predates_corpus=True,cases=2000,official_byte_aligned_checks=256,
                limits='No compiled provider/client, captured execution, target evaluator, runtime or automatic semantic proof. Below-hash controls test bindings, not mutant machine semantics.')
    collect.write_json(args.out,result)
    print(json.dumps(dict(status=result['status'],controls=len(controls),mathematical_wrong_rules=len(witnesses),regenerated_files_per_two_trees=2*len(expected_files),cases=2000)))


if __name__=='__main__':main()
