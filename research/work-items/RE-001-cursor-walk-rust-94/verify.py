#!/usr/bin/env python3
"""Static evidence and input-only own-Rust comparison with the frozen first-failure relation."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess

from oracle import check
from static_evidence import HERE,ROOT,TARGET,WINDOWS,read,sections,inspect,collect,require

SOURCE=ROOT/'src/node94-cursor-walk'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(row)==3 and row[1] in ('T','F','E') and re.fullmatch('[0-9a-f]{16}',row[2]) for row in parsed),'output format')
        require(len({r[0] for r in parsed})==len(parsed),'duplicate output ID')
        return parsed
    got,want=rows(actual),rows(expected)
    require([r[0] for r in got]==[r[0] for r in want],'output IDs/order/count')
    return [{'id':a[0],'actual':a[1:],'expected':b[1:]} for a,b in zip(got,want) if a!=b]


def archive_check(path,result):
    expected={f"opt{r['opt']}-build{r['build']}.tsv":r['output_sha256'] for r in result['runs']}
    expected.update({f"mutant-{m['name']}.tsv":m['output_sha256'] for m in result['mutants']})
    raw=path.read_bytes();require(raw[4:8]==bytes(4),'archive timestamp')
    streams=json.loads(gzip.decompress(raw))['streams']
    require(len(streams)==len(expected) and {s['name'] for s in streams}==set(expected),'archive labels/count')
    for s in streams:
        data=s['text'].encode('ascii')
        require(len(data)==s['bytes'] and sha(data)==s['sha256']==expected[s['name']],'archive raw-stream integrity')
    return len(streams)


def static_controls(data):
    secs=sections(data);eh=next(s for s in secs if s['name']=='.eh_frame')
    cases=[('full-target',0,b'X','target SHA-256',True)]
    records=json.loads((HERE/'static/records.json').read_text())
    from static_evidence import decode_rows
    for va,_,_ in decode_rows((HERE/'static/walk-gnu.txt').read_text(),0x3c1d690,0x3c1d6e1):
        raw,off=read(data,secs,va,1)
        cases.append((f'walk-instruction-{va:x}',off,bytes([raw[0]^1]),'walk body',False))
    for va in (0x3362f9d,0x3362fa2,0x3362fa6,0x3362fa9,0x3362fae,0x3362fb3,0x3362fb8):
        raw,off=read(data,secs,va,1)
        cases.append((f'caller-setup-{va:x}',off,bytes([raw[0]^1]),'caller body',False))
    for name in WINDOWS:
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    cases.append(('shared-cie',eh['offset']+8,b'X','CIE bytes',False))
    _,off=read(data,secs,0x3c1d6e1,1);cases.append(('padding',off,b'\x90','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('naming',rela['offset']+16,struct.pack('<q',0x3c1d690),'naming relocation',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x3c1d690-0x16488e0-5),'direct call census',False))
    results=[]
    for label,off,replacement,message,authenticate in cases:
        copy=bytearray(data);copy[off:off+len(replacement)]=replacement
        try:inspect(copy,authenticate=authenticate)
        except ValueError as exc:
            require(str(exc)==message,f'unexpected rejection {label}: {exc}')
            results.append({'name':label,'rejection':str(exc)})
        else:raise ValueError(f'static control survived: {label}')
    return results


MUTANTS={
    'empty-true':('if start == limit {\n        return Ok(false);','if start == limit {\n        return Ok(true);'),
    'advance-empty':('if start == limit {\n        return Ok(false);','if start == limit {\n        *cursor = cursor.wrapping_add(1);\n        return Ok(false);'),
    'reject-equal-outside':('if start == limit {','if start > records.len() { return Err(InvalidRange); }\n    if start == limit {'),
    'reject-exact-end':('limit > records.len()', 'limit >= records.len()'),
    'refusal-as-false':('return Err(InvalidRange);','return Ok(false);'),
    'skip-first':('while *cursor != limit {','*cursor += 1;\n    while *cursor != limit {'),
    'skip-last':('while *cursor != limit {','while (*cursor).saturating_add(1) < limit {'),
    'skip-every-second':('*cursor += 1;','*cursor = (*cursor).saturating_add(2).min(limit);'),
    'tag-three-accepted':('records[index][9] != 2 ||','(records[index][9] != 2 && records[index][9] != 3) ||'),
    'tag-eight-offset':('records[index][9] != 2','records[index][8] != 2'),
    'first-byte-offset':('records[index][0] != 0','records[index][1] != 0'),
    'invert-first-byte':('records[index][0] != 0','records[index][0] == 0'),
    'both-fail-required':('records[index][9] != 2 || records[index][0] != 0','records[index][9] != 2 && records[index][0] != 0'),
    'ignore-tag':('records[index][9] != 2 ||','false ||'),
    'ignore-first-byte':('|| records[index][0] != 0','|| false'),
    'only-check-first':('if records[index][9] != 2 || records[index][0] != 0 {','if index == start && (records[index][9] != 2 || records[index][0] != 0) {'),
    'failure-before-advance':('if records[index][9] != 2 || records[index][0] != 0 {\n            return Ok(false);','if records[index][9] != 2 || records[index][0] != 0 {\n            *cursor -= 1;\n            return Ok(false);'),
    'failure-consumes-rest':('if records[index][9] != 2 || records[index][0] != 0 {\n            return Ok(false);','if records[index][9] != 2 || records[index][0] != 0 {\n            *cursor = limit;\n            return Ok(false);'),
    'failure-true':('if records[index][9] != 2 || records[index][0] != 0 {\n            return Ok(false);','if records[index][9] != 2 || records[index][0] != 0 {\n            return Ok(true);'),
    'success-false':('    Ok(true)\n}', '    Ok(false)\n}'),
    'success-restores-cursor':('    Ok(true)\n}', '    *cursor = start;\n    Ok(true)\n}'),
}


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_cursor_walk','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_cursor_walk.rlib'],
           [rustc,'+1.94.1','--crate-name','walk_input_client','client.rs',*flags,'--extern','node94_cursor_walk=libnode94_cursor_walk.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_cursor_walk.rlib','client')}


def run(out,rustc):
    require(not out.exists(),'use fresh output directory');out.mkdir(parents=True)
    freeze=check();collect(out/'static')
    for file in (HERE/'static').iterdir():
        require((out/'static'/file.name).read_bytes()==file.read_bytes(),f'static drift: {file.name}')
    controls=static_controls(TARGET.read_bytes())
    inputs=gzip.decompress((HERE/'fixtures/inputs.tsv.gz').read_bytes());expected=gzip.decompress((HERE/'fixtures/expected.tsv.gz').read_bytes())
    source=(SOURCE/'lib.rs').read_text();commands=[];streams=[];runs=[];mutants=[];hashes={}
    def execute(directory,label):
        actual=subprocess.check_output([str(directory/'client')],input=inputs,cwd=directory)
        streams.append({'name':label+'.tsv','bytes':len(actual),'sha256':sha(actual),'text':actual.decode('ascii')})
        return actual
    for opt in (0,3):
        artifacts=[]
        for rep in (1,2):
            label=f'opt{opt}-build{rep}';directory=out/label
            artifacts.append(build(source,directory,opt,rustc,commands))
            actual=execute(directory,label);require(not compare(actual,expected),'native mismatch')
            runs.append({'opt':opt,'build':rep,'cases':freeze['cases'],'mismatches':0,'output_sha256':sha(actual)})
        require(artifacts[0]==artifacts[1],'build not reproducible');hashes[f'opt{opt}']=artifacts[0]
    for name,(old,new) in MUTANTS.items():
        require(source.count(old)==1,f'mutant anchor {name}')
        directory=out/('mutant-'+name);build(source.replace(old,new),directory,3,rustc,commands)
        actual=execute(directory,'mutant-'+name);differences=compare(actual,expected)
        require(differences,f'mutant survived: {name}')
        mutants.append({'name':name,'cases':freeze['cases'],'mismatches':len(differences),'first_witness':differences[0],'output_sha256':sha(actual)})
    comparator=[];lines=expected.splitlines(keepends=True)
    bad=lines[0].split(b'\t');bad[1]=b'T'
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:]))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'public status and full final cursor index; immutable input records; no masks',
            'compiler':subprocess.check_output([rustc,'+1.94.1','-vV'],text=True),'platform':platform.platform(),'python':platform.python_version(),
            'build_hashes':hashes,'runs':runs,'mutants':mutants,'static_controls':controls,'comparator_controls':comparator,
            'source_sha256':{name:sha((SOURCE/name).read_bytes()) for name in ('lib.rs','client.rs','Cargo.toml','Cargo.lock','rust-toolchain.toml')},
            'captured_execution':False,'instruction_emulation':False,'native_target_differential':False}
    packed=gzip.compress(json.dumps({'schema':1,'streams':streams},sort_keys=True,separators=(',',':')).encode('ascii'),compresslevel=9,mtime=0)
    (out/'raw-streams.json.gz').write_bytes(packed);archive_check(out/'raw-streams.json.gz',result)
    (out/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    print(f"PASS {freeze['cases']} cases x 4 native runs; {len(mutants)} observable compiled mutants; {len(controls)} static and {len(comparator)} comparator controls; repeated artifact hashes identical; {len(streams)} exact archived streams")


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path);p.add_argument('--check-archive',action='store_true');p.add_argument('--rustc',default=os.environ.get('RUSTC','/opt/homebrew/opt/rustup/bin/rustc'))
    args=p.parse_args()
    if args.check_archive:
        print('PASS archive streams:',archive_check(HERE/'native/raw-streams.json.gz',json.loads((HERE/'native/result.json').read_text())))
    elif args.out: run(args.out.resolve(),args.rustc)
    else: p.error('provide --out or --check-archive')
