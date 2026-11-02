#!/usr/bin/env python3
"""Static evidence and input-only own-Rust comparison with the frozen immutable-image copy relation."""
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

SOURCE=ROOT/'src/node94-gated-block-copy'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(row)==3 and re.fullmatch(r'E|V:[0-9a-f]{16}',row[1]) and re.fullmatch(r'-|[0-9a-f]+:[0-9a-f]{2}(?:,[0-9a-f]+:[0-9a-f]{2})*',row[2]) for row in parsed),'output format')
        require(len({r[0] for r in parsed})==len(parsed),'duplicate output ID')
        return parsed
    got,want=rows(actual),rows(expected)
    require([r[0] for r in got]==[r[0] for r in want],'output IDs/order/count')
    return [{'id':a[0],'actual':a[1:],'expected':b[1:]} for a,b in zip(got,want) if a!=b]


def archive_check(path,result):
    expected={f"opt{r['opt']}-build{r['build']}.tsv":r['output_sha256'] for r in result['runs']}
    expected.update({f"mutant-{m['name']}.tsv":m['output_sha256'] for m in result['mutants']})
    raw=path.read_bytes();require(raw[4:8]==bytes(4),'archive timestamp')
    archive=json.loads(gzip.decompress(raw))
    require(archive['schema']==2,'archive schema')
    lines=archive['lines'];streams=archive['streams']
    require(len(set(lines))==len(lines) and all(isinstance(line,str) and line.endswith('\n') for line in lines),'archive line dictionary')
    require(len(streams)==len(expected) and {s['name'] for s in streams}==set(expected),'archive labels/count')
    for s in streams:
        require(all(type(i)==int and 0<=i<len(lines) for i in s['line_ids']),'archive line indices')
        data=''.join(lines[i] for i in s['line_ids']).encode('ascii')
        require(len(data)==s['bytes'] and sha(data)==s['sha256']==expected[s['name']],'archive raw-stream integrity')
    return len(streams)


def pack_streams(streams):
    # Lossless shared line dictionary reduces repeated full-output streams.
    # Hashes/byte counts remain those of exact original stdout, not of indices.
    lines=[];seen={};encoded=[]
    for stream in streams:
        ids=[]
        for line in stream['text'].splitlines(keepends=True):
            if line not in seen:seen[line]=len(lines);lines.append(line)
            ids.append(seen[line])
        encoded.append({**{k:v for k,v in stream.items() if k!='text'},'line_ids':ids})
    return gzip.compress(json.dumps({'schema':2,'lines':lines,'streams':encoded},sort_keys=True,separators=(',',':')).encode('ascii'),compresslevel=9,mtime=0)


def static_controls(data):
    secs=sections(data);eh=next(s for s in secs if s['name']=='.eh_frame')
    cases=[('full-target',0,b'X','target SHA-256',True)]
    records=json.loads((HERE/'static/records.json').read_text())
    from static_evidence import decode_rows,CALLS,CIE_BYTES
    for va,_,_ in decode_rows((HERE/'static/copy-gnu.txt').read_text(),0x4ff8b30,0x4ff8b9c):
        raw,off=read(data,secs,va,1)
        cases.append((f'copy-instruction-{va:x}',off,bytes([raw[0]^1]),'copy body',False))
    for site in CALLS:
        name=next(name for name,(start,end,_) in WINDOWS.items() if start<=site<end)
        raw,off=read(data,secs,site,1)
        cases.append((f'caller-site-{site:x}',off,bytes([raw[0]^1]),f'{name} body',False))
    for va in (0x5023e7c,0x5023e87,0x5023e8e,0x5023e92,0x5023e99,0x5027f8c,0x5027f90,0x5027fa2,0x5027fa8):
        name=next(name for name,(start,end,_) in WINDOWS.items() if start<=va<end)
        raw,off=read(data,secs,va,1)
        cases.append((f'caller-setup-{va:x}',off,bytes([raw[0]^1]),f'{name} body',False))
    for name in WINDOWS:
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    cases.append(('shared-cie',eh['offset']+8,b'X','CIE bytes',False))
    for va in CIE_BYTES:
        if va==eh['address']:continue
        raw,off=read(data,secs,va+8,1);cases.append(('caller-cie',off,bytes([raw[0]^1]),'bound CIE bytes',False))
    _,off=read(data,secs,0x4ff8b9c,1);cases.append(('padding',off,b'\x90','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('naming',rela['offset']+16,struct.pack('<q',0x4ff8b30),'naming relocation',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x4ff8b30-0x16488e0-5),'direct call census',False))
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
    'flag-only-one':('if flag != 0 {','if flag == 1 {'),
    'ignore-flag':('if flag != 0 {','if flag != 0 || flag == 0 {'),
    'invert-flag':('if flag != 0 {','if flag == 0 {'),
    'wrong-index-offset':('index_source, 20, 4','index_source, 19, 4'),
    'index-big-endian':('i32::from_le_bytes','i32::from_be_bytes'),
    'saturating-decrement':('field.wrapping_sub(1)','field.saturating_sub(1)'),
    'unsigned-bound':('field.wrapping_sub(1) <= bound','(field.wrapping_sub(1) as u32) <= bound as u32'),
    'strict-bound':('field.wrapping_sub(1) <= bound','field.wrapping_sub(1) < bound'),
    'no-decrement':('field.wrapping_sub(1) <= bound','field <= bound'),
    'wrong-gate-offset':('source, 416, 1','source, 415, 1'),
    'gate-only-one':('image[gate] != 0','image[gate] == 1'),
    'invert-gate':('image[gate] != 0','image[gate] == 0'),
    'fallback-offset':('let mut displacement = 344;','let mut displacement = 345;'),
    'preferred-offset':('displacement = 392;','displacement = 391;'),
    'eager-index':('let mut displacement = 344;','let _ = span(image.len(), index_source, 20, 4)?;\n    let mut displacement = 344;'),
    'eager-gate':('let mut displacement = 344;','let _ = span(image.len(), source, 416, 1)?;\n    let mut displacement = 344;'),
    'require-whole-struct':('let mut displacement = 344;','let _ = span(image.len(), source, 0, 440)?;\n    let mut displacement = 344;'),
    'reject-exact-end':('if end > image_len {','if end >= image_len {'),
    'return-selected':('Ok(destination)','Ok(selected)'),
    'reverse-payload':('image[output..output + 48].copy_from_slice(&snapshot);','snapshot.reverse();\n    image[output..output + 48].copy_from_slice(&snapshot);'),
    'skip-final-chunk':('image[output..output + 48].copy_from_slice(&snapshot);','image[output..output + 32].copy_from_slice(&snapshot[..32]);'),
    'streaming-overlap':('image[output..output + 48].copy_from_slice(&snapshot);','for i in 0..48 { image[output+i] = image[selected+i]; }'),
    'swap-first-two-chunks':('image[output..output + 48].copy_from_slice(&snapshot);','snapshot[..32].rotate_left(16);\n    image[output..output + 48].copy_from_slice(&snapshot);'),
}


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_gated_block_copy','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_gated_block_copy.rlib'],
           [rustc,'+1.94.1','--crate-name','copy_input_client','client.rs',*flags,'--extern','node94_gated_block_copy=libnode94_gated_block_copy.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_gated_block_copy.rlib','client')}


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
    bad=lines[0].split(b'\t');bad[1]=b'V:ffffffffffffffff'
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:]))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'status, returned destination offset, and lossless differences over every image byte; no masks',
            'compiler':subprocess.check_output([rustc,'+1.94.1','-vV'],text=True),'platform':platform.platform(),'python':platform.python_version(),
            'build_hashes':hashes,'runs':runs,'mutants':mutants,'static_controls':controls,'comparator_controls':comparator,
            'source_sha256':{name:sha((SOURCE/name).read_bytes()) for name in ('lib.rs','client.rs','Cargo.toml','Cargo.lock','rust-toolchain.toml')},
            'captured_execution':False,'instruction_emulation':False,'native_target_differential':False}
    packed=pack_streams(streams)
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
