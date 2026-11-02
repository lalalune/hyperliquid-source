#!/usr/bin/env python3
"""Compare newly authored Rust with frozen whole-integer expectations."""
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

SOURCE=ROOT/'src/node94-multiply-subtract'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(r)==3 and re.fullmatch(r'[0-9a-f]{16}(,[0-9a-f]{16}){1,2}',r[1]) and re.fullmatch(r'[0-9a-f]{16}',r[2]) for r in parsed),'output format')
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
    for name,offsets in [('wide',(4,10,13,19,22,26,29,33,36,40,44,47,50,53,56,62,65,69,72,75,78,82,86,89)),('narrow',(4,7,11,14,17,20,24))]:
        for offset in offsets:
            va=WINDOWS[name][0]+offset;raw,off=read(data,secs,va,1)
            cases.append((f'{name}-instruction-{offset:x}',off,bytes([raw[0]^1]),f'{name} body',False))
    for va in (0x564a9ae,0x564a9e3,0x564a9fe,0x564aa26):
        raw,off=read(data,secs,va+1,1)
        cases.append((f'caller-{va:x}',off,bytes([raw[0]^1]),'caller body',False))
    for name,offset in [('wide',0x2dc468),('narrow',0x2dc47c),('caller',0x2d9f88)]:
        off=eh['offset']+offset+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    cases.append(('actual-overlap-injection',eh['offset']+0x2dc404+12,struct.pack('<I',0x565ef00-0x565eaa0),'wide FDE overlap',False))
    for va in (0x9185f0,0x9185f8,0x9179c0):
        raw,off=read(data,secs,va,1)
        cases.append((f'constant-{va:x}',off,bytes([raw[0]^1]),'caller constant',False))
    for va in (0x565ee9b,0x565eeba):
        _,off=read(data,secs,va,1)
        cases.append((f'padding-{va:x}',off,b'\xcc','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    for va in (0x565ee40,0x565eea0):
        cases.append((f'naming-{va:x}',rela['offset']+16,struct.pack('<q',va),'naming relocation',False))
    results=[]
    for label,off,replacement,message,authenticate in cases:
        copy=bytearray(data);copy[off:off+len(replacement)]=replacement
        try: inspect(copy,authenticate=authenticate)
        except ValueError as exc:
            require(str(exc)==message,f'unexpected rejection {label}: {exc}')
            results.append({'name':label,'rejection':str(exc)})
        else: raise ValueError(f'static control survived: {label}')
    return results


MUTANTS={
    'discard-first-high':('(first >> 64) + u128::from(second as u64)','u128::from(second as u64)'),
    'discard-product-carry':('(second >> 64) as u64 + (middle >> 64) as u64','(second >> 64) as u64'),
    'wrong-middle-half':('u128::from(second as u64)','second >> 64'),
    'ignore-low-borrow':('(out[2], original_low) < (product_top, product_low)','out[2] < product_top'),
    'borrow-on-equality':('(out[2], original_low) < (product_top, product_low)','(out[2], original_low) <= (product_top, product_low)'),
    'omit-addback-low':('let operand = u128::from(input[0]) | (u128::from(input[1]) << 64);','let operand = u128::from(input[1]) << 64;'),
    'omit-addback-high':('let operand = u128::from(input[0]) | (u128::from(input[1]) << 64);','let operand = u128::from(input[0]);'),
    'omit-addback':('difference.wrapping_add(operand)','difference.wrapping_add(operand & 0)'),
    'lose-addback-carry':('difference.wrapping_add(operand)','u128::from((difference as u64).wrapping_add(operand as u64)) | (u128::from(((difference >> 64) as u64).wrapping_add((operand >> 64) as u64)) << 64)'),
    'store-top-difference':('words: [corrected as u64, (corrected >> 64) as u64, adjusted]','words: [corrected as u64, (corrected >> 64) as u64, out[2].wrapping_sub(product_top).wrapping_sub(u64::from(original_low < product_low))]'),
    'propagate-addback-overflow':('scalar.wrapping_sub(u64::from(borrow))','scalar.wrapping_sub(u64::from(borrow)).wrapping_add(u64::from(borrow && difference.overflowing_add(operand).1))'),
    'wide-return-unadjusted':('return_value: adjusted,','return_value: scalar,'),
    'narrow-high-product':('input0.wrapping_mul(scalar)','((u128::from(input0) * u128::from(scalar)) >> 64) as u64'),
    'narrow-saturating':('out0.wrapping_sub(input0.wrapping_mul(scalar))','out0.saturating_sub(input0.wrapping_mul(scalar))'),
    'narrow-second-store':('words: [low, scalar]','words: [low, 0]'),
    'narrow-return':('return_value: scalar,','return_value: 0,'),
}


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_multiply_subtract','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_multiply_subtract.rlib'],
           [rustc,'+1.94.1','--crate-name','multiply_subtract_input_client','client.rs',*flags,'--extern','node94_multiply_subtract=libnode94_multiply_subtract.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_multiply_subtract.rlib','client')}


def run(out,rustc):
    require(not out.exists(),'use fresh output directory');out.mkdir(parents=True)
    freeze=check();collect(out/'static')
    for file in (HERE/'static').iterdir():
        require((out/'static'/file.name).read_bytes()==file.read_bytes(),f'static drift: {file.name}')
    controls=static_controls(TARGET.read_bytes())
    inputs=(HERE/'fixtures/inputs.tsv').read_bytes();expected=(HERE/'fixtures/expected.tsv').read_bytes()
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
    bad=lines[0].split(b'\t');bad[2]=b'0000000000000000\n'
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:]))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compiler':subprocess.check_output([rustc,'+1.94.1','-vV'],text=True),
            'platform':platform.platform(),'python':platform.python_version(),'build_hashes':hashes,'runs':runs,'mutants':mutants,'static_controls':controls,'comparator_controls':comparator,
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
