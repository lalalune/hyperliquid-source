#!/usr/bin/env python3
"""Static evidence and input-only own-Rust comparison with cost inversion."""
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

from oracle import check,cost
from static_evidence import HERE,ROOT,TARGET,WINDOWS,read,sections,inspect,collect,require

SOURCE=ROOT/'src/node94-shifted-divisor-scalar'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(r)==2 and re.fullmatch(r'[0-9a-f]{16}',r[1]) for r in parsed),'output format')
        require(len({r[0] for r in parsed})==len(parsed),'duplicate output ID')
        return parsed
    got,want=rows(actual),rows(expected)
    require([r[0] for r in got]==[r[0] for r in want],'output IDs/order/count')
    return [{'id':a[0],'actual':a[1],'expected':b[1]} for a,b in zip(got,want) if a!=b]


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
    for offset in (0,4,7,11,14,19,22,25,28,31,36,39,43,47,51,55,58,61,64,67,69,74,78,81,84,88,91):
        raw,off=read(data,secs,0x565ede0+offset,1)
        cases.append((f'producer-instruction-{offset:x}',off,bytes([raw[0]^1]),'producer body',False))
    for va in (0x564a99b,0x564a9bc,0x564a9f0,0x564aa0b):
        raw,off=read(data,secs,va+1,1)
        cases.append((f'caller-{va:x}',off,bytes([raw[0]^1]),'caller body',False))
    for name,offset in [('producer',0x2dc454),('caller',0x2d9f88)]:
        off=eh['offset']+offset+12;size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    for va in (0x9185f0,0x9185f8,0x9179c0):
        raw,off=read(data,secs,va,1)
        cases.append((f'constant-{va:x}',off,bytes([raw[0]^1]),'caller constant',False))
    _,off=read(data,secs,0x565ee3d,1);cases.append(('padding',off,b'\xcc','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('naming',rela['offset']+16,struct.pack('<q',0x565ede0),'naming relocation',False))
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
    '63-loop-decisions':('for _ in 0..64','for _ in 0..63'),
    '65-loop-decisions':('for _ in 0..64','for _ in 0..65'),
    'omit-final-decision':('let final_digit = u64::from(remainder >= weight);','let final_digit = u64::from(remainder >= weight) & 0;'),
    'strict-final-comparison':('let final_digit = u64::from(remainder >= weight);','let final_digit = u64::from(remainder > weight);'),
    'strict-loop-comparison':('let accepted = remainder >= weight;','let accepted = remainder > weight;'),
    'omit-saturation':('if first_bit != 0 { u64::MAX } else { value }','if first_bit != 0 { value } else { value }'),
    'wrong-saturation-bit':('let first_bit = digits >> 63;','let first_bit = digits >> 62;'),
    'discard-threshold-low':('let mut weight = threshold;','let mut weight = threshold & (u128::from(u64::MAX) << 64);'),
    'discard-threshold-high':('let mut weight = threshold;','let mut weight = threshold & u128::from(u64::MAX);'),
    'lose-cross-limb-shift':('weight >>= 1;','weight = ((weight >> 65) << 64) | u128::from((weight as u64) >> 1);'),
    'arithmetic-threshold-shift':('weight >>= 1;','weight = ((weight as i128) >> 1) as u128;'),
    'failed-subtract-not-restored':('if accepted {\n            remainder -= weight;\n        }','remainder = remainder.wrapping_sub(weight);'),
    'inverted-loop-digit':('digits = (digits << 1) | u64::from(accepted);','digits = (digits << 1) | u64::from(!accepted);'),
    'ceil-threshold-shift':('weight >>= 1;','weight = (weight >> 1) + (weight & 1);'),
    'skip-original-threshold':('let mut weight = threshold;','let mut weight = threshold >> 1;'),
}


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_shifted_divisor_scalar','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_shifted_divisor_scalar.rlib'],
           [rustc,'+1.94.1','--crate-name','shifted_scalar_input_client','client.rs',*flags,'--extern','node94_shifted_divisor_scalar=libnode94_shifted_divisor_scalar.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_shifted_divisor_scalar.rlib','client')}


def run(out,rustc):
    require(not out.exists(),'use fresh output directory');out.mkdir(parents=True)
    freeze=check();collect(out/'static')
    for file in (HERE/'static').iterdir():
        require((out/'static'/file.name).read_bytes()==file.read_bytes(),f'static drift: {file.name}')
    controls=static_controls(TARGET.read_bytes())
    inputs=(HERE/'fixtures/inputs.tsv').read_bytes();expected=(HERE/'fixtures/expected.tsv').read_bytes()
    for stimulus,answer in zip(inputs.decode().splitlines(),expected.decode().splitlines(),strict=True):
        label,n,d=stimulus.split('\t');name,q=answer.split('\t');n,d,q=int(n,16),int(d,16),int(q,16)
        require(label==name and cost(q,d)<=n,'oracle feasible boundary')
        require(q==2**64-1 or cost(q+1,d)>n,'oracle maximal boundary')
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
    bad=lines[0].split(b'\t');bad[1]=b'0000000000000000\n'
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:]))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'oracle_boundary_checks':freeze['cases'],
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
