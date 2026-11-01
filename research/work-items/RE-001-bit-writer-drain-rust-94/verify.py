#!/usr/bin/env python3
"""Static evidence and input-only own-Rust comparison with the frozen state relation."""
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

SOURCE=ROOT/'src/node94-bit-writer-drain'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(r)==13 and r[1] in ('0','1','2') and
                    all(re.fullmatch('[0-9a-f]{'+str(width)+'}',r[index]) for index,width in ((2,4),(3,8),(4,4),(5,16),(6,16),(8,8),(9,4),(10,16))) and
                    r[7] in ('S','E') and (re.fullmatch('[0-9a-f]{16}',r[11]) if r[7]=='S' else r[11]=='-'*16) and
                    (r[12]=='-' or re.fullmatch('(?:[0-9a-f]{2})+',r[12])) for r in parsed),'output format')
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
    for va,_,_ in decode_rows((HERE/'static/drain-gnu.txt').read_text(),0x5494050,0x54940d8):
        raw,off=read(data,secs,va,1)
        cases.append((f'drain-instruction-{va:x}',off,bytes([raw[0]^1]),'drain body',False))
    for name,(start,end,_) in WINDOWS.items():
        if name!='drain':
            for call in records['direct_calls']:
                va=int(call['site'],16)
                if start<=va<end:
                    raw,off=read(data,secs,va+1,1)
                    cases.append((f'call-{va:x}',off,bytes([raw[0]^1]),f'{name} body',False))
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    cases.append(('shared-cie',eh['offset']+8,b'X','CIE bytes',False))
    _,off=read(data,secs,0x54940d8,1);cases.append(('padding',off,b'\x90','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('naming',rela['offset']+16,struct.pack('<q',0x5494050),'naming relocation',False))
    # Add a matching E8 pattern outside any retained body to reach the census gate.
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x5494050-0x16488e0-5),'direct call census',False))
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
    'flush-above16':('if state.counter == 16 {','if state.counter >= 16 {'),
    'unsigned-counter':('else if state.counter <= 7 {','else if (state.counter as u32) <= 7 {'),
    'no-emit-through8':('else if state.counter <= 7 {','else if state.counter <= 8 {'),
    'sign-extend-noop-rax':('rax: state.counter as u32 as u64,','rax: state.counter as i64 as u64,'),
    'flush-big-endian':('emitted: state.accumulator.to_le_bytes(),','emitted: state.accumulator.to_be_bytes(),'),
    'flush-retains-accumulator':('accumulator: 0,','accumulator: state.accumulator,'),
    'flush-subtracts8':('counter: 0,','counter: state.counter - 8,'),
    'one-byte-high':('emitted: [state.accumulator as u8, 0],','emitted: [(state.accumulator >> 8) as u8, 0],'),
    'signed-word-shift':('accumulator: state.accumulator >> 8,','accumulator: ((state.accumulator as i16) >> 8) as u16,'),
    'one-counter-subtract7':('counter: state.counter.wrapping_sub(8),','counter: state.counter.wrapping_sub(7),'),
    'flush-position-saturates':('position: state.position.wrapping_add(2),','position: state.position.saturating_add(2),'),
    'one-position-saturates':('position: state.position.wrapping_add(1),','position: state.position.saturating_add(1),'),
    'one-rax-new-position':('rax: state.position,','rax: state.position.wrapping_add(1),'),
    'flush-rax-position':('rax: 0,','rax: state.position,'),
    'zero-output':('destination.copy_from_slice(&transition.emitted[..count]);','destination.fill(0);'),
    'omit-state-commit':('*state = transition.next;','*state = *state;'),
    'state-write-before-rejection':('let start = usize::try_from(state.position)', 'if output.is_empty() { *state = transition.next; }\n    let start = usize::try_from(state.position)'),
    'reject-exact-capacity':('let destination = output.get_mut(start..end)', 'if end == output.len() { return Err(OutputTooSmall); }\n    let destination = output.get_mut(start..end)'),
    'reject-noop-position':('if transition.emitted_len == 0 {','if transition.emitted_len == 0 {\n        if state.position > output.len() as u64 { return Err(OutputTooSmall); }'),
    'truncate-position':('usize::try_from(state.position)', 'usize::try_from(state.position as u32)'),
}


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_bit_writer_drain','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_bit_writer_drain.rlib'],
           [rustc,'+1.94.1','--crate-name','drain_input_client','client.rs',*flags,'--extern','node94_bit_writer_drain=libnode94_bit_writer_drain.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_bit_writer_drain.rlib','client')}


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
    bad=lines[0].split(b'\t');bad[3]=b'00000000'
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:]))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'projection bytes/count/state/RAX plus checked application status/state/RAX/full output buffer; no masks',
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
