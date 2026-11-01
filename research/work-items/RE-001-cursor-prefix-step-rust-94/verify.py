#!/usr/bin/env python3
"""Static evidence and input-only own-Rust comparison with the frozen immutable-image relation."""
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

SOURCE=ROOT/'src/node94-cursor-prefix-step'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        for row in parsed:
            require(len(row)==3 and re.fullmatch(r'U|V:[0-9a-f]{16}|E:[RSP]',row[1]),'output format')
            if row[2]!='-':
                require(re.fullmatch(r'[0-9a-f]+:[0-9a-f]{2}(,[0-9a-f]+:[0-9a-f]{2})*',row[2]),'image difference format')
                indices=[int(pair.split(':')[0],16) for pair in row[2].split(',')]
                require(indices==sorted(set(indices)),'image difference order/duplicates')
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
    from static_evidence import decode_rows,SLOTS
    for va,_,_ in decode_rows((HERE/'static/cursor-gnu.txt').read_text(),0x47d6b90,0x47d6be2):
        raw,off=read(data,secs,va,1)
        cases.append((f'cursor-instruction-{va:x}',off,bytes([raw[0]^1]),'cursor body',False))
    off=eh['offset']+int(records['windows']['cursor']['fde_section_offset'],16)+12
    size=struct.unpack_from('<I',data,off)[0]
    cases.append(('fde-range',off,struct.pack('<I',size+1),'cursor FDE overlap',False))
    cases.append(('shared-cie',eh['offset']+8,b'X','CIE bytes',False))
    _,off=read(data,secs,0x47d6be2,1);cases.append(('padding',off,b'\x90','alignment padding',False))
    for slot in SLOTS:
        _,off=read(data,secs,slot,8)
        cases.append((f'raw-slot-{slot:x}',off,b'X','raw slot bytes',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    for off in range(rela['offset'],rela['offset']+rela['size'],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot in SLOTS:
            cases.append((f'slot-addend-{slot:x}',off+16,struct.pack('<q',0),'naming relocations',False))
    first=next(off for off in range(rela['offset'],rela['offset']+rela['size'],24) if struct.unpack_from('<Q',data,off)[0]==SLOTS[0])
    cases.append(('wrong-relocation-kind',first+8,struct.pack('<Q',9),'naming relocations',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x47d6b90-0x16488e0-5),'direct call census',False))
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
    'only-flag-one':('if image[flag] == 0 {','if image[flag] != 1 {'),
    'signed-counter-gate':('if counter <= 1 {','if (counter as i64) <= 1 {'),
    'counter-zero-only':('if counter <= 1 {','if counter == 0 {'),
    'flag-marker':('image[marker] = 0x67;','image[marker] = 0x66;'),
    'counter-marker':('image[marker] = 0x50;','image[marker] = 0x51;'),
    'wrong-marker-offset':('const MARKER: usize = 0x1f3;','const MARKER: usize = 0x1f2;'),
    'subtract-one':('counter.wrapping_sub(2).to_le_bytes()','counter.wrapping_sub(1).to_le_bytes()'),
    'counter-big-endian':('counter.wrapping_sub(2).to_le_bytes()','counter.wrapping_sub(2).to_be_bytes()'),
    'prefix-unsigned':('i64::from(i16::from_be_bytes(prefix))','i64::from(u16::from_be_bytes(prefix))'),
    'prefix-little-endian':('i16::from_be_bytes(prefix)','i16::from_le_bytes(prefix)'),
    'omit-prefix-width':('let delta = i64::from(i16::from_be_bytes(prefix)) + 2;','let delta = i64::from(i16::from_be_bytes(prefix));'),
    'cursor-saturates':('cursor.wrapping_add(delta as u64)','cursor.saturating_add_signed(delta)'),
    'entry-prefix-snapshot':('image[counter_range].copy_from_slice(&counter.wrapping_sub(2).to_le_bytes());\n    let prefix = [image[prefix_start], image[prefix_start + 1]];', 'let prefix = [image[prefix_start], image[prefix_start + 1]];\n    image[counter_range].copy_from_slice(&counter.wrapping_sub(2).to_le_bytes());'),
    'counter-before-rejection':('let prefix_start = cursor','image[counter_range.clone()].copy_from_slice(&counter.wrapping_sub(2).to_le_bytes());\n    let prefix_start = cursor'),
    'reject-aliases':('image[counter_range].copy_from_slice', 'if prefix_start < counter_range.end && counter_range.start < prefix_end { return Err(AccessError::PrefixBounds); }\n    image[counter_range].copy_from_slice'),
    'reject-exact-prefix-end':('if prefix_end > image.len() {','if prefix_end >= image.len() {'),
    'require-next-in-image':('image[cursor_range].copy_from_slice', 'if next_cursor < base || next_cursor - base >= image.len() as u64 { return Err(AccessError::PrefixBounds); }\n    image[cursor_range].copy_from_slice'),
    'reject-image-ending-max':('base.checked_add(last).ok_or(AccessError::ImageRange)?;', 'base.checked_add(last.wrapping_add(1)).ok_or(AccessError::ImageRange)?;'),
    'truncate-state-offset':('let flag = field(state, FLAG, 1, image.len())?.start;', 'let state = state as u32 as usize;\n    let flag = field(state, FLAG, 1, image.len())?.start;'),
    'flag-rax-zero':('return Ok(ObservedRax::Unchanged);','return Ok(ObservedRax::Value(0));'),
    'counter-rax-unchanged':('return Ok(ObservedRax::Value(counter));','return Ok(ObservedRax::Unchanged);'),
    'advance-rax-old':('Ok(ObservedRax::Value(next_cursor))','Ok(ObservedRax::Value(cursor))'),
    'omit-cursor-store':('image[cursor_range].copy_from_slice(&next_cursor.to_le_bytes());','image[cursor_range].copy_from_slice(&cursor.to_le_bytes());'),
}


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_cursor_prefix_step','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_cursor_prefix_step.rlib'],
           [rustc,'+1.94.1','--crate-name','cursor_input_client','client.rs',*flags,'--extern','node94_cursor_prefix_step=libnode94_cursor_prefix_step.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_cursor_prefix_step.rlib','client')}


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
    bad=lines[0].split(b'\t');bad[1]=b'V:0000000000000000'
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:]))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'result/RAX observation plus lossless changed-byte list over every image byte; no masks',
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
