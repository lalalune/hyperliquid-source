#!/usr/bin/env python3
"""Static closure and input-only Rust comparison with a frozen whole-integer oracle."""
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

SOURCE=ROOT/'src/node94-correction384-family'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(row)==3 and (row[1]=='E' or re.fullmatch(r'V(?::[0-9a-f]{16}){9}|V(?::[0-9a-f]{16}){13}',row[1])) and (row[2]=='-' or re.fullmatch(r'(?:[0-9a-f]{2})+',row[2])) for row in parsed),'output format')
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
    for name in ('core','single','pair'):
        start,end,_=WINDOWS[name]
        for va,_,_ in decode_rows((HERE/f'static/{name}-gnu.txt').read_text(),start,end):
            raw,off=read(data,secs,va,1)
            cases.append((f'instruction-{va:x}',off,bytes([raw[0]^1]),f'{name} body',False))
    from static_evidence import JUMPS
    representatives={}
    for va in {**CALLS,**JUMPS}:
        owner=next(name for name,(start,end,_) in WINDOWS.items() if start<=va<end)
        representatives.setdefault(owner,va)
    for owner,va in representatives.items():
        raw,off=read(data,secs,va,1);cases.append((f'caller-{va:x}',off,bytes([raw[0]^1]),f'{owner} body',False))
    for name in WINDOWS:
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    for va in CIE_BYTES:
        raw,off=read(data,secs,va+8,1)
        cases.append((f'cie-{va:x}',off,bytes([raw[0]^1]),'CIE bytes' if va==eh['address'] else 'bound CIE bytes',False))
    for va in (0x565697c,0x5656a13,0x5656a83):
        _,off=read(data,secs,va,1);cases.append((f'padding-{va:x}',off,b'\xcc','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('extra-naming',rela['offset']+16,struct.pack('<q',0x5656980),'naming relocation',False))
    cases.append(('code-relocation',rela['offset'],struct.pack('<Q',0x5656981),'protected code relocation',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x5656980-0x16488e0-5),'direct call census',False))
    cases.append(('extra-jump-pattern',off,b'\xe9'+struct.pack('<i',0x5656980-0x16488e0-5),'direct jump census',False))
    from static_evidence import eh_frame_records
    _,fdes=eh_frame_records(data,secs)
    unrelated=next(f for f in fdes if f['start']==0x16488e0)
    va=unrelated['fde']+8;_,off=read(data,secs,va,4)
    cases.append(('unselected-fde-overlap',off,struct.pack('<i',0x5656980-va),'core FDE overlap',False))
    from static_evidence import NEXT_FDE
    va,_,_,_=NEXT_FDE
    _,off=read(data,secs,va+12,4)
    cases.append(('next-fde-range',off,struct.pack('<I',4),'next FDE bytes',False))
    results=[]
    for label,off,replacement,message,authenticate in cases:
        copy=bytearray(data);copy[off:off+len(replacement)]=replacement
        try:inspect(copy,authenticate=authenticate)
        except ValueError as exc:
            require(str(exc)==message,f'unexpected rejection {label}: {exc}')
            results.append({'name':label,'rejection':str(exc)})
        else:raise ValueError(f'static control survived: {label}')
    return results


MUTANTS={'entry-carry-not-erased': ('let mut carry = 0u128;', 'let mut carry = 1u128;'), 'drop-add-carry': ('carry = total >> 64;', 'carry = (total >> 64) & 0;'), 'add-limb-low32': ('a[i] as u128 + b[i] as u128 + carry', 'a[i] as u32 as u128 + b[i] as u32 as u128 + carry'), 'borrow-and': ('borrow = first || second;', 'borrow = first && second;'), 'drop-incoming-borrow': ('v.overflowing_sub(borrow as u64)', 'v.overflowing_sub((borrow as u64) & 0)'), 'select-ignore-carry': ('if carry != 0 || !borrow { reduced } else { sum }', 'if !borrow { reduced } else { sum }'), 'select-and': ('if carry != 0 || !borrow { reduced } else { sum }', 'if carry != 0 && !borrow { reduced } else { sum }'), 'select-inverted-borrow': ('if carry != 0 || !borrow { reduced } else { sum }', 'if carry != 0 || borrow { reduced } else { sum }'), 'equality-borrows': ('borrow = first || second;', 'borrow = first || second || sum[i] == correction[i];'), 'rdx-carry-only': ('carry as u64 + borrow as u64', 'carry as u64'), 'rdx-borrow-only': ('carry as u64 + borrow as u64', 'borrow as u64'), 'rdx-positive-count': ('0u64.wrapping_sub(carry as u64 + borrow as u64)', 'carry as u64 + borrow as u64'), 'rax-output': ('rax: sum[2],', 'rax: words[2],'), 'rsi-output': ('rsi: sum[5],', 'rsi: words[5],'), 'rbx-output': ('rbx: sum[3],', 'rbx: words[3],'), 'rbp-output': ('rbp: sum[4],', 'rbp: words[4],'), 'r14-output': ('r14: sum[0],', 'r14: words[0],'), 'r15-output': ('r15: sum[1],', 'r15: words[1],'), 'swap-output-limbs': ('Core {\n        words,', 'Core {\n        words: [words[1], words[0], words[2], words[3], words[4], words[5]],'), 'wrapper-rcx-destination': ('rcx: correction,', 'rcx: destination ^ (correction & 0),'), 'wrapper-rdi-correction': ('rdi: destination,', 'rdi: correction ^ (destination & 0),'), 'wrapper-r8-next': ('r8: core.words[0],', 'r8: core.words[1],'), 'wrapper-r9-next': ('r9: core.words[1],', 'r9: core.words[2],'), 'wrapper-r10-next': ('r10: core.words[2],', 'r10: core.words[3],'), 'wrapper-r11-next': ('r11: core.words[3],', 'r11: core.words[4],'), 'big-endian-load': ('u64::from_le_bytes(bytes)', 'u64::from_be_bytes(bytes)'), 'big-endian-store': ('words[i].to_le_bytes()', 'words[i].to_be_bytes()'), 'ignore-register-input': ('Input::Registers(words) => words,', 'Input::Registers(words) => { let _ = words; load(image, offset(image, base, base, 48)?) },'), 'core-early-store': ('let c = load(image, fix);', 'image[dest..dest + 48].fill(0);\n    let c = load(image, fix);'), 'pair-reverse-order': ('stage(image, dest + 48, lhs + 48, rhs + 48, fix);\n    let result = stage(image, dest, lhs, rhs, fix);', 'stage(image, dest, lhs, rhs, fix);\n    let result = stage(image, dest + 48, lhs + 48, rhs + 48, fix);'), 'pair-correction-snapshot': ('stage(image, dest + 48, lhs + 48, rhs + 48, fix);\n    let result = stage(image, dest, lhs, rhs, fix);', 'let cached = load(image, fix);\n    stage(image, dest + 48, lhs + 48, rhs + 48, fix);\n    let result = combine(load(image, lhs), load(image, rhs), cached);\n    store(image, dest, result.words);'), 'pair-all-snapshots': ('stage(image, dest + 48, lhs + 48, rhs + 48, fix);\n    let result = stage(image, dest, lhs, rhs, fix);', 'let cached = combine(load(image, lhs), load(image, rhs), load(image, fix));\n    stage(image, dest + 48, lhs + 48, rhs + 48, fix);\n    let result = cached;\n    store(image, dest, result.words);'), 'pair-last-registers-first': ('stage(image, dest + 48, lhs + 48, rhs + 48, fix);\n    let result = stage(image, dest, lhs, rhs, fix);', 'let result = stage(image, dest + 48, lhs + 48, rhs + 48, fix);\n    stage(image, dest, lhs, rhs, fix);'), 'pair-correction-offset': ('stage(image, dest + 48, lhs + 48, rhs + 48, fix);', 'stage(image, dest + 48, lhs + 48, rhs + 48, lhs);'), 'exact-end-refusal': ('if start.checked_add(width)? > image.len() {', 'if start.checked_add(width)? >= image.len() {'), 'image-end-max-refusal': ('<= (1u128 << 64)', '<= ((1u128 << 64) - 1)'), 'pair-refusal-mutates': ('let dest = offset(image, base, destination, 96)?;', 'let Some(dest) = offset(image, base, destination, 96) else { if !image.is_empty() { image[0] ^= 1; } return None; };')}


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_correction384_family','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_correction384_family.rlib'],
           [rustc,'+1.94.1','--crate-name','correction384_family_input_client','client.rs',*flags,'--extern','node94_correction384_family=libnode94_correction384_family.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        (directory.parent/'commands-partial.json').write_text(json.dumps(commands,indent=2)+'\n')
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_correction384_family.rlib','client')}


def run(out,rustc):
    require(not out.exists(),'use fresh output directory');out.mkdir(parents=True)
    freeze=check();cases=freeze['cases'];collect(out/'static')
    for file in (HERE/'static').iterdir():
        require((out/'static'/file.name).read_bytes()==file.read_bytes(),f'static drift: {file.name}')
    controls=static_controls(TARGET.read_bytes())
    inputs=gzip.decompress((HERE/'fixtures/inputs.tsv.gz').read_bytes());expected=gzip.decompress((HERE/'fixtures/expected.tsv.gz').read_bytes())
    source=(SOURCE/'lib.rs').read_text();commands=[];streams=[];runs=[];mutants=[];hashes={}
    def execute(directory,label):
        actual=subprocess.check_output([str(directory/'client')],input=inputs,cwd=directory)
        (out/(label+'.tsv.gz')).write_bytes(gzip.compress(actual,mtime=0))
        streams.append({'name':label+'.tsv','bytes':len(actual),'sha256':sha(actual),'text':actual.decode('ascii')})
        return actual
    for opt in (0,3):
        artifacts=[]
        for rep in (1,2):
            label=f'opt{opt}-build{rep}';directory=out/label
            artifacts.append(build(source,directory,opt,rustc,commands))
            actual=execute(directory,label);require(not compare(actual,expected),'native mismatch')
            runs.append({'opt':opt,'build':rep,'cases':cases,'mismatches':0,'output_sha256':sha(actual)})
        require(artifacts[0]==artifacts[1],'build not reproducible');hashes[f'opt{opt}']=artifacts[0]
    for name,(old,new) in MUTANTS.items():
        require(source.count(old)==1,f'mutant anchor {name}')
        directory=out/('mutant-'+name);build(source.replace(old,new),directory,3,rustc,commands)
        actual=execute(directory,'mutant-'+name);differences=compare(actual,expected)
        require(differences,f'mutant survived: {name}')
        mutants.append({'name':name,'cases':cases,'mismatches':len(differences),'first_witness':differences[0],'output_sha256':sha(actual)})
    comparator=[];lines=expected.splitlines(keepends=True)
    bad=lines[0].split(b'\t');bad[1]=b'V:'+b':'.join([b'ffffffffffffffff']*13)
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:])),('image',expected.replace(b'\t-\n',b'\t00\n',1))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'13 core or 9 wrapper full-width register values; every image byte; refusal status; no comparison masks',
            'compiler':subprocess.check_output([rustc,'+1.94.1','-vV'],text=True),'platform':platform.platform(),'python':platform.python_version(),
            'build_hashes':hashes,'runs':runs,'mutants':mutants,'static_controls':controls,'comparator_controls':comparator,
            'source_sha256':{name:sha((SOURCE/name).read_bytes()) for name in ('lib.rs','client.rs','Cargo.toml','Cargo.lock','rust-toolchain.toml')},
            'captured_execution':False,'instruction_emulation':False,'native_target_differential':False}
    packed=pack_streams(streams)
    (out/'raw-streams.json.gz').write_bytes(packed);archive_check(out/'raw-streams.json.gz',result)
    archive_controls=[]
    archive=json.loads(gzip.decompress(packed))
    for name in ('bad-line-index','wrong-stream-hash'):
        changed=json.loads(json.dumps(archive))
        if name=='bad-line-index':changed['streams'][0]['line_ids'][0]=len(changed['lines'])
        else:changed['streams'][0]['sha256']='0'*64
        path=out/(name+'.json.gz');path.write_bytes(gzip.compress(json.dumps(changed).encode(),mtime=0))
        try:archive_check(path,result)
        except ValueError as exc:archive_controls.append({'name':name,'rejection':str(exc)})
        else:raise ValueError('archive control survived')
    result['archive_controls']=archive_controls
    (out/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    print(f"PASS {cases} pre-Rust frozen cases x 4 native runs; {len(mutants)} observable compiled mutants; {len(controls)} static and {len(comparator)} comparator controls; repeated artifact hashes identical; {len(streams)} exact archived streams")


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path);p.add_argument('--check-archive',action='store_true');p.add_argument('--rustc',default=os.environ.get('RUSTC','/opt/homebrew/opt/rustup/bin/rustc'))
    args=p.parse_args()
    if args.check_archive:
        print('PASS archive streams:',archive_check(HERE/'native/raw-streams.json.gz',json.loads((HERE/'native/result.json').read_text())))
    elif args.out: run(args.out.resolve(),args.rustc)
    else: p.error('provide --out or --check-archive')
