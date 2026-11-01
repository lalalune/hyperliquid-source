#!/usr/bin/env python3
"""Static evidence and input-only own-Rust comparison with the frozen piecewise byte-selection relation."""
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
from supplement import verify as check_supplement
from static_evidence import HERE,ROOT,TARGET,WINDOWS,read,sections,inspect,collect,require

SOURCE=ROOT/'src/node94-bounded-byte-selector'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(row)==2 and re.fullmatch(r'E|V:[0-9a-f]{16}',row[1]) for row in parsed),'output format')
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
    for name in ('select','matches'):
        start,end,_=WINDOWS[name]
        for va,_,_ in decode_rows((HERE/f'static/{name}-gnu.txt').read_text(),start,end):
            raw,off=read(data,secs,va,1)
            cases.append((f'instruction-{va:x}',off,bytes([raw[0]^1]),f'{name} body',False))
    for site in CALLS:
        name=next(n for n,(start,end,_) in WINDOWS.items() if start<=site<end)
        raw,off=read(data,secs,site,1)
        cases.append((f'call-{site:x}',off,bytes([raw[0]^1]),f'{name} body',False))
    for name in WINDOWS:
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    for va in CIE_BYTES:
        raw,off=read(data,secs,va+8,1)
        cases.append((f'cie-{va:x}',off,bytes([raw[0]^1]),'CIE bytes' if va==eh['address'] else 'bound CIE bytes',False))
    for name in ('select','matches'):
        start,end,_=WINDOWS[name]
        _,off=read(data,secs,end,1);cases.append((f'{name}-padding',off,b'\x90','alignment padding',False))
        rela=next(s for s in secs if s['name']=='.rela.dyn')
        cases.append((f'{name}-extra-naming',rela['offset']+16,struct.pack('<q',start),'naming relocation',False))
        cases.append((f'{name}-code-relocation',rela['offset'],struct.pack('<Q',start+1),'protected code relocation',False))
        _,off=read(data,secs,0x16488e0,5)
        cases.append((f'{name}-extra-call-pattern',off,b'\xe8'+struct.pack('<i',start-0x16488e0-5),'direct call census',False))
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
    'ignore-disabled':('if enabled == 0 {','if { let _=enabled; false } {'),
    'flag-exact-one':('if enabled == 0 {','if enabled != 1 {'),
    'disabled-one':('return Ok(0);','return Ok(1);'),
    'eager-image-check':('    if enabled == 0 {','    image_fits(image, base)?;\n    if enabled == 0 {'),
    'wrong-sentinel':('if cached != 255 {','if cached != 254 {'),
    'always-read-inner':('    if cached != 255 {','    let _=word32(image, span(image,base,inner,20,4)?);\n    if cached != 255 {'),
    'no-field-decrement':('field.wrapping_sub(1)','field.wrapping_sub(0)'),
    'saturating-field-decrement':('field.wrapping_sub(1)','field.saturating_sub(1)'),
    'unsigned-cache-compare':('(field.wrapping_sub(1) as i32) <= index as i32','field.wrapping_sub(1) <= index'),
    'strict-cache-compare':('as i32) <= index as i32','as i32) < index as i32'),
    'big-endian-field':('u32::from_le_bytes','u32::from_be_bytes'),
    'big-endian-pointers':('u64::from_le_bytes','u64::from_be_bytes'),
    'low32-empty':('if high == low {','if high as u32 == low as u32 {'),
    'wrong-default':('context, 339, 1','context, 340, 1'),
    'eager-default':('    if high == low {','    let _=image[span(image,base,context,339,1)?];\n    if high == low {'),
    'zero-index-before-empty':('    if high == low {','    if index == 0 { return Ok(image[span(image,base,low,0,1)?]); }\n    if high == low {'),
    'drop-zero-index-shortcut':('let address = if index == 0 {','let address = if false {'),
    'ignore-bound':('index.wrapping_sub(bound)','index.wrapping_sub({let _=bound; 0})'),
    'omit-relative-plus-one':('wrapping_sub(bound).wrapping_add(1)','wrapping_sub(bound).wrapping_add(0)'),
    'omit-span-minus-one':('(high.wrapping_sub(low) as u32).wrapping_sub(1)','(high.wrapping_sub(low) as u32).wrapping_sub(0)'),
    'unsigned-span-cap':('relative.min(last).max(0) as u64','(relative as u32).min(last as u32) as u64'),
    'maximum-cap':('relative.min(last)','relative.max(last)'),
    'no-zero-floor':('relative.min(last).max(0)','relative.min(last)'),
    'require-low-mapped':('    let address =','    let _=span(image,base,low,0,1)?;\n    let address ='),
    'wrong-high-field':('context, 464, 8','context, 456, 8'),
    'checked-selected-add':('low.wrapping_add(step)','low.checked_add(step).ok_or(Unavailable)?'),
    'wrapper-negated':('Ok(selected == stored)','Ok(selected != stored)'),
    'wrapper-disabled':('context, index, bound, 1)?','context, index, bound, 0)?'),
    'wrapper-wrong-bound-field':('inner, 2800, 4','inner, 2796, 4'),
    'wrapper-wrong-context':('object.checked_add(904)','object.checked_add(900)'),
    'wrapper-wrong-comparison':('object, 4116, 1','object, 4115, 1'),
    'wrapper-lazy-bound':('let bound = word32(image, span(image, base, inner, 2800, 4)?);','let bound = span(image,base,inner,2800,4).map(|at|word32(image,at)).unwrap_or(0);'),
    'reject-exact-end':('ok_or(Unavailable)? > image.len()','ok_or(Unavailable)? >= image.len()'),
}



def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_bounded_byte_selector','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_bounded_byte_selector.rlib'],
           [rustc,'+1.94.1','--crate-name','selector_input_client','client.rs',*flags,'--extern','node94_bounded_byte_selector=libnode94_bounded_byte_selector.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        (directory.parent/'commands-partial.json').write_text(json.dumps(commands,indent=2)+'\n')
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_bounded_byte_selector.rlib','client')}


def run(out,rustc):
    require(not out.exists(),'use fresh output directory');out.mkdir(parents=True)
    freeze=check();collect(out/'static')
    for file in (HERE/'static').iterdir():
        require((out/'static'/file.name).read_bytes()==file.read_bytes(),f'static drift: {file.name}')
    controls=static_controls(TARGET.read_bytes())
    inputs=gzip.decompress((HERE/'fixtures/inputs.tsv.gz').read_bytes());expected=gzip.decompress((HERE/'fixtures/expected.tsv.gz').read_bytes())
    supplement=check_supplement()
    inputs+=gzip.decompress((HERE/'fixtures/supplement-inputs.tsv.gz').read_bytes());expected+=gzip.decompress((HERE/'fixtures/supplement-expected.tsv.gz').read_bytes())
    count=freeze['cases']+supplement['cases']
    source=(SOURCE/'lib.rs').read_text();commands=[];streams=[];runs=[];mutants=[];hashes={}
    def execute(directory,label):
        actual=subprocess.check_output([str(directory/'client')],input=inputs,cwd=directory)
        (out/(label+'.tsv')).write_bytes(actual)
        streams.append({'name':label+'.tsv','bytes':len(actual),'sha256':sha(actual),'text':actual.decode('ascii')})
        return actual
    for opt in (0,3):
        artifacts=[]
        for rep in (1,2):
            label=f'opt{opt}-build{rep}';directory=out/label
            artifacts.append(build(source,directory,opt,rustc,commands))
            actual=execute(directory,label);require(not compare(actual,expected),'native mismatch')
            runs.append({'opt':opt,'build':rep,'cases':count,'mismatches':0,'output_sha256':sha(actual)})
        require(artifacts[0]==artifacts[1],'build not reproducible');hashes[f'opt{opt}']=artifacts[0]
    for name,(old,new) in MUTANTS.items():
        require(source.count(old)==1,f'mutant anchor {name}')
        directory=out/('mutant-'+name);build(source.replace(old,new),directory,3,rustc,commands)
        actual=execute(directory,'mutant-'+name);differences=compare(actual,expected)
        require(differences,f'mutant survived: {name}')
        mutants.append({'name':name,'cases':count,'mismatches':len(differences),'first_witness':differences[0],'output_sha256':sha(actual)})
    comparator=[];lines=expected.splitlines(keepends=True)
    bad=lines[0].split(b'\t');bad[1]=b'V:ffffffffffffffff\n'
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:]))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'post_rust_supplement':supplement,'total_cases':count,'compared_fields':'status and exact complete raw RAX value; immutable data image; no masks',
            'compiler':subprocess.check_output([rustc,'+1.94.1','-vV'],text=True),'platform':platform.platform(),'python':platform.python_version(),
            'build_hashes':hashes,'runs':runs,'mutants':mutants,'static_controls':controls,'comparator_controls':comparator,
            'source_sha256':{name:sha((SOURCE/name).read_bytes()) for name in ('lib.rs','client.rs','Cargo.toml','Cargo.lock','rust-toolchain.toml')},
            'captured_execution':False,'instruction_emulation':False,'native_target_differential':False}
    packed=pack_streams(streams)
    (out/'raw-streams.json.gz').write_bytes(packed);archive_check(out/'raw-streams.json.gz',result)
    (out/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    print(f"PASS {count} cases ({freeze['cases']} pre-Rust + {supplement['cases']} post-Rust) x 4 native runs; {len(mutants)} observable compiled mutants; {len(controls)} static and {len(comparator)} comparator controls; repeated artifact hashes identical; {len(streams)} exact archived streams")


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path);p.add_argument('--check-archive',action='store_true');p.add_argument('--rustc',default=os.environ.get('RUSTC','/opt/homebrew/opt/rustup/bin/rustc'))
    args=p.parse_args()
    if args.check_archive:
        print('PASS archive streams:',archive_check(HERE/'native/raw-streams.json.gz',json.loads((HERE/'native/result.json').read_text())))
    elif args.out: run(args.out.resolve(),args.rustc)
    else: p.error('provide --out or --check-archive')
