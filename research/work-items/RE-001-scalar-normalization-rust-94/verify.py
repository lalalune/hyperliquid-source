#!/usr/bin/env python3
"""Complete static binding and input-only Rust comparison with a frozen big-integer image relation."""
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

SOURCE=ROOT/'src/node94-scalar-normalization'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(row)==3 and re.fullmatch(r'E|V:[0-9a-f]{16}:[0-9a-f]{16}:[0-9a-f]{16}',row[1]) and re.fullmatch(r'-|[0-9a-f]+:[0-9a-f]{2}(?:,[0-9a-f]+:[0-9a-f]{2})*',row[2]) for row in parsed),'output format')
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
    for va,_,_ in decode_rows((HERE/'static/normalize-gnu.txt').read_text(),0x565eaa0,0x565ec0b):
        raw,off=read(data,secs,va,1)
        cases.append((f'instruction-{va:x}',off,bytes([raw[0]^1]),'normalize body',False))
    for va in CALLS:
        raw,off=read(data,secs,va,1);cases.append((f'caller-{va:x}',off,bytes([raw[0]^1]),'caller body',False))
    for name in WINDOWS:
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    for va in CIE_BYTES:
        raw,off=read(data,secs,va+8,1)
        cases.append((f'cie-{va:x}',off,bytes([raw[0]^1]),'CIE bytes' if va==eh['address'] else 'bound CIE bytes',False))
    _,off=read(data,secs,0x565ec0b,1);cases.append(('padding',off,b'\xcc','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('extra-naming',rela['offset']+16,struct.pack('<q',0x565eaa0),'naming relocation',False))
    cases.append(('code-relocation',rela['offset'],struct.pack('<Q',0x565eaa1),'protected code relocation',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x565eaa0-0x16488e0-5),'direct call census',False))
    cases.append(('extra-jump-pattern',off,b'\xe9'+struct.pack('<i',0x565eaa0-0x16488e0-5),'direct jump census',False))
    from static_evidence import eh_frame_records
    _,fdes=eh_frame_records(data,secs)
    unrelated=next(f for f in fdes if f['start']==0x16488e0)
    va=unrelated['fde']+8;_,off=read(data,secs,va,4)
    cases.append(('unselected-fde-overlap',off,struct.pack('<i',0x565eaa0-va),'normalize FDE overlap',False))
    from static_evidence import NEXT_FDE
    va,_,_,_=NEXT_FDE
    raw,off=read(data,secs,va+12,4)
    cases.append(('next-fde-range',off,struct.pack('<I',4),'next FDE bytes',False))
    _,off=read(data,secs,0x565e78b,1);cases.append(('caller-padding',off,b'\xcc','alignment padding',False))
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
    'read-big-endian':('u64::from_le_bytes(bytes)','u64::from_be_bytes(bytes)'),
    'write-big-endian':('word.to_le_bytes()','word.to_be_bytes()'),
    'ones-complement-only':('let mut carry = 1u128;','let mut carry = 0u128;'),
    'negate-nonnegative':('if negative {\n        let mut carry', 'if !negative {\n        let mut carry'),
    'multiply-drop-carry':('u128::from(word) * u128::from(scalar) + carry','u128::from(word) * u128::from(scalar) + (carry & 0)'),
    'multiply-low32-word':('u128::from(word) * u128::from(scalar) + carry','u128::from(word as u32) * u128::from(scalar) + carry'),
    'multiply-low32-scalar':('u128::from(word) * u128::from(scalar) + carry','u128::from(word) * u128::from(scalar as u32) + carry'),
    'multiply-carry-shift63':('carry = product >> 64;','carry = product >> 63;'),
    'reject-exact-image-end':('> (1u128 << 64)','>= (1u128 << 64)'),
    'require-extra-source-byte':('source, 64)?','source, 65)?'),
    'require-extra-destination-byte':('destination, 32)?','destination, 33)?'),
    'refusal-writes-first-byte':('    if u128::from(base)', '    if let Some(byte) = image.get_mut(0) { *byte ^= 1; }\n    if u128::from(base)'),
    'scalar-sign-bit31':('let negative = scalar >> 63 != 0;','let negative = scalar >> 31 != 0;'),
    'scalar-no-magnitude':('        scalar.wrapping_neg()','        scalar'),
    'scalar-saturating-minimum':('scalar.wrapping_neg()','(scalar as i64).saturating_abs() as u64'),
    'ordinary-multiply-zero':('    let adjusted = negate_if(words, negative);','    if negative && words == [0; 4] { return [0; 5]; }\n    let adjusted = negate_if(words, negative);'),
    'omit-top-correction':('carry.wrapping_sub(if negative { magnitude } else { 0 })','carry.wrapping_sub(if negative { 0 } else { 0 })'),
    'add-top-correction':('carry.wrapping_sub(if negative { magnitude } else { 0 })','carry.wrapping_add(if negative { magnitude } else { 0 })'),
    'omit-early-stores':('    write_words(image, destination, [x, y]);','    // Deliberately omit the initial scalar stores.'),
    'swap-early-scalars':('write_words(image, destination, [x, y]);','write_words(image, destination, [y, x]);'),
    'second-product-uses-x':('contribution([words[4], words[5], words[6], words[7]], y)','contribution([words[4], words[5], words[6], words[7]], x)'),
    'second-product-uses-first-half':('contribution([words[4], words[5], words[6], words[7]], y)','contribution([words[0], words[1], words[2], words[3]], y)'),
    'sum-drop-carry':('u128::from(a[i]) + u128::from(b[i]) + carry','u128::from(a[i]) + u128::from(b[i]) + (carry & 0)'),
    'omit-fifth-sum-word':('for i in 0..5 {','for i in 0..4 {'),
    'shift32':('(sum[i] >> 31) | (sum[i + 1] << 33)','(sum[i] >> 32) | (sum[i + 1] << 32)'),
    'shift30':('(sum[i] >> 31) | (sum[i + 1] << 33)','(sum[i] >> 30) | (sum[i + 1] << 34)'),
    'shift-drop-neighbor':('(sum[i] >> 31) | (sum[i + 1] << 33)','sum[i] >> 31'),
    'sign-from-bit286':('let negative = sum[4] >> 63 != 0;','let negative = (sum[4] >> 30) & 1 != 0;'),
    'ignore-wrapped-double-minimum':('let negative = sum[4] >> 63 != 0;','let negative = sum[4] >> 63 != 0 || (x == (1 << 63) && y == (1 << 63));'),
    'truncate-negative-division':('    let output = negate_if(shifted, negative);','    let mut output = negate_if(shifted, negative);\n    if negative && (sum[0] & ((1 << 31) - 1)) != 0 {\n        let mut borrow=1u64;\n        for word in &mut output { let (v,b)=word.overflowing_sub(borrow); *word=v; borrow=u64::from(b); }\n    }'),
    'rax-inverted':('rax: u64::from(negative),','rax: u64::from(!negative),'),
    'rdx-unadjusted':('rdx: if negative { x.wrapping_neg() } else { x },','rdx: x,'),
    'rcx-unadjusted':('rcx: if negative { y.wrapping_neg() } else { y },','rcx: y,'),
    'rcx-carries-from-x':('rcx: if negative { y.wrapping_neg() } else { y },','rcx: if negative { y.wrapping_neg().wrapping_add(u64::from(x == 0)) } else { y },'),
    'omit-final-stores':('    write_words(image, destination, output);','    let _ = output;'),
    'reject-overlap':('    write_words(image, destination, [x, y]);','    if source < destination + 32 && destination < source + 64 { return Err(Unavailable); }\n    write_words(image, destination, [x, y]);'),
}




def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_scalar_normalization','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_scalar_normalization.rlib'],
           [rustc,'+1.94.1','--crate-name','scalar_normalization_input_client','client.rs',*flags,'--extern','node94_scalar_normalization=libnode94_scalar_normalization.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        (directory.parent/'commands-partial.json').write_text(json.dumps(commands,indent=2)+'\n')
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_scalar_normalization.rlib','client')}


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
        (out/(label+'.tsv')).write_bytes(actual)
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
    bad=lines[0].split(b'\t');bad[1]=b'V:ffffffffffffffff:ffffffffffffffff:ffffffffffffffff'
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:]))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    bad=lines[0].split(b'\t');bad[2]=b'0:ff\n'
    try:require(not compare(b'\t'.join(bad)+b''.join(lines[1:]),expected),'image bytes')
    except ValueError as exc:comparator.append({'name':'byte-delta','rejection':str(exc)})
    else:raise ValueError('byte comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'refusal status, all image-byte changes and all 64 bits of RAX/RDX/RCX; no masks',
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
