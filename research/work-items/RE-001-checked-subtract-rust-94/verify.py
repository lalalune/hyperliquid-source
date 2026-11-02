#!/usr/bin/env python3
"""Static evidence and input-only own-Rust comparison with the frozen whole-prefix integer and byte-priority relation."""
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

SOURCE=ROOT/'src/node94-checked-subtract'


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
    for va,_,_ in decode_rows((HERE/'static/subtract-gnu.txt').read_text(),0x2760a10,0x2760a67):
        raw,off=read(data,secs,va,1)
        cases.append((f'instruction-{va:x}',off,bytes([raw[0]^1]),'subtract body',False))
    for va in CALLS:
        raw,off=read(data,secs,va,1);cases.append((f'caller-{va:x}',off,bytes([raw[0]^1]),'caller body',False))
    for name in WINDOWS:
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    for va in CIE_BYTES:
        raw,off=read(data,secs,va+8,1)
        cases.append((f'cie-{va:x}',off,bytes([raw[0]^1]),'CIE bytes' if va==eh['address'] else 'bound CIE bytes',False))
    _,off=read(data,secs,0x2760a67,1);cases.append(('padding',off,b'\x90','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('extra-naming',rela['offset']+16,struct.pack('<q',0x2760a10),'naming relocation',False))
    cases.append(('code-relocation',rela['offset'],struct.pack('<Q',0x2760a11),'protected code relocation',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x2760a10-0x16488e0-5),'direct call census',False))
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
    'lose-incoming-borrow':('difference.overflowing_sub(u64::from(borrow))','difference.overflowing_sub(u64::from(borrow && false))'),
    'lose-extra-borrow':('borrow = first_borrow || extra_borrow;','let _=extra_borrow; borrow = first_borrow;'),
    'lose-first-borrow':('borrow = first_borrow || extra_borrow;','let _=first_borrow; borrow = extra_borrow;'),
    'intersect-borrows':('first_borrow || extra_borrow','first_borrow && extra_borrow'),
    'add-instead-subtract':('x.overflowing_sub(y)','x.overflowing_add(y)'),
    'reverse-subtraction':('x.overflowing_sub(y)','y.overflowing_sub(x)'),
    'signed-first-borrow':('x.overflowing_sub(y)','(x.wrapping_sub(y), (x as i64) < (y as i64))'),
    'low32-first-borrow':('x.overflowing_sub(y)','(x.wrapping_sub(y), (x as u32) < (y as u32))'),
    'skip-top-limb':('for limb in 0..4 {','for limb in 0..3 {'),
    'reverse-limb-order':('for limb in 0..4 {','for limb in (0..4).rev() {'),
    'big-endian-right':('u64::from_le_bytes(right_bytes)','u64::from_be_bytes(right_bytes)'),
    'big-endian-left':('u64::from_le_bytes(planned[8 * limb..8 * limb + 8].try_into().unwrap())','u64::from_be_bytes(planned[8 * limb..8 * limb + 8].try_into().unwrap())'),
    'big-endian-result':('difference.to_le_bytes()','difference.to_be_bytes()'),
    'snapshot-all-right-words':('if position >= a && position < a + 32 {','if false && position >= a && position < a + 32 {'),
    'miss-first-limb-overlay':('position >= a && position < a + 32','position >= a + 8 && position < a + 32'),
    'refuse-operand-aliases':('    let o = span','    if a < b+32 && b < a+32 { return Err(Unavailable); }\n    let o = span'),
    'same-pointer-noop':('    let o = span','    if a == b { return Ok(1); }\n    let o = span'),
    'preserve-left-on-failure':('image[a..a + 32].copy_from_slice(&planned);','if success { image[a..a + 32].copy_from_slice(&planned); }'),
    'omit-top-rewrite':('image[a..a + 32].copy_from_slice(&planned);','image[a..a + 24].copy_from_slice(&planned[..24]);'),
    'always-success':('let success = !borrow;','let success = !borrow || true;'),
    'invert-flag':('let flag = u64::from(success);','let flag = u64::from(!success);'),
    'flag-byte-only':('image[o..o + 8].copy_from_slice(&flag.to_le_bytes());','image[o]=flag as u8;'),
    'omit-high-copy':('image[o + 24..o + 40].copy_from_slice(&planned[16..32]);','image[o + 24..o + 24].copy_from_slice(&planned[16..16]);'),
    'high-copy-uses-low':('&planned[16..32]','&planned[..16]'),
    'late-low-snapshot':('image[o + 8..o + 24].copy_from_slice(&planned[..16]);','let late: [u8;16]=image[a..a+16].try_into().unwrap();\n        image[o + 8..o + 24].copy_from_slice(&late);'),
    'require-payload-on-failure':('    if success {\n        span(image, base, output, 40)?;\n    }','    span(image, base, output, 40)?;'),
    'return-output-address':('Ok(flag)','Ok(output)'),
    'reject-exact-end':('ok_or(Unavailable)? > image.len()','ok_or(Unavailable)? >= image.len()'),
    'write-before-payload-admission':('    if success {\n        span(image, base, output, 40)?;','    image[a..a+32].copy_from_slice(&planned);\n    if success {\n        span(image, base, output, 40)?;'),
}



def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_checked_subtract','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_checked_subtract.rlib'],
           [rustc,'+1.94.1','--crate-name','checked_subtract_input_client','client.rs',*flags,'--extern','node94_checked_subtract=libnode94_checked_subtract.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        (directory.parent/'commands-partial.json').write_text(json.dumps(commands,indent=2)+'\n')
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_checked_subtract.rlib','client')}


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
        (out/(label+'.tsv')).write_bytes(actual)
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
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'status, full raw RAX flag, and lossless differences over every image byte; no masks',
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
