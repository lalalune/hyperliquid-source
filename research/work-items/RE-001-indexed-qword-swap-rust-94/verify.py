#!/usr/bin/env python3
"""Static evidence and input-only own-Rust comparison with the frozen indexed-address and byte-priority relation."""
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

SOURCE=ROOT/'src/node94-indexed-qword-swap'


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
    for va,_,_ in decode_rows((HERE/'static/swap-gnu.txt').read_text(),0x4fa90a0,0x4fa9109):
        raw,off=read(data,secs,va,1)
        cases.append((f'instruction-{va:x}',off,bytes([raw[0]^1]),'swap body',False))
    for va in [*CALLS,0x4fabc6b,0x4fabc6e,0x4fabc71,0x4fabc74,0x4fac153,0x4fac158,0x4fac15b,0x4fac15e,0x4fac18b,0x4fac190,0x4fac193,0x4fac196,0x4fac1cc,0x4fac1d1,0x4fac1d4,0x4fac1d7]:
        raw,off=read(data,secs,va,1);cases.append((f'caller-{va:x}',off,bytes([raw[0]^1]),'caller body',False))
    for name in WINDOWS:
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    for va in CIE_BYTES:
        raw,off=read(data,secs,va+8,1)
        cases.append((f'cie-{va:x}',off,bytes([raw[0]^1]),'CIE bytes' if va==eh['address'] else 'bound CIE bytes',False))
    _,off=read(data,secs,0x4fa9109,1);cases.append(('padding',off,b'\x90','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('extra-naming',rela['offset']+16,struct.pack('<q',0x4fa90a0),'naming relocation',False))
    cases.append(('code-relocation',rela['offset'],struct.pack('<Q',0x4fa90a1),'protected code relocation',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x4fa90a0-0x16488e0-5),'direct call census',False))
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
    'signed-threshold':('index <= 31','(index as i64) <= 31'),
    'exclude-index31':('index <= 31','index < 31'),
    'include-index32-low':('index <= 31','index <= 32'),
    'truncate-index':('    let (field, entry) =','    let index = u64::from(index as u32);\n    let (field, entry) ='),
    'wrong-low-field':('(264, index)','(256, index)'),
    'wrong-high-field':('(272, index.wrapping_sub(32))','(264, index.wrapping_sub(32))'),
    'wrong-high-origin':('index.wrapping_sub(32)','index.wrapping_sub(31)'),
    'wrong-scale':('entry.wrapping_mul(8)','entry.wrapping_mul(4)'),
    'checked-index-scale':('entry.wrapping_mul(8)','entry.checked_mul(8).ok_or(Unavailable)?'),
    'checked-base-add':('Ok(table_base.wrapping_add(displacement))','table_base.checked_add(displacement).ok_or(Unavailable)'),
    'big-endian-base':('u64::from_le_bytes','u64::from_be_bytes'),
    'require-table-base':('    let displacement =','    let _ = span(image.len(), base, table_base, 0, 8)?;\n    let displacement ='),
    'require-table-owner':('    let offset =','    let _ = span(image.len(), base, table, 0, 1)?;\n    let offset ='),
    'require-both-fields':('    let offset =','    let _ = span(image.len(), base, table, 264, 16)?;\n    let offset ='),
    'first-uses-second-index':('first_table, first_index)?','first_table, { let _ = first_index; second_index })?'),
    'second-uses-first-table':('second_table, second_index)?','{ let _ = second_table; first_table }, second_index)?'),
    'reverse-store-order':('    image[second..second + 8].copy_from_slice(&first_value);\n    image[first..first + 8].copy_from_slice(&second_value);','    image[first..first + 8].copy_from_slice(&second_value);\n    image[second..second + 8].copy_from_slice(&first_value);'),
    'late-second-load':('    image[second..second + 8].copy_from_slice(&first_value);','    image[second..second + 8].copy_from_slice(&first_value);\n    let _ = second_value;\n    let second_value: [u8;8] = image[second..second+8].try_into().unwrap();'),
    'bytewise-interleave':('    image[second..second + 8].copy_from_slice(&first_value);\n    image[first..first + 8].copy_from_slice(&second_value);','    let _ = (first_value,second_value);\n    for i in 0..8 { let a=image[first+i];let b=image[second+i];image[second+i]=a;image[first+i]=b; }'),
    'drop-second-range-write':('image[second..second + 8].copy_from_slice(&first_value);','image[second..second].copy_from_slice(&first_value[..0]);'),
    'drop-first-range-write':('image[first..first + 8].copy_from_slice(&second_value);','image[first..first].copy_from_slice(&second_value[..0]);'),
    'reverse-data-bytes':('image[second..second + 8].copy_from_slice(&first_value);','let mut first_value=first_value;first_value.reverse();\n    image[second..second + 8].copy_from_slice(&first_value);'),
    'return-second-address':('Ok(first_address)','Ok(second_address)'),
    'return-first-data':('Ok(first_address)','Ok(u64::from_le_bytes(first_value))'),
    'reject-exact-end':('ok_or(Unavailable)? > len','ok_or(Unavailable)? >= len'),
}


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_indexed_qword_swap','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_indexed_qword_swap.rlib'],
           [rustc,'+1.94.1','--crate-name','swap_input_client','client.rs',*flags,'--extern','node94_indexed_qword_swap=libnode94_indexed_qword_swap.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_indexed_qword_swap.rlib','client')}


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
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'status, raw RAX address value, and lossless differences over every image byte; no masks',
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
