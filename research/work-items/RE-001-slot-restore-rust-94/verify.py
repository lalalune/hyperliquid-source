#!/usr/bin/env python3
"""Static evidence and input-only own-Rust comparison with the frozen immutable-image slot relation."""
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

SOURCE=ROOT/'src/node94-slot-restore'


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
    from static_evidence import decode_rows,NAMING
    for va,_,_ in decode_rows((HERE/'static/restore-gnu.txt').read_text(),0x3290130,0x3290192):
        raw,off=read(data,secs,va,1)
        cases.append((f'instruction-{va:x}',off,bytes([raw[0]^1]),'restore body',False))
    off=eh['offset']+int(records['windows']['restore']['fde_section_offset'],16)+12
    size=struct.unpack_from('<I',data,off)[0]
    cases.append(('fde-range',off,struct.pack('<I',size+1),'restore FDE overlap',False))
    cases.append(('cie',eh['offset']+8,b'X','CIE bytes',False))
    _,off=read(data,secs,0x3290192,1);cases.append(('padding',off,b'\x90','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('extra-naming',rela['offset']+16,struct.pack('<q',0x3290130),'naming relocation',False))
    for slot,_,_ in NAMING:
        matches=[off for off in range(rela['offset'],rela['offset']+rela['size'],24) if struct.unpack_from('<Q',data,off)[0]==slot]
        require(len(matches)==1,'slot relocation uniqueness')
        cases.append((f'relocation-{slot:x}',matches[0]+16,struct.pack('<q',0x3290131),'naming relocation',False))
        _,off=read(data,secs,slot,8);cases.append((f'slot-{slot:x}',off,b'\x01','relocation slot bytes',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x3290130-0x16488e0-5),'direct call census',False))
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
    'invert-selector':('if selector == 0 { 16 } else { 0 }','if selector != 0 { 16 } else { 0 }'),
    'selector-low-byte':('if selector == 0 { 16 } else { 0 }','if selector as u8 == 0 { 16 } else { 0 }'),
    'wrong-slot-stride':('if selector == 0 { 16 } else { 0 }','if selector == 0 { 8 } else { 0 }'),
    'wrong-kind-field':('displacement + 64, 1','displacement + 63, 1'),
    'signed-kind':('kind <= 4','(kind as i8) <= 4'),
    'full-band-includes-five':('kind <= 4','kind <= 5'),
    'half-band-includes-22':('(16..=21).contains(&kind)','(16..=22).contains(&kind)'),
    'half-band-includes-15':('(16..=21).contains(&kind)','(15..=21).contains(&kind)'),
    'half-band-all-high':('(16..=21).contains(&kind)','kind >= 16'),
    'old-scout-all-nonfull-half':('(16..=21).contains(&kind)','kind > 4'),
    'no-slot-clear':('image[slot..slot + 16].fill(0);','image[slot..slot].fill(0);'),
    'clear-only-eight':('image[slot..slot + 16].fill(0);','image[slot..slot + 8].fill(0);'),
    'drop-link-store':('image[link..link + 8].copy_from_slice(&new_link);','image[link..link].copy_from_slice(&new_link[..0]);'),
    'reverse-link':('image[link..link + 8].copy_from_slice(&new_link);','let mut new_link = new_link; new_link.reverse();\n    image[link..link + 8].copy_from_slice(&new_link);'),
    'wrong-owner-field':('owner, 216, 8','owner, 208, 8'),
    'wrong-hop-field':('hop, 568, 8','hop, 560, 8'),
    'half-restores-upper':('copy_from_slice(&old[..8]);','copy_from_slice(&old[8..]);'),
    'late-hop-snapshot':('image[tag] = 5;','let late: [u8;8] = image[hop_field..hop_field+8].try_into().unwrap();\n    image[link..link+8].copy_from_slice(&late);\n    image[tag] = 5;'),
    'late-slot-snapshot':('image[slot..slot + 16].fill(0);','image[slot..slot + 16].fill(0);\n    let old: [u8;16] = image[slot..slot+16].try_into().unwrap();\n    let _ = old;'),
    'tag-before-stores':('image[link..link + 8].copy_from_slice(&new_link);','image[tag] = 5;\n    image[link..link + 8].copy_from_slice(&new_link);'),
    'tag-four':('image[tag] = 5;','image[tag] = 4;'),
    'return-state':('Ok(output)','Ok(state)'),
    'require-whole-state':('let owner_field =','let _ = span(image.len(), base, state, 0, 81)?;\n    let owner_field ='),
    'require-hop-base':('let hop_field =','let _ = span(image.len(), base, hop, 0, 1)?;\n    let hop_field ='),
    'require-owner-base':('let owner_field =','let _ = span(image.len(), base, owner, 0, 1)?;\n    let owner_field ='),
    'reject-exact-end':('if end > len {','if end >= len {'),
}


def mutated(source,name,old,new):
    result=source.replace(old,new)
    if name=='tag-before-stores':
        where=result.rfind('    image[tag] = 5;')
        result=result[:where]+result[where:].replace('    image[tag] = 5;','',1)
    if name=='late-slot-snapshot':
        result=result.replace('let old: [u8; 16] = image[slot..slot + 16].try_into().unwrap();','let _entry_snapshot: [u8; 16] = image[slot..slot + 16].try_into().unwrap();')
    return result


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_slot_restore','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_slot_restore.rlib'],
           [rustc,'+1.94.1','--crate-name','restore_input_client','client.rs',*flags,'--extern','node94_slot_restore=libnode94_slot_restore.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_slot_restore.rlib','client')}


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
        directory=out/('mutant-'+name);build(mutated(source,name,old,new),directory,3,rustc,commands)
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
