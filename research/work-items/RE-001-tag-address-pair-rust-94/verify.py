#!/usr/bin/env python3
"""Static closure and input-only Rust comparison with a frozen interval-rank oracle."""
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

SOURCE=ROOT/'src/node94-tag-address-pair'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(row)==2 and re.fullmatch(r'V:[0-9a-f]{16}:[0-9a-f]{16}',row[1]) for row in parsed),'output format')
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
    for va,_,_ in decode_rows((HERE/'static/select-gnu.txt').read_text(),0x15d65b0,0x15d65f3):
        raw,off=read(data,secs,va,1)
        cases.append((f'instruction-{va:x}',off,bytes([raw[0]^1]),'select body',False))
    for va in CALLS:
        raw,off=read(data,secs,va,1);cases.append((f'caller-{va:x}',off,bytes([raw[0]^1]),'caller body',False))
    for name in WINDOWS:
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    for va in CIE_BYTES:
        raw,off=read(data,secs,va+8,1)
        cases.append((f'cie-{va:x}',off,bytes([raw[0]^1]),'CIE bytes' if va==eh['address'] else 'bound CIE bytes',False))
    _,off=read(data,secs,0x15d65f3,1);cases.append(('padding',off,b'\x90','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('extra-naming',rela['offset']+16,struct.pack('<q',0x15d65b0),'naming relocation',False))
    cases.append(('code-relocation',rela['offset'],struct.pack('<Q',0x15d65b1),'protected code relocation',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x15d65b0-0x16488e0-5),'direct call census',False))
    cases.append(('extra-jump-pattern',off,b'\xe9'+struct.pack('<i',0x15d65b0-0x16488e0-5),'direct jump census',False))
    from static_evidence import eh_frame_records
    _,fdes=eh_frame_records(data,secs)
    unrelated=next(f for f in fdes if f['start']==0x16488e0)
    va=unrelated['fde']+8;_,off=read(data,secs,va,4)
    cases.append(('unselected-fde-overlap',off,struct.pack('<i',0x15d65b0-va),'select FDE overlap',False))
    from static_evidence import SLOTS,NEXT_FDE
    va,_,_,_=NEXT_FDE
    raw,off=read(data,secs,va+12,4)
    cases.append(('next-fde-range',off,struct.pack('<I',4),'next FDE bytes',False))
    for address,(rela_off,addend) in SLOTS.items():
        _,off=read(data,secs,address,1)
        cases.append((f'slot-{address:x}',off,b'\x01','slot raw bytes',False))
        message='naming relocation' if address==0x5678ee8 else 'slot relocation closure'
        cases.append((f'slot-addend-{address:x}',rela_off+16,struct.pack('<q',addend+1),message,False))
        cases.append((f'slot-type-{address:x}',rela_off+8,struct.pack('<Q',1),message,False))
    cases.append(('partial-slot-writer',rela['offset'],struct.pack('<Q',0x5676ba9),'slot relocation closure',False))
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
    'signed-gate':('if tag < HALF {','if (tag as i64) < 0 {'),
    'low32-gate':('if tag < HALF {','if (tag as u32 as u64) < HALF {'),
    'inclusive-low-gate':('if tag < HALF {','if tag <= HALF {'),
    'wrong-sign-bit':('const HALF: u64 = 1 << 63;','const HALF: u64 = 1 << 31;'),
    'half-test-low32':('tag == HALF {','tag as u32 == HALF as u32 {'),
    'neg-zero-is-overflow':('tag == HALF {','tag == 0 {'),
    'half-test-plus-one':('tag == HALF {','tag == HALF + 1 {'),
    'literal-one-test-plus-two':('tag == HALF + 1 {','tag == HALF + 2 {'),
    'literal-one-test-low8':('tag == HALF + 1 {','tag as u8 == 1 {'),
    'object-offset-four':('object.wrapping_add(8)','object.wrapping_add(4)'),
    'object-offset-saturating':('object.wrapping_add(8)','object.saturating_add(8)'),
    'object-offset-omitted':('object.wrapping_add(8)','object'),
    'object-low32':('rax: object,','rax: object as u32 as u64,'),
    'incremented-object-low32':('rax: object.wrapping_add(8),','rax: object.wrapping_add(8) as u32 as u64,'),
    'swap-slot-addresses':('load_bias.wrapping_add(0x5676c20)','load_bias.wrapping_add(0x5676ba8)'),
    'ordinary-slot-content':('load_bias.wrapping_add(0x5676c20)','load_bias.wrapping_add(0x15d44e0)'),
    'half-slot-content':('load_bias.wrapping_add(0x5676ba8)','load_bias.wrapping_add(0x15d3e70)'),
    'ordinary-no-bias':('load_bias.wrapping_add(0x5676c20)','0x5676c20'),
    'half-no-bias':('load_bias.wrapping_add(0x5676ba8)','0x5676ba8'),
    'ordinary-bias-saturating':('load_bias.wrapping_add(0x5676c20)','load_bias.saturating_add(0x5676c20)'),
    'half-bias-saturating':('load_bias.wrapping_add(0x5676ba8)','load_bias.saturating_add(0x5676ba8)'),
    'ordinary-address-low32':('load_bias.wrapping_add(0x5676c20)','load_bias.wrapping_add(0x5676c20) as u32 as u64'),
    'bias-literal-one':('rdx: HALF + 1,','rdx: load_bias.wrapping_add(HALF + 1),'),
    'bias-literal-tail':('rdx: HALF + 2,','rdx: load_bias.wrapping_add(HALF + 2),'),
    'zero-literal-one':('rdx: HALF + 1,','rdx: 0,'),
    'collapse-tail-literal':('rdx: HALF + 2,','rdx: HALF + 1,'),
    'literal-one-rax-object':('rax: 0,\n            rdx: HALF + 1,','rax: object,\n            rdx: HALF + 1,'),
    'tail-rax-object':('rax: 0,\n            rdx: HALF + 2,','rax: object,\n            rdx: HALF + 2,'),
}




def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_tag_address_pair','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_tag_address_pair.rlib'],
           [rustc,'+1.94.1','--crate-name','tag_address_pair_input_client','client.rs',*flags,'--extern','node94_tag_address_pair=libnode94_tag_address_pair.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        (directory.parent/'commands-partial.json').write_text(json.dumps(commands,indent=2)+'\n')
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_tag_address_pair.rlib','client')}


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
    bad=lines[0].split(b'\t');bad[1]=b'V:ffffffffffffffff:ffffffffffffffff\n'
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:]))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'all 64 bits of both RAX and RDX; no masks',
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
