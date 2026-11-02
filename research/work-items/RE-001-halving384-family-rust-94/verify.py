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

SOURCE=ROOT/'src/node94-halving384-family'


def sha(data): return hashlib.sha256(data).hexdigest()


def compare(actual,expected):
    def rows(raw):
        parsed=[line.split('\t') for line in raw.decode('ascii').splitlines()]
        require(all(len(row)==3 and (row[1]=='E' or re.fullmatch(r'V(?::[0-9a-f]{16}){9}|V(?::[0-9a-f]{16}){12}',row[1])) and (row[2]=='-' or re.fullmatch(r'(?:[0-9a-f]{2})+',row[2])) for row in parsed),'output format')
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
    for name in ('core','single','repeated'):
        start,end,_=WINDOWS[name]
        for va,_,_ in decode_rows((HERE/f'static/{name}-gnu.txt').read_text(),start,end):
            raw,off=read(data,secs,va,1)
            cases.append((f'instruction-{va:x}',off,bytes([raw[0]^1]),f'{name} body',False))
    for va in CALLS:
        owner=next(name for name,(start,end,_) in WINDOWS.items() if start<=va<end)
        raw,off=read(data,secs,va,1);cases.append((f'caller-{va:x}',off,bytes([raw[0]^1]),f'{owner} body',False))
    for name in WINDOWS:
        off=eh['offset']+int(records['windows'][name]['fde_section_offset'],16)+12
        size=struct.unpack_from('<I',data,off)[0]
        cases.append((f'{name}-fde-range',off,struct.pack('<I',size+1),f'{name} FDE overlap',False))
    for va in CIE_BYTES:
        raw,off=read(data,secs,va+8,1)
        cases.append((f'cie-{va:x}',off,bytes([raw[0]^1]),'CIE bytes' if va==eh['address'] else 'bound CIE bytes',False))
    for va in (0x5656b0b,0x5656bb9,0x5656c2a):
        _,off=read(data,secs,va,1);cases.append((f'padding-{va:x}',off,b'\xcc','alignment padding',False))
    rela=next(s for s in secs if s['name']=='.rela.dyn')
    cases.append(('extra-naming',rela['offset']+16,struct.pack('<q',0x5656b20),'naming relocation',False))
    cases.append(('code-relocation',rela['offset'],struct.pack('<Q',0x5656b21),'protected code relocation',False))
    _,off=read(data,secs,0x16488e0,5)
    cases.append(('extra-call-pattern',off,b'\xe8'+struct.pack('<i',0x5656b20-0x16488e0-5),'direct call census',False))
    cases.append(('extra-jump-pattern',off,b'\xe9'+struct.pack('<i',0x5656b20-0x16488e0-5),'direct jump census',False))
    from static_evidence import eh_frame_records
    _,fdes=eh_frame_records(data,secs)
    unrelated=next(f for f in fdes if f['start']==0x16488e0)
    va=unrelated['fde']+8;_,off=read(data,secs,va,4)
    cases.append(('unselected-fde-overlap',off,struct.pack('<i',0x5656b20-va),'core FDE overlap',False))
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


MUTANTS={'parity-second-bit': ('input[0] & 1 == 1', 'input[0] & 2 == 2'), 'parity-inverted': ('input[0] & 1 == 1', 'input[0] & 1 == 0'), 'add-even-also': ('let selected = if input[0] & 1 == 1 { correction } else { ZERO };', 'let selected = correction;'), 'drop-add-carry': ('carry = total >> 64;', 'carry = (total >> 64) & 0;'), 'drop-385th-bit': ('(words[5] >> 1) | (high << 63)', '(words[5] >> 1) | ((high & 0) << 63)'), 'cross-word-bit62': ('(words[i + 1] << 63)', '(words[i + 1] << 62)'), 'word-shift-two': ('(words[i] >> 1)', '(words[i] >> 2)'), 'count-low16': ('let low_count = raw_count as u32;', 'let low_count = raw_count as u16 as u32;'), 'count-zero-one': ('1u64 << 32', '1u64'), 'count-zero-2pow31': ('1u64 << 32', '1u64 << 31'), 'count-use-high32': ('let low_count = raw_count as u32;', 'let low_count = (raw_count >> 32) as u32;'), 'one-extra-pass': ('value = next(value, correction);', 'value = next(next(value, correction), correction);'), 'no-tail': ('if remaining == 0 || value == ZERO {', 'if remaining <= u64::MAX || value == ZERO {'), 'even-divisor-not-minus-one': ('difference(correction, ONE).0', 'correction'), 'wrong-inverse-two': ('let mut power = sum(half(divisor, 0), ONE).0;', 'let mut power = half(divisor, 0);'), 'drop-modular-carry': ('if high != 0 || !borrow { reduced } else { total }', 'if (high != 0 && false) || !borrow { reduced } else { total }'), 'borrow-and': ('borrow = first || second;', 'borrow = first && second;'), 'multiply-bits-forward': ('for bit in (0..384).rev() {', 'for bit in 0..384 {'), 'multiply-missing-top-word': ('for bit in (0..384).rev() {', 'for bit in (0..320).rev() {'), 'power-shift-two': ('remaining >>= 1;', 'remaining >>= 2;'), 'core-rax-full': ('rax: words[2] & LOW,', 'rax: words[2],'), 'core-rsi-full': ('rsi: words[5] & LOW,', 'rsi: words[5],'), 'core-rbx-wrong': ('rbx: words[3] & LOW,', 'rbx: words[2] & LOW,'), 'core-rbp-wrong': ('rbp: words[4] & LOW,', 'rbp: words[3] & LOW,'), 'core-r14-wrong': ('r14: words[0] & LOW,', 'r14: words[1] & LOW,'), 'core-r15-wrong': ('r15: words[1] & LOW,', 'r15: words[2] & LOW,'), 'wrapper-rax-full': ('rax: value[2] & LOW,', 'rax: value[2],'), 'wrapper-rsi-full': ('rsi: value[5] & LOW,', 'rsi: value[5],'), 'single-rdx-zero': ('Wrapper::Single => (next(a, c), correction),', 'Wrapper::Single => (next(a, c), 0),'), 'repeated-rdx-count': ('(repeated_value(a, c, raw_count), 0)', '(repeated_value(a, c, raw_count), raw_count)'), 'wrapper-rcx-input': ('rcx: correction,', 'rcx: input,'), 'wrapper-rdi-input': ('rdi: destination,', 'rdi: input,'), 'wrapper-r8-cleared-high': ('r8: value[0],', 'r8: value[0] & LOW,'), 'wrapper-r9-next': ('r9: value[1],', 'r9: value[2],'), 'wrapper-r10-next': ('r10: value[2],', 'r10: value[3],'), 'wrapper-r11-next': ('r11: value[3],', 'r11: value[4],'), 'big-endian-loads': ('u64::from_le_bytes(bytes)', 'u64::from_be_bytes(bytes)'), 'big-endian-stores': ('value[i].to_le_bytes()', 'value[i].to_be_bytes()'), 'early-destination-clear': ('let c = load(image, adjustment);', 'image[dest..dest + 48].fill(0);\n    let c = load(image, adjustment);'), 'exact-end-refusal': ('if start.checked_add(48)? > image.len() {', 'if start.checked_add(48)? >= image.len() {'), 'image-end-max-refusal': ('> (1u128 << 64)', '>= (1u128 << 64)')}


def build(source,directory,opt,rustc,commands):
    directory.mkdir(parents=True)
    (directory/'lib.rs').write_text(source);shutil.copyfile(SOURCE/'client.rs',directory/'client.rs')
    flags=['--edition=2024','-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=yes','-C','panic=abort','-C','debuginfo=0','--remap-path-prefix',f'{directory}=/component','-D','warnings']
    calls=[[rustc,'+1.94.1','--crate-name','node94_halving384_family','--crate-type=rlib','lib.rs',*flags,'-o','libnode94_halving384_family.rlib'],
           [rustc,'+1.94.1','--crate-name','halving384_family_input_client','client.rs',*flags,'--extern','node94_halving384_family=libnode94_halving384_family.rlib','-o','client']]
    for command in calls:
        p=subprocess.run(command,cwd=directory,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        commands.append({'cwd':str(directory.relative_to(ROOT)),'argv':command,'exit':p.returncode,'output':p.stdout})
        (directory.parent/'commands-partial.json').write_text(json.dumps(commands,indent=2)+'\n')
        require(p.returncode==0,f'Rust build failed: {p.stdout}')
    return {n:sha((directory/n).read_bytes()) for n in ('libnode94_halving384_family.rlib','client')}


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
    bad=lines[0].split(b'\t');bad[1]=b'V:'+b':'.join([b'ffffffffffffffff']*12)
    for name,raw in [('value',b'\t'.join(bad)+b''.join(lines[1:])),('missing',b''.join(lines[:-1])),('duplicate',expected+lines[0]),('order',lines[1]+lines[0]+b''.join(lines[2:])),('image',expected.replace(b'\t-\n',b'\t00\n',1))]:
        try: require(not compare(raw,expected),'output values')
        except ValueError as exc: comparator.append({'name':name,'rejection':str(exc)})
        else: raise ValueError('comparator control survived')
    result={'target_sha256':freeze['target_sha256'],'freeze':freeze,'compared_fields':'12 core or 9 wrapper full-width register values; every image byte; refusal status; no comparison masks',
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
