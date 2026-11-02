#!/usr/bin/env python3
"""Compare independently authored Rust with the accepted fresh-20-byte hash cut.

Oracle/controls use the separately authorized bounded Python captured-arithmetic
interpreter with byte-bound initialization/loop/tail lowerings. No native capture,
runtime seed, wallet key, chain state or generic incremental writer is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import address_hash20 as native

ROOT=native.ROOT
TARGET=ROOT/native.BINARY
COMPONENT=ROOT/'src/node94-table-hash20'
SOURCE=COMPONENT/'lib.rs'
PACKET=ROOT/'research/work-items/RE-001-table-hash20-rust-94'
SEEDS=((0,0),(native.MASK,native.MASK),
       (0x0706050403020100,0x0f0e0d0c0b0a0908),(1<<63,1))


def need(condition,message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stimuli():
    rows=[]
    base=bytes(range(20))
    for seed in SEEDS:
        for pos in range(20):
            for byte in range(256):
                rows.append((seed,base[:pos]+bytes([byte])+base[pos+1:]))
    for seed in SEEDS:
        for message in (bytes(20),b'\xff'*20,base,bytes(16)+b'\xff'*4,b'\xff'*16+bytes(4)):
            rows.append((seed,message))
    state=0x94a20b164f0
    def next_word():
        nonlocal state
        state=(state*6364136223846793005+1442695040888963407)&native.MASK
        return state
    for _ in range(256):
        seed=(next_word(),next_word())
        message=b''.join(next_word().to_bytes(8,'little') for _ in range(3))[:20]
        rows.append((seed,message))
    return rows


def oracle(binary=TARGET):
    data=Path(binary).read_bytes()
    need(len(data)==91774280 and sha(data)==native.SHA256,'pinned node94 identity mismatch')
    record=native.build(data)
    need(record==json.loads((native.PACKET/'records.json').read_text()),'accepted native records differ')
    image=native.Image(data)
    inputs,expected=[],[]
    rows=stimuli()
    for index,(seed,message) in enumerate(rows):
        actual=native.target_hash(image,seed,message)
        need(actual==native.reference_hash(seed,message),'actual captured arithmetic differs from independent math')
        inputs.append(f'{index}\t{seed[0]:016x}\t{seed[1]:016x}\t{message.hex()}\n')
        expected.append(f'{index}\t{actual:016x}\n')
    smoke=[]
    for seed in SEEDS:
        for message in (bytes(range(20)),bytes(20),b'\xff'*20):
            actual=native.target_hash(image,seed,message)
            smoke.append(f'{seed[0]:016x}\t{seed[1]:016x}\t{message.hex()}\t{actual:016x}\n')
    return {'inputs':''.join(inputs).encode(),'expected':''.join(expected).encode(),
            'smoke':''.join(smoke).encode(),'count':len(rows),'distinct_inputs':len(set(rows)),
            'record':record,'authorized_offline_Python_captured_arithmetic_interpreter':True}


def target_controls(binary=TARGET):
    data=Path(binary).read_bytes()
    native.build(data)
    image=native.Image(data)
    seed=(0,0);message=bytes(range(20))
    expected=native.target_hash(image,seed,message)
    results=[]
    for name,va,replacement in (
        ('compression-rotation',0x288e3ad,12),
        ('finalization-rotation',0x284106a,12),
        ('initialization-constant',0x204ec0,image.read(0x204ec0,1)[0]^1)):
        private=bytearray(data);private[image.off(va,1)]=replacement
        actual=native.target_hash(native.Image(private),seed,message)
        need(actual!=expected,'actual arithmetic counterfactual lacks changed hash')
        try:
            native.observe(private)
        except ValueError as error:
            rejected=str(error)
        else:
            raise ValueError('changed native arithmetic was accepted')
        results.append({'name':name,'address':hex(va),'synthetic_seed':seed,'message_hex':message.hex(),
                        'expected':f'{expected:016x}','mutated':f'{actual:016x}','rejected':rejected,
                        'authorized_offline_Python_instruction_evaluation':True,'native_capture_launched':False})
    return results


DRIVER='''extern crate node94_table_hash20;
use node94_table_hash20::table_hash20;
use std::io::{self,Write};
fn main() {
    let text=std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let mut out=io::BufWriter::new(io::stdout().lock());
    for line in text.lines() {
        let f:Vec<_>=line.split_whitespace().collect();
        let seed=[u64::from_str_radix(f[1],16).unwrap(),u64::from_str_radix(f[2],16).unwrap()];
        let bytes:Vec<u8>=(0..f[3].len()).step_by(2).map(|at|u8::from_str_radix(&f[3][at..at+2],16).unwrap()).collect();
        let message:[u8;20]=bytes.try_into().unwrap();
        writeln!(out,"{}\\t{:016x}",f[0],table_hash20(seed,&message)).unwrap();
    }
}
'''


def build(binary,rustc,output,controls=False):
    output=Path(output).absolute()
    need(not output.exists(),'output directory must be new')
    expected=oracle(binary)
    freeze=json.loads((PACKET/'PRE-RUST-FREEZE.json').read_text())
    need((freeze['input_sha256'],freeze['expected_sha256'])==
         (sha(expected['inputs']),sha(expected['expected'])),'frozen corpus identity differs')
    need((COMPONENT/'target-smoke.tsv').read_bytes()==expected['smoke'],'frozen smoke differs')
    rustc=Path(rustc).absolute()
    version=subprocess.check_output([str(rustc),'-vV'],text=True)
    need(version.startswith('rustc 1.94.1 '),'repository research compiler must be Rust1.94.1')
    linker=os.environ.get('RECONSTRUCTION_LINKER') or shutil.which('cc')
    need(linker is not None,'host linker required')
    paths=[SOURCE,COMPONENT/'target-smoke.tsv',Path(__file__),rustc,Path(linker)]
    before=[sha(p.read_bytes()) for p in paths]
    output.mkdir(parents=True)
    (output/'inputs.tsv').write_bytes(expected['inputs'])
    (output/'expected.tsv').write_bytes(expected['expected'])
    (output/'driver.rs').write_text(DRIVER)
    commands=[]
    def execute(label,args,fail=False):
        p=subprocess.run(list(map(str,args)),cwd=ROOT,capture_output=True,stdin=subprocess.DEVNULL)
        for kind,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            (output/(label+'.'+kind)).write_bytes(raw)
        commands.append({'label':label,'exit':p.returncode,
                         'argv':[str(a).replace(str(output),'$OUTPUT').replace(str(ROOT),'$REPO')
                                 .replace(str(rustc),'$RUSTC').replace(linker,'$LINKER') for a in args],
                         'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
        need(p.returncode!=0 if fail else p.returncode==0,label+' unexpected exit; raw logs retained')
        return p.stdout
    def compile_compare(name,source,opt):
        folder=output/name;folder.mkdir()
        flags=['--edition=2021','-D','warnings','-C',f'opt-level={opt}','-C','overflow-checks=on',
               '-C','codegen-units=1','-C','linker='+linker,'--remap-path-prefix',str(ROOT)+'=/reconstruction']
        library=folder/'libnode94_table_hash20.rlib'
        execute(name+'-library',[rustc,'--crate-name','node94_table_hash20','--crate-type=rlib',source,'-o',library,*flags])
        driver=folder/'driver'
        execute(name+'-link',[rustc,output/'driver.rs','--extern','node94_table_hash20='+str(library),'-o',driver,*flags])
        actual=execute(name+'-run',[driver,output/'inputs.tsv'])
        need(len(actual.splitlines())==expected['count'],'production output count differs')
        return {'name':name,'opt_level':opt,'matches':actual==expected['expected'],
                'mismatches':sum(a!=b for a,b in zip(actual.splitlines(),expected['expected'].splitlines())),
                'actual_sha256':sha(actual),'library_sha256':sha(library.read_bytes())},flags,folder
    profiles=[]
    for name,opt in [('debug',0),('optimized',3)]:
        result,flags,folder=compile_compare(name,SOURCE,opt)
        need(result['matches'],'Rust hash differs from captured arithmetic')
        unit=folder/'tests'
        execute(name+'-test-build',[rustc,'--crate-name','node94_table_hash20','--test',SOURCE,'-o',unit,*flags])
        tests=execute(name+'-tests',[unit])
        need(b'1 passed; 0 failed' in tests,'ordinary frozen smoke test did not run')
        profiles.append(result)
    repeated,_,_=compile_compare('optimized-repeat',SOURCE,3)
    need(repeated['library_sha256']==profiles[1]['library_sha256'],'own optimized rlib not reproducible')
    mutants=[]
    if controls:
        source=SOURCE.read_text()
        for name,old,new in [('rotation13-to12','rotate_left(13)','rotate_left(12)'),
                             ('length-in-wrong-byte','20_u64 << 56','20_u64 << 48'),
                             ('two-final-rounds','0..3','0..2')]:
            need(source.count(old)==1,'ambiguous Rust hash mutation site')
            private=output/('source-'+name);private.mkdir()
            path=private/'lib.rs';path.write_text(source.replace(old,new))
            (private/'target-smoke.tsv').write_bytes(expected['smoke'])
            result,flags,folder=compile_compare('mutant-'+name,path,0)
            need(not result['matches'] and result['mismatches']>0,'compiled hash mutation escaped comparator')
            unit=folder/'tests'
            execute(name+'-test-build',[rustc,'--crate-name','node94_table_hash20','--test',path,'-o',unit,*flags])
            execute(name+'-tests',[unit],fail=True)
            mutants.append(result)
    need(before==[sha(p.read_bytes()) for p in paths],'source/compiler/linker changed')
    need(sha(Path(binary).read_bytes())==native.SHA256,'capture changed during comparison')
    report={'status':'PASS','target_sha256':native.SHA256,'compiler':version,
            'linker_version':subprocess.check_output([linker,'--version'],text=True),
            'sdkroot':os.environ.get('SDKROOT'),'case_count':expected['count'],
            'distinct_seed_message_pairs':expected['distinct_inputs'],'input_sha256':sha(expected['inputs']),
            'expected_sha256':sha(expected['expected']),'source_compiler_linker_sha256':before,
            'profiles':profiles,'own_optimized_rlib_raw_reproducible':True,'rust_mutants':mutants,
            'target_controls':target_controls(binary) if controls else [],'commands':commands,
            'authorized_offline_Python_captured_arithmetic_interpretation':True,
            'native_capture_launched':False,
            'limits':'Fresh fixed20byte math only; byte-bound init/loop/tail lowerings, not whole generic writer interpretation; no runtime seed/ABI/address derivation/whole function/target byte claim.'}
    (output/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--controls',action='store_true')
    args=parser.parse_args()
    try:
        report=build(args.binary,args.rustc,args.output,args.controls)
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        parser.exit(1,str(error)+'\n')
    print(json.dumps({'status':report['status'],'cases_per_profile':report['case_count']}))
