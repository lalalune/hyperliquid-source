#!/usr/bin/env python3
"""Build one independent scalar Rust expression against the byte-derived oracle.

Only newly authored Rust is executed. The original node is mmap-read and
hashed; its existing static algebra supplies expectations, without % or Rust.
"""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import time

import state_dump_result_projection_static as original

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'artifacts/node/94/hl-node'
COMPONENT = ROOT/'src/node94-euclidean-remainder'
SOURCE = COMPONENT/'lib.rs'
FIXTURE = COMPONENT/'target-vectors.tsv'
ORIGINAL_COMMIT = '1cf8e6b4af0a049978627dee8de0146c1303aff6'
CRATE = 'node94_euclidean_remainder'
MIN64,MAX64,MASK64 = -(1<<63),(1<<63)-1,(1<<64)-1


def need(condition,message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def input_cases():
    """Boundary/structured/seeded arithmetic cases, not native reachability claims."""
    values={MIN64,MAX64,-86401,-86400,-86399,-65536,-1,0,1,65535,65536,86399,86400,86401}
    for edge in (MIN64,MAX64):
        for delta in range(-8,9):
            if MIN64<=edge+delta<=MAX64:values.add(edge+delta)
    quotients=set(range(-16,17))
    for bit in range(47):quotients.update((-(1<<bit),1<<bit))
    for quotient in quotients:
        for delta in (-86401,-86400,-86399,-1,0,1,86399,86400,86401):
            value=quotient*86400+delta
            if MIN64<=value<=MAX64:values.add(value)
    state=0x739b8d612af045ce
    for _ in range(1024):
        state=(state*0x5851f42d4c957f2d+0x14057b7ef767814f)&MASK64
        values.add(state if state<(1<<63) else state-(1<<64))
    return sorted(values)


def oracle(binary=TARGET):
    """Retained native integer equations, not target execution or Rust output."""
    with Path(binary).open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as data:
        original.authenticate(data)
        record=original.inspect(data)
        secs=original.sections(data)
        _,body=original.read_va(data,secs,original.START,original.END-original.START)
        _,consumer=original.read_va(data,secs,original.USE_START,original.USE_END-original.USE_START)
        original.authenticate(data)
    parameters=record['operands']
    rows=[(value,original.projection(value,parameters)['second_field']) for value in input_cases()]
    need(all(0<=result<86400 for _,result in rows),'derived expression result outside proved range')
    fixture=''.join(f'{value}\t{result}\n' for value,result in rows).encode('ascii')
    inputs=''.join(f'{value}\n' for value,_ in rows).encode('ascii')
    return {'record':record,'rows':rows,'fixture':fixture,'inputs':inputs,'body':body,'consumer':consumer,
            'metadata':{'target':record['target'],'original_static_commit':ORIGINAL_COMMIT,
                        'parameters':parameters,'whole_i64_algebra':record['proof'],
                        'case_count':len(rows),'fixture_sha256':sha(fixture),'inputs_sha256':sha(inputs),
                        'expected_values':'Actual extracted multiply-high/shift/sign/repair equations; no % or rem_euclid in expected-value generation.',
                        'limits':'Total scalar arithmetic cases, not observed full-helper successes; original guards/callees/ABI remain conditional.'}}


def verify_fixture(expected,fixture=FIXTURE):
    need(Path(fixture).read_bytes()==expected['fixture'],'Rust fixture differs from fresh target-expression expectations')


def target_controls(expected):
    results=[]
    for name,site,raw,witness in (
        ('multiplier-minus-one',0x151cbf1,(0x1845c8a0ce512956).to_bytes(8,'little'),86400),
        ('high-shift12',0x151cc09,b'\x0c',172800),
        ('quotient-sign-shift62',0x151cc05,b'\x3e',-86400)):
        changed=bytearray(expected['body']);offset=site-original.START;changed[offset:offset+len(raw)]=raw
        parameters=original.extract(bytes(changed),expected['consumer'])
        before=original.projection(witness,expected['record']['operands'])['second_field']
        after=original.projection(witness,parameters)['second_field']
        need(after!=before,'actual operand mutation lacks a semantic counterexample')
        try:original.validate(parameters)
        except ValueError as error:reason=str(error)
        else:raise ValueError('actual operand mutation unexpectedly accepted')
        results.append({'name':name,'site':hex(site),'witness':witness,'expected':before,
                        'mutated_expression_result':after,'semantic_difference':True,'rejection':reason,
                        'captured_target_executed_or_modified':False})
    return results


HARNESS = r'''extern crate node94_euclidean_remainder;
use std::io::{self, Write};
fn main() {
    let path = std::env::args().nth(1).expect("input-only corpus path");
    let inputs = std::fs::read_to_string(path).expect("input-only corpus");
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in inputs.lines() {
        let value: i64 = line.parse().expect("signed64 input");
        writeln!(output, "{}\t{}", value,
            node94_euclidean_remainder::euclidean_remainder_86400(value)).unwrap();
    }
}
'''


def file_digest(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for raw in iter(lambda:stream.read(1<<20),b''):digest.update(raw)
    return digest.hexdigest()


def build(binary,rustc,output,controls=False):
    """Execute our new Rust only; native expectations are derived beforehand."""
    output=Path(output)
    need(not output.exists(),'Output directory must be new; previous evidence is preserved')
    expected=oracle(binary)
    verify_fixture(expected)
    rustc=Path(rustc).absolute()
    version=subprocess.check_output([str(rustc),'-vV'],text=True)
    need(version.startswith('rustc 1.94.1 '),'Research component requires repository-pinned rustc1.94.1')
    source_before={str(p.relative_to(ROOT)):file_digest(p) for p in (SOURCE,FIXTURE,Path(__file__))}
    compiler_before=file_digest(rustc)
    linker=shutil.which('cc')
    need(linker is not None,'Host C linker driver cc is required')
    linker_version=subprocess.check_output([linker,'--version'],text=True)
    linker_before=file_digest(linker)
    output.mkdir(parents=True,exist_ok=False)
    (output/'oracle.json').write_text(json.dumps(expected['metadata'],indent=2)+'\n')
    (output/'inputs.txt').write_bytes(expected['inputs'])
    (output/'expected.tsv').write_bytes(expected['fixture'])
    (output/'comparison-main.rs').write_text(HARNESS)
    (output/'rustc-version.txt').write_text(version)
    calls=[]
    environment=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    def execute(label,argv,required_exit=0):
        start=time.monotonic();process=subprocess.run([str(a) for a in argv],cwd=ROOT,
                   env=environment,stdin=subprocess.DEVNULL,capture_output=True)
        logs={}
        for kind,raw in (('stdout',process.stdout),('stderr',process.stderr)):
            p=output/(label+'.'+kind);p.write_bytes(raw)
            logs[kind]={'file':p.name,'bytes':len(raw),'sha256':sha(raw)}
        calls.append({'label':label,'argv':[str(a) for a in argv],'exit_code':process.returncode,
                      'seconds':round(time.monotonic()-start,3),'logs':logs})
        if required_exit is not None:
            need(process.returncode==required_exit,f'{label} failed; retained original stdout/stderr')
        return process
    def flags(opt):
        return ['--edition=2021','-D','warnings','-C','codegen-units=1','-C',f'opt-level={opt}',
                '-C','overflow-checks=on','-C','linker='+linker,'--remap-path-prefix',str(ROOT)+'=/reconstruction']
    def library(label,source,opt,directory):
        directory.mkdir(parents=True,exist_ok=False)
        target=directory/('lib'+CRATE+'.rlib')
        execute(label,[rustc,'--crate-name',CRATE,'--crate-type=rlib',source,'-o',target,
                       '-C','metadata=node94-remainder-86400',*flags(opt)])
        return target
    def linked_values(label,library_path,opt,directory):
        executable=directory/'comparison'
        execute(label+'-link',[rustc,'--crate-name','remainder_comparison',output/'comparison-main.rs',
                '--extern',CRATE+'='+str(library_path),'-o',executable,*flags(opt)])
        return execute(label+'-run',[executable,output/'inputs.txt']).stdout
    profiles=[]
    for name,opt in (('debug',0),('optimized',3)):
        directory=output/name
        library_path=library(name+'-library',SOURCE,opt,directory)
        unit=directory/'module-tests'
        execute(name+'-test-build',[rustc,'--crate-name',CRATE,'--test',SOURCE,'-o',unit,*flags(opt)])
        tests=execute(name+'-tests',[unit,'--nocapture'])
        need(b'1 passed; 0 failed; 0 ignored' in tests.stdout,'Ordinary Rust corpus test did not run')
        actual=linked_values(name+'-production',library_path,opt,directory)
        need(actual==expected['fixture'],f'{name} production library differs from independent target expression')
        profiles.append({'name':name,'opt_level':opt,'ordinary_Rust_tests':1,
                         'independent_production_cases':len(expected['rows']),
                         'actual_values_sha256':sha(actual),'expected_values_sha256':sha(expected['fixture']),
                         'library_sha256':file_digest(library_path),'matched':True})
    first=library('repro-a',SOURCE,3,output/'repro-a')
    second=library('repro-b',SOURCE,3,output/'repro-b')
    reproducibility={'build_a_bytes':first.stat().st_size,'build_b_bytes':second.stat().st_size,
                     'build_a_sha256':file_digest(first),'build_b_sha256':file_digest(second),
                     'raw_equal':first.read_bytes()==second.read_bytes(),'normalization':'none',
                     'original_node_binary_match_claimed':False}
    need(reproducibility['raw_equal'],'Own same-toolchain library builds are not raw reproducible')
    mutants=[]
    if controls:
        source=SOURCE.read_text();needle='value.rem_euclid(86_400) as u32'
        need(source.count(needle)==1,'Semantic mutation site is ambiguous')
        changes=[('wrong-divisor','value.rem_euclid(86_399) as u32'),
                 ('signed-remainder','(value % 86_400) as u32'),
                 ('narrow-u16','(value.rem_euclid(86_400) as u16) as u32'),
                 ('wrong-zero','if value == 0 { 86_400 } else { value.rem_euclid(86_400) as u32 }')]
        for name,replacement in changes:
            directory=output/('mutant-'+name);directory.mkdir()
            path=directory/'lib.rs';path.write_text(source.replace(needle,replacement))
            (directory/'target-vectors.tsv').write_bytes(expected['fixture'])
            library_path=library('mutant-'+name+'-library',path,0,directory/'build')
            actual=linked_values('mutant-'+name+'-production',library_path,0,directory)
            need(actual!=expected['fixture'],'Compiled semantic mutation escaped independent comparison')
            lines=actual.decode().splitlines();need(len(lines)==len(expected['rows']),'Mutant output count differs')
            mismatches=[]
            for (input_value,wanted),line in zip(expected['rows'],lines):
                shown,observed=map(int,line.split('\t'));need(shown==input_value,'Mutant input order differs')
                if observed!=wanted:mismatches.append({'input':input_value,'expected':wanted,'actual':observed})
            need(mismatches,'Mutant lacked a value mismatch')
            unit=directory/'module-tests'
            execute('mutant-'+name+'-test-build',[rustc,'--crate-name',CRATE,'--test',path,'-o',unit,*flags(0)])
            failure=execute('mutant-'+name+'-tests',[unit,'--nocapture'],required_exit=None)
            need(failure.returncode!=0 and b'assertion' in failure.stdout+failure.stderr,
                 'Mutant did not fail the actual compiled semantic assertion')
            mutants.append({'name':name,'compiled':True,'ordinary_test_failed':True,
                            'independent_production_mismatches':len(mismatches),'first_witness':mismatches[0],
                            'source_sha256':file_digest(path),'library_sha256':file_digest(library_path)})
    source_after={str(p.relative_to(ROOT)):file_digest(p) for p in (SOURCE,FIXTURE,Path(__file__))}
    need(source_before==source_after and compiler_before==file_digest(rustc)
         and linker_before==file_digest(linker),'Source/compiler/linker-driver changed during build')
    with Path(binary).open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as data:
        original.authenticate(data)
    result={'status':'SCALAR_RUST_EXPRESSION_BUILD_AND_COMPARISON_PASS','original_static_commit':ORIGINAL_COMMIT,
            'compiler':{'argv':str(rustc),'version':version,'executable_sha256':compiler_before,
                        'meaning':'Repository-pinned research component compiler, not recovered original node compiler.'},
            'host_linker_driver':{'path':linker,'version':linker_version,'sha256':linker_before,'explicitly_passed_to_rustc':True},
            'source_sha256s':source_before,'source_compiler_and_target_unchanged':True,
            'oracle':expected['metadata'],'profiles':profiles,'same_toolchain_reproducibility':reproducibility,
            'compiled_Rust_mutations':mutants,'target_operand_controls':target_controls(expected) if controls else [],
            'commands':calls,'captured_original_executed_or_emulated':False,
            'limits':['Only this pure total numeric expression; original status/index/callee/ABI guards still qualify native writes.',
                      'Finite compiled comparisons support the scalar implementation; no original compiler/ABI/whole-helper/byte-match/component gate.',
                      'No Cargo workspace/dependencies; source test and library built directly with rustc; all compiler outputs in requested fresh directory.']}
    (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--rustc',type=Path,required=True,help='Trusted actual repo-pinned1.94.1 compiler; no toolchain is installed by this runner')
    parser.add_argument('--output',type=Path,required=True,help='Fresh directory for all owned build/test outputs')
    parser.add_argument('--controls',action='store_true')
    args=parser.parse_args();result=build(args.binary,args.rustc,args.output,args.controls)
    print(json.dumps({'status':result['status'],'profiles':result['profiles'],
                      'semantic_Rust_mutations':len(result['compiled_Rust_mutations']),
                      'target_controls':len(result['target_operand_controls']),
                      'own_builds_raw_equal':result['same_toolchain_reproducibility']['raw_equal']},sort_keys=True))
