"""Reproduce the bounded node94 local-port Rust comparison, without networking."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import node_port_native as native

ROOT=Path(__file__).resolve().parents[1]
COMPONENT=ROOT/'src/node94-local-port'
PACKET=ROOT/'research/work-items/RE-012-local-port-rust-94'


def need(condition,message):
    if not condition:
        raise ValueError(message)


def build(rustc,output):
    output=Path(output)
    need(not output.exists(),'output must be new')
    output.mkdir(parents=True)
    result=native.produce(output/'native')
    actual=(output/'native/target-vectors.tsv').read_bytes()
    need(actual==(COMPONENT/'target-vectors.tsv').read_bytes(),'frozen vector identity differs before compiler')
    freeze=json.loads((PACKET/'frozen-before-rust.json').read_text())
    need((output/'native/freeze.json').read_bytes()==(PACKET/'frozen-before-rust.json').read_bytes(),
         'frozen native contract differs before compiler')
    version=subprocess.check_output([str(rustc),'-Vv'],text=True)
    need(version.startswith('rustc 1.94.1 ('),'comparison requires pinned rustc1.94.1')
    rows=[line.split('\t') for line in actual.decode().splitlines()]
    inputs=''.join('\t'.join(row[:2])+'\n' for row in rows)
    expected=''.join('\t'.join(row[2:])+'\n' for row in rows)
    commands=[]
    def run(args,**kwargs):
        command=[str(arg) for arg in args]
        commands.append(command)
        return subprocess.run(command,check=True,text=True,capture_output=True,**kwargs)
    profiles={}
    for opt in (0,3):
        exe=output/f'port-o{opt}'
        run([rustc,'--edition=2021','-C',f'opt-level={opt}',COMPONENT/'input_only_driver.rs','-o',exe])
        actual=run([exe],input=inputs).stdout
        (output/f'output-o{opt}.tsv').write_text(actual)
        need(actual==expected,'compiled Rust differs from native corridor')
        profiles[str(opt)]={'rows':len(rows),'match':True,'stdout_sha256':hashlib.sha256(actual.encode()).hexdigest()}
    tests=output/'unit-tests'
    run([rustc,'--edition=2021','--test',COMPONENT/'lib.rs','-o',tests])
    (output/'unit-test-output.txt').write_text(run([tests]).stdout)
    mutations=[]
    source=(COMPONENT/'lib.rs').read_text()
    driver=(COMPONENT/'input_only_driver.rs').read_text()
    for name,old,new in [('stride','checked_mul(1000)','checked_mul(999)'),
                         ('add','checked_add(offset)','checked_add(offset.saturating_add(1))'),
                         ('selector4','Self::Selector4 => 3998','Self::Selector4 => 3999')]:
        need(source.count(old)==1,'mutation binding changed')
        folder=output/('mutant-'+name);folder.mkdir()
        (folder/'lib.rs').write_text(source.replace(old,new))
        (folder/'input_only_driver.rs').write_text(driver)
        exe=folder/'driver'
        run([rustc,'--edition=2021','-C','opt-level=3',folder/'input_only_driver.rs','-o',exe])
        mutated=run([exe],input=inputs).stdout.splitlines()
        need(len(mutated)==len(rows),'mutant row count differs')
        mismatches=sum(a!=b for a,b in zip(mutated,expected.splitlines()))
        need(mismatches>0,'compiled mutation escaped native comparator')
        mutations.append({'name':name,'mismatches':mismatches,'rows':len(rows)})
    libraries=[]
    for name in ('build-one','build-two'):
        folder=output/name;folder.mkdir()
        artifact=folder/'node94_port.rlib'
        run([rustc,'--edition=2021','--crate-name','node94_port','--crate-type','rlib',
             '-C','opt-level=3','-C','metadata=node94_port',COMPONENT/'lib.rs','-o',artifact])
        libraries.append(artifact.read_bytes())
    need(libraries[0]==libraries[1],'same-basename raw Rust archives differ')
    report={'native':result,'profiles':profiles,'compiled_mutants':mutations,
            'raw_rlib_equal':True,'rlib_sha256':hashlib.sha256(libraries[0]).hexdigest(),
            'rustc':version,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'commands':commands,'captured_native_execution':False,
            'authorized_offline_python_instruction_evaluation':True}
    (output/'build-result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=build(args.rustc,args.output)
    print(json.dumps({key:report[key] for key in ('native','profiles','compiled_mutants','raw_rlib_equal')}))
