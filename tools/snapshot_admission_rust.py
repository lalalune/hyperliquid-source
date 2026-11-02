"""Compare bounded independently authored Rust with accepted node94 window bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import snapshot_admission as native

ROOT=Path(__file__).resolve().parents[1]
COMPONENT=ROOT/'src/node94-snapshot-admission'
PACKET=ROOT/'research/work-items/RE-001-snapshot-admission-rust-94'


def need(ok,message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stimuli():
    rows=[(tag,height,native.MASK) for height in range(20001) for tag in (0,1,2,0xffffffff)]
    for height in (0,1,9999,10000,10001,20000,(1<<63)-1,1<<63,(1<<63)+1,native.MASK):
        for frozen in sorted({0,height,max(0,height-1),min(native.MASK,height+1),native.MASK}):
            for tag in (0,1,2,0xffffffff):
                rows.append((tag,height,frozen))
    return list(dict.fromkeys(rows))


def oracle(binary=ROOT/native.BINARY):
    data=Path(binary).read_bytes()
    record=native.build(data)
    need(record==json.loads((native.PACKET/'records.json').read_text()),'accepted native records differ')
    image=native.Image(data)
    inputs=[];expected=[];states=stimuli()
    codes={'freeze':'F','periodic':'P','skip':'S','panic':'X'}
    for lane,case in enumerate(native.CASES):
        for tag,height,frozen in states:
            actual=codes[native.replay(image,case,tag,height,frozen)]
            independent='X' if tag==1 and frozen<height else 'F' if tag==1 and frozen==height else 'P' if height%10000==0 else 'S'
            need(actual==independent,'native admission differs from independent predicate')
            inputs.append(f'{lane}\t{tag}\t{height}\t{frozen}\n')
            expected.append(actual+'\n')
    return {'inputs':''.join(inputs).encode(),'expected':''.join(expected).encode(),
            'count':len(inputs),'distinct_inputs':len(states),'record':record,'controls':[]}


def build(binary,rustc,output):
    output=Path(output)
    need(not output.exists(),'output must be new')
    result=oracle(binary)
    freeze=json.loads((PACKET/'FREEZE.json').read_text())
    need(sha(result['inputs'])==freeze['input_sha256'] and sha(result['expected'])==freeze['expected_sha256'],
         'frozen expectations differ before compiler')
    version=subprocess.check_output([str(rustc),'-Vv'],text=True)
    need(version.startswith('rustc 1.94.1 ('),'pinned rustc1.94.1 required')
    output.mkdir(parents=True)
    (output/'inputs.tsv').write_bytes(result['inputs']);(output/'expected.tsv').write_bytes(result['expected'])
    commands=[]
    def run(argv,**kwargs):
        argv=list(map(str,argv));commands.append(argv)
        return subprocess.run(argv,text=True,capture_output=True,**kwargs)
    def library(source,folder,opt):
        folder.mkdir()
        lib=folder/'libnode94_snapshot_admission.rlib'
        args=[rustc,'--edition=2021','--crate-name','node94_snapshot_admission','--crate-type','rlib',
              '-C',f'opt-level={opt}','-C','codegen-units=1','-C','overflow-checks=on',
              '-C','metadata=node94_snapshot_admission','-D','warnings',source,'-o',lib]
        p=run(args);need(p.returncode==0,p.stderr)
        exe=folder/'driver'
        p=run([rustc,'--edition=2021','-C',f'opt-level={opt}','-D','warnings',
               COMPONENT/'input_only_driver.rs','--extern',f'node94_snapshot_admission={lib}','-o',exe])
        need(p.returncode==0,p.stderr)
        return lib,exe
    profiles={}
    for opt in (0,3):
        _,exe=library(COMPONENT/'lib.rs',output/f'o{opt}',opt)
        p=run([exe],input=result['inputs'].decode())
        need(p.returncode==0 and p.stdout.encode()==result['expected'],'compiled Rust differs')
        (output/f'output-o{opt}.tsv').write_text(p.stdout)
        profiles[str(opt)]={'rows':result['count'],'match':True,'stdout_sha256':sha(p.stdout.encode())}
    def test(source,folder):
        exe=folder/'smoke-test'
        p=run([rustc,'--edition=2021','--test',source,'-o',exe]);need(p.returncode==0,p.stderr)
        return run([exe])
    p=test(COMPONENT/'lib.rs',output);need(p.returncode==0,p.stdout+p.stderr)
    (output/'unit-test-output.txt').write_text(p.stdout)
    source=(COMPONENT/'lib.rs').read_text();mutants=[]
    for name,old,new in [('period','is_multiple_of(10_000)','is_multiple_of(1_000)'),
                         ('past-freeze','return Selected::PastFreezeAssertion','return Selected::Freeze'),
                         ('tag','if tag == 1','if tag == 0')]:
        need(source.count(old)==1,'compiled mutation binding changed')
        folder=output/('mutant-'+name);folder.mkdir()
        changed=folder/'lib.rs';changed.write_text(source.replace(old,new))
        (folder/'target-smoke.tsv').write_bytes((COMPONENT/'target-smoke.tsv').read_bytes())
        _,exe=library(changed,folder/'build',3)
        p=run([exe],input=result['inputs'].decode())
        need(p.returncode==0,'mutant must emit comparison rows')
        actual=p.stdout.splitlines();expected=result['expected'].decode().splitlines()
        mismatch=sum(a!=b for a,b in zip(actual,expected))
        need(len(actual)==len(expected) and mismatch>0,'compiled mutation escaped')
        smoke=test(changed,folder)
        need(smoke.returncode!=0,'mutant passed compiled target-smoke assertions')
        mutants.append({'name':name,'rows':len(actual),'mismatches':mismatch,'compiled_smoke_exit':smoke.returncode})
    repeat,_=library(COMPONENT/'lib.rs',output/'o3-repeat',3)
    original=(output/'o3/libnode94_snapshot_admission.rlib').read_bytes()
    need(original==repeat.read_bytes(),'raw own-rust archive not reproducible')
    report={'rows':result['count'],'distinct_inputs':result['distinct_inputs'],'profiles':profiles,
            'compiled_mutants':mutants,'raw_own_rlib_equal':True,'rlib_sha256':sha(original),
            'source_sha256':sha(source.encode()),'rustc':version,'commands':commands,
            'authorized_offline_python_instruction_evaluation':True,'native_capture_executed':False}
    (output/'build-result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=ROOT/native.BINARY)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=build(args.binary,args.rustc,args.output)
    print(json.dumps({k:report[k] for k in ('rows','distinct_inputs','profiles','compiled_mutants','raw_own_rlib_equal')}))
