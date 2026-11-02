#!/usr/bin/env python3
"""Authenticate static evidence, then compare independent compiled Rust to pre-Rust observations.
No captured executable, emulator, live network or chain operation is used.
"""
import argparse,gzip,hashlib,importlib.util,json,subprocess
from pathlib import Path
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
KIND='flag-sync'
def require(ok,msg):
    if not ok:raise ValueError(msg)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--rustc',default='rustc');args=parser.parse_args()
    freeze=json.loads((P/'ORACLE-FREEZE.json').read_text())
    for name,digest in freeze['sha256'].items():require(sha(P/name)==digest,'Frozen file changed: '+name)
    for name,digest in freeze['dependencies'].items():require(sha(ROOT/name)==digest,'Admitted dependency changed: '+name)
    admitted=module('admission',P/'admission.py').inspect()
    require(json.loads(json.dumps(admitted))==json.loads((P/'admitted.json').read_text()),'Static target evidence changed')
    oracle=module('oracle',P/'oracle.py');cases=oracle.cases()
    inputs=''.join(','.join(map(str,x))+'\n' for x in cases)
    expected=[','.join(map(str,oracle.expected(x))) for x in cases]
    require(inputs==(P/'inputs.tsv').read_text(),'Frozen inputs differ')
    require('\n'.join(expected)+'\n'==gzip.decompress((P/'expected.tsv.gz').read_bytes()).decode(),'Frozen observations differ')
    require(len(cases)==freeze['cases'],'Case denominator changed')
    source=ROOT/'src'/f'node94-resume-nine-{KIND}'
    work=ROOT/'work'/f'RE-001-resume-nine-{KIND}-rust-94';work.mkdir(parents=True,exist_ok=True)
    out=P/'qualification';out.mkdir(exist_ok=True);streams=out/'streams';streams.mkdir(exist_ok=True)
    commands=[]
    def run(argv,input=None):
        result=subprocess.run(argv,input=input,text=True,capture_output=True,timeout=120,cwd=ROOT)
        ident=f'{len(commands):03d}'
        for channel,text in [('stdout',result.stdout),('stderr',result.stderr)]:
            sanitized=text.replace(str(ROOT),'<REPO>').replace(str(Path.home()),'<HOME>')
            (streams/f'{ident}.{channel}.txt.gz').write_bytes(gzip.compress(sanitized.encode(),mtime=0))
        commands.append({'argv':[str(x).replace(str(ROOT),'<REPO>').replace(args.rustc,'<RUSTC>')for x in argv],'exit_code':result.returncode,'stream_id':ident,'stdin_sha256':None if input is None else hashlib.sha256(input.encode()).hexdigest()})
        require(result.returncode==0,'Qualification command failed: '+ident+'\n'+result.stderr)
        return result.stdout
    def build(lib,directory,opt):
        directory.mkdir(parents=True,exist_ok=True)
        flags=['--edition=2021','-C',f'opt-level={opt}','--remap-path-prefix',str(ROOT)+'=<REPO>']
        run([args.rustc,*flags,'--crate-type=rlib','--crate-name=node94_leaf',str(lib),'-o',str(directory/'libnode94_leaf.rlib')])
        run([args.rustc,*flags,str(source/'client.rs'),'--extern','node94_leaf='+str(directory/'libnode94_leaf.rlib'),'-o',str(directory/'client')])
        return directory/'client'
    builds=[]
    for opt in [0,3]:
        hashes=[]
        for repeat in [1,2]:
            directory=work/f'O{opt}-{repeat}';exe=build(source/'lib.rs',directory,opt)
            actual=run([str(exe)],input=inputs).splitlines()
            require(actual==expected,'Compiled Rust disagrees with pre-Rust observations')
            (out/f'O{opt}-{repeat}.txt.gz').write_bytes(gzip.compress(('\n'.join(actual)+'\n').encode(),mtime=0))
            hashes.append({n:sha(directory/n) for n in ['client','libnode94_leaf.rlib']})
        require(hashes[0]==hashes[1],'Repeated compiler artifacts differ')
        builds.append({'opt_level':opt,'cases':len(cases),'repeat_byte_identical':True,'artifact_sha256':hashes[0]})
    primary=(source/'lib.rs').read_text();mutations=[('invert-clear', 'memory.load_u64(base)? != 0', 'memory.load_u64(base)? == 0'), ('invert-copy', 'value != memory.load_u64(base.wrapping_add(0x58))?', 'value == memory.load_u64(base.wrapping_add(0x58))?'), ('wrong-return-register', 'Ok(value)', 'Ok(0)')];controls=[]
    for name,old,new in mutations:
        require(old in primary,'Mutation no longer applies: '+name)
        mutant=work/(name+'.rs');mutant.write_text(primary.replace(old,new));exe=build(mutant,work/name,3)
        actual=run([str(exe)],input=inputs).splitlines()
        require(len(actual)==len(expected),'Mutant omitted observations: '+name)
        mismatches=[i for i,(a,b)in enumerate(zip(actual,expected))if a!=b]
        successful=[i for i in mismatches if actual[i].startswith('0,') and expected[i].startswith('0,')]
        require(bool(mismatches) and bool(successful),'Mutation did not change an admitted successful observation: '+name)
        index=successful[0];raw='\n'.join(actual)+'\n';(out/(name+'.txt.gz')).write_bytes(gzip.compress(raw.encode(),mtime=0))
        controls.append({'name':name,'cases':len(cases),'mismatches':len(mismatches),'joint_success_mismatches':len(successful),'process_exit':0,'output_sha256':hashlib.sha256(raw.encode()).hexdigest(),'first_joint_success_witness':{'index':index,'input':cases[index],'expected':expected[index],'actual':actual[index]}})
    compiler=run([args.rustc,'-Vv']).strip()
    record={'base':freeze['base'],'target_sha256':freeze['target_sha256'],'kind':KIND,'cases':len(cases),'source_sha256':{n:sha(source/n)for n in ['lib.rs','client.rs']},'qualifier_sha256':sha(P/'verify.py'),'primary_successful_observations':sum(x.startswith('0,')for x in expected),'builds':builds,'negative_controls':controls,'compiler':compiler,'commands':commands,'captured_binary_executed':False,'instruction_emulator_used':False,'native_abi_fault_equivalence':False,'full_component_gate_requested':False}
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'kind':KIND,'cases':len(cases),'primary_successes':record['primary_successful_observations'],'builds':4,'negative_controls':[{k:v for k,v in c.items()if k not in ['first_joint_success_witness']}for c in controls]}))
if __name__=='__main__':main()
