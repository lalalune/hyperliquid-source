#!/usr/bin/env python3
"""Static admission plus frozen observations vs separately compiled Rust.
Never execute the captured node, visor, or an instruction emulator.
"""
import argparse, gzip, hashlib, importlib.util, json, subprocess, sys
from pathlib import Path
P=Path(__file__).resolve().parent
ROOT=P.parents[2]
KIND='gated-byte'
TOOL='foundation_gated_byte_test'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--rustc',default='rustc');args=ap.parse_args()
    freeze=json.loads((P/'ORACLE-FREEZE.json').read_text())
    for name,digest in freeze['sha256'].items():require(sha(P/name)==digest,'frozen file changed: '+name)
    require(sha(ROOT/'tools'/f'{TOOL}.py')==freeze['checker_sha256'],'base checker changed')
    sys.path.insert(0,str(ROOT/'tools'))
    checker=load('admission',ROOT/'tools'/f'{TOOL}.py')
    observed=checker.inspect(ROOT/'artifacts/node/94/hl-node')
    require(json.loads(json.dumps(observed))==json.loads((P/'admitted.json').read_text()),'target admission changed')
    oracle=load('oracle',P/'oracle.py')
    vectors=(P/'vectors.tsv').read_text().splitlines()
    regenerated=[','.join(map(str,x))+'\t'+','.join(map(str,oracle.expected(x))) for x in oracle.cases()]
    require(vectors==regenerated,'frozen observations do not reproduce')
    inputs='\n'.join(row.split('\t')[0] for row in vectors)+'\n'
    expected=[row.split('\t')[1] for row in vectors]
    source=ROOT/'src'/f'node94-{KIND}'
    work=ROOT/'work'/f'RE-001-{KIND}-rust-94';work.mkdir(parents=True,exist_ok=True)
    output=P/'qualification';output.mkdir(exist_ok=True)
    commands=[]
    def run(argv,**kw):
        commands.append([str(x).replace(str(ROOT),'<REPO>').replace(args.rustc,'<RUSTC>') for x in argv])
        r=subprocess.run(argv,text=True,capture_output=True,timeout=120,**kw)
        require(r.returncode==0,'command failed: '+str(argv)+'\n'+r.stderr)
        return r.stdout
    def build(lib,out,opt):
        out.mkdir(parents=True,exist_ok=True)
        common=['--edition=2021','-C',f'opt-level={opt}','--remap-path-prefix',str(ROOT)+'=<REPO>']
        run([args.rustc,*common,'--crate-type=rlib','--crate-name=node94_leaf',str(lib),'-o',str(out/'libnode94_leaf.rlib')])
        run([args.rustc,*common,str(source/'client.rs'),'--extern','node94_leaf='+str(out/'libnode94_leaf.rlib'),'-o',str(out/'client')])
        return out/'client'
    builds=[]
    for opt in [0,3]:
        pairs=[]
        for repeat in [1,2]:
            directory=work/f'O{opt}-{repeat}'
            exe=build(source/'lib.rs',directory,opt)
            actual=run([str(exe)],input=inputs).splitlines()
            require(actual==expected,'compiled Rust disagrees with frozen observations')
            (output/f'O{opt}-{repeat}.txt.gz').write_bytes(gzip.compress(('\n'.join(actual)+'\n').encode(),mtime=0))
            pairs.append({name:sha(directory/name) for name in ['client','libnode94_leaf.rlib']})
        require(pairs[0]==pairs[1],'repeat build bytes differ')
        builds.append({'opt_level':opt,'cases':len(expected),'repeat_byte_identical':True,'artifacts':pairs[0]})
    original=(source/'lib.rs').read_text()
    mutations=[('truncate-qword', 'memory.load_u64(base.wrapping_add(0xb0))? == 0', 'memory.load_u64(base.wrapping_add(0xb0))? as u32 == 0'), ('invert-gate', 'memory.load_u8(base.wrapping_add(0xb8))? == 0', 'memory.load_u8(base.wrapping_add(0xb8))? != 0')]
    controls=[]
    for name,old,new in mutations:
        require(old in original,'mutation no longer applies: '+name)
        mutant=work/(name+'.rs');mutant.write_text(original.replace(old,new))
        exe=build(mutant,work/name,3)
        actual=run([str(exe)],input=inputs).splitlines()
        require(len(actual)==len(expected),'mutant exited without all observations')
        mismatches=sum(a!=b for a,b in zip(actual,expected))
        require(mismatches>0,'comparator failed to reject mutation: '+name)
        controls.append({'name':name,'mismatches':mismatches,'cases':len(expected),'process_exit':0})
    result={'base':freeze['base'],'kind':KIND,'target_sha256':freeze['target'],'cases':len(expected),'source_sha256':{name:sha(source/name) for name in ['lib.rs','client.rs']},'qualifier_sha256':sha(P/'verify.py'),'builds':builds,'negative_controls':controls,'rustc':run([args.rustc,'-Vv']).strip(),'commands':commands,'captured_binary_executed':False,'instruction_emulator_used':False,'native_abi_or_fault_equivalence':False,'whole_component_gate_requested':False}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'kind':KIND,'cases':len(expected),'builds':len(builds)*2,'negative_controls':controls}))
if __name__=='__main__':main()
