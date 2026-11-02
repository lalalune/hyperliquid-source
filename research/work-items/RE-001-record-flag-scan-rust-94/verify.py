#!/usr/bin/env python3
"""Static target admission and frozen observations against authored Rust only."""
from pathlib import Path
import argparse,gzip,hashlib,importlib.util,json,subprocess
P=Path(__file__).resolve().parent
ROOT=P.parents[2]
KIND='record-flag-scan'
MUTATIONS=[('lose-slow-rax-prefix', 'let prefix = (count << 4) & !0xff;', 'let prefix = 0;'), ('lose-fast-rax-prefix', 'return Ok((returned & !0xff) | 1);', 'return Ok(1);'), ('wrong-fast-threshold', 'count >= 10001', 'count >= 10000'), ('skip-empty-pointer-read', 'let mut pointer = view.read_u64(object.wrapping_add(8))?;', 'if count == 0 { return Ok(1); }\n    let mut pointer = view.read_u64(object.wrapping_add(8))?;')]
def require(ok,message):
    if not ok:raise ValueError(message)
def digest(data):return hashlib.sha256(data).hexdigest()
def sha(path):return digest(path.read_bytes())
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--rustc',default='rustc');args=parser.parse_args()
    frozen=json.loads((P/'ORACLE-FREEZE.json').read_text())
    corpus=gzip.decompress((P/'vectors.tsv.gz').read_bytes())
    for name,wanted in frozen['sha256'].items():
        actual=digest(corpus) if name=='vectors.tsv' else sha(P/name)
        require(actual==wanted,'Frozen input changed: '+name)
    admit=load('scoped_admission',P/'admit.py')
    require(admit.source_hashes()==frozen['source_dependencies'],'Pinned checker/dependency bytes changed')
    binary=(ROOT/'artifacts/node/94/hl-node').read_bytes()
    observed=admit.inspect(binary);wanted=json.loads((P/'admitted.json').read_text())
    require(json.loads(json.dumps(observed))==wanted,'Target static admission changed')
    admit.check_selected_regions(binary,wanted)
    structural=[];changed=bytearray(binary)
    for region in wanted['regions']:
        position=region['file_offset'];changed[position]^=1
        try:admit.check_selected_regions(changed,wanted)
        except ValueError:rejected=True
        else:rejected=False
        changed[position]^=1
        require(rejected,'Changed selected region admitted')
        structural.append({'region':region['name'],'changed_file_offset':position,'rejected_below_whole_digest':True})
    outside=len(changed)-1
    require(not any(r['file_offset']<=outside<r['file_offset']+r['bytes'] for r in wanted['regions']),'Choose a truly unselected byte')
    changed[outside]^=1
    admit.check_selected_regions(changed,wanted)
    try:admit.inspect(changed)
    except ValueError:rejected=True
    else:rejected=False
    require(rejected,'Whole-capture mismatch admitted')
    oracle=load('scoped_oracle',P/'oracle.py')
    vectors=corpus.decode().splitlines()
    regenerated=[','.join(map(str,x))+'\t'+','.join(map(str,oracle.expected(x))) for x in oracle.cases()]
    require(vectors==regenerated,'Frozen independent observations differ')
    inputs='\n'.join(row.split('\t')[0] for row in vectors)+'\n'
    expected=[row.split('\t')[1] for row in vectors]
    source=ROOT/'src'/('node94-'+KIND)
    work=ROOT/'work'/('RE-001-'+KIND+'-rust-94');work.mkdir(parents=True,exist_ok=True)
    output=P/'qualification';output.mkdir(exist_ok=True)
    commands=[]
    def run(argv,**kwargs):
        command=[str(v).replace(str(ROOT),'<REPO>').replace(args.rustc,'<RUSTC>') for v in argv]
        result=subprocess.run(argv,text=True,capture_output=True,timeout=180,**kwargs)
        commands.append({'argv':command,'exit':result.returncode})
        log={'argv':command,'exit':result.returncode,'stdout':result.stdout.replace(str(ROOT),'<REPO>'),'stderr':result.stderr.replace(str(ROOT),'<REPO>')}
        (output/f'command-{len(commands):03}.json.gz').write_bytes(gzip.compress((json.dumps(log,indent=2)+'\n').encode(),mtime=0))
        require(result.returncode==0,'Command failed: '+str(command)+'\n'+result.stderr)
        return result.stdout
    def build(library,directory,opt):
        directory.mkdir(parents=True,exist_ok=True)
        options=['--edition=2021','-C',f'opt-level={opt}','--remap-path-prefix',str(ROOT)+'=<REPO>']
        run([args.rustc,*options,'--crate-name=node94_leaf','--crate-type=rlib',str(library),'-o',str(directory/'libnode94_leaf.rlib')])
        run([args.rustc,*options,str(source/'client.rs'),'--extern','node94_leaf='+str(directory/'libnode94_leaf.rlib'),'-o',str(directory/'client')])
        return directory/'client'
    profiles=[]
    for opt in [0,3]:
        hashes=[]
        for repeat in [1,2]:
            directory=work/f'O{opt}-{repeat}';exe=build(source/'lib.rs',directory,opt)
            actual=run([str(exe)],input=inputs).splitlines()
            require(actual==expected,'Rust output differs from frozen target-grounded relation')
            raw=('\n'.join(actual)+'\n').encode()
            (output/f'O{opt}-{repeat}.txt.gz').write_bytes(gzip.compress(raw,mtime=0))
            hashes.append({name:sha(directory/name) for name in ['client','libnode94_leaf.rlib']})
        require(hashes[0]==hashes[1],'Repeated artifacts differ')
        profiles.append({'opt_level':opt,'cases_per_execution':len(expected),'repeat_artifacts_byte_identical':True,'artifact_sha256':hashes[0]})
    original=(source/'lib.rs').read_text();controls=[]
    for name,old,new in MUTATIONS:
        require(old in original,'Compiled mutation no longer applies: '+name)
        path=work/(name+'.rs');path.write_text(original.replace(old,new))
        exe=build(path,work/name,3);actual=run([str(exe)],input=inputs).splitlines()
        require(len(actual)==len(expected),'Mutant did not produce every observation')
        differences=[i for i,(a,b)in enumerate(zip(actual,expected)) if a!=b]
        require(differences,'Mutation was not detected: '+name)
        first=differences[0];a=actual[first].split(',');b=expected[first].split(',')
        position=next((i for i in range(max(len(a),len(b))) if (a[i] if i<len(a) else None)!=(b[i] if i<len(b) else None)),None)
        (output/(name+'.txt.gz')).write_bytes(gzip.compress(('\n'.join(actual)+'\n').encode(),mtime=0))
        controls.append({'name':name,'mismatches':len(differences),'cases':len(expected),'process_exit':0,'first_witness':{'case':first,'input':vectors[first].split('\t')[0],'first_different_output_column':position,'actual':a[position] if position<len(a) else None,'expected':b[position] if position<len(b) else None}})
    version=run([args.rustc,'-Vv']).strip()
    result={'base':frozen['base'],'target_sha256':frozen['target_sha256'],'kind':KIND,'cases':len(expected),'frozen_sha256':sha(P/'ORACLE-FREEZE.json'),'source_sha256':{name:sha(source/name) for name in ['lib.rs','client.rs']},'qualifier_sha256':sha(P/'verify.py'),'profiles':profiles,'compiled_controls':controls,'structural_controls':structural,'outside_selected_regions_control':{'selected_region_check_passed':True,'whole_capture_check_rejected':True},'rustc':version,'commands':commands,'captured_program_executed':False,'instruction_emulator_used':False,'full_component_gate_requested':False,'native_abi_or_fault_equivalence_claimed':False}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'kind':KIND,'cases':len(expected),'compiled_controls':[{k:v for k,v in x.items() if k!='first_witness'} for x in controls],'structural_controls':len(structural)}))
if __name__=='__main__':main()
