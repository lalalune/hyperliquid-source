#!/usr/bin/env python3
"""Reauthenticate static target evidence and compare independently compiled Rust.
Captured node/visor code and instruction emulators are never executed.
"""
import argparse,gzip,hashlib,importlib.util,json,struct,subprocess,sys
from pathlib import Path
P=Path(__file__).resolve().parent;ROOT=P.parents[2];KIND='copy16'
FDE_OFFSETS=[(2869668, 88426256, 88426286)]
MUTATIONS=[('shifted-destination', 'memory.write_16(dest, chunk)?', 'memory.write_16(dest.wrapping_add(1), chunk)?'), ('reversed-snapshot', 'let chunk = memory.read_16(q.wrapping_sub(0x10))?;', 'let mut chunk = memory.read_16(q.wrapping_sub(0x10))?; chunk.reverse();'), ('wrong-return', 'rax: 1,', 'rax: 2,'), ('wrong-rdx', 'rdx: q,', 'rdx: q.wrapping_add(16),')]
def require(ok,message):
    if not ok:raise ValueError(message)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--rustc',default='rustc');args=ap.parse_args()
    freeze=json.loads((P/'ORACLE-FREEZE.json').read_text())
    for name,sha in freeze['sha256'].items():require(digest(P/name)==sha,'frozen file changed: '+name)
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
    require(len(data)==91774280 and hashlib.sha256(data).hexdigest()==freeze['target_sha256'],'capture identity changed')
    sys.path.insert(0,str(ROOT/'tools'));reports=[]
    for tool,sha in freeze['checker_sha256'].items():
        path=ROOT/'tools'/f'{tool}.py';require(digest(path)==sha,'base inspector changed')
        m=load(tool,path)
        observed=m.inspect(ROOT/'artifacts/node/94/hl-node') if hasattr(m,'inspect') else m.analyze(data)
        reports.append({'checker':tool,'report':observed})
    require(json.loads(json.dumps(reports))==json.loads((P/'admitted.json').read_text()),'base target evidence differs')
    from elf_index import sections
    eh=next(s for s in sections(data) if s['name']=='.eh_frame');fdes=[]
    for offset,start,end in FDE_OFFSETS:
        raw=data[eh['offset']+offset:eh['offset']+offset+16]
        length,cie,relative,extent=struct.unpack('<IIiI',raw)
        require(length>=12 and length<128,'FDE length invalid')
        require(offset+4-cie==0,'unexpected CIE reference')
        pc=eh['address']+offset+8+relative
        require((pc,pc+extent)==(start,end),'raw FDE range differs')
        record=data[eh['offset']+offset:eh['offset']+offset+length+4]
        fdes.append({'section_offset':hex(offset),'start':hex(pc),'end':hex(pc+extent),'record_sha256':hashlib.sha256(record).hexdigest(),'raw_hex':record.hex()})
    oracle=load('frozen_oracle',P/'oracle.py')
    lines=gzip.decompress((P/'vectors.tsv.gz').read_bytes()).decode().splitlines()
    regenerated=[','.join(map(str,x))+'\t'+','.join(map(str,oracle.expected(x))) for x in oracle.cases()]
    require(lines==regenerated,'frozen corpus does not reproduce')
    inputs='\n'.join(row.split('\t')[0] for row in lines)+'\n'
    expected=[row.split('\t')[1] for row in lines]
    require(len(expected)==freeze['cases'],'wrong observation denominator')
    source=ROOT/'src'/f'node94-remaining-nine-{KIND}'
    work=ROOT/'work'/f'RE-001-remaining-nine-{KIND}-rust-94';work.mkdir(parents=True,exist_ok=True)
    output=P/'qualification';output.mkdir(exist_ok=True)
    streams=output/'commands';streams.mkdir(exist_ok=True)
    commands=[]
    def sanitize(s):return s.replace(str(ROOT),'<REPO>').replace(str(Path.home()),'<HOME>').replace(args.rustc,'<RUSTC>')
    def run(argv,input=None):
        result=subprocess.run(argv,input=input,text=True,capture_output=True,timeout=120)
        ordinal=len(commands)
        stdout=result.stdout if input is not None else sanitize(result.stdout)
        payload={'command':[sanitize(str(v)) for v in argv],'exit_code':result.returncode,'stdout':stdout,'stderr':sanitize(result.stderr)}
        raw=(json.dumps(payload,ensure_ascii=False)+'\n').encode()
        path=streams/f'{ordinal:03}.json.gz';path.write_bytes(gzip.compress(raw,mtime=0))
        commands.append({'command':payload['command'],'exit_code':result.returncode,'stream':str(path.relative_to(P)),'stream_sha256':digest(path)})
        require(result.returncode==0,'command failed: '+str(payload['command'])+'\n'+payload['stderr'])
        return result.stdout
    def build(lib,directory,opt):
        directory.mkdir(parents=True,exist_ok=True)
        common=['--edition=2021','-C',f'opt-level={opt}','--remap-path-prefix',str(ROOT)+'=<REPO>']
        run([args.rustc,*common,'--crate-type=rlib','--crate-name=node94_leaf',str(lib),'-o',str(directory/'libnode94_leaf.rlib')])
        run([args.rustc,*common,str(source/'client.rs'),'--extern','node94_leaf='+str(directory/'libnode94_leaf.rlib'),'-o',str(directory/'client')])
        return directory/'client'
    builds=[]
    for opt in [0,3]:
        identities=[]
        for repeat in [1,2]:
            directory=work/f'O{opt}-{repeat}';exe=build(source/'lib.rs',directory,opt)
            actual=run([str(exe)],inputs).splitlines()
            require(actual==expected,'compiled Rust/frozen observation disagreement')
            (output/f'O{opt}-{repeat}.csv.gz').write_bytes(gzip.compress(('\n'.join(actual)+'\n').encode(),mtime=0))
            identities.append({name:digest(directory/name) for name in ['client','libnode94_leaf.rlib']})
        require(identities[0]==identities[1],'repeat binary build differs')
        builds.append({'opt_level':opt,'cases':len(expected),'repeats':2,'raw_identical_repeat':True,'artifacts':identities[0]})
    original=(source/'lib.rs').read_text();controls=[]
    for name,old,new in MUTATIONS:
        require(old in original,'mutation no longer applies: '+name)
        mutant=work/(name+'.rs');mutant.write_text(original.replace(old,new))
        actual=run([str(build(mutant,work/name,3))],inputs).splitlines()
        require(len(actual)==len(expected),'mutant omitted observations')
        mismatches=[i for i,(a,b)in enumerate(zip(actual,expected)) if a!=b]
        require(bool(mismatches),'comparator missed mutation: '+name)
        positive=sum(1 for i in mismatches if KIND=='error-continuation' or(expected[i].startswith('0,') and actual[i].startswith('0,')))
        require(positive>0,'mutation changes only safe refusals: '+name)
        (output/f'mutant-{name}.csv.gz').write_bytes(gzip.compress(('\n'.join(actual)+'\n').encode(),mtime=0))
        i=mismatches[0]
        controls.append({'name':name,'mismatches':len(mismatches),'successful_observation_mismatches':positive,'cases':len(expected),'process_exit':0,'first_witness':{'input':lines[i].split('\t')[0],'expected':expected[i],'actual':actual[i]}})
    version=run([args.rustc,'-Vv']).strip()
    result={'base':freeze['base'],'kind':KIND,'target_sha256':freeze['target_sha256'],'cases':len(expected),'safe_success_cases':len(expected) if KIND=='error-continuation' else sum(x.startswith('0,')for x in expected),'source_sha256':{name:digest(source/name) for name in ['lib.rs','client.rs']},'qualifier_sha256':digest(P/'verify.py'),'fde_decode':fdes,'builds':builds,'negative_controls':controls,'rustc':version,'commands':commands,'captured_binary_executed':False,'instruction_emulator_used':False,'native_abi_or_fault_equivalence':False,'progress_gate_requested':False}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'kind':KIND,'cases':len(expected),'success':result['safe_success_cases'],'negative_controls':[(c['name'],c['mismatches'],c['successful_observation_mismatches'])for c in controls]}))
if __name__=='__main__':main()
