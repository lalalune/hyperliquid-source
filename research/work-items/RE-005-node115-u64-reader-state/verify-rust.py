#!/usr/bin/env python3
"""Run independently built Rust against frozen static expectations and compiled mutants."""
import argparse,hashlib,json,os,struct,subprocess
from pathlib import Path
P=Path(__file__).resolve().parent;ROOT=P.parents[2];SOURCE=ROOT/'src/node115-u64-reader-state'
def require(ok,reason):
    if not ok:raise ValueError(reason)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--rustc',required=True);ap.add_argument('--linker',required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--host',default='x86_64-pc-windows-gnullvm');args=ap.parse_args();out=args.output;out.mkdir(parents=True,exist_ok=True)
    cases=[line.rsplit('\t',1) for line in (P/'cases.tsv').read_text().splitlines()];inputs=('\n'.join(a for a,b in cases)+'\n').encode();expected=[b for a,b in cases]
    raw=(SOURCE/'lib.rs').read_text();probe=(SOURCE/'probe.rs').read_bytes();records=[]
    controls=[
      ('threshold9','input.len() <= 8','input.len() <= 9'),
      ('omit-slow-consumption','if slow {\n            self.remaining = &input[1..];\n        }','if false { self.remaining = &input[1..]; }'),
      ('invert-error-field','if slow { 3 } else { 2 }','if slow { 2 } else { 3 }'),
      ('limit-equality-refused','if next > limit','if next >= limit'),
      ('rollback-limit-charge','self.charged = next;','if next <= limit { self.charged = next; }'),
      ('shortfall-always-one','(width - input.len()) as u64','1'),
      ('wrong-endian','u64::from_le_bytes(value)','u64::from_be_bytes(value)'),
      ('aggregate-charge8','self.charge(32)?;','self.charge(8)?;'),
      ('omit-aggregate-unclaim','self.charged -= 8;','self.charged -= 0;'),
    ]
    def compile_run(name,text,opt):
        d=out/name;d.mkdir(exist_ok=False);(d/'lib.rs').write_text(text);(d/'probe.rs').write_bytes(probe)
        common=['--edition=2024','--target='+args.host,'-C','opt-level='+str(opt),'-C','linker='+args.linker,'-C','linker-flavor=ld.lld'];lib=d/'libreader.rlib';exe=d/'reader.exe'
        commands=[[args.rustc,str(d/'lib.rs'),'--crate-type=rlib','--crate-name=node115_u64_reader_state',*common,'-o',str(lib)],[args.rustc,str(d/'probe.rs'),'--extern','node115_u64_reader_state='+str(lib),*common,'-o',str(exe)]]
        for i,command in enumerate(commands):
            print('$ '+name+' compile '+str(i),flush=True);r=subprocess.run(command,capture_output=True,timeout=60);(d/('compile'+str(i)+'.log')).write_bytes(r.stdout+r.stderr);require(r.returncode==0,'mutant/control compilation '+name)
        r=subprocess.run([str(exe)],input=inputs,capture_output=True,timeout=30);(d/'stdout.txt').write_bytes(r.stdout);(d/'stderr.txt').write_bytes(r.stderr);observed=r.stdout.decode().splitlines();diff=[i+1 for i,(a,b) in enumerate(zip(observed,expected)) if a!=b]
        return {'name':name,'optLevel':opt,'exitCode':r.returncode,'cases':len(cases),'outputRows':len(observed),'differentRows':len(diff),'firstDifferentRow':diff[0] if diff else None,'allMatch':r.returncode==0 and observed==expected,'sourceSHA256':hashlib.sha256(text.encode()).hexdigest(),'exeSHA256':hashlib.sha256(exe.read_bytes()).hexdigest(),'commands':commands}
    for opt in [0,3]:
        r=compile_run('baseline-o'+str(opt),raw,opt);require(r['allMatch'],'baseline frozen cases');records.append(r)
    for name,before,after in controls:
        require(raw.count(before)==1,'unique mutation site '+name);r=compile_run(name,raw.replace(before,after),3);require(not r['allMatch'] and r['differentRows']>0,'mutant not detected '+name);records.append(r)
    result={'frozenCorpusSHA256':hashlib.sha256((P/'cases.tsv').read_bytes()).hexdigest(),'cases':len(cases),'baselineBuilds':2,'compiledMutants':len(controls),'records':records,'targetExecution':False,'meaning':'Logical results against frozen static projection only, not differential target execution or binary identity'}
    (out/'compiled-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='records'}),flush=True)
if __name__=='__main__':main()
