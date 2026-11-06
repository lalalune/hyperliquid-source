#!/usr/bin/env python3
"""Compile independent date/time text rendering and compare frozen stdlib formatting."""
from pathlib import Path
import argparse,hashlib,json,subprocess
import oracle
P=Path(__file__).resolve().parent;ROOT=P.parents[2];SRC=ROOT/'src/node115-timespec-difference/src/lib.rs';PROBE=SRC.with_name('probe.rs')
def sha(b):return hashlib.sha256(b).hexdigest()
def need(v,m):
 if not v:raise ValueError(m)
def main(out,rustc):
 out.mkdir(parents=True,exist_ok=False);f=json.loads((P/'freeze.json').read_text());need(not f['new_rust_exists_at_freeze'],'not pre-Rust frozen');g=oracle.freeze()
 for k,v in g.items():need(f[k]==v,'oracle freeze drift '+k)
 inputs=''.join(' '.join(map(str,r))+'\n' for r in oracle.rows()).encode();expected=''.join(oracle.result(r)+'\n' for r in oracle.rows()).encode();(out/'input.txt').write_bytes(inputs);(out/'expected.txt').write_bytes(expected)
 def run(cmd,label,stdin=None):
  r=subprocess.run(cmd,input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT);(out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr);need(r.returncode==0,'process '+label);return r.stdout
 def build(path,label,opt):
  lib=out/('lib'+label+'.rlib');exe=out/(label+'.exe')
  run([rustc,'--edition=2024','--crate-name','node115_timespec_difference','--crate-type=rlib','-C','opt-level='+str(opt),str(path),'-o',str(lib)],label+'-lib')
  run([rustc,'--edition=2024',str(PROBE),'--extern','node115_timespec_difference='+str(lib),'-o',str(exe)],label+'-probe')
  return run([str(exe)],label+'-actual',inputs)
 builds=[]
 for opt in [0,3]:
  label='opt'+str(opt);actual=build(SRC,label,opt);need(actual==expected,'production mismatch '+label);builds.append({'opt_level':opt,'cases':g['cases'],'output_sha256':sha(actual)})
 text=SRC.read_text();mutations={
 'equal-is-negative':('if self >= other {','if self > other {'),
 'positive-result-tag':('Ok(self.magnitude(other))','Err(self.magnitude(other))'),
 'negative-result-tag':('Err(other.magnitude(self))','Ok(other.magnitude(self))'),
 'clamp-unsigned-seconds-span':('self.seconds.abs_diff(other.seconds)','self.seconds.abs_diff(other.seconds).min(i64::MAX as u64)'),
 'omit-seconds-borrow':('seconds - 1,','seconds,'),
 'borrow-base-minus-one':('self.nanoseconds + 1_000_000_000 - other.nanoseconds','self.nanoseconds + 999_999_999 - other.nanoseconds'),
 'reject-valid-nanos-max':('nanoseconds >= 1_000_000_000','nanoseconds >= 999_999_999'),
 }
 killed=[]
 for label,(old,new) in mutations.items():
  need(text.count(old)==1,'mutant selector '+label);path=out/(label+'.rs');path.write_text(text.replace(old,new));actual=build(path,label,3);need(actual!=expected,'surviving mutant '+label)
  a=actual.splitlines();e=expected.splitlines();row=next(i for i,(x,y) in enumerate(zip(a,e)) if x!=y);killed.append({'name':label,'normal_exit':True,'first_case':row,'input':inputs.splitlines()[row].decode(),'actual':a[row].decode()[:300],'expected':e[row].decode()[:300]})
 result={'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','cases':g['cases'],'freeze':f,'builds':builds,'mutants':killed,'source_sha256':sha(SRC.read_bytes()),'probe_sha256':sha(PROBE.read_bytes()),'captured_execution_or_emulation':False,'oracle_limits':'independent Python arbitrary-precision signed nanoseconds; no native execution or ABI equivalence','rustc':run([rustc,'--version'],'rustc-version').decode().strip()}
 (out/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'cases':g['cases'],'builds':len(builds),'mutants_killed':len(killed)},indent=2))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);ap.add_argument('--rustc',default='rustc');a=ap.parse_args();main(a.out.resolve(),a.rustc)
