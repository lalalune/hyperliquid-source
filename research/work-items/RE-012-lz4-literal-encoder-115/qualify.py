#!/usr/bin/env python3
"""Compile the independently authored Rust, compare every sink byte, kill mutants."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys
import oracle
P=Path(__file__).resolve().parent;ROOT=P.parents[2];SRC=ROOT/'src/node115-lz4-literal-encoder/src/lib.rs';PROBE=SRC.with_name('probe.rs')
def sha(b):return hashlib.sha256(b).hexdigest()
def need(v,m):
 if not v:raise ValueError(m)
def main(out,rustc):
 out.mkdir(parents=True,exist_ok=False);f=json.loads((P/'freeze.json').read_text());need(not f['new_rust_exists_at_freeze'],'not pre-Rust frozen');g=oracle.generate()
 for k,v in g.items():need(f[k]==v,'oracle freeze drift '+k)
 # Reciprocal optimization: C*255=2**71+127; for all x<=2**64-1,
 # error x*127/(255*2**71)<1/255. Because x/255 has fractional
 # multiples of 1/255, floor(x*C/2**71) == floor(x/255).
 C=0x8080808080808081;need(C*255==2**71+127,'reciprocal');need((2**64-1)*127<2**71,'reciprocal error bound')
 inputs=''.join(' '.join(map(str,r))+'\n' for r in oracle.cases()).encode();expected=''.join(oracle.result(r)+'\n' for r in oracle.cases()).encode();(out/'input.txt').write_bytes(inputs);(out/'expected.txt').write_bytes(expected)
 def run(cmd,label,stdin=None):
  r=subprocess.run(cmd,input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT);(out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr);need(r.returncode==0,'process '+label);return r.stdout
 def build(path,label,opt):
  lib=out/('lib'+label+'.rlib');exe=out/(label+'.exe')
  run([rustc,'--edition=2024','--crate-name','node115_lz4_literal_encoder','--crate-type=rlib','-C','opt-level='+str(opt),str(path),'-o',str(lib)],label+'-lib')
  run([rustc,'--edition=2024',str(PROBE),'--extern','node115_lz4_literal_encoder='+str(lib),'-o',str(exe)],label+'-probe')
  return run([str(exe)],label+'-actual',inputs)
 builds=[]
 for opt in [0,3]:
  label='opt'+str(opt);actual=build(SRC,label,opt);need(actual==expected,'production mismatch '+label);builds.append({'opt_level':opt,'cases':g['cases'],'output_sha256':sha(actual)})
 text=SRC.read_text();mutations={
 'token-low-nibble':('(count.min(15) as u8) << 4','((count.min(15) as u8) << 4) | 1'),
 'skip-required-zero-extension':('if count >= 15 {','if count > 15 {'),
 'ff-boundary':('while excess >= 255 {','while excess > 255 {'),
 'extension-divisor':('excess -= 255;','excess -= 254;'),
 'partial-append':('return Err(Error::Literals);\n    }','let spare = sink.len() - *used; sink[*used..].copy_from_slice(&input[anchor..anchor + spare]);\n        return Err(Error::Literals);\n    }'),
 'length-before-copy':('*used = next;','*used = next - 1;'),
 }
 killed=[]
 for label,(old,new) in mutations.items():
  need(text.count(old)==1,'mutant selector '+label);path=out/(label+'.rs');path.write_text(text.replace(old,new));actual=build(path,label,3);need(actual!=expected,'surviving mutant '+label)
  a=actual.splitlines();e=expected.splitlines();row=next(i for i,(x,y) in enumerate(zip(a,e)) if x!=y);killed.append({'name':label,'normal_exit':True,'first_case':row,'input':inputs.splitlines()[row].decode(),'actual':a[row].decode()[:150],'expected':e[row].decode()[:150]})
 result={'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','cases':g['cases'],'freeze':f,'builds':builds,'mutants':killed,'source_sha256':sha(SRC.read_bytes()),'probe_sha256':sha(PROBE.read_bytes()),'captured_execution_or_emulation':False,'reciprocal_identity':'all unsigned64 x; integer-error bound, no captured instruction evaluator'}
 (out/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'cases':g['cases'],'builds':len(builds),'mutants_killed':len(killed)},indent=2))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);ap.add_argument('--rustc',default='rustc');a=ap.parse_args();main(a.out.resolve(),a.rustc)
