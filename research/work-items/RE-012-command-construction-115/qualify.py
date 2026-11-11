#!/usr/bin/env python3
"""Build the actual normal command state and its genuine pinned CString dependency."""
from pathlib import Path
import gzip,hashlib,json,subprocess,shutil,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(P));import oracle,verify
C=R/'src/node115-command-construction'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 out=Path(sys.argv[1]).resolve();assert not out.exists();out.mkdir(parents=True);raw,meta=oracle.freeze();f=json.loads((P/'freeze.json').read_text());assert f['new_rust_exists'] is False and raw==gzip.decompress(bytes.fromhex((P/'cases.tsv.gz.hex').read_text())) and sha(raw)==f['fixture_sha256']
 for k in ['oracle_sha256','scope_sha256']:assert meta[k]==f[k]
 origin=json.loads((C/'cstring/ORIGIN.json').read_text());assert sha((C/'cstring/lib.rs').read_bytes())==origin['source_sha256'];rows=[s.split('\t') for s in raw.decode().splitlines()];inputs=''.join('\t'.join(r[:2])+'\n' for r in rows);expected=''.join(r[2]+'\n' for r in rows);source=(C/'src/lib.rs').read_text();probe=(C/'src/probe.rs').read_text()
 def run(name,body,release):
  d=out/name;(d/'src').mkdir(parents=True)
  for n in ['Cargo.toml','Cargo.lock']:(d/n).write_bytes((C/n).read_bytes())
  shutil.copytree(C/'cstring',d/'cstring');(d/'src/lib.rs').write_text(body);(d/'src/probe.rs').write_text(probe);cmd=['cargo','+1.95.0','build','--offline','--locked','--manifest-path',str(d/'Cargo.toml')]+(['--release'] if release else []);p=subprocess.run(cmd,text=True,capture_output=True);(d/'compiler.stdout').write_text(p.stdout);(d/'compiler.stderr').write_text(p.stderr);assert p.returncode==0,(name,p.stderr);exe=d/'target'/('release' if release else 'debug')/'command-construction-probe';p=subprocess.run([str(exe)],input=inputs,text=True,capture_output=True);(d/'actual.txt').write_text(p.stdout);(d/'stderr.txt').write_text(p.stderr);return p,{'name':name,'exit':p.returncode,'source_sha256':sha(body.encode()),'actual_sha256':sha(p.stdout.encode()),'executable_sha256':sha(exe.read_bytes())}
 results=[]
 for release in [False,True]:
  p,j=run('production-'+str(release),source,release);assert p.returncode==0 and p.stdout==expected;results.append({**j,'matched_rows':len(rows)})
 controls=[('wrong-leading-kind',"if input.first() == Some(&b'/') {\n            2","if input.first() == Some(&b'/') {\n            1"),('backslash-classification',"input.contains(&b'/')","input.contains(&b'\\\\')"),('wrong-placeholder','<string-with-nul>','<invalid-nul>'),('reset-nul-flag','if bad {\n            self.saw_nul = true;\n        }','self.saw_nul = bad;'),('program-pointer-alias','vec![argv0.as_ptr(), ptr::null()]','vec![program.as_ptr(), ptr::null()]'),('missing-null-terminator','self.argv.push(ptr::null());','self.argv.push(pointer);'),('classify-after-substitution','let kind = if','let input=if input.contains(&0){&b"<string-with-nul>"[..]}else{input}; let kind = if')];mutants=[]
 for name,old,new in controls:
  assert source.count(old)==1,(name,source.count(old));p,j=run(name,source.replace(old,new),True);assert p.returncode!=0 or p.stdout!=expected;diff=next((i for i,(a,b) in enumerate(zip(p.stdout.splitlines(),expected.splitlines())) if a!=b),None);mutants.append({**j,'first_output_mismatch':diff,'detected':True})
 j={'cases':len(rows),'freeze':f,'production':results,'compiled_mutants':mutants,'dependency':origin,'source_sha256':sha((C/'src/lib.rs').read_bytes()),'probe_sha256':sha((C/'src/probe.rs').read_bytes()),'captured_execution_or_emulation':False,'limits':'Complete selected normal-return program/argument construction only, no execution or allocation-failure/unwind-state/nativeABI equivalence. Physical pointer ownership assertions are extra post-source controls, not pre-Rust frozen addresses.'};(out/'qualification.json').write_text(json.dumps(j,indent=2)+'\n');print(json.dumps({'cases':len(rows),'production_profiles':2,'compiled_mutants_detected':len(mutants)}))
if __name__=='__main__':main()
