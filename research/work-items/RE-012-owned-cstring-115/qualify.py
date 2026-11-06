#!/usr/bin/env python3
"""Actual compiled Rust / System allocator controls, no captured execution."""
from pathlib import Path
import json,gzip,hashlib,subprocess,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(P));import oracle,verify
C=R/'src/node115-owned-cstring'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 out=Path(sys.argv[1]).resolve();assert not out.exists();out.mkdir(parents=True);raw,meta=oracle.freeze();f=json.loads((P/'freeze.json').read_text());stored=gzip.decompress(bytes.fromhex((P/'cases.tsv.gz.hex').read_text()));assert raw==stored and sha(raw)==f['fixture_sha256'] and f['new_rust_exists'] is False
 for k in ['oracle_sha256','scope_sha256']:assert meta[k]==f[k]
 rows=[s.split('\t') for s in raw.decode().splitlines()];frozen_rows=len(rows);extra=[(a,1,bytes(n)) for a in range(16) for n in [1,7,15,16,17,33,256,385]];rows += [[str(a),str(fail),b.hex(),oracle.result((a,fail,b))] for a,fail,b in extra];inputs=''.join('\t'.join(r[:3])+'\n' for r in rows);expected=''.join(r[3]+'\n' for r in rows);source=(C/'src/lib.rs').read_text();probe=(C/'src/probe.rs').read_text();results=[]
 def run(name,body,release):
  d=out/name;(d/'src').mkdir(parents=True)
  for n in ['Cargo.toml','Cargo.lock']:(d/n).write_bytes((C/n).read_bytes())
  (d/'src/lib.rs').write_text(body);(d/'src/probe.rs').write_text(probe);cmd=['cargo','+1.95.0','build','--offline','--locked','--manifest-path',str(d/'Cargo.toml')]+(['--release'] if release else []);p=subprocess.run(cmd,text=True,capture_output=True);(d/'compiler.stdout').write_text(p.stdout);(d/'compiler.stderr').write_text(p.stderr);assert p.returncode==0,(name,p.stderr)
  exe=d/'target'/('release' if release else 'debug')/'owned-cstring-probe';p=subprocess.run([str(exe)],input=inputs,text=True,capture_output=True);(d/'actual.txt').write_text(p.stdout);(d/'stderr.txt').write_text(p.stderr);return p,{'name':name,'exit':p.returncode,'actual_sha256':sha(p.stdout.encode()),'executable_sha256':sha(exe.read_bytes())}
 for release in [False,True]:
  p,j=run('production-'+str(release),source,release);assert p.returncode==0 and p.stdout==expected;results.append({**j,'matched_rows':len(rows)})
 controls=[('reject_before_allocation','let mut bytes = Vec::new();','if let Some(position)=input.iter().position(|b|*b==0){return Err(Error::InteriorNul{position,bytes:Vec::new()});} let mut bytes = Vec::new();'),('extra_capacity','try_reserve_exact(capacity)','try_reserve_exact(capacity + 1)'),('last_nul','input.iter().position','input.iter().rposition'),('wrong_nul_byte','*b == 0','*b == 1'),('wrong_terminator','bytes.push(0);','bytes.push(1);'),('off_by_one_position','position, bytes','position: position + 1, bytes'),('append_on_rejection','return Err(Error::InteriorNul { position, bytes });','bytes.push(0); return Err(Error::InteriorNul { position, bytes });')];mutants=[]
 for name,old,new in controls:
  assert source.count(old)==1,(name,source.count(old));p,j=run(name,source.replace(old,new),True);assert p.returncode!=0 or p.stdout!=expected;diff=next((i for i,(a,b) in enumerate(zip(p.stdout.splitlines(),expected.splitlines())) if a!=b),None);mutants.append({**j,'first_output_mismatch':diff,'detected':True})
 j={'cases':len(rows),'pre_rust_frozen_cases':frozen_rows,'post_rust_additional_allocation_order_cases':len(extra),'freeze':f,'production':results,'compiled_mutants':mutants,'source_sha256':sha((C/'src/lib.rs').read_bytes()),'probe_sha256':sha((C/'src/probe.rs').read_bytes()),'captured_execution_or_emulation':False,'limits':'Selected converter normal/error logical bytes and first allocation boundary; not original fatal/panic/allocator ABI or generic finalizer states.'};(out/'qualification.json').write_text(json.dumps(j,indent=2)+'\n');print(json.dumps({'cases':len(rows),'production_profiles':2,'compiled_mutants_detected':len(mutants)}))
if __name__=='__main__':main()
