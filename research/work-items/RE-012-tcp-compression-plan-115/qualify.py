#!/usr/bin/env python3
"""Compile independently authored Rust; never run captured code or emulate it."""
import argparse,hashlib,json,subprocess
from pathlib import Path
import oracle
P=Path(__file__).resolve().parent
R=P.parents[2]
S=R/'src/node115-tcp-compression-plan'
def sha(b):return hashlib.sha256(b).hexdigest()
def run(args,out,stdin=None):
 p=subprocess.run(args,input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 out.with_suffix('.stdout').write_bytes(p.stdout);out.with_suffix('.stderr').write_bytes(p.stderr)
 if p.returncode:raise RuntimeError((args,p.returncode,p.stderr.decode()))
 return p.stdout

def main(out):
 out.mkdir(parents=True,exist_ok=False)
 frozen=json.loads((P/'freeze.json').read_text());cases=(P/'cases.tsv').read_bytes()
 assert not frozen['new_rust_exists']
 assert sha(cases)==frozen['cases_sha256'] and sha((P/'oracle.py').read_bytes())==frozen['oracle_sha256']
 assert oracle.corpus()==cases
 all_pairs=[row.split(b'\t') for row in cases.splitlines()]
 pairs=[(a,b) for a,b in all_pairs if all(int(v)<=2**64-1 for v in a.split())]
 inputs=b'\n'.join(a for a,b in pairs)+b'\n';expected=b'\n'.join(b for a,b in pairs)+b'\n'
 (out/'inputs.txt').write_bytes(inputs);(out/'expected.txt').write_bytes(expected)
 source=(S/'src/lib.rs').read_text();probe=S/'src/probe.rs'
 mutants=[('threshold','input_len < 1025','input_len < 1024'),('full-width-field','let low = context_field as u16;','let low = context_field;'),('codec-split','input_len < 65535','input_len <= 65535'),('inner-endian','(input_len as u32).to_le_bytes()','(input_len as u32).to_be_bytes()'),('caller-clamp','with_prefix.min(self.allocation_bytes)','with_prefix'),('outer-endian','length.to_be_bytes()','length.to_le_bytes()'),('success-marker','self.allocation_bytes), 1)','self.allocation_bytes), 0)'),('unwrap-fallback','tag == 1','tag == 0')]
 results=[]
 for name,opt,body in [('production0',0,source),('production3',3,source)]+[(name,3,source.replace(old,new)) for name,old,new in mutants]:
  d=out/name;d.mkdir();lib=d/'lib.rs';lib.write_text(body)
  if name not in ['production0','production3']:assert body!=source,name
  rlib=d/'libnode115_tcp_compression_plan.rlib'
  run(['rustc','--edition=2024','--crate-name','node115_tcp_compression_plan','--crate-type','rlib','-C',f'opt-level={opt}',str(lib),'-o',str(rlib)],d/'library')
  exe=d/'probe'
  run(['rustc','--edition=2024','-C',f'opt-level={opt}',str(probe),'--extern',f'node115_tcp_compression_plan={rlib}','-o',str(exe)],d/'compile-probe')
  actual=run([str(exe)],d/'actual',inputs)
  rows=actual.splitlines();assert len(rows)==len(pairs)
  mismatches=[i for i,((_,wanted),got) in enumerate(zip(pairs,rows)) if wanted!=got]
  if name.startswith('production'):assert not mismatches,(name,mismatches[:2])
  else:assert mismatches,name
  results.append({'name':name,'optimization':opt,'exit':0,'rows':len(rows),'mismatches':len(mismatches),'first_mismatch':mismatches[0] if mismatches else None,'actual_sha256':sha(actual),'library_sha256':sha(rlib.read_bytes())})
 result={'target_sha256':frozen['target_sha256'],'cases':len(pairs),'excluded_unrepresentable_u64_rows':len(all_pairs)-len(pairs),'valid_subset_selected_after_rust':True,'fixture_sha256':sha(cases),'fixture_frozen_before_new_rust':True,'results':results,'source_sha256':{str(f.relative_to(R)):sha(f.read_bytes()) for f in sorted(S.rglob('*')) if f.is_file() and 'target' not in f.parts},'captured_code_executed_or_emulated':False}
 (out/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--out',type=Path,required=True);main(a.parse_args().out)
