#!/usr/bin/env python3
"""Qualify our real no_std rlib against pure std::path Unix parsing. No OS I/O."""
from pathlib import Path
import hashlib,itertools,json,random,subprocess,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(P));import verify as ev

def paths():
 for n in range(10):
  for x in itertools.product(b'./a',repeat=n):yield bytes(x)
 for n in range(7):
  for x in itertools.product(b'./a\0\xff\\',repeat=n):yield bytes(x)
 rng=random.Random(115)
 for _ in range(5000):yield bytes(rng.choice(b'./ab\0\xff\\') for _ in range(rng.randrange(1,100)))
 for n in [0,1,7,8,15,16,31,32,63,64]:
  for x in [b'/./',b'//../',b'./a//../b/.',b'\xff/\0/../\xfe',b'../..',b'.',b'/',b'\\a\\b']:yield b'a/'*n+x

def digest(d):return hashlib.sha256(d).hexdigest()
def main():
 out=Path(sys.argv[1]);rustc=Path(sys.argv[2]);ev.need(not out.exists(),'fresh output required');out.mkdir(parents=True);ev.collect(ev.TARGET.read_bytes(),True)
 values=sorted(set(paths()));payload=''.join(x.hex()+'\n' for x in values);(out/'inputs.hex').write_text(payload);source=R/'src/node115-reverse-path-components/src';library=(source/'lib.rs').read_text();probe=(source/'probe.rs').read_text();results=[];references=None
 def build_and_run(label,src,opt):
  d=out/label;d.mkdir();(d/'lib.rs').write_text(src);(d/'probe.rs').write_text(probe);lib=d/'libnode115_reverse_path_components.rlib';exe=d/'probe';commands=[[str(rustc),'--edition=2021','--crate-name','node115_reverse_path_components','--crate-type','rlib','-C','opt-level='+opt,str(d/'lib.rs'),'-o',str(lib)],[str(rustc),'--edition=2021','-C','opt-level='+opt,'--extern','node115_reverse_path_components='+str(lib),str(d/'probe.rs'),'-o',str(exe)]]
  for i,cmd in enumerate(commands):
   p=subprocess.run(cmd,capture_output=True,text=True);(d/f'compiler{i}.stdout').write_text(p.stdout);(d/f'compiler{i}.stderr').write_text(p.stderr);ev.need(p.returncode==0,'real compiler failure '+label)
  p=subprocess.run([str(exe)],input=payload,capture_output=True,text=True);(d/'probe.stdout').write_text(p.stdout);(d/'probe.stderr').write_text(p.stderr);ev.need(p.returncode==0,'own probe failure '+label);rows=[line.split('\t') for line in p.stdout.splitlines()];ev.need(len(rows)==len(values) and all(len(x)==2 for x in rows),'probe row grammar');return rows,{'library_sha256':digest(lib.read_bytes()),'executable_sha256':digest(exe.read_bytes()),'commands':commands}
 for opt in ['0','3']:
  rows,build=build_and_run('production'+opt,library,opt);ref='\n'.join(x[1] for x in rows)+'\n';actual='\n'.join(x[0] for x in rows)+'\n';ev.need(actual==ref,'std reference mismatch '+opt)
  if references is None:references=ref
  ev.need(references==ref,'reference drift');results.append({'opt':opt,'matched_rows':len(values),'logical_output_sha256':digest(actual.encode()),**build})
 mutants=[]
 controls=[('lose root','let root = path.first() == Some(&b\'/\');','let root = false;',1),('lose initial current','!root && path.first()','false && !root && path.first()',1),('parent becomes current','Component::Parent','Component::Current',1),('keep body current segments','part == b"."','part == b"..never"',1),('preserve trailing body dot','part != b"."','part != b"..never"',1),('consume protected separator','usize::from(start > self.protected)','usize::from(start > 0)',1)]
 expected=references.splitlines()
 for n,(name,old,new,count) in enumerate(controls):
  ev.need(library.count(old)==count,'mutant selector '+name);rows,build=build_and_run('mutant'+str(n),library.replace(old,new),'3');ev.need('\n'.join(x[1] for x in rows)+'\n'==references,'mutant changed reference');diff=[i for i,x in enumerate(rows) if x[0]!=x[1]];ev.need(diff,'surviving compiled mutant '+name);i=diff[0];mutants.append({'name':name,'mismatches':len(diff),'witness_hex':values[i].hex(),'actual':rows[i][0],'expected':rows[i][1],**build})
 result={'target_sha256':ev.SPEC['target_sha256'],'cases':len(values),'input_sha256':digest(payload.encode()),'expected_sha256':digest(references.encode()),'oracle':'std::path::Components pure Unix parser; bytes via OsStrExt, never filesystem operations','ordering':'Reference generated after initial source authoring; no pre-production expectation claim','rustc':subprocess.check_output([str(rustc),'-Vv'],text=True),'rustc_executable_sha256':digest(rustc.read_bytes()),'production':results,'compiled_mutants_detected':mutants,'captured_code_executed_or_emulated':False,'native_abi_or_byte_equivalence_claimed':False};(out/'expected.txt').write_text(references);(out/'qualification.json').write_text(ev.dump(result));print(ev.dump({'cases':len(values),'matched_profiles':len(results),'compiled_mutants_detected':len(mutants)}))
if __name__=='__main__':main()
