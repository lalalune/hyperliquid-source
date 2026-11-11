"""Compile own Rust, replay pre-Rust frozen rows and compile actual mutants."""
from pathlib import Path
import argparse,subprocess,hashlib,json,gzip,re
import oracle
P=Path(__file__).resolve().parent;R=P.parents[2];C=R/'src/node115-elf-build-id'
def sha(b):return hashlib.sha256(b).hexdigest()
def need(v,m):
 if not v:raise ValueError(m)
def qualify(out,rustc):
 need(not out.exists(),'fresh output required');out.mkdir(parents=True)
 freeze=json.loads((P/'freeze.json').read_text());raw=gzip.decompress(bytes.fromhex((P/'cases.tsv.gz.hex').read_text()));need(sha(raw)==freeze['fixture_sha256'],'fixture hash');need(raw==oracle.generate(),'independent oracle drift');need(sha((P/'oracle.py').read_bytes())==freeze['oracle_sha256'],'oracle identity');need(sha((P/'scope.json').read_bytes())==freeze['scope_sha256'],'scope identity')
 rows=raw.decode().splitlines();inputs=('\n'.join('\t'.join(r.split('\t')[:2]) for r in rows)+'\n').encode();expected=[r.split('\t')[2] for r in rows];(out/'input.tsv').write_bytes(inputs);(out/'expected.txt').write_text('\n'.join(expected)+'\n')
 source=(C/'src/lib.rs').read_text();probe=(C/'src/probe.rs').read_text();(out/'probe.rs').write_text(probe)
 def run(name,src,opt):
  d=out/name;d.mkdir();(d/'lib.rs').write_text(src)
  lib=d/'libnode115_elf_build_id.rlib';exe=d/'probe.exe'
  for label,cmd in [('library',[rustc,'--edition=2024','--crate-name','node115_elf_build_id','--crate-type','rlib','-C',f'opt-level={opt}',str(d/'lib.rs'),'-o',str(lib)]),('probe',[rustc,'--edition=2024','-C',f'opt-level={opt}',str(out/'probe.rs'),'--extern',f'node115_elf_build_id={lib}','-o',str(exe)])]:
   p=subprocess.run(cmd,capture_output=True);(d/(label+'.stdout')).write_bytes(p.stdout);(d/(label+'.stderr')).write_bytes(p.stderr);need(p.returncode==0,name+' compile '+label)
  p=subprocess.run([str(exe)],input=inputs,capture_output=True);(d/'actual.stdout').write_bytes(p.stdout);(d/'actual.stderr').write_bytes(p.stderr);actual=p.stdout.decode().splitlines();witness=next((i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b),None)
  if len(actual)!=len(expected) and witness is None:witness=min(len(actual),len(expected))
  return {'name':name,'exit':p.returncode,'rows':len(actual),'matched':sum(a==b for a,b in zip(actual,expected)),'first_mismatch':witness,'source_sha256':sha(src.encode()),'output_sha256':sha(p.stdout),'exe':exe}
 profiles=[]
 for opt in [0,3]:
  x=run('production-'+str(opt),source,opt);need(x['exit']==0 and x['matched']==len(rows) and x['rows']==len(rows),'production mismatch');x.pop('exe');profiles.append(x)
 mutants=[('wrong-section-kind','!= 7','!= 8'),('reject-zero-alignment','raw_alignment <= 4','raw_alignment > 0 && raw_alignment <= 4'),('ignore-eight-alignment','raw_alignment == 8','raw_alignment == 7'),('trim-one-nul','while name.last() == Some(&0)','if name.last() == Some(&0)'),('wrong-note-kind','kind == 3','kind == 2'),('strict-final-padding','if name == b"GNU" && kind == 3','if aligned(descriptor_end, alignment) <= notes.len() && name == b"GNU" && kind == 3'),('bad-section-aborts-file','let Some(mut notes) = file.get(offset..end) else {\n            continue;','let Some(mut notes) = file.get(offset..end) else {\n            return None;'),('wrong-eight-descriptor-alignment','let descriptor = aligned(12 + name_length, alignment);','let descriptor = aligned(12 + name_length, 4);')]
 controls=[]
 for name,a,b in mutants:
  need(source.count(a)==1,name+' mutation anchor');src=source.replace(a,b);x=run(name,src,3);need(x['exit']==0 and x['first_mismatch'] is not None,name+' not rejected normally');x.pop('exe');controls.append(x)
 exe=out/'production-3/probe.exe';p=subprocess.run([str(exe),str(R/'artifacts/node/115/hl-node')],capture_output=True);need(p.returncode==0,'artifact scan');(out/'artifact-probe.stdout').write_bytes(p.stdout);(out/'artifact-probe.stderr').write_bytes(p.stderr)
 text=subprocess.check_output(['readelf','-n',str(R/'artifacts/node/115/hl-node')],text=True);(out/'readelf-notes.txt').write_text(text.replace(str(R/'artifacts/node/115/hl-node'),'<authenticated-node115>'));build_id=re.search(r'Build ID: ([0-9a-f]+)',text).group(1);actual=p.stdout.decode().strip();need(actual.split(':')[-1]==build_id,'GNU readelf build id mismatch')
 result={'target_sha256':'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','compiler':subprocess.check_output([rustc,'--version'],text=True).strip(),'rows_per_profile':len(rows),'fixture_sha256':sha(raw),'profiles':profiles,'compiled_mutants':controls,'artifact_build_id':build_id,'artifact_probe':actual,'artifact_oracle':'Independent GNU readelf -n, no captured executable run','source_sha256':{p.relative_to(R).as_posix():sha(p.read_bytes()) for p in sorted(C.rglob('*')) if p.is_file() and 'target' not in p.parts},'capture_execution_or_emulation':False};(out/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--out',type=Path,required=True);a.add_argument('--rustc',required=True);args=a.parse_args();print(json.dumps(qualify(args.out,args.rustc),indent=2))
