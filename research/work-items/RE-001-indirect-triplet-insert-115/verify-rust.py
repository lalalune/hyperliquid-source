"""Build owned source, compare complete sealed streams and compiled mutants."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time
parser=argparse.ArgumentParser();parser.add_argument('--rustc',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
p=Path(__file__).resolve().parent;root=p.parents[2];src=root/'src/node115-indirect-triplet-insert';out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);rustc=args.rustc.resolve();records=[]
rows=[json.loads(s) for s in (p/'inputs.jsonl').read_text().splitlines()];expected=(p/'expected.jsonl').read_bytes()
transport=''.join(str(k)+'\t'+(','.join(str(v)+':'+str(key) for v,key in records) or '-')+'\t'+(','.join(':'.join(map(str,key)) for key in keys) or '-')+'\n' for k,records,keys in rows).encode();(out/'inputs.tsv').write_bytes(transport)
def run(name,command,stdin=None,code=0):
 t=time.monotonic();r=subprocess.run(list(map(str,command)),input=stdin,capture_output=True);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
 entry=dict(name=name,command=[str(c).replace(str(root.parent),'<work>') for c in command],exit=r.returncode,wall_seconds=round(time.monotonic()-t,3),stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_sha256=hashlib.sha256(r.stderr).hexdigest());records.append(entry);(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(entry),flush=True)
 if r.returncode!=code:raise ValueError('unexpected exit '+name+' '+r.stderr.decode(errors='replace'))
 return r.stdout
def library(source,lib,opt,name):run(name,[rustc,'--edition=2021','--crate-type=rlib','--crate-name=node115_indirect_triplet_insert','-C',f'opt-level={opt}',source,'-o',lib])
def compare(lib,opt,name,mutant=False):
 exe=out/(name+'-driver');test=out/(name+'-test');extern=['--extern','node115_indirect_triplet_insert='+str(lib)]
 run(name+'-driver-build',[rustc,'--edition=2021','-C',f'opt-level={opt}',src/'input_only_driver.rs',*extern,'-o',exe])
 actual=run(name+'-actual',[exe],transport);(out/(name+'-actual.jsonl')).write_bytes(actual);lines=actual.splitlines();gold=expected.splitlines()
 if len(lines)!=len(gold):raise ValueError('incomplete stream '+name)
 count=sum(a!=b for a,b in zip(lines,gold))
 if bool(count)!=mutant:raise ValueError('unexpected comparison '+name+' '+str(count))
 run(name+'-test-build',[rustc,'--edition=2021','--test','-C',f'opt-level={opt}',p/'client_fixture.rs',*extern,'-o',test]);run(name+'-test',[test],code=101 if mutant else 0)
 return count

def prepare_fixture():
 import gzip
 data=gzip.decompress((p/'client_fixture.rs.gz').read_bytes())
 want=json.loads((p/'fixture-selection.json').read_text())['rust_fixture_sha256']
 if hashlib.sha256(data).hexdigest()!=want:raise ValueError('compressed fixture drift')
 (p/'client_fixture.rs').write_bytes(data)
prepare_fixture()

run('rust-version',[rustc,'-vV']);source=(src/'lib.rs').read_text();results={}
for opt in [0,3]:
 lib=out/f'libnode115_indirect_triplet_insert_o{opt}.rlib';library(src/'lib.rs',lib,opt,f'original-o{opt}-library');results[f'original-o{opt}']=compare(lib,opt,f'original-o{opt}')
 if opt==3:
  first=lib.read_bytes();library(src/'lib.rs',lib,opt,'repeat-library')
  if first!=lib.read_bytes():raise ValueError('same-path repeat differs')
  results['repeat']=compare(lib,opt,'repeat')
builder='fn order(key: [u32; 3]) -> (i32, u32, u32) {\n    (key[0] as i32, key[1], key[2])\n}'
mutants=[
 ('unsigned-first',builder,'fn order(key: [u32; 3]) -> (u32,u32,u32) { (key[0],key[1],key[2]) }'),
 ('signed-second',builder,'fn order(key: [u32; 3]) -> (i32,i32,u32) { (key[0] as i32,key[1] as i32,key[2]) }'),
 ('signed-third',builder,'fn order(key: [u32; 3]) -> (i32,u32,i32) { (key[0] as i32,key[1],key[2] as i32) }'),
 ('equal-key-crossing',' < order(',' <= order('),
 ('payload-only','records.swap(at, at - 1);','let temp=records[at].payload;records[at].payload=records[at-1].payload;records[at-1].payload=temp;'),
 ('key-only','records.swap(at, at - 1);','let temp=records[at].key;records[at].key=records[at-1].key;records[at-1].key=temp;'),
 ('skip-first-suffix','for i in k as usize..records.len() {','for i in k as usize+1..records.len() {'),
 ('restart-prefix','for i in k as usize..records.len() {','for i in 1..records.len() {'),
 ('left-boundary','while at > 0','while at > 1'),
 ('skip-hole','at -= 1;','at = at.saturating_sub(2);'),
 ('lower-guard','if k == 0 ||','if k <= 1 ||'),
 ('upper-guard','|| k > records.len() as u64','|| k >= records.len() as u64'),
]
for name,before,after in mutants:
 if source.count(before)!=1:raise ValueError('ambiguous mutation '+name)
 file=out/(name+'.rs');file.write_text(source.replace(before,after));lib=out/('lib'+name.replace('-','_')+'.rlib');library(file,lib,3,name+'-library');results[name]=compare(lib,3,name,True)
report=dict(pre_rust_seal='5f27e1e2ebd588189c153c460124c292e5c2e0f8',rows=len(rows),fixture_rows=json.loads((p/'fixture-selection.json').read_text())['rows'],source_sha256=hashlib.sha256((src/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((src/'input_only_driver.rs').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((p/'client_fixture.rs').read_bytes()).hexdigest(),input_sha256=hashlib.sha256((p/'inputs.jsonl').read_bytes()).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),mismatches=results,commands=records,platform='macOS arm64 host research rustc1.94.1 edition2021; no original compiler, Linux execution or target-byte claim',repeat='same-path opt3 rlib byte-equal and outputs repeat; separate-directory build unmeasured')
(p/'rust-results.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL BUILD/STREAM/FIXTURE/MUTANT CHECKS PASS',results,flush=True)
