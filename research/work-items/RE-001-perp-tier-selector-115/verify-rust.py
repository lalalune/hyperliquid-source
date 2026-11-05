"""Build owned source, compare complete sealed streams and compiled mutants."""
from pathlib import Path
import argparse,gzip,hashlib,json,subprocess,time
parser=argparse.ArgumentParser();parser.add_argument('--rustc',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
p=Path(__file__).resolve().parent;root=p.parents[2];src=root/'src/node115-perp-tier-selector';out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);rustc=args.rustc.resolve();records=[]
def prepare_fixture():
 target=p/'client_fixture.rs'
 if not target.exists():target.write_bytes(gzip.decompress((p/'client_fixture.rs.gz').read_bytes()))
 expected=json.loads((p/'fixture-selection.json').read_text())['rust_fixture_sha256']
 if hashlib.sha256(target.read_bytes()).hexdigest()!=expected:raise ValueError('fixture content differs from tested archive')
prepare_fixture()
rows=[json.loads(s) for s in (p/'inputs.jsonl').read_text().splitlines()];expected=(p/'expected.jsonl').read_bytes()
def csv(values):return ','.join(map(str,values)) or '-'
def fields(values):return '/'.join(csv(v) for v in values) or '-'
def line(row):
 key,desc,guard,retained,rootid,height,nodes,ring=row
 ns=';'.join(csv(k)+':'+csv(c)+':'+fields(v) for k,c,v in nodes) or '-'
 rs='!' if ring is None else ':'.join([str(ring[0]),str(ring[3]),csv(ring[1]),fields(ring[2])])
 return '\t'.join(map(str,[key,desc,guard,retained,rootid,height,ns,rs]))+'\n'
transport=''.join(line(r) for r in rows).encode();(out/'inputs.tsv').write_bytes(transport)
def run(name,command,stdin=None,code=0):
 t=time.monotonic();r=subprocess.run(list(map(str,command)),input=stdin,capture_output=True);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
 entry=dict(name=name,command=[str(c).replace(str(root.parent),'<work>') for c in command],exit=r.returncode,wall_seconds=round(time.monotonic()-t,3),stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_sha256=hashlib.sha256(r.stderr).hexdigest());records.append(entry);(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(entry),flush=True)
 if r.returncode!=code:raise ValueError('unexpected exit '+name+' '+r.stderr.decode(errors='replace'))
 return r.stdout
def library(source,lib,opt,name):run(name,[rustc,'--edition=2021','--crate-type=rlib','--crate-name=node115_perp_tier_selector','-C',f'opt-level={opt}',source,'-o',lib])
def compare(lib,opt,name,mutant=False):
 exe=out/(name+'-driver');test=out/(name+'-test');extern=['--extern','node115_perp_tier_selector='+str(lib)]
 run(name+'-driver-build',[rustc,'--edition=2021','-C',f'opt-level={opt}',src/'input_only_driver.rs',*extern,'-o',exe])
 actual=run(name+'-actual',[exe],transport);(out/(name+'-actual.jsonl')).write_bytes(actual);lines=actual.splitlines();gold=expected.splitlines()
 if len(lines)!=len(gold):raise ValueError('incomplete stream '+name)
 count=sum(a!=b for a,b in zip(lines,gold))
 if bool(count)!=mutant:raise ValueError('unexpected comparison '+name+' '+str(count))
 run(name+'-test-build',[rustc,'--edition=2021','--test','-C',f'opt-level={opt}',p/'client_fixture.rs',*extern,'-o',test]);run(name+'-test',[test],code=101 if mutant else 0)
 return count
run('rust-version',[rustc,'-vV']);source=(src/'lib.rs').read_text();results={}
for opt in [0,3]:
 lib=out/f'libnode115_perp_tier_selector_o{opt}.rlib';library(src/'lib.rs',lib,opt,f'original-o{opt}-library');results[f'original-o{opt}']=compare(lib,opt,f'original-o{opt}')
 if opt==3:
  first=lib.read_bytes();library(src/'lib.rs',lib,opt,'repeat-library')
  if first!=lib.read_bytes():raise ValueError('same-path repeat differs')
  results['repeat']=compare(lib,opt,'repeat')
builder='fn returned(words: [u64; 3], origin: RowOrigin) -> Frontier {\n    Frontier::Returned { words, origin }\n}'
mutants=[
 ('threshold','if input.key < 50 {','if input.key < 49 {'),
 ('guard','if input.guard != 0 {','if input.guard == 0 {'),
 ('global-retained','[1, 0, input.retained]','[1, 0, 0]'),
 ('global-cell','index: input.key,','index: input.key / 2,'),
 ('tree-unsigned','input.key > node.keys[pos]','(input.key as i32) > (node.keys[pos] as i32)'),
 ('tree-equality','input.key == node.keys[pos]','input.key != node.keys[pos]'),
 ('tree-child','id = node.children[pos];','id = node.children[0];'),
 ('tree-depth','if depth == 0 {','if depth <= 1 {'),
 ('tree-field-row','node.fields[pos],','node.fields[0],'),
 ('tree-pointer','byte_offset: 24,','byte_offset: 16,'),
 ('ring-head','Some((head + lo) % capacity)','Some(lo)'),
 ('ring-unsigned','rows[physical].key < key','(rows[physical].key as i32) < (key as i32)'),
 ('ring-count','let mut hi = count;','let mut hi = capacity;'),
 ('ring-pointer','byte_offset: 32,','byte_offset: 24,'),
 ('field-order',builder,'fn returned(mut words: [u64; 3], origin: RowOrigin) -> Frontier { words.swap(0,1); Frontier::Returned { words, origin } }'),
 ('last-word',builder,'fn returned(mut words: [u64; 3], origin: RowOrigin) -> Frontier { words[2]=0; Frontier::Returned { words, origin } }'),
]
for name,before,after in mutants:
 if source.count(before)!=1:raise ValueError('ambiguous mutation '+name)
 file=out/(name+'.rs');file.write_text(source.replace(before,after));lib=out/('lib'+name.replace('-','_')+'.rlib');library(file,lib,3,name+'-library');results[name]=compare(lib,3,name,True)
report=dict(pre_rust_seal='1de14ed03dc45c5e2c1e1e1ea8b4d7e6588843d4',original_prefix_seal='836753bd8d07e01e7a357f510765f550e7780beb',rows=len(rows),fixture_rows=json.loads((p/'fixture-selection.json').read_text())['rows'],source_sha256=hashlib.sha256((src/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((src/'input_only_driver.rs').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((p/'client_fixture.rs').read_bytes()).hexdigest(),input_sha256=hashlib.sha256((p/'inputs.jsonl').read_bytes()).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),mismatches=results,commands=records,platform='macOS arm64 host research rustc1.94.1 edition2021; no original compiler, Linux execution or target-byte claim',repeat='same-path opt3 rlib byte-equal and outputs repeat; separate-directory build unmeasured')
(p/'rust-results.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL BUILD/STREAM/FIXTURE/MUTANT CHECKS PASS',results,flush=True)
