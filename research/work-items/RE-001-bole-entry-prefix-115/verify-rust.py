"""Compile owned Rust and compare complete sealed streams; no target process."""
from pathlib import Path
import argparse,hashlib,json,subprocess,time
parser=argparse.ArgumentParser();parser.add_argument('--rustc',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
p=Path(__file__).resolve().parent;root=p.parents[2];src=root/'src/node115-bole-entry-prefix';out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);rustc=args.rustc.resolve();records=[]
rows=[json.loads(s) for s in (p/'inputs.jsonl').read_text().splitlines()];expected=(p/'expected.jsonl').read_bytes()
def line(row):return '\t'.join(','.join(map(str,v)) or '-' if isinstance(v,list) else str(v) for v in row)+'\n'
transport=''.join(line(r) for r in rows).encode();(out/'inputs.tsv').write_bytes(transport)
def run(name,command,stdin=None,code=0):
 t=time.monotonic();r=subprocess.run(list(map(str,command)),input=stdin,capture_output=True);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
 entry=dict(name=name,command=[str(c).replace(str(root.parent),'<work>') for c in command],exit=r.returncode,wall_seconds=round(time.monotonic()-t,3),stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_sha256=hashlib.sha256(r.stderr).hexdigest());records.append(entry);(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(entry),flush=True)
 if r.returncode!=code:raise ValueError('unexpected exit '+name+' '+r.stderr.decode(errors='replace'))
 return r.stdout
def library(source,lib,opt,name):run(name,[rustc,'--edition=2021','--crate-type=rlib','--crate-name=node115_bole_entry_prefix','-C',f'opt-level={opt}',source,'-o',lib])
def compare(lib,opt,name,mutant=False):
 exe=out/(name+'-driver');test=out/(name+'-test');extern=['--extern','node115_bole_entry_prefix='+str(lib)]
 run(name+'-driver-build',[rustc,'--edition=2021','-C',f'opt-level={opt}',src/'input_only_driver.rs',*extern,'-o',exe])
 actual=run(name+'-actual',[exe],transport);(out/(name+'-actual.jsonl')).write_bytes(actual);lines=actual.splitlines();gold=expected.splitlines()
 if len(lines)!=len(gold):raise ValueError('incomplete stream '+name)
 count=sum(a!=b for a,b in zip(lines,gold))
 if bool(count)!=mutant:raise ValueError('unexpected comparisons '+name+' '+str(count))
 run(name+'-test-build',[rustc,'--edition=2021','--test','-C',f'opt-level={opt}',p/'client_fixture.rs',*extern,'-o',test]);run(name+'-test',[test],code=101 if mutant else 0)
 return count
run('rust-version',[rustc,'-vV']);source=(src/'lib.rs').read_text();results={}
for opt in [0,3]:
 lib=out/f'libnode115_bole_entry_prefix_o{opt}.rlib';library(src/'lib.rs',lib,opt,f'original-o{opt}-library');results[f'original-o{opt}']=compare(lib,opt,f'original-o{opt}')
 if opt==3:
  first=lib.read_bytes();library(src/'lib.rs',lib,opt,'repeat-library')
  if lib.read_bytes()!=first:raise ValueError('same-path rlib rebuild differs')
  results['repeat']=compare(lib,opt,'repeat')
mutants=[
 ('zero-index','if input.primary == 0 {','if input.primary == u64::MAX {'),
 ('primary-equality','if input.primary >= input.primary_len {','if input.primary > input.primary_len {'),
 ('secondary-premature','if secondary >= input.occupied.len() as u64 {','if secondary >= input.occupied.len().saturating_sub(1) as u64 {'),
 ('occupied-test','if input.occupied[secondary as usize] == 0 {','if input.occupied[secondary as usize] != 0 {'),
 ('reverse-scan','for &secondary in input.indices {','for &secondary in input.indices.iter().rev() {'),
 ('skip-first','for &secondary in input.indices {','for &secondary in input.indices.iter().skip(1) {'),
 ('lookup-lane','let lane = if input.header == 0x8000_0000_0000_0000 {','let lane = if input.header == 0 {'),
 ('map-empty-equality','&& input.map_len == 0 {','&& input.map_len <= 1 {'),
 ('map-empty-before-selection','for &secondary in input.indices {','if input.header == 0x8000_0000_0000_0000 && input.map_len == 0 { return Some(Frontier::Returned2); } for &secondary in input.indices {'),
 ('selected-index','                secondary,\n','                secondary: 0,\n'),
 ('auxiliary-copy','auxiliary: input.auxiliary,','auxiliary: 0,'),
 ('float-bit-copy','float_bits: input.float_bits,','float_bits: 0,'),
]
for name,before,after in mutants:
 if source.count(before)!=1:raise ValueError('ambiguous mutation '+name)
 file=out/(name+'.rs');file.write_text(source.replace(before,after));lib=out/('lib'+name.replace('-','_')+'.rlib');library(file,lib,3,name+'-library');results[name]=compare(lib,3,name,True)
report=dict(pre_rust_seal='9c03984b0c82f878458c786345c5d5eedbf8b054',rows=len(rows),fixture_rows=json.loads((p/'fixture-selection.json').read_text())['rows'],source_sha256=hashlib.sha256((src/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((src/'input_only_driver.rs').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((p/'client_fixture.rs').read_bytes()).hexdigest(),input_sha256=hashlib.sha256((p/'inputs.jsonl').read_bytes()).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),mismatches=results,commands=records,platform='macOS arm64 host research, edition2021 rustc1.94.1; no original compiler/Linux/node qualification',repeat='same-path opt3 rlib byte-equal and all outputs identical; separate-directory rebuild unmeasured')
(p/'rust-results.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL BUILD/STREAM/FIXTURE/MUTANT CHECKS PASS',results,flush=True)
