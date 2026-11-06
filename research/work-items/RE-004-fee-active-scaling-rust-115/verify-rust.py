"""Build owned source, compare complete sealed streams and compiled mutants."""
from pathlib import Path
import argparse,gzip,hashlib,json,subprocess,time
parser=argparse.ArgumentParser();parser.add_argument('--rustc',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
p=Path(__file__).resolve().parent;root=p.parents[2];src=root/'src/node115-fee-active-scaling';out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);rustc=args.rustc.resolve();records=[]
rows=[json.loads(s) for s in (p/'inputs.jsonl').read_text().splitlines()];expected=(p/'expected.jsonl').read_bytes()
transport=''.join(raw+'\t'+str(seed)+'\n' for raw,seed in rows).encode();(out/'inputs.tsv').write_bytes(transport)
client_data=gzip.decompress((p/'client-inputs.tsv.gz').read_bytes())
if client_data!=transport:raise ValueError('client transport differs from sealed inputs')
(p/'client-inputs.tsv').write_bytes(client_data)
def run(name,command,stdin=None,code=0):
 t=time.monotonic();r=subprocess.run(list(map(str,command)),input=stdin,capture_output=True);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
 entry=dict(name=name,command=[str(c).replace(str(root.parent),'<work>') for c in command],exit=r.returncode,wall_seconds=round(time.monotonic()-t,3),stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_sha256=hashlib.sha256(r.stderr).hexdigest());records.append(entry);(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(entry),flush=True)
 if r.returncode!=code:raise ValueError('unexpected exit '+name+' '+r.stderr.decode(errors='replace'))
 return r.stdout
def library(source,lib,opt,name):run(name,[rustc,'--edition=2021','--crate-type=rlib','--crate-name=node115_fee_active_scaling','-C',f'opt-level={opt}',source,'-o',lib])
def compare(lib,opt,name,mutant=False):
 exe=out/(name+'-driver');test=out/(name+'-test');extern=['--extern','node115_fee_active_scaling='+str(lib)]
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
 lib=out/f'libnode115_fee_active_scaling_o{opt}.rlib';library(src/'lib.rs',lib,opt,f'original-o{opt}-library');results[f'original-o{opt}']=compare(lib,opt,f'original-o{opt}')
 if opt==3:
  first=lib.read_bytes();library(src/'lib.rs',lib,opt,'repeat-library')
  if first!=lib.read_bytes():raise ValueError('same-path repeat differs')
  results['repeat']=compare(lib,opt,'repeat')
mutants=[('scale-first', 'word(raw, 0x60).checked_mul(100)', 'word(raw, 0x60).checked_mul(101)'), ('scale-second', 'word(raw, 0x68).checked_mul(100)', 'word(raw, 0x68).checked_mul(101)'), ('scale-outer', 'word(raw, 8).checked_mul(100)', 'word(raw, 8).checked_mul(101)'), ('scale-inner', 'word(raw, 0x40).checked_mul(100)', 'word(raw, 0x40).checked_mul(101)'), ('scale-last', 'word(raw, 0x70).checked_mul(100)', 'word(raw, 0x70).checked_mul(101)'), ('outer-equality', 'word(raw, 0) == 1', 'word(raw, 0) != 0'), ('inner-sentinel', 'word(raw, 0x28) != 0x8000_0000_0000_0000', 'word(raw, 0x28) == 0x8000_0000_0000_0000'), ('inner-error-kind', 'return failure(Exit::InnerDiagnostic, seed);', 'return failure(Exit::LastDiagnostic, seed);'), ('last-error-kind', 'return failure(Exit::LastDiagnostic, seed);', 'return failure(Exit::InnerDiagnostic, seed);'), ('outer-tail', '&raw[0x10..0x24]', '&raw[0x0c..0x20]'), ('inner-tail', '&raw[0x48..0x5c]', '&raw[0x44..0x58]'), ('inner-header', '&raw[0x28..0x38]', '&raw[0x20..0x30]'), ('inactive-outer', 'output[8..36].fill(None);', 'output[8..36].fill(Some(0));'), ('padding-canary', 'let mut output = [Some(seed); 120];', 'let mut output = [Some(seed ^ 1); 120];')]
for name,before,after in mutants:
 if source.count(before)!=1:raise ValueError('ambiguous mutation '+name)
 file=out/(name+'.rs');file.write_text(source.replace(before,after));lib=out/('lib'+name.replace('-','_')+'.rlib');library(file,lib,3,name+'-library');results[name]=compare(lib,3,name,True)
report=dict(pre_rust_seal='f11c79c7ef09056be02de8e7a294f2c6c72b1a19',rows=len(rows),fixture_rows=json.loads((p/'fixture-selection.json').read_text())['rows'],source_sha256=hashlib.sha256((src/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((src/'input_only_driver.rs').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((p/'client_fixture.rs').read_bytes()).hexdigest(),input_sha256=hashlib.sha256((p/'inputs.jsonl').read_bytes()).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),mismatches=results,commands=records,platform='macOS arm64 host research rustc1.94.1 edition2021; no original compiler, Linux execution or target-byte claim',repeat='same-path opt3 rlib byte-equal and outputs repeat; separate-directory build unmeasured')
(p/'rust-results.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL BUILD/STREAM/FIXTURE/MUTANT CHECKS PASS',results,flush=True)
