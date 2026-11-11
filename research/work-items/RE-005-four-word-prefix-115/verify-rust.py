from pathlib import Path
import hashlib,json,subprocess,time,sys,argparse
parser=argparse.ArgumentParser();parser.add_argument('--rustc',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
root=Path(__file__).resolve().parents[3];p=Path(__file__).resolve().parent;src=root/'src/node115-four-word-prefix';out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
rustc=args.rustc.resolve();records=[]
rows=[json.loads(s) for s in (p/'inputs.jsonl').read_text().splitlines()]
transport=''.join(raw+'\t'+('-' if limit is None else str(limit))+'\t'+str(count)+'\n' for raw,limit,count in rows).encode();expected=(p/'expected.jsonl').read_bytes()
(out/'inputs.tsv').write_bytes(transport)
def run(name,command,stdin=None,code=0):
 t=time.monotonic();r=subprocess.run(list(map(str,command)),input=stdin,capture_output=True);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
 entry=dict(name=name,command=[str(c).replace(str(root.parent),'<work>') for c in command],exit=r.returncode,wall_seconds=round(time.monotonic()-t,3),stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_sha256=hashlib.sha256(r.stderr).hexdigest());records.append(entry);(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(entry),flush=True)
 if r.returncode!=code:raise ValueError('unexpected exit '+name+' '+r.stderr.decode(errors='replace'))
 return r.stdout
def extern(lib,dep):return ['-L','dependency='+str(out),'--extern','node115_four_word_prefix='+str(lib),'--extern','node115_u64_reader_state='+str(dep)]
def library(source,lib,dep,opt,name):run(name,[rustc,'--edition=2021','--crate-type=rlib','--crate-name=node115_four_word_prefix','-C',f'opt-level={opt}',source,'--extern','node115_u64_reader_state='+str(dep),'-o',lib])
def compare(lib,dep,opt,name,mutant=False):
 exe=out/(name+'-driver');test=out/(name+'-test')
 run(name+'-driver-build',[rustc,'--edition=2021','-C',f'opt-level={opt}',src/'input_only_driver.rs',*extern(lib,dep),'-o',exe])
 actual=run(name+'-actual',[exe],transport);(out/(name+'-actual.jsonl')).write_bytes(actual)
 lines=actual.splitlines();gold=expected.splitlines()
 if len(lines)!=len(gold):raise ValueError('not a complete stream '+name)
 mismatches=sum(a!=b for a,b in zip(lines,gold))
 if bool(mismatches)!=mutant:raise ValueError('wrong comparison '+name+' '+str(mismatches))
 run(name+'-test-build',[rustc,'--edition=2021','--test','-C',f'opt-level={opt}',p/'client_fixture.rs',*extern(lib,dep),'-o',test])
 run(name+'-test',[test],code=101 if mutant else 0)
 return mismatches
source=(src/'lib.rs').read_text();results={}
run('rust-version',[rustc,'-vV'])
for opt in [0,3]:
 dep=out/f'libnode115_u64_reader_state_o{opt}.rlib';lib=out/f'libnode115_four_word_prefix_o{opt}.rlib'
 run(f'dependency-o{opt}',[rustc,'--edition=2021','--crate-type=rlib','--crate-name=node115_u64_reader_state','-C',f'opt-level={opt}',root/'src/node115-u64-reader-state/lib.rs','-o',dep])
 library(src/'lib.rs',lib,dep,opt,f'original-o{opt}-library');results[f'original-o{opt}']=compare(lib,dep,opt,f'original-o{opt}')
 if opt==3:
  first=lib.read_bytes();library(src/'lib.rs',lib,dep,opt,'repeat-library')
  if first!=lib.read_bytes():raise ValueError('same-path rlib repeat differs')
  results['repeat']=compare(lib,dep,opt,'repeat')
mutants=[('aggregate-precharge', 'let mut words = [0; 4];\n        for word in &mut words {\n            *word = self.word()?;\n        }', 'let mut aggregate = Reader::new(self.remaining,self.limit,self.charged); let result=aggregate.read_four(); self.remaining=aggregate.remaining(); self.charged=aggregate.charged(); let words = result.map_err(Error::Read)?;'), ('rollback-word-charge', 'self.charged = reader.charged();', 'if result.is_ok() { self.charged = reader.charged(); }'), ('rollback-word-cursor', 'self.remaining = reader.remaining();', 'if result.is_ok() { self.remaining = reader.remaining(); }'), ('byte-charge-eight', '.checked_add(1)', '.checked_add(8)'), ('byte-overflow-wrap', '.checked_add(1)', '.wrapping_add(1).checked_add(0)'), ('byte-limit-equality', 'if next > limit {', 'if next >= limit {'), ('byte-rollback-limit', 'self.charged = next;', 'if next <= limit { self.charged = next; }'), ('mode-not-consumed', 'self.remaining = rest;', 'if mode <= 1 { self.remaining = rest; }'), ('mode-two-accepted', '1 => Some(self.word()?),', '1 | 2 => Some(self.word()?),'), ('tail-discarded', '1 => Some(self.word()?),', '1 => { self.word()?; None },'), ('field-order', 'Ok(Fields { words, tail })', 'words.swap(0,3); Ok(Fields { words, tail })')]
dep=out/'libnode115_u64_reader_state_o3.rlib'
for name,before,after in mutants:
 if source.count(before)!=1:raise ValueError('ambiguous mutant '+name)
 file=out/(name+'.rs');file.write_text(source.replace(before,after));lib=out/('lib'+name.replace('-','_')+'.rlib')
 library(file,lib,dep,3,name+'-library');results[name]=compare(lib,dep,3,name,True)
report=dict(pre_rust_seal='eb1274be65964c8c7d2642505b50df40db445877',rows=len(rows),fixture_rows=128,source_sha256=hashlib.sha256((src/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((src/'input_only_driver.rs').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((p/'client_fixture.rs').read_bytes()).hexdigest(),dependency_sha256=hashlib.sha256((root/'src/node115-u64-reader-state/lib.rs').read_bytes()).hexdigest(),input_sha256=hashlib.sha256((p/'inputs.jsonl').read_bytes()).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),mismatches=results,commands=records,platform='macOS arm64 host research build; edition2021 rustc1.94.1; no original Cargo/Linux build claim',repeat='same-path opt3 rlib byte-equal and all outputs identical; not a separate-directory rebuild')
(p/'rust-results.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL BUILD/STREAM/FIXTURE/MUTANT CHECKS PASS',results,flush=True)
