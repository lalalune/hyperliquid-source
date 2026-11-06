"""Build owned source, compare complete sealed streams and compiled mutants."""
from pathlib import Path
import argparse,gzip,hashlib,json,subprocess,time
parser=argparse.ArgumentParser();parser.add_argument('--rustc',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
p=Path(__file__).resolve().parent;root=p.parents[2];src=root/'src/node115-user-admission-prefix';out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);rustc=args.rustc.resolve();records=[]
rows=[json.loads(s) for s in (p/'inputs.jsonl').read_text().splitlines()];expected=(p/'expected.jsonl').read_bytes()
transport=''.join('\t'.join([row[0],*map(str,row[1:6]),','.join(map(str,row[6])) or '-',row[7],row[8],str(row[9])])+'\n' for row in rows).encode();(out/'inputs.tsv').write_bytes(transport)
client_data=gzip.decompress((p/'client-inputs.tsv.gz').read_bytes())
if client_data!=transport:raise ValueError('client transport differs from sealed inputs')
(p/'client-inputs.tsv').write_bytes(client_data)
def run(name,command,stdin=None,code=0):
 t=time.monotonic();r=subprocess.run(list(map(str,command)),input=stdin,capture_output=True);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr)
 entry=dict(name=name,command=[str(c).replace(str(root.parent),'<work>') for c in command],exit=r.returncode,wall_seconds=round(time.monotonic()-t,3),stdout_sha256=hashlib.sha256(r.stdout).hexdigest(),stderr_sha256=hashlib.sha256(r.stderr).hexdigest());records.append(entry);(out/'commands.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(entry),flush=True)
 if r.returncode!=code:raise ValueError('unexpected exit '+name+' '+r.stderr.decode(errors='replace'))
 return r.stdout
def library(source,lib,opt,name):run(name,[rustc,'--edition=2021','--crate-type=rlib','--crate-name=node115_user_admission_prefix','-C',f'opt-level={opt}',source,'-o',lib])
def compare(lib,opt,name,mutant=False):
 exe=out/(name+'-driver');test=out/(name+'-test');extern=['--extern','node115_user_admission_prefix='+str(lib)]
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
 lib=out/f'libnode115_user_admission_prefix_o{opt}.rlib';library(src/'lib.rs',lib,opt,f'original-o{opt}-library');results[f'original-o{opt}']=compare(lib,opt,f'original-o{opt}')
 if opt==3:
  first=lib.read_bytes();library(src/'lib.rs',lib,opt,'repeat-library')
  if first!=lib.read_bytes():raise ValueError('same-path repeat differs')
  results['repeat']=compare(lib,opt,'repeat')
mutants=[
 ('encoded-mask','raw & (1 << 63) == 0','raw & (1 << 63) != 0'),
 ('encoded-addend','0x8000_0000_0000_0001','0x8000_0000_0000_0002'),
 ('encoded-equality','if encoded == 2 {','if encoded == 3 {'),
 ('current-bit','if input.active == 0 {','if input.active & 1 == 0 {'),
 ('zero-mode','if input.mode == 0 {','if input.mode & 1 == 0 {'),
 ('identity-bit','input.descriptor[0x4e] & 1','input.descriptor[0x4e] & 2'),
 ('operation-bit','operation & 1','operation & 2'),
 ('amount-equality','if amount >= LIMIT {','if amount > LIMIT {'),
 ('amount-signed','if amount >= LIMIT {','if (amount as i64) >= LIMIT as i64 {'),
 ('budget-add','(amount | input.budget)','amount.wrapping_add(input.budget)'),
 ('descriptor-flag','if input.descriptor[0x50] != 0 {','if input.descriptor[0x50] == 0 {'),
 ('aux-flag','if input.aux == 0 {','if input.aux != 0 {'),
 ('node-count-width','u64::from(count) * 20','u64::from(count as u8) * 20'),
 ('depth-step','height -= 1;','height = height.saturating_sub(2);'),
 ('payload-offset','output[8..16]','output[4..12]'),
 ('peer-source','input.descriptor[0x4f..0x63]','input.descriptor[0x4b..0x5f]'),
 ('identity-tail','identity: input.identity,','identity: {let mut v=input.identity;v[16..20].copy_from_slice(&input.identity[12..16]);v},'),
 ('context-source','context: input.context,','context: {let mut v=input.context;v[..8].copy_from_slice(&input.context[4..12]);v},'),
]
for name,before,after in mutants:
 if source.count(before)!=1:raise ValueError('ambiguous mutation '+name)
 file=out/(name+'.rs');file.write_text(source.replace(before,after));lib=out/('lib'+name.replace('-','_')+'.rlib');library(file,lib,3,name+'-library');results[name]=compare(lib,3,name,True)
report=dict(pre_rust_seal='346c23e088ae040ab3aab877f400f798154495e9',rows=len(rows),fixture_rows=json.loads((p/'fixture-selection.json').read_text())['rows'],source_sha256=hashlib.sha256((src/'lib.rs').read_bytes()).hexdigest(),driver_sha256=hashlib.sha256((src/'input_only_driver.rs').read_bytes()).hexdigest(),fixture_sha256=hashlib.sha256((p/'client_fixture.rs').read_bytes()).hexdigest(),input_sha256=hashlib.sha256((p/'inputs.jsonl').read_bytes()).hexdigest(),expected_sha256=hashlib.sha256(expected).hexdigest(),mismatches=results,commands=records,platform='macOS arm64 host research rustc1.94.1 edition2021; no original compiler, Linux execution or target-byte claim',repeat='same-path opt3 rlib byte-equal and outputs repeat; separate-directory build unmeasured')
(p/'rust-results.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL BUILD/STREAM/FIXTURE/MUTANT CHECKS PASS',results,flush=True)
