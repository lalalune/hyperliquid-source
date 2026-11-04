#!/usr/bin/env python3
"""Authenticate and replay bounded H2 framing evidence; never run target code."""
import base64,gzip,hashlib,importlib.util,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
PACKET=Path(__file__).resolve().parent;ROOT=PACKET.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import h2_framing_115_static as c
PACKET_FILES=['CONTRACT.md', 'README.md', 'licensed-sources.json.gz', 'native/commands.json', 'native/driver.rs', 'native/qualify.py', 'native/result.json', 'oracle/FREEZE.json', 'oracle/cases.jsonl.gz', 'oracle/extraction.json', 'oracle/relation.py', 'preparation/build_oracle.py', 'raw-streams.json.gz', 'scope-review.json', 'source-countercheck.json', 'sources.json', 'spec.json', 'static/buffered_wrapper.gnu.stderr', 'static/buffered_wrapper.gnu.txt', 'static/buffered_wrapper.llvm.stderr', 'static/buffered_wrapper.llvm.txt', 'static/builder.gnu.stderr', 'static/builder.gnu.txt', 'static/builder.llvm.stderr', 'static/builder.llvm.txt', 'static/commands.json', 'static/decoder.gnu.stderr', 'static/decoder.gnu.txt', 'static/decoder.llvm.stderr', 'static/decoder.llvm.txt', 'static/h2_constructor.gnu.stderr', 'static/h2_constructor.gnu.txt', 'static/h2_constructor.llvm.stderr', 'static/h2_constructor.llvm.txt', 'static/poll_reader_a.gnu.stderr', 'static/poll_reader_a.gnu.txt', 'static/poll_reader_a.llvm.stderr', 'static/poll_reader_a.llvm.txt', 'static/poll_reader_b.gnu.stderr', 'static/poll_reader_b.gnu.txt', 'static/poll_reader_b.llvm.stderr', 'static/poll_reader_b.llvm.txt', 'static/promote_shared.gnu.stderr', 'static/promote_shared.gnu.txt', 'static/promote_shared.llvm.stderr', 'static/promote_shared.llvm.txt', 'static/records.json', 'static/split_to.gnu.stderr', 'static/split_to.gnu.txt', 'static/split_to.llvm.stderr', 'static/split_to.llvm.txt', 'validation.json', 'verify.py']
DEPENDENCIES=['tools/h2_framing_115_static.py','tools/elf_index.py','tools/fde_extents.py','tests/test_h2_framing_115.py','src/node115-h2-framing/src/lib.rs','src/node115-h2-framing/README.md','src/node115-h2-framing/Cargo.toml','src/node115-h2-framing/Cargo.lock']
def load(path):return json.loads(Path(path).read_bytes(),object_pairs_hook=c.unique)
def inventory(packet):
 expected=set(PACKET_FILES)|{'MANIFEST.sha256'};dirs={p.as_posix()for n in expected for p in Path(n).parents if p.as_posix()!='.'};files=set();actualdirs=set()
 c.require(not packet.is_symlink(),'packet symlink')
 for p in packet.rglob('*'):
  c.require(not p.is_symlink(),'packet symlink');n=p.relative_to(packet).as_posix()
  if p.is_dir():actualdirs.add(n)
  else:c.require(p.is_file(),'not a file');files.add(n)
 c.require(files==expected and actualdirs==dirs,'closed packet inventory differs')
def manifest():
 expected={str(PACKET.relative_to(ROOT)/n)for n in PACKET_FILES}|set(DEPENDENCIES);seen=set()
 for line in (PACKET/'MANIFEST.sha256').read_text().splitlines():
  digest,name=line.split('  ',1);c.require(name not in seen and name in expected,'manifest row inventory differs');seen.add(name);path=Path(name);c.require(not path.is_absolute() and '..'not in path.parts,'unsafe path');q=ROOT
  for part in path.parts:q=q/part;c.require(not q.is_symlink(),'manifest symlink')
  c.require(q.is_file() and c.digest(q.read_bytes())==digest,'manifest content differs: '+name)
 c.require(seen==expected,'manifest missing files')
def archive(path):
 d=json.loads(gzip.decompress(Path(path).read_bytes()),object_pairs_hook=c.unique);c.require(d['schema']==1,'archive schema');out={}
 for row in d['streams']:
  label=row['label'];c.require(label not in out,'duplicate stream');raw=base64.b64decode(row['base64'],validate=True);c.require(type(row['bytes'])is int and row['bytes']==len(raw) and row['sha256']==c.digest(raw),'stream hash/size');out[label]=raw
 return out

def verify_values():
 raw=gzip.decompress((PACKET/'oracle/cases.jsonl.gz').read_bytes());freeze=load(PACKET/'oracle/FREEZE.json');c.require(c.digest(raw)==freeze['raw_sha256'] and c.digest((PACKET/'oracle/cases.jsonl.gz').read_bytes())==freeze['archive_sha256'],'oracle freeze differs')
 src=PACKET/'oracle/relation.py';d=load(PACKET/'oracle/extraction.json');c.require(c.digest(src.read_bytes())==d['relation_sha256'],'relation digest');original=(PACKET/'preparation/build_oracle.py').read_bytes();c.require(c.digest(original)==freeze['oracle_source_sha256']==d['original_source_sha256'],'oracle source chronology');c.require(original.split(b'r=random.Random',1)[0].rstrip()+b'\n'==src.read_bytes(),'oracle relation extraction differs')
 spec=importlib.util.spec_from_file_location('h2_frozen_relation',src);m=importlib.util.module_from_spec(spec)
 old_bytecode=sys.dont_write_bytecode;sys.dont_write_bytecode=True
 try:spec.loader.exec_module(m)
 finally:sys.dont_write_bytecode=old_bytecode
 rows=[json.loads(x,object_pairs_hook=c.unique)for x in raw.splitlines()];c.require(len(rows)==freeze['cases']==28360,'case count')
 for row in rows:c.require(m.expect(row['input'])==row['expected'],'frozen relation mismatch')
 inputs=''.join('|'.join(map(str,x['input']))+'\n'for x in rows).encode();want=''.join(x['expected']+'\n'for x in rows).encode();streams=archive(PACKET/'raw-streams.json.gz');report=load(PACKET/'native/result.json');c.require(report['source_sha256']==c.digest((ROOT/'src/node115-h2-framing/src/lib.rs').read_bytes()),'qualified source differs');c.require(report['driver_sha256']==c.digest((PACKET/'native/driver.rs').read_bytes()),'driver differs');c.require(report['input_sha256']==c.digest(inputs) and report['expected_sha256']==c.digest(want),'qualification fixtures differ');c.require(streams['native/inputs.txt']==inputs and streams['native/expected.txt']==want,'retained fixture streams differ')
 c.require(len(report['correct'])==4 and len(report['controls'])==12,'native inventory');commands=load(PACKET/'native/commands.json');c.require(len({x['label']for x in commands})==len(commands),'duplicate commands')
 for command in commands:
  label=command['label'];c.require(command['exit_code']==0,'native nonzero exit');c.require(c.digest(streams['native/'+label+'.stdout'])==command['stdout_sha256'] and c.digest(streams['native/'+label+'.stderr'])==command['stderr_sha256'],'command stream differs')
 for r in report['correct']:
  out=streams['native/'+r['label']+'-run.stdout'];c.require(out==want and c.digest(out)==r['output_sha256'],'native correct differs')
 for r in report['controls']:
  out=streams['native/'+r['label']+'-run.stdout'];got=out.splitlines();expected=want.splitlines();diff=[i for i,(a,b)in enumerate(zip(got,expected))if a!=b];c.require(len(got)==len(expected) and diff and len(diff)==r['differences'] and diff[0]==r['first_difference'] and c.digest(out)==r['output_sha256'],'ineffective/corrupt mutant')
 return len(rows),len(streams)

def main():
 inventory(PACKET);manifest();report=c.analyze(c.TARGET.read_bytes());c.require(report==load(PACKET/'static/records.json'),'static replay differs');commands=load(PACKET/'static/commands.json');seen=set()
 for row in commands:
  name,provider=row['name'],row['provider'];c.require((name,provider)not in seen,'duplicate export');seen.add((name,provider));b=report['bodies'][name];raw=(PACKET/f'static/{name}.{provider}.txt').read_bytes();err=(PACKET/f'static/{name}.{provider}.stderr').read_bytes();c.require(row['exit_code']==0 and c.digest(raw)==row['stdout_sha256'] and c.digest(err)==row['stderr_sha256'],'decoder stream differs');rows,joins=c.native_rows(raw.decode(),int(b['start'],16),int(b['end'],16));want=[(int(i['va'],16),bytes.fromhex(i['bytes']))for i in b['instructions']];c.require(rows==want and joins==row['lock_prefix_joins'],'native decode differs')
 c.require(seen=={(n,p)for n in report['bodies']for p in ['gnu','llvm']},'export inventory');sources=archive(PACKET/'licensed-sources.json.gz')
 for row in load(PACKET/'sources.json'):c.require(row['sha256']==c.digest(sources[row['file']]) and row['bytes']==len(sources[row['file']]),'source registry differs')
 cases,streams=verify_values();print(json.dumps(dict(status='PASS',bodies=len(report['bodies']),bytes=report['complete_bytes'],instructions=report['instructions'],cases=cases,builds=4,mutants=12,streams=streams,captured_execution=False)))
if __name__=='__main__':main()
