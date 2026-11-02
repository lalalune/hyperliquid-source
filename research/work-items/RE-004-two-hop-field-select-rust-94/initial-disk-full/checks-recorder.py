import base64,gzip,hashlib,json,os,subprocess
from pathlib import Path
root=Path.cwd();out=root/'work/two-hop-field-select-rust/checks';out.mkdir(exist_ok=False)
p=root/'research/work-items/RE-004-two-hop-field-select-rust-94'
sha=lambda b:hashlib.sha256(b).hexdigest()
enc=lambda d:(json.dumps(d,sort_keys=True,indent=2)+'\n').encode()
env=dict(os.environ);env['PATH']='/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:'+env['PATH']
commands=[['make','doctor'],['make','verify'],['make','catalogue-check'],['make','reproduce'],['python3','tools/foundation_two_hop_field_select.py','--check','research/work-items/foundation-two-hop-field-select-94/evidence.json'],['python3','-m','unittest','tests.test_foundation_two_hop_field_select','tests.test_fde_extents_cie_aug_encoding','tests.test_gnu_binutils_tools','-v'],['/Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustfmt','--edition','2021','--check','src/node94-two-hop-field-select/lib.rs','src/node94-two-hop-field-select/input_only_driver.rs'],['/opt/homebrew/opt/binutils/bin/objdump','--version'],['/usr/bin/objdump','--version']]
calls=[];streams={}
for i,cmd in enumerate(commands):
 r=subprocess.run(cmd,capture_output=True,env=env);logs={}
 for name,raw in [('stdout',r.stdout),('stderr',r.stderr)]:
  key=f'{i}-{name}';streams[key]=raw;logs[name]={'file':key,'bytes':len(raw),'sha256':sha(raw)}
 calls.append({'argv':cmd,'exit_code':r.returncode,'logs':logs});(out/'commands.json').write_bytes(enc(calls))
 archive={'encoding':'base64','streams':{n:sha(b) for n,b in streams.items()},'payloads':{sha(b):base64.b64encode(b).decode() for b in streams.values()}}
 (out/'streams.json.gz').write_bytes(gzip.compress(enc(archive),compresslevel=1,mtime=0))
 print(i,cmd[0:3],r.returncode,flush=True)
 if r.returncode:raise SystemExit('check failed; exact streams retained')
for call in calls:
 for log in call['logs'].values():
  raw=base64.b64decode(archive['payloads'][log['sha256']],validate=True)
  if sha(raw)!=log['sha256'] or len(raw)!=log['bytes']:raise ValueError('archive drift')
(p/'checks-commands.json').write_bytes(enc(calls));(p/'checks-streams.json.gz').write_bytes((out/'streams.json.gz').read_bytes())
result={'commands':len(calls),'streams':len(streams),'all_exit_zero':True,'raw_archive_sha256':sha((out/'streams.json.gz').read_bytes()),'archive_parameters':{'compression':'gzip','level':1,'mtime':0},'source_base':subprocess.check_output(['git','rev-parse','HEAD']).decode().strip(),'shared_baseline':'Separate parent baseline at source 56c0ec672bd8fdcfaa80f2db700a61e6240b3663 attempted 971 files / 15462 reported tests / 69 skips. Original make test exit 2 solely three Errno28 disk-full files; their 20 tests passed isolated retry. No successful full-sweep rerun or per-head full-suite, skipped Linux qualification or hosted success is claimed.'}
(p/'checks.json').write_bytes(enc(result))
