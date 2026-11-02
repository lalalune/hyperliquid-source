from pathlib import Path
import importlib.util,json,subprocess,sys,time,hashlib
B=Path('/tmp/hl-resume-20261101/selector-56c');O=Path('/tmp/hl-resume-20261101/string-pad-ledger-09b36530');HEAD='09b36530336a7ffaed7571b2dc51acddc4f5c862'
spec=importlib.util.spec_from_file_location('g',B/'research/work-items/RE-005-string-pad-94/validate_string_pad.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
known=json.loads(Path('/tmp/hl-resume-20261101/string-pad-build-70cc50b2/BEFORE.json').read_text());prefix=Path('/tmp/hl-resume-20261101/toolchain/prefix')
assert not O.exists();O.mkdir()
sha=lambda x:hashlib.sha256(x).hexdigest()
pins=json.loads((B/'provenance/sources.json').read_text())['repositories']
def audit():
 value={'repositories':[],'tracked_physical_inputs':{},'provider_payloads':{},'installed_component_manifests':{}}
 for relative,expected in [('.',HEAD)]+[(p['path'],p['commit'])for p in pins]:
  root=B/relative
  assert Path(g.git(root,'rev-parse','--show-toplevel')).resolve()==root.resolve()
  head=g.git(root,'rev-parse','HEAD');status=g.git(root,'status','--porcelain','--untracked-files=all');assert head==expected and not status
  value['repositories'].append({'path':relative,'head':head,'tree':g.git(root,'rev-parse','HEAD^{tree}'),'status':status})
  entries=subprocess.check_output(['git','-C',str(root),'ls-files','--stage','-z'],env=g.CLEAN_ENV)
  for raw in entries.split(b'\0')[:-1]:
   metadata,name=raw.split(b'\t',1);mode,oid,stage=metadata.split(b' ');assert stage==b'0'
   if mode==b'160000':assert relative=='.'and name.decode()in{p['path']for p in pins};continue
   path=Path(relative)/name.decode();value['tracked_physical_inputs'][str(path)]=g.physical(B/path)
 for name,expected in known['provider_payloads'].items():
  actual=g.physical(prefix/name);assert actual==expected;value['provider_payloads'][name]=actual
 for name,expected in known['installed_component_manifests'].items():
  actual=g.physical(prefix/'lib/rustlib'/name);assert actual==expected;value['installed_component_manifests'][name]=actual
 for key,path in [('target',B/'artifacts/node/94/hl-node'),('core_archive',prefix/'lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib'),('linker',Path('/usr/bin/gcc').resolve()),('ld_bfd',Path('/usr/bin/ld.bfd').resolve()),('provider_audit',Path('/tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json')),('runner',B/'research/work-items/RE-005-string-pad-94/validate_string_pad.py')]:
  actual=g.physical(path);assert actual==known[key];value[key]=actual
 return value
before=audit();(O/'BEFORE.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
env=dict(g.CLEAN_ENV,PATH=str(prefix/'bin')+':/usr/local/bin:/usr/bin:/bin');calls=[]
commands=[('verify',['make','-j1','PYTHON='+sys.executable+' -B','verify']),('catalogue-check',['make','-j1','PYTHON='+sys.executable+' -B','catalogue-check']),('byte-accounting-tests',[sys.executable,'-B','-m','unittest','discover','-s','tests','-p','test_byte_progress.py','-v'])]
for label,argv in commands:
 start=time.monotonic();p=subprocess.run(argv,cwd=B,env=env,capture_output=True);row={'label':label,'argv':argv,'exit':p.returncode,'seconds':time.monotonic()-start,'streams':{}}
 for name,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
  path=O/(label+'.'+name);path.write_bytes(raw);row['streams'][name]={'file':path.name,'bytes':len(raw),'sha256':sha(raw)}
 calls.append(row);print(json.dumps(row),flush=True)
 if p.returncode:break
after=audit();(O/'AFTER.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n');(O/'CALLS.json').write_text(json.dumps(calls,sort_keys=True,indent=2)+'\n')
result={'status':'PASS'if before==after and len(calls)==3 and all(c['exit']==0 for c in calls)else'FAIL','head':HEAD,'same_inputs':before==after,'tracked_physical_inputs':len(before['tracked_physical_inputs']),'pinned_repositories':len(pins),'provider_payloads':len(before['provider_payloads']),'installed_manifests':len(before['installed_component_manifests']),'calls':calls,'wrapper_sha256':sha(Path(__file__).read_bytes()),'full_make_test':'NOT_RUN','captured_execution_or_instruction_evaluator':False}
(O/'RESULT.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result),flush=True);raise SystemExit(0 if result['status']=='PASS'else 1)
