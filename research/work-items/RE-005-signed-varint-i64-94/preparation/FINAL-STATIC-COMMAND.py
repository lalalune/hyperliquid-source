"""Four required static targets for the signed357 evidence checkpoint."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,time

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'tools'))
from signed_varint_i64_rust import audit

OUT=ROOT/'work/final-static-signed-varint-i64'
RUSTC=Path('/tmp/hl-resume-20261101/toolchain/prefix/bin/rustc')
CARGO=Path('/workspace/mayhem-build-repeat/toolchain/rust/bin/cargo')
PROVIDER=Path('/tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json')
ENV={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LC_ALL':'C','LANG':'C',
     'TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1'}
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def need(ok,message):
    if not ok:raise ValueError(message)

need(not OUT.exists(),'Preserve earlier static output')
OUT.mkdir()
script=Path(__file__).read_bytes()
before=audit(ROOT,RUSTC,CARGO,PROVIDER)
need(not before['status'],'Final static checkpoint must be clean')
(OUT/'BEFORE.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
calls=[]
for target in ['doctor','verify','catalogue-check','reproduce']:
    argv=['make','-j1','PYTHON=python3 -B',target]
    start=time.monotonic()
    result=subprocess.run(argv,cwd=ROOT,env=ENV,stdin=subprocess.DEVNULL,
                          capture_output=True,timeout=180)
    logs={}
    for kind,raw in [('stdout',result.stdout),('stderr',result.stderr)]:
        name=target+'.'+kind
        (OUT/name).write_bytes(raw)
        logs[kind]={'file':name,'bytes':len(raw),'sha256':sha(raw)}
    calls.append({'argv':argv,'exit_code':result.returncode,
                  'seconds':round(time.monotonic()-start,3),'logs':logs})
    (OUT/'CALLS.json').write_text(json.dumps(calls,indent=2)+'\n')
    need(result.returncode==0,'Actual scoped static target failed: '+target)
after=audit(ROOT,RUSTC,CARGO,PROVIDER)
need(before==after and script==Path(__file__).read_bytes(),
     'Static source/pins/provider/tools/head/tree/status changed')
(OUT/'AFTER.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
summary={'status':'PASS','source_head':before['head'],'source_tree':before['tree'],
         'clean_before_after':True,'actual_physical_inputs':before['physical_count'],
         'actual_pins':len(before['pins']),
         'actual_provider_payloads':len(before['provider_payloads']),
         'actual_installed_manifests':len(before['installed_manifests']),
         'identity_maps_unchanged':True,'wrapper_sha256':sha(script),'calls':calls,
         'limits':['Four required static targets only; eleven owned native/static methods passed in C1.',
                   'No compiler repeat; reviewed source, driver, fixture, manifests, dependency and qualifiers are unchanged from C1.',
                   'Captured execution, new instruction evaluators, expanded/full suite and hosted CI NOT RUN.']}
(OUT/'RESULT.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary))
