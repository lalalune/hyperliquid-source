"""Exact bounded final static checks; captured binaries never execute."""
from pathlib import Path
import hashlib,json,os,shutil,stat,subprocess,time

ROOT=Path(__file__).resolve().parents[4]
OUT=ROOT/'work/final-static-u128-binary64'
PREFIX=Path('/tmp/hl-resume-20261101/toolchain/prefix')
PROVIDER=PREFIX.parent/'PROVIDER-AUDIT.json'
ENV={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'LC_ALL':'C','LANG':'C','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1'}
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def need(ok,message):
    if not ok:raise ValueError(message)

def physical(path):
    path=Path(path)
    mode=oct(stat.S_IMODE(path.lstat().st_mode))
    if path.is_symlink():
        raw=os.readlink(path).encode();return {'kind':'symlink-text','physical_mode':mode,'bytes':len(raw),'sha256':sha(raw)}
    need(path.is_file(),'Expected physical regular file: '+str(path))
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda:stream.read(1<<20),b''):digest.update(part)
    return {'kind':'file','physical_mode':mode,'bytes':path.stat().st_size,'sha256':digest.hexdigest()}

def git(repo,*args):
    return subprocess.check_output(['/usr/bin/git',*args],cwd=repo,env=ENV,stdin=subprocess.DEVNULL)

def audit():
    files={};pins={}
    def walk(repo,prefix=''):
        for raw in git(repo,'ls-files','--stage','-z').split(b'\0'):
            if not raw:continue
            header,name=raw.split(b'\t',1);mode,oid,stage=header.decode().split();need(stage=='0','Unmerged input')
            name=name.decode();rel=Path(name);need(not rel.is_absolute() and '..' not in rel.parts,'Escaping tracked path')
            path=repo/rel;key=prefix+name
            if mode=='160000':
                head=git(path,'rev-parse','HEAD').decode().strip();state=git(path,'status','--porcelain=v1','--untracked-files=all').decode()
                need(head==oid and not state,'Actual pinned child changed: '+key)
                pins[key]={'index':oid,'actual':head,'clean':True};walk(path,key+'/')
            else:
                need(mode in ('100644','100755','120000'),'Unsupported tracked mode')
                need((mode=='120000')==path.is_symlink(),'Physical/index file kind differs')
                files[key]={'index_mode':mode,**physical(path)}
    walk(ROOT);need(len(pins)==7,'Seven actual pinned children required')
    need(physical(PROVIDER)['sha256']=='56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6','Provider audit differs')
    provider=json.loads(PROVIDER.read_text());payloads={};manifests={}
    for row in provider['payloads']:
        rel=Path(row['path']);need(not rel.is_absolute() and '..' not in rel.parts,'Provider path escapes prefix')
        value=physical(PREFIX/rel);need(value['bytes']==row['bytes'] and value['sha256']==row['sha256'],'Provider payload differs')
        payloads[row['path']]=value
    need(len(payloads)==provider['payload_count']==103,'Provider payload denominator differs')
    for name,digest in provider['installed_manifest_sha256'].items():
        need(Path(name).name==name,'Provider manifest escapes prefix')
        value=physical(PREFIX/'lib/rustlib'/name);need(value['sha256']==digest,'Installed manifest differs');manifests[name]=value
    need(len(manifests)==2,'Installed manifest denominator differs')
    tools={}
    for name in ['cc','ld.bfd','objdump']:
        chosen=shutil.which(name,path='/usr/bin:/bin');need(chosen is not None,'Missing actual tool: '+name)
        canonical=Path(chosen).resolve(strict=True);tools[name]={'chosen':chosen,'canonical':str(canonical),**physical(canonical)}
    return {'head':git(ROOT,'rev-parse','HEAD').decode().strip(),'tree':git(ROOT,'rev-parse','HEAD^{tree}').decode().strip(),
            'status':git(ROOT,'status','--porcelain=v1','--untracked-files=all').decode(),'physical_count':len(files),'physical':files,
            'pins':pins,'provider':payloads,'installed_manifests':manifests,'tools':tools}

need(not OUT.exists(),'Preserve earlier static output');OUT.mkdir()
script=Path(__file__).read_bytes();before=audit();need(not before['status'],'Final static checkpoint must be clean')
(OUT/'BEFORE.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
commands=[['make','-j1','PYTHON=python3 -B',name] for name in ['doctor','verify','catalogue-check','reproduce']]
commands.append(['python3','-B','-m','unittest','tests.test_u128_binary64_contract','-v'])
calls=[]
for index,argv in enumerate(commands):
    start=time.monotonic();result=subprocess.run(argv,cwd=ROOT,env=ENV,stdin=subprocess.DEVNULL,capture_output=True,timeout=180)
    logs={}
    for kind,raw in [('stdout',result.stdout),('stderr',result.stderr)]:
        name=f'{index}-{argv[-1]}.{kind}';(OUT/name).write_bytes(raw);logs[kind]={'file':name,'bytes':len(raw),'sha256':sha(raw)}
    calls.append({'argv':argv,'exit_code':result.returncode,'seconds':round(time.monotonic()-start,3),'logs':logs})
    (OUT/'CALLS.json').write_text(json.dumps(calls,indent=2)+'\n')
    need(result.returncode==0,'Actual scoped static command failed: '+str(argv))
after=audit();need(before==after and script==Path(__file__).read_bytes(),'Static inputs/provider/head/tree/status/tools changed')
(OUT/'AFTER.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
summary={'status':'PASS','source_head':before['head'],'source_tree':before['tree'],'clean_before_after':True,
         'actual_physical_inputs':before['physical_count'],'actual_pins':len(before['pins']),
         'actual_provider_payloads':len(before['provider']),'actual_installed_manifests':len(before['installed_manifests']),
         'identity_maps_unchanged':True,'wrapper_sha256':sha(script),'calls':calls,
         'limits':['Four required static targets and ten owned native controls only; expanded/full suite, hosted CI and captured execution NOT RUN.',
                   'Own Rust numerical qualification remains on separately reviewed clean C1; later metadata does not change its executable inputs.']}
(OUT/'RESULT.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
