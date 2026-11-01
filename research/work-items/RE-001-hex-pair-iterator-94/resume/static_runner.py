from pathlib import Path
import hashlib,json,os,stat,subprocess,time
ROOT=Path('/tmp/hl-resume-20261101/formatter-56c')
OUT=ROOT.parent/'hex-iterator-static-56c-ba9cb94b';OUT.mkdir(exist_ok=False)
ENV=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',TMPDIR='/tmp/hv',REA_NODE='/tmp/beam-20261101/toolchain/node-v22.23.4-linux-x64/bin/node')
Path('/tmp/hv').mkdir(exist_ok=True)
def git(repo,*args):return subprocess.check_output(['git','-C',str(repo),*args],env=ENV,text=True).strip()
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for part in iter(lambda:f.read(1<<20),b''):h.update(part)
    return h.hexdigest()
def inventory():
    pins=json.loads((ROOT/'provenance/sources.json').read_text())['repositories']
    result={'head':git(ROOT,'rev-parse','HEAD'),'tree':git(ROOT,'rev-parse','HEAD^{tree}'),'status':git(ROOT,'status','--porcelain'),'repositories':{},'files':{}}
    for repo in [ROOT,*[ROOT/p['path'] for p in pins]]:
        label='.' if repo==ROOT else str(repo.relative_to(ROOT))
        result['repositories'][label]={'head':git(repo,'rev-parse','HEAD'),'status':git(repo,'status','--porcelain')}
        raw=subprocess.check_output(['git','-C',str(repo),'ls-files','-s','-z'],env=ENV)
        for entry in raw.split(b'\0'):
            if not entry:continue
            info,name=entry.split(b'\t',1);mode,oid,stage=info.decode().split(' ')
            if mode=='160000':continue
            p=repo/os.fsdecode(name);s=p.lstat()
            digest=hashlib.sha256(os.fsencode(os.readlink(p))).hexdigest() if stat.S_ISLNK(s.st_mode) else sha(p)
            result['files'][str(p.relative_to(ROOT))]={'mode':s.st_mode,'inode':s.st_ino,'links':s.st_nlink,'size':s.st_size,'sha256':digest,'gitBlob':oid}
    return result
before=inventory();(OUT/'BEFORE.json').write_text(json.dumps(before,sort_keys=True)+'\n')
assert before['head']=='ba9cb94bad8617cd1f8cd5565306ae37f6861f81' and not before['status']
results=[]
for name in ['doctor','verify','catalogue-check','reproduce']:
    started=time.monotonic();cmd=['make',name]
    with (OUT/(name+'.stdout')).open('wb') as stdout,(OUT/(name+'.stderr')).open('wb') as stderr:
        r=subprocess.run(cmd,cwd=ROOT,env=ENV,stdout=stdout,stderr=stderr)
    results.append({'command':cmd,'exitCode':r.returncode,'seconds':round(time.monotonic()-started,3),'stdoutSha256':sha(OUT/(name+'.stdout')),'stderrSha256':sha(OUT/(name+'.stderr'))})
    print(json.dumps(results[-1]),flush=True)
    if r.returncode:break
after=inventory();(OUT/'AFTER.json').write_text(json.dumps(after,sort_keys=True)+'\n')
record={'head':before['head'],'files':len(before['files']),'submodules':len(before['repositories'])-1,'unchanged':before==after,'checks':results,'test':'NOT RUN: expanded captured-instruction evaluator authorization not provided','hostedCI':'NOT RUN'}
(OUT/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)
assert before==after and len(results)==4 and all(r['exitCode']==0 for r in results)
