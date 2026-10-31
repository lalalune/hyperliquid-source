"""Reproduce legacy literal membership on real pinned inputs; never run a captured target."""
import hashlib,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
import argparse
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check',action='store_true')
parser.add_argument('--output',type=Path)
parser.add_argument('--logs-dir',type=Path)
args=parser.parse_args()
anchor=Path(__file__).resolve().parents[3]
source=anchor
packet=Path(__file__).resolve().parent
logs_context=tempfile.TemporaryDirectory(prefix='hl-legacy-logs-')
out=args.logs_dir or Path(logs_context.name)
out.mkdir(parents=True,exist_ok=True)
env=dict(os.environ,GIT_CONFIG_GLOBAL=os.devnull,GIT_CONFIG_NOSYSTEM='1',GIT_LFS_SKIP_SMUDGE='1')
for i,(key,value) in enumerate([('filter.lfs.clean','git-lfs clean -- %f'),('filter.lfs.smudge','git-lfs smudge -- %f'),('filter.lfs.process','git-lfs filter-process'),('filter.lfs.required','true')]):
    env[f'GIT_CONFIG_KEY_{i}']=key;env[f'GIT_CONFIG_VALUE_{i}']=value
env['GIT_CONFIG_COUNT']='4'
def git(repo,*args):return subprocess.check_output(['git','-C',str(repo),*args],env=env,text=True).strip()
with tempfile.TemporaryDirectory(prefix='hl-legacy-source-') as temporary:
    root=Path(temporary)
    shutil.copytree(source/'tools',root/'tools',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(source/'provenance',root/'provenance')
    shutil.copytree(anchor/'research/imported',root/'research/imported')
    manifest=json.loads((root/'provenance/artifacts.json').read_text())
    for item in manifest['files']:
        dest=root/item['path'];dest.parent.mkdir(parents=True,exist_ok=True)
        dest.symlink_to(anchor/item['path'])
    imports=json.loads((source/'provenance/imports.json').read_text())
    for item in imports['files']:
        if item['path'].startswith(('references/','upstream/')):continue
        dest=root/item['path'];dest.parent.mkdir(parents=True,exist_ok=True)
        if not dest.exists():dest.symlink_to(anchor/item['path'])
    sources=json.loads((source/'provenance/sources.json').read_text())
    for record in sources['repositories']:
        dest=root/record['path'];dest.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run(['git','clone','--quiet','--shared','--no-checkout',str(anchor/record['path']),str(dest)],env=env,check=True)
        git(dest,'checkout','--quiet','--detach',record['commit'])
    # Materialize the existing authenticated duplicate without downloading LFS.
    # A normal file retains its committed LFS-normalized identity.
    shutil.copyfile(anchor/'references/can1357-hl/bin/hl-node-mainnet-new',root/'references/can1357-hl/bin/hl-node-mainnet-new')
    ref=root/'references/can1357-hl'
    assert git(ref,'hash-object','--path=bin/hl-node-mainnet-new','bin/hl-node-mainnet-new')==git(ref,'rev-parse','HEAD:bin/hl-node-mainnet-new')
    # Refresh the owned clone's stat cache after manual LFS materialization.
    git(ref,'add','--','bin/hl-node-mainnet-new')
    assert not git(ref,'diff','--cached','--raw')
    def run(name,command):
        with (out/(name+'.log')).open('w') as log:
            r=subprocess.run(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=600)
        return r.returncode
    checks={}
    checks['clean-verify']=run('legacy-clean-verify',['python3','tools/verify_imports.py'])
    if checks['clean-verify']:
        ref=root/'references/can1357-hl'
        diagnostics={'status':git(ref,'status','--porcelain','--untracked-files=all'),'diff':git(ref,'diff','--raw'),'cached':git(ref,'diff','--cached','--raw'),'headBlob':git(ref,'rev-parse','HEAD:bin/hl-node-mainnet-new'),'attributes':git(ref,'check-attr','-a','--','bin/hl-node-mainnet-new'),'index':git(ref,'ls-files','-s','bin/hl-node-mainnet-new'),'cleanHash':git(ref,'hash-object','--path=bin/hl-node-mainnet-new','bin/hl-node-mainnet-new')}
        (out/'legacy-clone-diagnostic.json').write_text(json.dumps(diagnostics,indent=2)+'\n')
        print(json.dumps(diagnostics),flush=True)
        raise RuntimeError('Clean verifier fixture not ready; no product conclusion')
    checks['clean-reproduce']=run('legacy-clean-reproduce',['python3','tools/reproduce.py'])
    assert checks['clean-verify']==0 and checks['clean-reproduce']==0
    before=json.loads((root/'work/reproduced/can1357-literal-classes.raw.json').read_text())
    ref=root/'references/can1357-hl'
    backup=ref/'.history/base/duration.rs'
    backup.parent.mkdir(parents=True)
    shutil.copyfile(ref/'base/duration.rs',backup)
    exclude=ref/'.git/info/exclude';exclude.write_text(exclude.read_text()+'\n.history/\n')
    assert git(ref,'check-ignore','.history/base/duration.rs')=='.history/base/duration.rs'
    assert not git(ref,'status','--porcelain','--untracked-files=all')
    grounding_before=subprocess.check_output(['python3','tools/legacy/grounding.py',str(ref),str(root/'artifacts/node/94/hl-node')],cwd=root,env=env)
    # Grounding baseline must exclude the ignored history too. Compare with its
    # own clean input after temporarily removing this one owned copy.
    backup.unlink()
    grounding_clean=subprocess.check_output(['python3','tools/legacy/grounding.py',str(ref),str(root/'artifacts/node/94/hl-node')],cwd=root,env=env)
    shutil.copyfile(ref/'base/duration.rs',backup)
    checks['history-verify']=run('legacy-history-verify',['python3','tools/verify_imports.py'])
    checks['history-reproduce']=run('legacy-history-reproduce',['python3','tools/reproduce.py'])
    after=json.loads((root/'work/reproduced/can1357-literal-classes.raw.json').read_text())
    target=anchor/'artifacts/node/94/hl-node'
    result={'previousSourceHead':'5bc9baff84b04c87ad9fa737d3e1711f1271eb2b','targetSha256':hashlib.sha256(target.read_bytes()).hexdigest(),'referenceCommit':git(ref,'rev-parse','HEAD'),'checks':checks,'importedFiles':len(imports['files']),'pinnedRepositories':len(sources['repositories']),'cleanLiteralCount':len(before['items']),'historyLiteralCount':len(after['items']),'historyRows':[x for x in after['items'] if x['crate']=='.history'],'countsUnchanged':before['counts']==after['counts'],'completeRawOutputUnchanged':before==after,'groundingOutputUnchanged':grounding_clean==grounding_before,'sourceStatus':git(ref,'status','--porcelain','--untracked-files=all'),'capturedBinaryExecuted':False}
    if args.check:
        assert result==json.loads((packet/'legacy-inputs-after.json').read_text()), 'Legacy source input regression'
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='historyRows'}))
