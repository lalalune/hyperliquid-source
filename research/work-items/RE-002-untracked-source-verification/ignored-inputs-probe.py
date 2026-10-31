"""Task-local candidate probe; creates no Rust workspace and runs no target."""
from contextlib import redirect_stdout
import hashlib
import argparse
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

anchor=Path(__file__).resolve().parents[3]
packet=Path(__file__).resolve().parent
sys.path.insert(0,str(anchor/'tools'))
import catalogue
import exchange_dispatch
import verify_imports as verifier
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check',action='store_true')
parser.add_argument('--output',type=Path)
args=parser.parse_args()

pin='999556f6e0a474b8312db96ec3149e1c44e97c23'
target_sha='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
artifact=anchor/'artifacts/node/94/hl-node'
assert hashlib.sha256(artifact.read_bytes()).hexdigest()==target_sha
# Only this probe process changes environment; never touch user/global config.
os.environ.update(GIT_CONFIG_GLOBAL='/dev/null',GIT_CONFIG_NOSYSTEM='1',GIT_LFS_SKIP_SMUDGE='1')

def git(repo,*args):
    return subprocess.check_output(['git','-C',str(repo),*args],text=True).strip()

def accepted(root):
    try:
        with redirect_stdout(io.StringIO()):
            verifier.verify(root)
        return True
    except ValueError:
        return False

with tempfile.TemporaryDirectory(prefix='hl-ignored-catalogue-') as directory:
    root=Path(directory)
    reference=root/'references/can1357-hl'
    reference.parent.mkdir()
    subprocess.run(['git','clone','--quiet','--shared','--no-checkout',str(anchor/'references/can1357-hl'),str(reference)],check=True)
    git(reference,'checkout','--quiet','--detach',pin)
    for name in ('research/components.json','research/progress.json',
                 'research/imported/hl-node-94.inventory.json','research/imported/hl-node-115.inventory.json',
                 'research/imported/hl-visor.inventory.json','research/imported/can1357-literal-classes.json'):
        destination=root/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(anchor/name,destination)
    destination=root/'artifacts/node/94/hl-node'
    destination.parent.mkdir(parents=True)
    destination.symlink_to(artifact)
    (root/'provenance').mkdir()
    imports=json.loads((anchor/'provenance/imports.json').read_text())
    sources=json.loads((anchor/'provenance/sources.json').read_text())
    for name in ('imports.json','sources.json'):
        shutil.copyfile(anchor/'provenance'/name,root/'provenance'/name)
    for item in imports['files']:
        destination=root/item['path']
        if destination.exists():
            continue
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.symlink_to(anchor/item['path'])
    for source in sources['repositories']:
        if source['path']=='references/can1357-hl':
            continue
        destination=root/source['path']
        destination.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run(['git','clone','--quiet','--shared','--no-checkout',str(anchor/source['path']),str(destination)],check=True)
        git(destination,'checkout','--quiet','--detach',source['commit'])
    original=catalogue.generate(root)
    original_document=json.loads(original['research/catalogue/components.json'])
    elf=exchange_dispatch.Elf(artifact.read_bytes())
    starts,ends=exchange_dispatch.fde_index(elf)
    original_survey=exchange_dispatch.survey_addresses(reference/'l1/exchange',starts,ends)
    assert accepted(root)
    exclude=reference/'.git/info/exclude'
    exclude.write_text(exclude.read_text()+'\n*.backup.rs\n')
    backup=reference/'base/local.backup.rs'
    # A normal local backup stays in the temporary reference copy only.
    shutil.copyfile(reference/'base/duration.rs',backup)
    exchange_backup=reference/'l1/exchange/local.backup.rs'
    shutil.copyfile(reference/'l1/exchange/impl_execute_action.rs',exchange_backup)
    assert git(reference,'check-ignore','base/local.backup.rs')=='base/local.backup.rs'
    status=git(reference,'status','--porcelain','--untracked-files=all')
    with_backup=catalogue.generate(root)
    backup_document=json.loads(with_backup['research/catalogue/components.json'])
    backup_survey=exchange_dispatch.survey_addresses(reference/'l1/exchange',starts,ends)
    ignored_accepted=accepted(root)
    regular=reference/'base/local-untracked.rs'
    regular.write_text('// explicit independent local fixture\n')
    untracked_accepted=accepted(root)
    regular.unlink()
    tracked=reference/'base/duration.rs'
    tracked.write_bytes(tracked.read_bytes()+b'\n// explicit corruption control\n')
    modified_accepted=accepted(root)
    record={'fixture':'Task-local clone of pinned reference; canonical metadata and read-only authenticated node94. No target execution or Rust implementation.',
            'targetSha256':target_sha,'referenceCommit':pin,
            'importedFilesVerified':len(imports['files']),'sourceRepositoriesVerified':len(sources['repositories']),
            'cleanReferenceCount':original_document['path_totals']['reference'],
            'ignoredBackupReferenceCount':backup_document['path_totals']['reference'],
            'ignoredBackupStatus':status,'sourceAcceptedWithIgnoredBackup':ignored_accepted,
            'generatedOutputsUnchanged':original==with_backup,
            'backupCountedAsSource':any('base/local.backup.rs' in row['reference_paths'] for row in backup_document['components']),
            'cleanAddressSurveyCount':len(original_survey),'ignoredBackupAddressSurveyCount':len(backup_survey),
            'addressSurveyUnchanged':original_survey==backup_survey,
            'ordinaryUntrackedAccepted':untracked_accepted,'trackedModificationAccepted':modified_accepted}
    assert ignored_accepted and not status and not untracked_accepted and not modified_accepted
    if args.check:
        assert record==json.loads((packet/'ignored-inputs-after.json').read_text()), 'Ignored source input regression'
    if args.output:
        args.output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))
