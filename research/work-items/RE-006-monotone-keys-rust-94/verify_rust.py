#!/usr/bin/env python3
"""Prepare frozen fixtures; optionally build only with a supplied pinned rustc."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = ROOT/'src/node94-orderbook'
MODULE = COMPONENT/'src/monotone_keys.rs'
FROZEN = ROOT/'research/work-items/RE-006-large-sort-monotone-path-94/fixtures.json'
FROZEN_SHA = '086d75c7e15d84bd83c9575640b02286fd53b291d390badab30f0054af34b542'
CRATE = 'node94_orderbook'
MUTANT_DOMAINS = {
    'signed-comparisons':'qualified native value relation',
    'reject-ascending-ties':'qualified native value relation',
    'skip-final-pair':'qualified native value relation',
    'reverse-ascending':'qualified native value relation',
    'upper-limit-4095':'qualified native value relation',
    'allow-descending-ties':'chosen safe API policy only',
}


def require(ok,message):
    if not ok: raise ValueError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def render(value): return json.dumps(value,sort_keys=True,indent=2)+'\n'
def packed(words): return b''.join(struct.pack('<Q',x) for x in words)


def live_source_files():
    tracked=subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z','--',str(COMPONENT.relative_to(ROOT))])
    paths={ROOT/name for name in tracked.decode().split('\0') if name}
    paths.add(MODULE)
    result={}
    for path in sorted(paths):
        require(path.is_file() and not path.is_symlink(),'component source missing or symlinked: '+str(path))
        result['component/'+str(path.relative_to(COMPONENT))]=path
    result['driver/input_only_driver.rs']=HERE/'input_only_driver.rs'
    return result


def tree_manifest(directory):
    result={}
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(),'source snapshot contains symlink')
        if path.is_file():
            raw=path.read_bytes(); result[str(path.relative_to(directory))]=dict(sha256=sha(raw),bytes=len(raw))
    return result


def check_snapshot(directory,expected):
    require(tree_manifest(directory)==expected,'fixed compiler-read source snapshot changed')


def check_live_source(expected):
    actual={name:dict(sha256=sha(path.read_bytes()),bytes=path.stat().st_size) for name,path in live_source_files().items()}
    require(actual==expected,'live candidate no longer matches compiled source snapshot')


def source_snapshot(out):
    directory=out/'source-snapshot'
    require(not directory.exists(),'choose a fresh --out: source snapshot already exists')
    directory.mkdir(parents=True)
    for name,path in live_source_files().items():
        destination=directory/name; destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(path.read_bytes())
    manifest=tree_manifest(directory)
    check_live_source(manifest)
    return directory,manifest


def checked_fixture_artifacts(out,fixture):
    payloads={}
    for name,key in [('input.bin','input_sha256'),('expected.bin','expected_sha256')]:
        path=out/name
        require(path.is_file() and not path.is_symlink(),'missing or symlinked fixture artifact: '+name)
        raw=path.read_bytes()
        require(sha(raw)==fixture[key],'frozen fixture artifact changed: '+name)
        payloads[name]=raw
    return payloads['input.bin']


def cases():
    raw=FROZEN.read_bytes(); require(sha(raw)==FROZEN_SHA,'qualified pre-Rust fixture identity mismatch')
    qualified=[]; maximum=2**64-1
    for frozen in json.loads(raw)['cases']:
        if 'expected_output_sha256' not in frozen: continue
        n,family=frozen['count'],frozen['family']
        if family=='constant': words=[2**63]*n
        elif family=='nondecreasing_ties': words=[(i//3)*maximum//((n-1)//3) for i in range(n)]
        else:
            words=[i*maximum//(n-1) for i in range(n)]
            if family=='decreasing': words.reverse()
        require(sha(packed(words))==frozen['input_sha256'],'frozen input recipe changed')
        expected=list(reversed(words)) if family=='decreasing' else list(words)
        require(sha(packed(expected))==frozen['expected_output_sha256'],'pre-Rust native-derived expectation changed')
        qualified.append(dict(name=frozen['name'],words=words,expected=expected,
                              status=1 if family=='decreasing' else 0,scope='qualified native value relation'))
    require(len(qualified)==76,'qualified denominator changed')
    policies=[]
    for n in [0,20,4097]:
        words=list(range(n)); policies.append(dict(name='unsupported-length-'+str(n),words=words,expected=list(words),status=2,scope='chosen safe API policy only'))
    words=list(range(21,0,-1)); words[2]=words[1]
    policies.append(dict(name='unsupported-descending-tie',words=words,expected=list(words),status=3,scope='chosen safe API policy only'))
    words=list(range(21)); words[10]=0
    policies.append(dict(name='unsupported-nonmonotone',words=words,expected=list(words),status=3,scope='chosen safe API policy only'))
    return qualified+policies


def protocol(rows,expected=False):
    out=bytearray(b'M94OUT01' if expected else b'M94IN001'); out+=struct.pack('<I',len(rows))
    for index,row in enumerate(rows):
        words=row['expected'] if expected else row['words']
        out+=struct.pack('<I',index)
        if expected: out+=bytes([row['status']])
        out+=struct.pack('<I',len(words))+packed(words)
    return bytes(out)


def decode_output(raw,rows):
    require(raw[:8]==b'M94OUT01' and len(raw)>=12,'invalid output header')
    require(struct.unpack_from('<I',raw,8)[0]==len(rows),'output count mismatch')
    position=12; result=[]
    for index,row in enumerate(rows):
        require(position+9<=len(raw),'truncated output record')
        got_id,status,count=struct.unpack_from('<IBI',raw,position); position+=9
        require(got_id==index and count==len(row['words']),'output identity/length mismatch')
        require(position+count*8<=len(raw),'truncated output words')
        words=list(struct.unpack_from('<'+'Q'*count,raw,position));position+=count*8
        result.append(dict(name=row['name'],status=status,words=words))
    require(position==len(raw),'trailing output bytes')
    return result


def compare(raw,rows):
    mismatches=[]
    for actual,expected in zip(decode_output(raw,rows),rows):
        if actual['status']!=expected['status'] or actual['words']!=expected['expected']:
            mismatches.append(dict(name=expected['name'],scope=expected['scope'],
                expected_status=expected['status'],actual_status=actual['status'],
                expected_sha256=sha(packed(expected['expected'])),actual_sha256=sha(packed(actual['words']))))
    return mismatches


def wrong_variants(source):
    changes={
        'signed-comparisons': [('words[1] < words[0]','(words[1] as i64) < (words[0] as i64)'),
                               ('pair[1] >= pair[0]','(pair[1] as i64) >= (pair[0] as i64)'),
                               ('pair[1] < pair[0]','(pair[1] as i64) < (pair[0] as i64)')],
        'reject-ascending-ties':[('} else if pair[1] < pair[0] {','} else if pair[1] <= pair[0] {')],
        'allow-descending-ties':[('if pair[1] >= pair[0] {','if pair[1] > pair[0] {')],
        'skip-final-pair':[('for left in 0..(length / 2) {','for left in 0..(length / 2 - 1) {')],
        'reverse-ascending':[('if ordering == QualifiedOrdering::StrictlyDecreasing {','if ordering == QualifiedOrdering::Nondecreasing {')],
        'upper-limit-4095':[('MAX_WORDS: usize = 4096','MAX_WORDS: usize = 4095')],
    }
    result={}
    for name,replacements in changes.items():
        modified=source
        for before,after in replacements:
            require(modified.count(before)==1,'mutation source anchor changed: '+name)
            modified=modified.replace(before,after)
        result[name]=modified
    return result


def prepare(out):
    rows=cases(); out.mkdir(parents=True,exist_ok=True)
    snapshot,source_manifest=source_snapshot(out)
    stimulus,golden=protocol(rows),protocol(rows,expected=True)
    (out/'input.bin').write_bytes(stimulus);(out/'expected.bin').write_bytes(golden)
    require(not compare(golden,rows),'fixture self-admission failed')
    changed=bytearray(golden); changed[21]^=1
    require(bool(compare(changed,rows)),'corrupted full-buffer output not rejected')
    variants=wrong_variants((snapshot/'component/src/monotone_keys.rs').read_text())
    result=dict(qualified_cases=76,safe_api_policy_cases=5,input_sha256=sha(stimulus),expected_sha256=sha(golden),
        frozen_source={'path':str(FROZEN.relative_to(ROOT)),'sha256':FROZEN_SHA},
        source_sha256=source_manifest['component/src/monotone_keys.rs']['sha256'],
        driver_sha256=source_manifest['driver/input_only_driver.rs']['sha256'],
        source_snapshot=str(snapshot),source_manifest=source_manifest,
        planned_mutants={name:dict(source_sha256=sha(text.encode()),required_counterexample_scope=MUTANT_DOMAINS[name]) for name,text in variants.items()},
        compiled_rust_status='not run by fixture preparation',target_runtime_execution=False,
        no_write_limit='Source ascending path has no mutation; physical compiled stores require a separate native audit.')
    (out/'fixture-report.json').write_text(render(result))
    return rows,result


def build(rustc,out,rows,fixture):
    rustc=rustc.resolve(); require(rustc.is_file(),'supplied rustc does not exist')
    version=subprocess.check_output([str(rustc),'-vV'],text=True)
    require(version.startswith('rustc 1.94.1 '),'required pinned Rust 1.94.1 is unavailable')
    compiler_sha=sha(rustc.read_bytes())
    snapshot=Path(fixture['source_snapshot']); manifest=fixture['source_manifest']
    component=snapshot/'component'; driver=snapshot/'driver/input_only_driver.rs'
    check_snapshot(snapshot,manifest)
    logs=[]
    def run(label,argv,stdin=None):
        command=list(map(str,argv)); result=subprocess.run(command,input=stdin,capture_output=True)
        (out/(label+'.stdout')).write_bytes(result.stdout);(out/(label+'.stderr')).write_bytes(result.stderr)
        logs.append(dict(label=label,argv=command,exit_code=result.returncode,stdout_sha256=sha(result.stdout),stderr_sha256=sha(result.stderr)))
        require(result.returncode==0,'command failed: '+label)
        return result.stdout
    builds=[]
    for opt in [0,3]:
        for repeat in [0,1]:
            prefix=f'o{opt}-r{repeat}'; library=out/('libnode94_orderbook-'+prefix+'.rlib'); client=out/(prefix+'-client')
            flags=['--edition=2024','-D','warnings','-C',f'opt-level={opt}','-C','overflow-checks=yes']
            check_snapshot(snapshot,manifest)
            run(prefix+'-library',[rustc,'--crate-name',CRATE,'--crate-type=rlib',component/'src/lib.rs','-o',library,*flags])
            run(prefix+'-client-build',[rustc,driver,'--extern',CRATE+'='+str(library),'-o',client,*flags])
            output=run(prefix+'-client-run',[client],checked_fixture_artifacts(out,fixture))
            require(not compare(output,rows),'compiled production output mismatch: '+prefix)
            builds.append(dict(profile=prefix,library_sha256=sha(library.read_bytes()),client_sha256=sha(client.read_bytes()),output_sha256=sha(output),mismatches=0))
        unit=out/f'o{opt}-unit-tests'
        run(f'o{opt}-test-build',[rustc,'--test',component/'src/lib.rs','-o',unit,*flags])
        run(f'o{opt}-test-run',[unit,'--nocapture'])
    mutants=[]
    for name,source in wrong_variants((component/'src/monotone_keys.rs').read_text()).items():
        check_snapshot(snapshot,manifest)
        directory=out/('mutant-'+name); shutil.copytree(component,directory)
        (directory/'src/monotone_keys.rs').write_text(source)
        mutant_manifest=tree_manifest(directory)
        library=out/('libnode94_orderbook-mutant-'+name+'.rlib');client=out/('mutant-'+name+'-client')
        run(name+'-library',[rustc,'--edition=2024','--crate-name',CRATE,'--crate-type=rlib',directory/'src/lib.rs','-C','opt-level=3','-C','overflow-checks=yes','-o',library])
        run(name+'-client-build',[rustc,'--edition=2024',driver,'--extern',CRATE+'='+str(library),'-o',client])
        output=run(name+'-client-run',[client],checked_fixture_artifacts(out,fixture));misses=compare(output,rows)
        native=[m for m in misses if m['scope']=='qualified native value relation']
        policy=[m for m in misses if m['scope']=='chosen safe API policy only']
        required=MUTANT_DOMAINS[name]
        if required=='qualified native value relation':
            require(bool(native),'native-domain mutant has no qualified counterexample: '+name)
        else:
            require(bool(policy) and not native,'safe-API-only control has wrong counterexample scope: '+name)
        check_snapshot(directory,mutant_manifest)
        mutants.append(dict(name=name,source_manifest=mutant_manifest,required_counterexample_scope=required,
            native_domain_mismatches=len(native),safe_api_policy_mismatches=len(policy),
            first_native_counterexample=native[0] if native else None,
            first_policy_counterexample=policy[0] if policy else None))
    check_snapshot(snapshot,manifest); check_live_source(manifest)
    checked_fixture_artifacts(out,fixture)
    require(sha(rustc.read_bytes())==compiler_sha,'invoked compiler executable changed during run')
    result=dict(compiler_version=version,compiler_sha256=compiler_sha,source_manifest=manifest,fixture=fixture,builds=builds,mutants=mutants,commands=logs,
                target_runtime_execution=False,limits='Value/API comparison to frozen static expectations; no target execution, original ABI, physical-store equality or machine-code equivalence.')
    (out/'build-report.json').write_text(render(result))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--rustc',type=Path)
    args=parser.parse_args(); rows,result=prepare(args.out)
    if args.rustc is None:
        print('Prepared 76 frozen native-derived cases and 5 safe-API policy cases. Rust build NOT RUN: supply existing pinned rustc 1.94.1 with --rustc.')
        return
    build(args.rustc,args.out,rows,result)
    print('Pinned Rust production builds and component tests passed; five native-domain variants and one safe-API-only control met their separate counterexample requirements.')


if __name__=='__main__': main()
