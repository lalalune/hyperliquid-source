#!/usr/bin/env python3
"""Build/test independently authored Rust only. Never execute captured bytes."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
BUILD_ENV = dict(os.environ, CARGO_INCREMENTAL='0', RUSTFLAGS='', CARGO_ENCODED_RUSTFLAGS='', RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='')
ITEM = Path(__file__).resolve().parent
SOURCE = Path('src/node115-scalar-reduction')
WORK = ROOT/'work/scalar-reduction-build'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args,expect=0,cwd=ROOT):
    result = subprocess.run(args,cwd=cwd,env=BUILD_ENV,text=True,capture_output=True)
    if (result.returncode==0)!=(expect==0):
        raise ValueError('unexpected build/test status: '+' '.join(args)+'\n'+result.stdout+result.stderr)
    return {'command':args,'cwd':'<repo>' if cwd==ROOT else str(cwd.relative_to(ROOT)),
            'returncode':result.returncode,'stdout':result.stdout.replace(str(ROOT),'<repo>'),
            'stderr':result.stderr.replace(str(ROOT),'<repo>')}


def main():
    WORK.mkdir(parents=True,exist_ok=True)
    observations = []
    manifest = str(SOURCE/'Cargo.toml')
    for mode in ([],['--release']):
        observations.append(run(['cargo','+1.95.0','test',*mode,'--offline','--locked','--manifest-path',manifest,
                                 '--target-dir','work/scalar-reduction-build/tests'+('-release' if mode else '-debug')]))
    observations.append(run(['cargo','+1.95.0','fmt','--check','--manifest-path',manifest]))
    observations.append(run(['cargo','+1.95.0','clippy','--offline','--locked','--manifest-path',manifest,
                             '--target-dir','work/scalar-reduction-build/clippy','--','-D','warnings']))
    artifacts = []
    for name in ('a','b'):
        dest = Path(f'work/scalar-reduction-build/release-{name}')
        if (ROOT/dest).exists():
            shutil.rmtree(ROOT/dest)
        observations.append(run(['cargo','+1.95.0','build','--release','--offline','--locked','--manifest-path',manifest,'--target-dir',str(dest)]))
        artifact = ROOT/dest/'release/libnode115_scalar_reduction.rlib'
        artifacts.append({'path':str(artifact.relative_to(ROOT)),'sha256':sha(artifact),'size':artifact.stat().st_size})
    if artifacts[0]['sha256']!=artifacts[1]['sha256']:
        raise ValueError('independent Rust release archives differ')
    original = (ROOT/SOURCE/'lib.rs').read_text()
    mutations = []
    for name,old,new in [('order-low-limb-plus-one','0xbfd2_5e8c_d036_4141','0xbfd2_5e8c_d036_4142'),
                          ('inverted-overflow-flag','overflow: !borrow','overflow: borrow')]:
        base = WORK/name
        source = base/SOURCE
        source.mkdir(parents=True,exist_ok=True)
        for filename in ('Cargo.toml','Cargo.lock'):
            shutil.copyfile(ROOT/SOURCE/filename,source/filename)
        changed = original.replace(old,new)
        if changed==original:
            raise ValueError('mutation did not change source')
        (source/'lib.rs').write_text(changed)
        corpus = base/'research/work-items'/ITEM.name/'observed/boundaries.tsv'
        corpus.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ITEM/'observed/boundaries.tsv',corpus)
        result = run(['cargo','+1.95.0','test','--offline','--locked','--manifest-path',str(SOURCE/'Cargo.toml'),
                      '--target-dir','target'],expect=1,cwd=base)
        if 'test result: FAILED' not in result['stdout'] or 'assertion `left == right` failed' not in result['stdout']:
            raise ValueError('mutation failed outside expected comparison')
        mutations.append({'name':name,'diff':''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),fromfile='original/lib.rs',tofile='mutated/lib.rs')),'run':result})
    result = {'executed':'only newly authored Rust; no captured instructions',
              'environment':{key:BUILD_ENV[key] for key in ('CARGO_INCREMENTAL','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER')},
              'rustc':subprocess.check_output(['rustc','+1.95.0','-vV'],text=True),
              'cargo':subprocess.check_output(['cargo','+1.95.0','--version'],text=True).strip(),
              'linker':subprocess.check_output(['cc','--version'],text=True).splitlines()[0],
              'source_sha256':{f:sha(ROOT/SOURCE/f) for f in ('lib.rs','Cargo.toml','Cargo.lock')},
              'runs':observations,'release_archives':artifacts,'release_archives_equal':True,'mutation_controls':mutations,
              'limits':'release archive equality compares two local source builds, not the captured target; no ABI or target byte-equivalence claim'}
    (ITEM/'observed/build.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Debug/release corpus tests, fmt, clippy, two equal release archives and two rejected Rust mutations passed.')


if __name__=='__main__':
    main()
