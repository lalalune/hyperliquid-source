"""Offline build of unmodified checksum-pinned public crates; no listener runs.

Supply the three official archives named in ARCHIVES. Only the reviewed libc
host build-configuration helper executes; emitted Linux objects never execute.
All commands in published records replace host paths with explicit tokens.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

ARCHIVES = {
    'mio-1.0.2.crate': '80e04d1dcff3aae0704555fe5fee3bcfaf3d1fdf8a7e521d5b9d2b42acb52cec',
    'libc-0.2.149.crate': 'a08173bc88b7955d1b3145aa561539096c421ac8debde8cbc3612ec635fee29b',
    'rust-std-1.94.1-x86_64-unknown-linux-gnu.tar.xz': '74109ee2c19098f1d7122087dd338a8f643203b3ce678c9d58169db733e17a03',
}
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, why):
    if not ok:
        raise ValueError(why)


def main(args):
    out, inputs, rustc = args.out.resolve(), args.input_dir.resolve(), args.rustc.resolve()
    out.mkdir(parents=True, exist_ok=False)
    logs = out / 'logs'; logs.mkdir()
    artifacts = out / 'candidate-release'; artifacts.mkdir()
    (out / 'empty-path').mkdir()
    records = []
    paths = [(str(rustc), '<rustc>'), (str(out), '<build>'), (str(inputs), '<inputs>')]

    def clean(text):
        for before, after in paths:
            text = text.replace(before, after)
        return text

    def run(argv, label, cwd=out, env=None):
        argv = [str(x) for x in argv]
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True)
        streams = {}
        for suffix, raw in [('stdout', p.stdout), ('stderr', p.stderr)]:
            # Exact local output remains available in ignored build storage.
            (logs / (label + '.raw.' + suffix)).write_bytes(raw)
            public = clean(raw.decode('utf-8', 'backslashreplace')).encode()
            (logs / (label + '.' + suffix)).write_bytes(public)
            streams[suffix] = {'raw_bytes': len(raw), 'raw_sha256': sha(raw),
                               'normalized_sha256': sha(public), 'normalization': 'host path tokens only'}
        records.append({'argv': [clean(x) for x in argv], 'cwd': clean(str(cwd)),
                        'label': label, 'exit': p.returncode, 'streams': streams})
        (out / 'commands.json').write_text(json.dumps(records, indent=2) + '\n')
        need(p.returncode == 0, label + ' failed; exact logs retained')
        return p.stdout

    checked = {}
    for name, digest in ARCHIVES.items():
        archive = inputs / name
        raw = archive.read_bytes()
        need(sha(raw) == digest, 'archive identity: ' + name)
        checked[name] = {'bytes': len(raw), 'sha256': digest}
        destination = out / ('official' if name.endswith('.tar.xz') else 'vendor')
        with tarfile.open(archive) as tf:
            tf.extractall(destination, filter='data')
    libc, mio = out / 'vendor/libc-0.2.149', out / 'vendor/mio-1.0.2'
    sysroot = out / 'official/rust-std-1.94.1-x86_64-unknown-linux-gnu/rust-std-x86_64-unknown-linux-gnu'
    need(not (mio / 'build.rs').exists(), 'Mio has no build hook')
    source_hashes = {str(p.relative_to(out)): sha(p.read_bytes()) for root in (libc, mio) for p in root.rglob('*') if p.is_file()}
    (out / 'source-manifest.json').write_text(json.dumps(source_hashes, indent=2, sort_keys=True) + '\n')
    version = run([rustc, '-vV'], 'rustc-version').decode()
    need('release: 1.94.1\n' in version and 'commit-hash: ' + COMMIT + '\n' in version, 'compiler release/commit')
    # These exact archive-authenticated hooks/manifests were read before this
    # recipe was authorized. The helper can run only the exact rustc path;
    # optional freebsd-version/emcc probes cannot resolve in the empty PATH.
    run([rustc, libc / 'build.rs', '--edition=2015', '-o', artifacts / 'libc-build-config'], 'libc-build-config-compile')
    env = {'PATH': str(out / 'empty-path'), 'RUSTC': str(rustc), 'CARGO_FEATURE_STD': '1'}
    helper = run([artifacts / 'libc-build-config'], 'libc-build-config-run', cwd=libc, env=env)
    cfg = [line.split('=', 1)[1] for line in helper.decode().splitlines() if line.startswith('cargo:rustc-cfg=')]
    flags = ['--target=x86_64-unknown-linux-gnu', '--sysroot', sysroot,
             '-C', 'opt-level=3', '-C', 'codegen-units=1', '-C', 'panic=unwind',
             '-C', 'debug-assertions=no', '-C', 'overflow-checks=no', '-C', 'debuginfo=0',
             '--remap-path-prefix', str(out) + '=/listener-source-candidate']
    libc_argv = [rustc, libc / 'src/lib.rs', '--crate-name=libc', '--crate-type=rlib', '--edition=2015',
                 '--cfg', 'feature="default"', '--cfg', 'feature="std"']
    for setting in cfg:
        libc_argv.extend(['--cfg', setting])
    run([*libc_argv, *flags, '-o', artifacts / 'liblibc.rlib'], 'libc-compile')
    run([rustc, mio / 'src/lib.rs', '--crate-name=mio', '--crate-type=rlib', '--edition=2021',
         '--cfg', 'feature="net"', '--cfg', 'feature="os-poll"', '--extern', 'libc=' + str(artifacts / 'liblibc.rlib'),
         *flags, '--emit=link,obj', '--out-dir', artifacts, '--cap-lints', 'allow'], 'mio-compile')
    need(all(sha((out / name).read_bytes()) == digest for name, digest in source_hashes.items()), 'unmodified public source')
    record = {'archives': checked, 'rustc_version': version, 'rustc_sha256': sha(rustc.read_bytes()),
              'libc_cfg': cfg, 'features': {'mio': ['net', 'os-poll'], 'libc': ['default', 'std']},
              'disabled_default_mio_feature': 'log', 'candidate_dependency_graph_only': True,
              'original_lock_or_features_known': False, 'cap_lints': 'allow (dependency lint policy only)',
              'source_modified': False, 'listener_or_target_executed': False,
              'reviewed_libc_host_configuration_helper_executed': True,
              'artifact_hashes': {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())} for p in artifacts.iterdir() if p.is_file()}}
    (out / 'result.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps(record, indent=2, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    main(parser.parse_args())
