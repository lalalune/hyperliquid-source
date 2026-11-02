"""Build unmodified public socket2 candidates offline; no Linux object executes.

Only checksum-bound libc build configuration programs execute on the host.
They receive an empty PATH and the exact compiler path. This is a candidate
recipe, not recovery of the target's original dependency lock or compiler.
"""
import argparse
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

ARCHIVES = {
    'socket2-0.4.10.crate': '9f7916fc008ca5542385b89a3d3ce689953c143e9304a9bf8beec1de48994c0d',
    'socket2-0.5.7.crate': 'ce305eb0b4296696835b71df73eb912e0f1ffd2556a501fcede6e0c50349191c',
    'libc-0.2.149.crate': 'a08173bc88b7955d1b3145aa561539096c421ac8debde8cbc3612ec635fee29b',
    'libc-0.2.150.crate': '89d92a4743f9a61002fae18374ed11e7973f530cb3a3255fb354818118b2203c',
    'rust-std-1.94.1-x86_64-unknown-linux-gnu.tar.xz': '74109ee2c19098f1d7122087dd338a8f643203b3ce678c9d58169db733e17a03',
}
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
RUSTC_SHA256 = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'


def sha(b):
    return hashlib.sha256(b).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def main(args):
    out, rustc = args.out.resolve(), args.rustc.resolve()
    inputs = [p.resolve() for p in args.input_dir]
    out.mkdir(parents=True, exist_ok=False)
    logs = out / 'logs'; logs.mkdir()
    empty = out / 'empty-path'; empty.mkdir()
    commands = []
    tokens = [(str(rustc), '<rustc>'), (str(out), '<build>')]
    tokens += [(str(p), '<inputs-' + str(i) + '>') for i, p in enumerate(inputs)]

    def clean(s):
        for before, after in tokens:
            s = s.replace(before, after)
        return s

    def run(argv, label, cwd=out, env=None):
        argv = list(map(str, argv))
        p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True)
        streams = {}
        for suffix, raw in [('stdout', p.stdout), ('stderr', p.stderr)]:
            (logs / (label + '.raw.' + suffix)).write_bytes(raw)
            normalized = clean(raw.decode('utf-8', 'backslashreplace')).encode()
            (logs / (label + '.' + suffix)).write_bytes(normalized)
            streams[suffix] = {'bytes': len(raw), 'sha256': sha(raw),
                               'normalized_sha256': sha(normalized)}
        commands.append({'label': label, 'argv': [clean(s) for s in argv],
                         'cwd': clean(str(cwd)), 'exit': p.returncode, 'streams': streams})
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        need(p.returncode == 0, label + ' failed; exact streams retained')
        return p.stdout

    acquisition = {}
    for name, expected in ARCHIVES.items():
        candidates = [p / name for p in inputs if (p / name).is_file()]
        need(bool(candidates), 'missing archive: ' + name)
        raw = candidates[0].read_bytes()
        need(sha(raw) == expected, 'archive digest: ' + name)
        acquisition[name] = {'bytes': len(raw), 'sha256': expected}
        with tarfile.open(candidates[0]) as archive:
            archive.extractall(out / ('official' if name.endswith('.xz') else 'vendor'), filter='data')
    roots = [out / 'vendor' / n for n in ['socket2-0.4.10', 'socket2-0.5.7', 'libc-0.2.149', 'libc-0.2.150']]
    source_manifest = {str(p.relative_to(out)): sha(p.read_bytes()) for root in roots for p in root.rglob('*') if p.is_file()}
    (out / 'source-manifest.json').write_text(json.dumps(source_manifest, indent=2, sort_keys=True) + '\n')
    sysroot = out / 'official/rust-std-1.94.1-x86_64-unknown-linux-gnu/rust-std-x86_64-unknown-linux-gnu'
    version = run([rustc, '-vV'], 'rustc-version').decode()
    need('release: 1.94.1\n' in version and 'commit-hash: ' + COMMIT + '\n' in version, 'compiler pin')
    need(sha(rustc.read_bytes()) == RUSTC_SHA256, 'exact observed compiler executable')
    flags = ['--target=x86_64-unknown-linux-gnu', '--sysroot', sysroot,
             '-C', 'opt-level=3', '-C', 'codegen-units=1', '-C', 'panic=unwind',
             '-C', 'debug-assertions=no', '-C', 'overflow-checks=no', '-C', 'debuginfo=0',
             '--remap-path-prefix', str(out) + '=/keepalive-source-candidate']
    builds = []
    for socket_version, libc_version, edition in [('0.4.10', '0.2.149', '2018'), ('0.5.7', '0.2.150', '2021')]:
        library = out / 'vendor' / ('libc-' + libc_version)
        socket = out / 'vendor' / ('socket2-' + socket_version)
        need(not (socket / 'build.rs').exists(), 'unexpected socket2 build hook')
        label = 'socket2-' + socket_version
        artifact = out / label; artifact.mkdir()
        run([rustc, library / 'build.rs', '--edition=2015', '-o', artifact / 'libc-build-config'], label + '-config-build')
        helper = run([artifact / 'libc-build-config'], label + '-config-run', library,
                     {'PATH': str(empty), 'RUSTC': str(rustc), 'CARGO_FEATURE_STD': '1'})
        cfg = [line.split('=', 1)[1] for line in helper.decode().splitlines() if line.startswith('cargo:rustc-cfg=')]
        libc_argv = [rustc, library / 'src/lib.rs', '--crate-name=libc', '--crate-type=rlib', '--edition=2015',
                     '--cfg', 'feature="default"', '--cfg', 'feature="std"']
        for c in cfg:
            libc_argv.extend(['--cfg', c])
        run([*libc_argv, *flags, '-o', artifact / 'liblibc.rlib'], label + '-libc-build')
        socket_argv = [rustc, socket / 'src/lib.rs', '--crate-name=socket2', '--crate-type=rlib', '--edition=' + edition,
                       '--cfg', 'feature="all"', '--extern', 'libc=' + str(artifact / 'liblibc.rlib'),
                       *flags, '--emit=link,obj', '--cap-lints', 'allow']
        run([*socket_argv, '--out-dir', artifact], label + '-build')
        opt0 = artifact / 'opt0'; opt0.mkdir()
        opt0_argv = [('opt-level=0' if str(x) == 'opt-level=3' else x) for x in socket_argv]
        run([*opt0_argv, '--out-dir', opt0], label + '-opt0-build')
        opt0_repeat = opt0 / 'repeat'; opt0_repeat.mkdir()
        run([*opt0_argv, '--out-dir', opt0_repeat], label + '-opt0-repeat')
        need(all((opt0 / n).read_bytes() == (opt0_repeat / n).read_bytes()
                 for n in ['socket2.o', 'libsocket2.rlib']), 'own opt0 repeat differs')
        repeat = artifact / 'repeat'; repeat.mkdir()
        run([*socket_argv, '--out-dir', repeat], label + '-repeat')
        repeated = {name: (artifact / name).read_bytes() == (repeat / name).read_bytes()
                    for name in ['socket2.o', 'libsocket2.rlib']}
        need(all(repeated.values()), 'own socket2 repeat differs')
        builds.append({'socket2': socket_version, 'libc': libc_version, 'libc_cfg': cfg,
                       'socket2_features': ['all'], 'opt_levels': [0, 3],
                       'opt0_repeat_objects_and_rlibs_raw_equal': True, 'repeat_raw_equal': repeated,
                       'artifacts': {str(p.relative_to(out)): {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
                                     for p in artifact.rglob('*') if p.is_file()}})
    need(all(sha((out / p).read_bytes()) == h for p, h in source_manifest.items()), 'public source was modified')
    result = {'archives': acquisition, 'compiler_version': version, 'compiler_sha256': sha(rustc.read_bytes()),
              'builds': builds, 'original_dependency_graph_known': False,
              'source_modified': False, 'linux_objects_executed': False,
              'only_reviewed_host_configuration_helpers_executed': True,
              'log_normalization': 'host paths replaced by explicit tokens only; raw streams retained'}
    (out / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'candidate_builds': len(builds), 'repeat_objects_and_rlibs_equal': True}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', action='append', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    main(parser.parse_args())
