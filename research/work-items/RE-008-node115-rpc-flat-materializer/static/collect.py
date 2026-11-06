"""DRAFT optional fresh GNU export, reviewed static inputs only; do not run yet."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import types

HERE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--objdump', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--scope-sha256', required=True)
    args = p.parse_args()
    scope_raw = (HERE / 'scope.json').read_bytes()
    if hashlib.sha256(scope_raw).hexdigest() != args.scope_sha256:
        raise ValueError('external scope identity')
    scope = json.loads(scope_raw)
    verify_path = HERE / 'verify.py'
    verify_source = verify_path.read_bytes()
    if verify_path.is_symlink() or hashlib.sha256(verify_source).hexdigest() != scope['verifier_sha256']:
        raise ValueError('paired reviewed verifier identity')
    verify = types.ModuleType('rpc_static_verify')
    verify.__file__ = str(verify_path)
    # Execute the exact authenticated Python source buffer. Do not use an import
    # loader that may consume an existing .pyc or reopen the source after hashing.
    exec(compile(verify_source, str(verify_path), 'exec'), verify.__dict__)
    verify.need(not args.output.exists(), 'fresh output directory')
    scope, data, modules, image, facts, retained = verify.admit(args.root.resolve(), args.evidence.resolve(), args.scope_sha256)
    tool = args.objdump.resolve()
    verify.need(tool.is_file() and verify.sha(tool.read_bytes()) == scope['GNU']['sha256'], 'installed GNU pin')
    args.output.mkdir(parents=True)
    output = args.output.resolve()
    snapshot = output / 'authenticated-node115'
    snapshot.write_bytes(data)
    snapshot.chmod(0o400)
    verify.authenticate(snapshot.read_bytes(), scope)
    commands = []

    def run(label, argv):
        try:
            child = subprocess.run(argv, cwd=output, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            stdout, stderr, status, diagnostic = child.stdout, child.stderr, child.returncode, None
        except subprocess.TimeoutExpired as error:
            stdout, stderr, status = error.stdout or b'', error.stderr or b'', 'timeout'
            diagnostic = str(error).encode()
        except OSError as error:
            stdout, stderr, status, diagnostic = b'', b'', 'launch-error', str(error).encode()
        for kind, raw in [('stdout', stdout), ('stderr', stderr)]:
            (output / (label + '.' + kind)).write_bytes(raw)
        record = {'argv': argv, 'exit': status, 'stdout_sha256': verify.sha(stdout), 'stderr_sha256': verify.sha(stderr)}
        if diagnostic is not None:
            (output / (label + '.diagnostic')).write_bytes(diagnostic)
            record['diagnostic_sha256'] = verify.sha(diagnostic)
        commands.append(record)
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        verify.need(status == 0, 'static tool failure; all actual streams retained')
        return stdout

    version = run('gnu-version', [str(tool), '--version'])
    verify.need(verify.sha(version) == scope['GNU']['version_stdout_sha256'], 'GNU version output pin')
    bodies = []
    for body in scope['bodies']:
        if body['role'] not in ('flat', 'materializer'):
            continue
        lower, upper = body['fde']['start'], body['fde']['end']
        raw = run(body['role'] + '.gnu', [str(tool), '-d', '-M', 'intel', '--insn-width=16', f'--start-address={lower:#x}', f'--stop-address={upper:#x}', snapshot.name])
        rows = verify.export_rows(raw, lower, upper, image.get(lower, upper - lower))
        verify.need(len(rows) == body['rows'] and verify.structural_census(rows, lower, upper) == body['census'], 'fresh complete GNU structure')
        bodies.append({'role': body['role'], 'stdout_sha256': verify.sha(raw), 'bytes': upper - lower, 'rows': len(rows)})
    verify.authenticate(snapshot.read_bytes(), scope)
    verify.authenticate((args.root / scope['target']['path']).read_bytes(), scope)
    verify.need(verify.sha(tool.read_bytes()) == scope['GNU']['sha256'], 'final GNU pin')
    snapshot.unlink()
    (output / 'result.json').write_text(json.dumps({'bodies': bodies, 'commands': commands, 'limits': 'Static GNU reads of authenticated data, no target execution.'}, indent=2) + '\n')


if __name__ == '__main__':
    main()
