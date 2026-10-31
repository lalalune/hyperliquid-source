"""Exercise actual foundation CLIs with a source-only/LFS-pointer fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def probe(binary, objdump):
    binary = binary.resolve()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == SHA256
    version = subprocess.check_output([objdump, '--version'], text=True).splitlines()[0]
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        fixture = Path(directory) / 'source only'
        (fixture / 'tools').mkdir(parents=True)
        for name in ('foundation_millis.py', 'foundation_duration_guards.py', 'elf_index.py'):
            shutil.copyfile(ROOT / 'tools' / name, fixture / 'tools' / name)
        for name in ('foundation-millis-94', 'foundation-duration-guards-94'):
            shutil.copytree(ROOT / 'research/work-items' / name,
                            fixture / 'research/work-items' / name)
        pointer = fixture / 'artifacts/node/94/hl-node'
        pointer.parent.mkdir(parents=True)
        pointer.write_text('version https://git-lfs.github.com/spec/v1\n'
                           'oid sha256:' + SHA256 + '\nsize 91774280\n')
        relative = Path(os.path.relpath(binary, fixture))
        for tool in ('foundation_millis.py', 'foundation_duration_guards.py'):
            for case, selected, native in (
                    ('retained', binary, False),
                    ('native-absolute', binary, True),
                    ('native-relative', relative, True),
                    ('invalid-pointer', pointer, True)):
                command = [sys.executable, str(fixture / 'tools' / tool), '--binary', str(selected)]
                if native:
                    command += ['--objdump', objdump]
                result = subprocess.run(command, cwd=fixture, text=True, capture_output=True)
                row = {'tool': tool, 'case': case, 'exit': result.returncode}
                if result.returncode == 0:
                    parsed = json.loads(result.stdout)
                    row['result_sha256'] = hashlib.sha256(json.dumps(parsed, sort_keys=True).encode()).hexdigest()
                else:
                    row['native_default_path_failure'] = 'file format not recognized' in result.stderr
                    row['identity_rejected'] = 'size/SHA-256' in result.stderr
                rows.append(row)
    return {'target_sha256': SHA256, 'tool': version, 'rows': rows,
            'captured_target_executed': False,
            'limitations': 'Native provider is real GNU objdump. Retained LLVM exports and GNU output can have distinct instruction counts (open PR554); this probe does not assert canonical equality between those modes.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--objdump', default='objdump')
    args = parser.parse_args()
    print(json.dumps(probe(args.binary, args.objdump), indent=2))
