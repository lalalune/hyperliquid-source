#!/usr/bin/env python3
"""Launch the pinned REA package with a supported Node and native analysis tools."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from doctor import locate_ghidra
from artifacts import check

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / 'config/rea.json').read_text())


def supported_node(version):
    match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)', version.strip())
    if not match:
        return False
    major, minor, patch = map(int, match.groups())
    return ((major == 22 and (minor, patch) >= (23, 4)) or
            (major == 24 and (minor, patch) >= (22, 1)) or
            (major, minor, patch) >= (26, 12, 1))


def find_node():
    explicit = os.environ.get('REA_NODE')
    if explicit:
        candidates = [explicit]
    else:
        if 'preferred_node' not in CONFIG:
            raise ValueError('config/rea.json missing preferred_node')
        candidates = [str(Path.home() / '.nvm/versions/node' / ('v' + CONFIG['preferred_node']) / 'bin/node'),
                      shutil.which('node'), '/opt/homebrew/bin/node', '/usr/local/bin/node']
        candidates += [str(p) for p in sorted((Path.home() / '.nvm/versions/node').glob('*/bin/node'), reverse=True)]
    for item in dict.fromkeys(c for c in candidates if c):
        try:
            result = subprocess.run([item, '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and supported_node(result.stdout):
                return Path(item).resolve()
        except (OSError, subprocess.TimeoutExpired):
            continue
    raise ValueError('REA 6.8.0 needs Node ^22.23.4, ^24.22.1 or >=26.12.1. Install the .nvmrc version or set REA_NODE to a supported executable.')


def environment(node):
    env = os.environ.copy()
    env['PATH'] = str(node.parent) + os.pathsep + env.get('PATH', '')
    # Explicit user configuration wins over automatic workstation discovery.
    if not env.get('GHIDRA_INSTALL_DIR'):
        ghidra = locate_ghidra()
        if ghidra:
            env['GHIDRA_INSTALL_DIR'] = str(ghidra)
    if not env.get('JAVA_HOME'):
        java = shutil.which('java', path=env['PATH'])
        if java:
            home = Path(java).resolve().parent.parent
            if (home / 'bin/java').is_file():
                env['JAVA_HOME'] = str(home)
    return env


def target(name):
    relative = CONFIG['targets'][name]
    item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == relative)
    check(ROOT / relative, item)
    return {'path': str(ROOT / relative), 'sha256': item['sha256'], 'provider_id': CONFIG['provider']}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == 'target':
        name = args[1] if len(args) == 2 else CONFIG['default_target']
        if name not in CONFIG['targets']:
            raise ValueError('Unknown target; use 94, 115 or visor')
        print(json.dumps(target(name), indent=2))
        return
    profile = None
    if args[:1] == ['--profile']:
        if len(args) < 3 or args[1] not in CONFIG.get('profiles', {}):
            raise ValueError('Unknown REA profile')
        profile = CONFIG['profiles'][args[1]]
        args = args[2:]
    node = find_node()
    env = environment(node)
    if profile is not None:
        env['REA_GHIDRA_DISABLED_ANALYZERS'] = ','.join(profile['disabled_analyzers'])
    if args and args[0] == 'install':
        npm = node.parent / 'npm'
        if not npm.is_file():
            raise ValueError(f'npm missing beside {node}; install npm for this runtime')
        command = [str(npm), 'ci', '--ignore-scripts', '--no-audit', '--no-fund']
    else:
        package = ROOT / 'node_modules/rea-agents'
        if not (package / 'package.json').is_file():
            raise ValueError('Pinned REA package is absent. Run make rea-install.')
        metadata = json.loads((package / 'package.json').read_text())
        if metadata.get('version') != CONFIG['version']:
            raise ValueError('REA package version differs from config/rea.json; run make rea-install')
        command = [str(node), str(package / 'scripts/rea.mjs'), *(args or ['--help'])]
    os.chdir(ROOT)
    os.execvpe(command[0], command, env)


if __name__ == '__main__':
    try:
        main()
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
