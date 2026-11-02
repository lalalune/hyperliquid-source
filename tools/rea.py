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
from artifacts import check, load_manifest

ROOT = Path(__file__).resolve().parents[1]


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'Duplicate key in REA config input: {key}')
        out[key] = value
    return out


def load_config(path):
    return json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=_unique_object)


CONFIG = load_config(ROOT / 'config/rea.json')


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
                      shutil.which('node')]
        # The shell's first Node can be incompatible while a later PATH
        # entry already contains a supported runtime. Keep PATH order.
        candidates += [shutil.which('node', path=directory) for directory in os.get_exec_path()]
        candidates += ['/opt/homebrew/bin/node', '/usr/local/bin/node']
        candidates += [str(p) for p in sorted((Path.home() / '.nvm/versions/node').glob('*/bin/node'), reverse=True)]
    for item in dict.fromkeys(c for c in candidates if c):
        try:
            result = subprocess.run([item, '--version'], capture_output=True, text=True, timeout=5, encoding='utf-8')
            if result.returncode == 0 and supported_node(result.stdout):
                return Path(item).resolve()
        except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
            continue
    raise ValueError('REA 6.8.0 needs Node ^22.23.4, ^24.22.1 or >=26.12.1. Install the .nvmrc version or set REA_NODE to a supported executable.')


def find_java_home(java):
    """Resolve a full JDK, including macOS's system launcher and Java 8 JREs."""
    executable = Path(java).resolve()
    if sys.platform == 'darwin' and executable == Path('/usr/bin/java').resolve():
        # This is an OS launcher, not a JDK at /usr. Use the platform JDK
        # resolver without dumping potentially private JVM properties.
        try:
            result = subprocess.run(['/usr/libexec/java_home'], capture_output=True,
                                    text=True, timeout=5, encoding='utf-8')
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode or not result.stdout.strip():
            return None
        home = Path(result.stdout.strip())
        if not home.is_absolute():
            return None
    else:
        home = executable.parent.parent
    # Java 8 can expose the nested JRE executable even when a full JDK exists.
    if home.name == 'jre' and (home.parent / 'bin/javac').is_file():
        home = home.parent
    if (home / 'bin/java').is_file() and (home / 'bin/javac').is_file():
        return home
    return None


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
            home = find_java_home(java)
            if home is not None:
                env['JAVA_HOME'] = str(home)
    return env


def target(name):
    if 'provider' not in CONFIG:
        raise ValueError('config/rea.json missing provider')
    if 'targets' not in CONFIG:
        raise ValueError('config/rea.json missing targets')
    relative = CONFIG['targets'][name]
    item = next((i for i in load_manifest(ROOT)['files'] if i['path'] == relative), None)
    if item is None:
        raise ValueError(f'config/rea.json target {name!r} has no provenance/artifacts.json entry')
    missing = [field for field in ('size', 'sha256') if field not in item]
    if missing:
        raise ValueError(f'config/rea.json target {name!r} manifest entry for {relative!r} is missing {", ".join(missing)}')
    check(ROOT / relative, item)
    return {'path': str(ROOT / relative), 'sha256': item['sha256'], 'provider_id': CONFIG['provider']}


def npm_shim(node, platform=None):
    """Return the npm entry point beside `node` for this platform.

    Node ships an extensionless POSIX `npm` script and an `npm.cmd` batch shim
    side by side on Windows. Picking `npm` there hands a shell script to
    CreateProcess, so `make rea-install` fails before npm sees an argument.
    """
    platform = os.name if platform is None else platform
    names = ('npm.cmd', 'npm.bat') if platform == 'nt' else ('npm',)
    for name in names:
        candidate = node.parent / name
        if candidate.is_file():
            return candidate
    raise ValueError(f'npm missing beside {node}; install npm for this runtime')


def run_install(node, env, windows=None):
    """Run `npm ci` for the pinned REA package.

    POSIX replaces the launcher process as before. Windows cannot exec a batch
    shim, so it runs it and returns the status for the caller to propagate.
    """
    windows = os.name == 'nt' if windows is None else windows
    npm = npm_shim(node, 'nt' if windows else 'posix')
    command = [str(npm), 'ci', '--ignore-scripts', '--no-audit', '--no-fund']
    if windows:
        return subprocess.run(command, env=env).returncode
    os.execvpe(command[0], command, env)
    return None


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == 'target':
        if len(args) > 2:
            raise ValueError('Usage: rea.py target [115|visor]; unexpected extra arguments')
        if 'targets' not in CONFIG:
            raise ValueError('config/rea.json missing targets')
        if len(args) == 2:
            name = args[1]
        elif 'default_target' not in CONFIG:
            raise ValueError('config/rea.json missing default_target')
        else:
            name = CONFIG['default_target']
        if name not in CONFIG['targets']:
            raise ValueError('Unknown target; use 115 or visor')
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
        if 'disabled_analyzers' not in profile:
            raise ValueError('config/rea.json profile missing disabled_analyzers')
        env['REA_GHIDRA_DISABLED_ANALYZERS'] = ','.join(profile['disabled_analyzers'])
    if args and args[0] == 'install':
        os.chdir(ROOT)
        status = run_install(node, env)
        if status is not None:
            raise SystemExit(status)
        return
    package = ROOT / 'node_modules/rea-agents'
    if not (package / 'package.json').is_file():
        raise ValueError('Pinned REA package is absent. Run make rea-install.')
    metadata = json.loads((package / 'package.json').read_text(encoding='utf-8'))
    if 'version' not in CONFIG:
        raise ValueError('config/rea.json missing version')
    if metadata.get('version') != CONFIG['version']:
        raise ValueError('REA package version differs from config/rea.json; run make rea-install')
    command = [str(node), str(package / 'scripts/rea.mjs'), *(args or ['--help'])]
    os.chdir(ROOT)
    if sys.platform == 'win32':
        # Windows exec overlays do not return the child's failure status.
        raise SystemExit(os.spawnve(os.P_WAIT, command[0], command, env))
    os.execvpe(command[0], command, env)


if __name__ == '__main__':
    try:
        main()
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
