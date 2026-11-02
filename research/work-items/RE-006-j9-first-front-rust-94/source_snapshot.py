"""Fixed compiler-read snapshot guards, reused from the reviewed RE-006 harness.

ROOT/COMPONENT/MODULE/HERE and require/sha are supplied by bind(). No target runs.
"""
from pathlib import Path
import hashlib
import subprocess

ROOT = COMPONENT = MODULE = HERE = None


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bind(root, component, module, here):
    global ROOT, COMPONENT, MODULE, HERE
    ROOT, COMPONENT, MODULE, HERE = root, component, module, here


def source_files():
    raw = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z', '--', 'src/node94-orderbook'])
    paths = {ROOT / name for name in raw.decode().split('\0') if name}
    paths.add(MODULE)
    result = {'component/' + str(p.relative_to(COMPONENT)): p for p in paths}
    result['driver/input_only_driver.rs'] = HERE / 'input_only_driver.rs'
    return result


def manifest(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(), 'snapshot symlink')
        if path.is_file():
            raw = path.read_bytes()
            result[str(path.relative_to(directory))] = dict(bytes=len(raw), sha256=sha(raw))
    return result


def check_snapshot(directory, expected):
    require(manifest(directory) == expected, 'fixed source snapshot changed')


def check_live(expected):
    actual = {}
    for name, path in source_files().items():
        require(path.is_file() and not path.is_symlink(), 'live source missing/symlink')
        raw = path.read_bytes()
        actual[name] = dict(bytes=len(raw), sha256=sha(raw))
    require(actual == expected, 'live source differs from compiled snapshot')
