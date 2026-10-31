#!/usr/bin/env python3
"""Read-only research-tool preflight. Never launches captured binaries or Ghidra."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def locate_ghidra():
    candidates = []
    if os.environ.get('GHIDRA_HOME'):
        candidates.append(Path(os.environ['GHIDRA_HOME']))
    candidates.extend(sorted((Path.home() / '.local/share/rea-tools').glob('ghidra_*_PUBLIC'), reverse=True))
    for directory in candidates:
        for script_name in ['support/analyzeHeadless', 'support/analyzeHeadless.bat']:
            if (directory / script_name).is_file():
                return directory
    return None


def locate_llvm():
    if os.environ.get('LLVM_OBJDUMP'):
        val = os.environ['LLVM_OBJDUMP']
        if Path(val).is_file():
            return val
        return shutil.which(val)
    fallback_paths = [
        Path('/opt/homebrew/opt/llvm/bin/llvm-objdump'),
        Path('/usr/local/opt/llvm/bin/llvm-objdump'),
        Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'LLVM/bin/llvm-objdump.exe',
        Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'LLVM/bin/llvm-objdump.exe',
    ]
    return shutil.which('llvm-objdump') or next((str(p) for p in fallback_paths if p.is_file()), None)


def probe(name, command):
    if not command or not command[0]:
        return {'name': name, 'available': False}
    try:
        p = subprocess.run(command, text=True, capture_output=True, timeout=10)
        lines = (p.stdout + p.stderr).splitlines()
        return {'name': name, 'available': p.returncode == 0, 'version': lines[0] if lines else '', 'executable': command[0]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'name': name, 'available': False, 'error': str(exc)}


def probe_git_lfs():
    lfs_bin = shutil.which('git-lfs')
    if lfs_bin:
        return probe('git-lfs', [lfs_bin, 'version'])
    git_bin = shutil.which('git')
    if git_bin:
        res = probe('git-lfs', [git_bin, 'lfs', 'version'])
        if res.get('available'):
            return res
    return {'name': 'git-lfs', 'available': False}


def report():
    required = [probe('python', [sys.executable, '--version'])]
    for name, args in [('git', ['--version']), ('gpg', ['--version']), ('rg', ['--version'])]:
        required.append(probe(name, [shutil.which(name), *args]))
    required.append(probe_git_lfs())
    optional = [probe('llvm-objdump', [locate_llvm(), '--version']), probe('java', [shutil.which('java'), '-version'])]
    rustup = shutil.which('rustup')
    for version in ['1.94.1', '1.95.0']:
        optional.append(probe('rust-' + version, [rustup, 'run', version, 'rustc', '--version']))
    ghidra = locate_ghidra()
    ghidra_version = None
    if ghidra:
        properties = ghidra / 'Ghidra/application.properties'
        if properties.is_file():
            ghidra_version = next((line.split('=', 1)[1] for line in properties.read_text().splitlines() if line.startswith('application.version=')), None)
    return {'analysis_ready': all(t['available'] for t in required) and sys.version_info >= (3, 10),
            'exact_rebuild_ready': False,
            'missing_rebuild_evidence': ['Recovered Cargo manifests and dependency locks', 'Target Linux build flags and exact LLVM/fork provenance', 'Accepted reconstructed implementation and comparison harness'],
            'required_tools': required, 'optional_tools': optional,
            'ghidra': {'available': ghidra is not None, 'home': str(ghidra) if ghidra else None, 'version': ghidra_version, 'started': False},
            'captured_binaries_executed': False}


if __name__ == '__main__':
    data = report()
    print(json.dumps(data, indent=2))
    raise SystemExit(0 if data['analysis_ready'] else 1)
