#!/usr/bin/env python3
"""Print a verified, release-specific Ghidra import command; do not launch it."""
import argparse
import json
import os
from pathlib import Path
import shlex

from artifacts import ROOT, check
from doctor import locate_ghidra

def render_import_plan(ghidra, project_dir, name, binary, log, *, windows):
    """Print for the native host shell; the plan itself launches nothing."""
    launcher = ghidra / 'support' / ('analyzeHeadless.bat' if windows else 'analyzeHeadless')
    if not launcher.is_file():
        raise ValueError(f'Selected Ghidra has no native headless launcher: {launcher}')
    command = [str(launcher), str(project_dir), name,
               '-import', str(binary), '-processor', 'x86:LE:64:default',
               '-analysisTimeoutPerFile', '1800', '-max-cpu', '4', '-log', str(log)]
    if windows:
        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"
        return '\n'.join([
            '# PowerShell static import plan only; no node execution.',
            'New-Item -ItemType Directory -Force -Path ' + quote(project_dir) + ' | Out-Null',
            '& ' + ' '.join(quote(arg) for arg in command),
        ])
    return '\n'.join([
        '# Static import plan only. Creates a separate analysis project; no node execution.',
        'mkdir -p ' + shlex.quote(str(project_dir)),
        shlex.join(command),
    ])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release', choices=['94', '115'], required=True)
    args = p.parse_args()
    ghidra = locate_ghidra()
    if not ghidra:
        raise SystemExit('Set GHIDRA_HOME to an installation with support/analyzeHeadless')
    relative = f'artifacts/node/{args.release}/hl-node'
    item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == relative)
    check(ROOT / relative, item)
    project_dir = ROOT / 'work/ghidra'
    name = f"hl-node-{args.release}-{item['sha256'][:12]}"
    if (project_dir / (name + '.gpr')).exists():
        raise SystemExit('Existing Ghidra project found. Reuse it explicitly; do not reimport or overwrite it.')
    print(render_import_plan(ghidra, project_dir, name, ROOT / relative,
                             ROOT / 'work' / f'{name}.ghidra.log', windows=os.name == 'nt'))


if __name__ == '__main__':
    main()
