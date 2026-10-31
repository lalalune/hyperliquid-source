#!/usr/bin/env python3
"""Validate doctor preflight enhancements across platform boundaries."""
import argparse
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
import sys
sys.path.insert(0, str(ROOT / 'tools'))
import doctor


def probe_cross_platform():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)

        # 1. Test Ghidra batch detection
        win_ghidra = base / 'ghidra_win'
        (win_ghidra / 'support').mkdir(parents=True)
        (win_ghidra / 'support/analyzeHeadless.bat').write_text('@echo off\n')
        old_ghidra = os.environ.get('GHIDRA_HOME')
        os.environ['GHIDRA_HOME'] = str(win_ghidra)
        ghidra_detected = doctor.locate_ghidra() == win_ghidra
        if old_ghidra is not None:
            os.environ['GHIDRA_HOME'] = old_ghidra
        else:
            os.environ.pop('GHIDRA_HOME', None)

        # 2. Test standard Windows LLVM discovery via ProgramFiles fallback
        fake_pf = base / 'ProgramFiles'
        llvm_bin = fake_pf / 'LLVM/bin'
        llvm_bin.mkdir(parents=True)
        llvm_target = llvm_bin / 'llvm-objdump.exe'
        llvm_target.write_text('')

        old_llvm_env = os.environ.pop('LLVM_OBJDUMP', None)
        old_pf = os.environ.get('ProgramFiles')
        os.environ['ProgramFiles'] = str(fake_pf)
        with patch('shutil.which', return_value=None):
            llvm_detected = doctor.locate_llvm() == str(llvm_target)
        if old_pf is not None:
            os.environ['ProgramFiles'] = old_pf
        else:
            os.environ.pop('ProgramFiles', None)
        if old_llvm_env is not None:
            os.environ['LLVM_OBJDUMP'] = old_llvm_env

        # 3. Test git-lfs fallback to git subcommand when standalone binary is missing
        def mock_which(cmd):
            if cmd == 'git-lfs':
                return None
            if cmd == 'git':
                return '/usr/bin/git'
            return None

        with patch('shutil.which', side_effect=mock_which):
            with patch('doctor.probe', return_value={'name': 'git-lfs', 'available': True, 'version': 'git-lfs/3.4.0'}) as mock_p:
                lfs_res = doctor.probe_git_lfs()
                lfs_fallback_detected = lfs_res.get('available') is True and mock_p.call_args[0][1] == ['/usr/bin/git', 'lfs', 'version']

        return {
            "ghidra_batch_support_detected": ghidra_detected,
            "git_lfs_subcommand_fallback": lfs_fallback_detected,
            "standard_windows_llvm_detected": llvm_detected
        }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()

    result = probe_cross_platform()
    print(json.dumps(result, indent=2))
    if args.check:
        expected = json.loads((Path(__file__).parent / 'after.json').read_text())
        if result != expected:
            raise SystemExit(1)
