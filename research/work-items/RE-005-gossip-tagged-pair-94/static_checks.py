"""Retain four authorized static repository checks around this evidence tree."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import sys

PACKET = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('tagged_pair_run', PACKET / 'run.py')
qualifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualifier)


def snapshot():
    result = qualifier.audit()
    result['static_tools'] = {
        name: {'resolved': str(Path(shutil.which(name)).resolve()),
               **qualifier.file_record(Path(shutil.which(name)).resolve())}
        for name in ['make', 'rg', 'readelf', 'git', 'git-lfs', 'gpg']
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    qualifier.require(not out.exists() and out.is_relative_to(qualifier.ROOT / 'work'), 'Preserve previous static logs')
    qualifier.require(not qualifier.git('status', '--porcelain=v1', '--untracked-files=all'), 'Commit evidence checkpoint first')
    out.mkdir(parents=True)
    before = snapshot()
    qualifier.save(out / 'AUDIT-BEFORE.json', before)
    run = qualifier.Experiment(out, {})
    run.env['PATH'] = '/usr/local/bin:/usr/bin:/bin'
    try:
        for target in ['doctor', 'verify', 'catalogue-check', 'reproduce']:
            run.command(target, ['/usr/bin/make', 'PYTHON=' + sys.executable, target])
    finally:
        after = snapshot()
        qualifier.save(out / 'AUDIT-AFTER.json', after)
        qualifier.require(before == after, 'Static checks changed physical inputs or tools')
    qualifier.save(out / 'RESULT.json', {'source_checkpoint': before['head'], 'commands': run.commands,
                   'physical_inputs_identical': True, 'full_current_suite': 'NOT_RUN', 'CI': 'NOT_RUN',
                   'component_gates': False})
    print(json.dumps({'status': 'PASS', 'checks': 4, 'head': before['head']}, sort_keys=True))


if __name__ == '__main__':
    main()
