#!/usr/bin/env python3
"""Recount the immutable merged-main snapshot without changing historical evidence."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import re
import subprocess

COMMIT = '0e70dfafd1ae86649a1660405b9110dbebe93050'
TREE = '1ff44e49fab7e702781c35a5c87fa2affd59cae6'
PACKET = 'research/work-items/RE-001-node115-progress-review-2026-11-09'
LEGACY_SHA = '1eb1c2a2c68d175240da09d515eb2f44bedb50508dc8309dc8d64948ca6093b2'
HISTORICAL_EVIDENCE_SHA = 'a5f4b0b49a0b123cff451a5d726c517bb5892e72a73d85f0a8304b786273a0be'
START = '<!-- BEGIN GENERATED PROGRESS -->'
END = '<!-- END GENERATED PROGRESS -->'

def need(ok, detail):
    if not ok:
        raise ValueError(detail)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])

def generated(text):
    need(text.count(START) == text.count(END) == 1, 'one generated marker pair')
    before, tail = text.split(START)
    need(END in tail, 'ordered generated markers')
    return START + tail.split(END)[0] + END

def audit(repo, provider):
    need(git(repo, 'rev-parse', COMMIT + '^{tree}').decode().strip() == TREE,
         'immutable merged-main tree')
    legacy_path = provider / PACKET / 'verify.py'
    need(sha(legacy_path.read_bytes()) == LEGACY_SHA, 'historical auditor unchanged')
    need(sha((provider / PACKET / 'evidence.json').read_bytes()) == HISTORICAL_EVIDENCE_SHA,
         'historical evidence unchanged')
    spec = importlib.util.spec_from_file_location('immutable_progress_auditor', legacy_path)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    current = old.snapshot(repo, provider, COMMIT)
    # Read the immutable pre-documentation-refresh README from Git. Only its
    # generated block must also match the provider; appended review prose may change.
    pinned_readme = git(repo, 'show', COMMIT + ':README.md').decode()
    current['readme_audit'] = old.readme_check(pinned_readme, current)
    block = generated(pinned_readme)
    need(generated((provider / 'README.md').read_text()) == block,
         'provider generated progress block matches immutable snapshot')
    pinned_packet_readme = git(repo, 'show', COMMIT + ':' + PACKET + '/README.md')
    need((provider / PACKET / 'README.md').read_bytes().startswith(pinned_packet_readme),
         'historical review narrative preserved as prefix')
    need(current['accepted_full_scope_gates'] == current['complete_components'] == 0,
         'no unsupported full-scope gate advancement')
    need(all(not row['accepted_evidence'] and
             row['whole_component_function_denominator'] is None
             for row in current['component_assessment']),
         'full-component evidence and function denominators remain unaccepted/unmeasured')
    need('first-party' not in current['dependency_comparisons'],
         'dependency matches earn no first-party byte credit')
    coverage_raw = git(repo, 'show', COMMIT + ':research/catalogue/byte-coverage.json')
    coverage = json.loads(coverage_raw)
    totals = coverage['totals']['node115']
    independent = current['comparisons']
    for key in ['bytes', 'raw_equal_bytes', 'raw_equal_windows',
                'relocation_qualified_windows', 'windows', 'non_relocation_bytes']:
        need(totals[key] == independent[key], 'generated/independent total: ' + key)
    need(totals['relocation_bytes'] == independent['masked_bytes'],
         'generated/independent relocation-byte total')
    need(independent['relocation_qualified_windows'] == independent['windows'] and
         totals['equal_non_relocation_bytes'] == independent['non_relocation_bytes'],
         'all compared non-relocation positions match')
    need(coverage['targets']['node115']['text_bytes'] == current['text_bytes'],
         'generated/ELF-parsed text denominator')
    for name, stats in current['dependency_comparisons'].items():
        actual = coverage['dependencies']['node115'][name]
        for key in ['bytes', 'raw_equal_bytes', 'raw_equal_windows',
                    'relocation_qualified_windows', 'windows', 'non_relocation_bytes']:
            need(actual[key] == stats[key], 'generated/independent dependency: ' + name + '/' + key)
    extent = [{'id': r['id'], 'target_bytes': r['target_bytes'],
               'source_bytes': r['source_bytes'], 'credit': 0}
              for r in coverage.get('extent_mismatches', [])]
    need(extent == current['extent_mismatches'], 'unequal extents preserved without credit')
    historical = json.loads((provider / PACKET / 'evidence.json').read_text())
    previous = historical['pending_integration_snapshot']
    need(current['comparisons'] == previous['comparisons'] and
         current['percentages'] == previous['percentages'],
         'no unsupported byte or completion increase since pending snapshot')
    need(current['inventory']['rust_areas'] == previous['inventory']['rust_areas'] and
         current['inventory']['cargo_manifests'] == previous['inventory']['cargo_manifests'],
         'post-review source inventory unchanged')
    controls = old.controls()
    need(controls['negative_controls_attempted'] == controls['negative_controls_detected'] == 4,
         'historical comparator controls still reject all four corruptions')
    source_paths = ['AGENTS.md', 'docs/SCOPE.md', 'research/progress.json',
                    'research/components.json', 'research/byte-windows.json',
                    'provenance/artifacts.json', 'tools/catalogue.py',
                    'tools/byte_progress.py', 'research/catalogue/byte-coverage.json',
                    'README.md']
    return {
        'schema_version': 1,
        'reviewed_on': '2026-11-09',
        'snapshot_kind': 'merged-main-before-documentation-refresh',
        'method': 'The unchanged SHA-bound historical auditor independently parses ELF64 sections, inventories immutable Git paths, authenticates all pinned evidence and compares complete bodies with recorded relocation masks. This wrapper checks the merged-main README fractions and generated catalogue against those independent totals; production comparator functions are not imported.',
        'audit_source_sha256': sha(Path(__file__).read_bytes()),
        'historical_auditor_sha256': LEGACY_SHA,
        'historical_evidence_sha256': HISTORICAL_EVIDENCE_SHA,
        'tooling': {'python': platform.python_version(),
                    'git': git(repo, '--version').decode().strip()},
        'source_sha256': {name: sha(git(repo, 'show', COMMIT + ':' + name))
                          for name in source_paths},
        'main': current,
        'generated_readme_block_sha256': sha(block.encode()),
        'readme_binding': 'Full README audit is of the pinned Git commit. Provider generated block must match; later prose outside the markers is intentionally not part of that hash.',
        'generated_catalogue_totals_match_independent_auditor': True,
        'historical_controls_replayed': controls,
        'delta_from_historical_pending_snapshot': {
            'research_work_items': current['inventory']['work_items'] - previous['inventory']['work_items'],
            'rust_areas': 0, 'cargo_manifests': 0, 'accepted_gates': 0,
            'compared_bytes': 0, 'raw_equal_bytes': 0},
        'preserved_negative_results': current['extent_mismatches'],
        'limitations': [
            'The snapshot pins the merged source tree before this append-only documentation refresh; it does not claim the refreshed documentation commit was the old main.',
            'Inventory counts and PR closure are not completion or remaining-effort measures.',
            'All aligned comparison windows are existing public dependencies; no first-party component byte comparison is registered.',
            'Full-component function/byte denominators, dependency/private-fork closure, integrated node build, whole-ELF identity and end-to-end behavior remain unestablished.',
            'Static accounting only: no captured machine code, live networking or chain action is executed.']}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--provider', type=Path, required=True)
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument('--out', type=Path)
    output.add_argument('--check', type=Path)
    args = parser.parse_args()
    report = audit(args.repo.resolve(), args.provider.resolve())
    if args.check:
        expected = json.loads(args.check.read_text())
        # Tool versions are observations, not numerical acceptance inputs. Keep
        # the original versions in evidence but permit a different local runtime.
        got = dict(report); want = dict(expected)
        got.pop('tooling'); want.pop('tooling')
        need(got == want, 'post-merge snapshot differs from committed evidence')
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'commit': COMMIT, 'tree': TREE,
                      'inventory': report['main']['inventory'],
                      'percentages': report['main']['percentages'],
                      'comparisons': report['main']['comparisons'],
                      'controls': report['historical_controls_replayed']}, indent=2))

if __name__ == '__main__':
    main()
