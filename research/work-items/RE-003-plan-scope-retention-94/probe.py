#!/usr/bin/env python3
"""Replay real plan-only CLI scope retention and existing rejection controls."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile


TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--planner', type=Path, required=True)
    args = parser.parse_args()
    planner = args.planner.resolve()
    examples = planner.parents[1] / 'research/work-items/RE-003-harness-design/examples'
    original = json.loads((examples / 'plan-only.json').read_text(encoding='utf-8'))
    if original['target_release'] != '94' or original['target_sha256'] != TARGET_SHA256:
        raise ValueError('probe requires the committed node #94 plan-only example')
    component = copy.deepcopy(original)
    component['component_id'] = 'foundation'
    question = copy.deepcopy(original)
    question['bounded_question'] = 'Record a second bounded offline question without executing a target'
    cases = [('original', original, 0), ('changed-component', component, 0), ('changed-question', question, 0)]
    for name in ('deny-execute', 'deny-network', 'deny-wrong-digest'):
        cases.append((name, json.loads((examples / (name + '.json')).read_text(encoding='utf-8')), 2))
    results = []
    with tempfile.TemporaryDirectory(prefix='harness-scope-probe-') as directory:
        for name, request, expected in cases:
            data = (json.dumps(request, sort_keys=True, indent=2) + '\n').encode('utf-8')
            path = Path(directory) / (name + '.json')
            path.write_bytes(data)
            command = [sys.executable, '-B', str(planner), '--request', str(path)]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            result = json.loads(completed.stdout)
            results.append({'case': name, 'request_sha256': hashlib.sha256(data).hexdigest(),
                            'request_scope': {key: request[key] for key in ('component_id', 'bounded_question')},
                            'expected_returncode': expected, 'returncode': completed.returncode,
                            'result': result, 'stdout': completed.stdout, 'stderr': completed.stderr})
    positive = results[:3]
    report = {'schema_version': 1, 'task_id': 'RE-003', 'target_release': '94', 'target_sha256': TARGET_SHA256,
              'python_version': platform.python_version(),
              'planner_sha256': hashlib.sha256(planner.read_bytes()).hexdigest(),
              'command_template': 'python3 -B <planner> --request <temporary-request.json>',
              'cases': results, 'case_count': len(results),
              'all_expected_statuses': all(row['returncode'] == row['expected_returncode'] for row in results),
              'scope_retained': all(all(row['result'].get(key) == value for key, value in row['request_scope'].items()) for row in positive),
              'component_change_visible': positive[0]['result'] != positive[1]['result'],
              'question_change_visible': positive[0]['result'] != positive[2]['result'],
              'captured_binary_reads_or_executions': 0,
              'limits': 'Plan metadata and three existing rejection controls only; no comparator, target behavior, identity or component gate claim.'}
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
