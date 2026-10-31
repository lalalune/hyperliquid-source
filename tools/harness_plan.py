#!/usr/bin/env python3
"""Validate an offline differential harness request; never execute a target."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-003-harness-design'
PROTOCOL_PATH = PACKET / 'protocol.json'
FIXTURES_PATH = PACKET / 'fixture-identities.json'
APPROVAL_PATH = PACKET / 'APPROVAL.md'

REQUIRED_REQUEST_FIELDS = (
    'request_id',
    'component_id',
    'bounded_question',
    'target_release',
    'target_sha256',
    'fixture_ids',
    'declared_side_effects',
    'network',
    'execute_target',
    'approval_present',
)

KNOWN_TARGET_DIGESTS = {
    '94': '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
    '115': 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301',
    'visor': '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31',
}


def load_json(path: Path):
    return json.loads(path.read_text())


def validate_protocol(protocol: dict) -> None:
    required = [
        'schema_version',
        'task_id',
        'execution_default',
        'requires_execution_approval',
        'isolation',
        'fixture_identity_fields',
        'positive_controls',
        'negative_controls',
        'request_fields',
        'acceptance_checklist',
    ]
    missing = [key for key in required if key not in protocol]
    if missing:
        raise ValueError(f'protocol.json missing fields: {missing}')
    if protocol.get('task_id') != 'RE-003':
        raise ValueError('protocol.json task_id must be RE-003')
    if protocol.get('execution_default') != 'denied':
        raise ValueError('execution_default must be denied')
    if not protocol.get('requires_execution_approval'):
        raise ValueError('requires_execution_approval must be true')
    isolation = protocol['isolation']
    if isolation.get('network') != 'deny':
        raise ValueError('isolation.network must default to deny')
    if not protocol['positive_controls'] or not protocol['negative_controls']:
        raise ValueError('protocol must name positive and negative controls')
    for field in REQUIRED_REQUEST_FIELDS:
        if field not in protocol['request_fields']:
            raise ValueError(f'protocol request_fields missing {field}')


def validate_fixtures(fixtures_doc: dict, protocol: dict) -> dict:
    if fixtures_doc.get('task_id') != 'RE-003':
        raise ValueError('fixture-identities.json task_id must be RE-003')
    fields = protocol['fixture_identity_fields']
    by_id = {}
    for row in fixtures_doc.get('fixtures', []):
        missing = [key for key in fields if key not in row]
        if missing:
            raise ValueError(f'fixture {row.get("fixture_id")} missing {missing}')
        fid = row['fixture_id']
        if fid in by_id:
            raise ValueError(f'duplicate fixture_id: {fid}')
        digest = row['target_sha256']
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError(f'fixture {fid} has invalid target_sha256')
        by_id[fid] = row
    if not by_id:
        raise ValueError('fixture-identities.json has no fixtures')
    return by_id


def approval_covers(request_id: str) -> bool:
    if not APPROVAL_PATH.is_file():
        return False
    text = APPROVAL_PATH.read_text()
    return request_id in text and 'authorized' in text.lower()


def validate_request(request: dict, fixtures_by_id: dict) -> dict:
    missing = [key for key in REQUIRED_REQUEST_FIELDS if key not in request]
    if missing:
        raise ValueError(f'request missing fields: {missing}')

    release = request['target_release']
    if release not in KNOWN_TARGET_DIGESTS:
        raise ValueError(f'unknown target_release: {release}')
    expected = KNOWN_TARGET_DIGESTS[release]
    if request['target_sha256'] != expected:
        raise ValueError(
            f'target_sha256 does not match release {release}: '
            f'expected {expected}'
        )

    if request['network'] not in ('deny', 'allow'):
        raise ValueError('network must be deny or allow')

    fixture_ids = request['fixture_ids']
    if not isinstance(fixture_ids, list) or not fixture_ids:
        raise ValueError('fixture_ids must be a non-empty list')
    seen_fixture_ids = set()
    for fid in fixture_ids:
        if fid in seen_fixture_ids:
            raise ValueError(f'duplicate fixture_id: {fid}')
        seen_fixture_ids.add(fid)
        if fid not in fixtures_by_id:
            raise ValueError(f'unknown fixture_id: {fid}')
        row = fixtures_by_id[fid]
        if row['target_sha256'] != request['target_sha256']:
            raise ValueError(
                f'fixture {fid} digest {row["target_sha256"]} does not match '
                f'request digest {request["target_sha256"]}'
            )

    if not isinstance(request['declared_side_effects'], list):
        raise ValueError('declared_side_effects must be a list')

    required_effects = []
    seen_effects = set()
    for fid in fixture_ids:
        effects = fixtures_by_id[fid].get('declared_side_effects', [])
        if not isinstance(effects, list):
            raise ValueError(f'fixture {fid} declared_side_effects must be a list')
        for effect in effects:
            if effect not in seen_effects:
                seen_effects.add(effect)
                required_effects.append(effect)

    missing_effects = [
        effect for effect in required_effects
        if effect not in request['declared_side_effects']
    ]
    if missing_effects:
        raise ValueError(
            'request declared_side_effects omits selected fixture effects: '
            f'{missing_effects}'
        )

    plan_effects = list(dict.fromkeys(
        [*required_effects, *request['declared_side_effects']]
    ))

    execute = bool(request['execute_target'])
    network_allow = request['network'] == 'allow'
    approval_claimed = bool(request['approval_present'])
    approval_ok = approval_covers(request['request_id'])

    if approval_claimed and not approval_ok:
        raise ValueError(
            'approval_present is true but APPROVAL.md does not cover this request_id'
        )

    if network_allow and not approval_ok:
        raise ValueError(
            'network allow requires APPROVAL.md covering this request_id (fail closed)'
        )

    if execute and not approval_ok:
        raise ValueError(
            'execute_target requires APPROVAL.md covering this request_id '
            '(fail closed; this tool never spawns hl-node or hl-visor)'
        )

    if execute:
        raise ValueError(
            'harness_plan is plan-only and refuses to spawn targets even when '
            'APPROVAL.md is present; use a separately reviewed runner'
        )

    return {
        'status': 'planned',
        'request_id': request['request_id'],
        'target_release': release,
        'target_sha256': request['target_sha256'],
        'fixture_ids': fixture_ids,
        'network': request['network'],
        'execute_target': False,
        'declared_side_effects': plan_effects,
        'workdir': 'work/harness/',
        'note': 'Plan only. No captured binary was executed.',
    }


def check_packet() -> None:
    protocol = load_json(PROTOCOL_PATH)
    validate_protocol(protocol)
    fixtures = validate_fixtures(load_json(FIXTURES_PATH), protocol)
    if APPROVAL_PATH.exists():
        raise ValueError(
            'APPROVAL.md is present in the design packet; remove it from the '
            'committed tree (approvals are local and per-request)'
        )
    plan_only = load_json(PACKET / 'examples/plan-only.json')
    plan = validate_request(plan_only, fixtures)
    print(json.dumps({'protocol': 'ok', 'fixtures': len(fixtures), 'plan': plan}, indent=2))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true', help='validate the RE-003 packet')
    group.add_argument('--request', type=Path, help='path to a harness request JSON')
    args = parser.parse_args(argv)

    if args.check:
        check_packet()
        return 0

    protocol = load_json(PROTOCOL_PATH)
    validate_protocol(protocol)
    fixtures = validate_fixtures(load_json(FIXTURES_PATH), protocol)
    request = load_json(args.request)
    try:
        plan = validate_request(request, fixtures)
    except ValueError as exc:
        print(json.dumps({'status': 'rejected', 'reason': str(exc)}, indent=2))
        return 2
    print(json.dumps(plan, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
