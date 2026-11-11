#!/usr/bin/env python3
"""Standalone tests for packet RE-001-node115-lu-opt-groups56-60-leaves.

Tamper controls run FIRST: each must make the verifier fail. A tamper
control that does not fail the verifier fails the test run. No unittest
TestCase is used (this is a custom runner); run the file directly.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

SLUG = 'RE-001-node115-lu-opt-groups56-60-leaves'
LEAVES = [
    ('prof_leak', 0x6374170, 0x63741f6, 134, 36),
    ('prof_leak_error', 0x6374200, 0x6374286, 134, 36),
    ('prof_accum', 0x6373da0, 0x6373e26, 134, 36),
    ('prof_recent_alloc_max', 0x6374290, 0x63744a7, 535, 147),
    ('prof_stats', 0x63744b0, 0x6374536, 134, 36),
]

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, 'research', 'work-items', SLUG)
VERIFIER = os.path.join(ROOT, 'tools', 'node115_lu_opt_groups56_60_leaves.py')
BIN = os.path.join(ROOT, 'artifacts', 'node', '115', 'hl-node')

passed = 0
failed = 0


def check(cond, msg):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print('FAIL:', msg)


def run_verifier(env_extra=None, cwd=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, VERIFIER],
                          capture_output=True, text=True, env=env, cwd=cwd)


def run_verifier_at(tools_path, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, tools_path],
                          capture_output=True, text=True, env=env)


def temp_layout():
    """Replicate the repo layout under a tempdir (packet dir + tools +
    tests), reusing the sha-checked binary path (no 105MB copy/link)."""
    tmp = tempfile.mkdtemp(prefix='hl273_')
    pkt = os.path.join(tmp, 'research', 'work-items', SLUG)
    os.makedirs(os.path.join(tmp, 'tools'))
    os.makedirs(os.path.join(tmp, 'tests'))
    shutil.copytree(PACKET, pkt)
    shutil.copy(VERIFIER, os.path.join(tmp, 'tools', os.path.basename(VERIFIER)))
    shutil.copy(os.path.abspath(__file__),
                os.path.join(tmp, 'tests', os.path.basename(__file__)))
    return tmp, pkt


def test_tamper_hex():
    tmp, pkt = temp_layout()
    try:
        p = os.path.join(pkt, 'prof_leak.hex')
        b = bytearray(open(p, 'rb').read())
        b[10] ^= 0xff
        open(p, 'wb').write(bytes(b))
        r = run_verifier_at(os.path.join(tmp, 'tools',
                                         os.path.basename(VERIFIER)),
                            {'HL273_ROOT': tmp, 'HL273_BIN': BIN})
        check(r.returncode != 0, 'tamper hex flip must fail verifier')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_strict():
    tmp, pkt = temp_layout()
    try:
        rp = os.path.join(pkt, 'records.json')
        rec = json.load(open(rp))
        rec['exhibits'][0]['strict'] += 1
        json.dump(rec, open(rp, 'w'), indent=2)
        r = run_verifier_at(os.path.join(tmp, 'tools',
                                         os.path.basename(VERIFIER)),
                            {'HL273_ROOT': tmp, 'HL273_BIN': BIN})
        check(r.returncode != 0, 'tamper strict-count must fail verifier')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_overlap():
    tmp, pkt = temp_layout()
    try:
        fake = tempfile.mkdtemp(prefix='hl273_prior_')
        os.makedirs(os.path.join(fake, 'fake-prior'))
        json.dump({'exhibits': [{'name': 'fake', 'range': ['0x6374170',
                                                            '0x63741f6']}]},
                  open(os.path.join(fake, 'fake-prior', 'records.json'), 'w'))
        r = run_verifier_at(os.path.join(tmp, 'tools',
                                         os.path.basename(VERIFIER)),
                            {'HL273_ROOT': tmp, 'HL273_BIN': BIN,
                             'HL273_PRIOR_ROOTS': fake})
        check(r.returncode != 0 and 'disjoint' in r.stdout,
              'tamper injected overlap must fail verifier on disjointness')
        shutil.rmtree(fake, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_tamper_slot():
    tmp, pkt = temp_layout()
    try:
        rp = os.path.join(pkt, 'records.json')
        rec = json.load(open(rp))
        rec['exhibits'][0]['value_slot'] = '0x6713604'
        json.dump(rec, open(rp, 'w'), indent=2)
        r = run_verifier_at(os.path.join(tmp, 'tools',
                                         os.path.basename(VERIFIER)),
                            {'HL273_ROOT': tmp, 'HL273_BIN': BIN})
        check(r.returncode != 0, 'tamper value-slot must fail verifier')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_clean_temp_copy():
    tmp, pkt = temp_layout()
    try:
        r = run_verifier_at(os.path.join(tmp, 'tools',
                                         os.path.basename(VERIFIER)),
                            {'HL273_ROOT': tmp, 'HL273_BIN': BIN})
        check(r.returncode == 0,
              'clean temp copy must pass verifier: ' + r.stdout[-500:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_regen_and_strict():
    for name, s, e, nb, ns in LEAVES:
        stored = open(os.path.join(PACKET, f'{name}.objdump.txt'),
                      errors='replace').read()
        regen = subprocess.run(
            ['objdump', '-d', '--start-address', hex(s),
             '--stop-address', hex(e), BIN],
            capture_output=True, text=True).stdout
        si = [l.strip() for l in stored.splitlines()
              if re.match(r'^\s*[0-9a-f]+:\t', l)]
        ri = [l.strip() for l in regen.splitlines()
              if re.match(r'^\s*[0-9a-f]+:\t', l)]
        check(si == ri, f'{name} regen comparison')
        strict = sum(1 for l in stored.splitlines()
                     if re.match(r'^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]', l))
        check(strict == ns, f'{name} independent strict recount')


def test_totals():
    rec = json.load(open(os.path.join(PACKET, 'records.json')))
    check(rec['totals']['bytes'] == 1071, 'total bytes 1071')
    check(rec['totals']['strict'] == 291, 'total strict 291')
    check(sum(e['bytes'] for e in rec['exhibits']) == 1071,
          'exhibit bytes sum')
    check(sum(e['strict'] for e in rec['exhibits']) == 291,
          'exhibit strict sum')
    check(rec['leaves_remaining_after'] == 111, 'leaves remaining 111')


def main():
    # tamper controls FIRST
    test_tamper_hex()
    test_tamper_strict()
    test_tamper_overlap()
    test_tamper_slot()
    test_clean_temp_copy()
    test_regen_and_strict()
    test_totals()
    print(f'{passed} passed, {failed} failed')
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
