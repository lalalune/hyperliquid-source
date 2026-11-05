from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import timeout_cache_count148_owner_static as subject

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)

RECORDS = (ROOT_DIR / 'research/work-items'
           / 'RE-005-node115-timeout-cache-count148-owner/records.json')


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class TimeoutCacheCount148OwnerStaticTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.got = subject.analyze(DATA)

    def test_records_match_recomputed_analysis(self):
        expected = json.loads(RECORDS.read_text())
        got = dict(self.got)
        got['artifact'] = {
            'bytes': got['artifact']['bytes'],
            'path': 'artifacts/node/115/hl-node',
            'sha256': got['artifact']['sha256'],
            'snapshot': '<authenticated-node115>',
        }
        self.assertEqual(canonical(expected), canonical(got))

    def test_byte_pins_match_artifact(self):
        self.assertEqual(self.got['byte_pins'], subject.BYTE_PINS)

    def test_layout_constants(self):
        layout = self.got['layout']
        rec = layout['entry_record']
        self.assertEqual(rec['size'], '0x20')
        self.assertEqual(rec['once_state_ctor_init'], 3)
        obj = layout['entry_object']
        self.assertEqual(obj['alloc_size'], '0x150')
        self.assertEqual(obj['count148_ctor_init'], 1)
        self.assertEqual(obj['record_handle_count'], 'obj+0x148')
        self.assertEqual(layout['count148']['increment_sites'], 0)

    def test_count148_has_exactly_one_rmw_site(self):
        sites148 = [s for s in self.got['lock_rmw_sites']
                    if s['disp'] == '0x148']
        self.assertEqual(
            [(s['site'], s['body'], s['kind'], s['reg']) for s in sites148],
            [('0x5cfc8fa', 'handle_drop_148', 'incdec', 1)])
        sites140 = [s for s in self.got['lock_rmw_sites']
                    if s['disp'] == '0x140']
        self.assertEqual(
            {(s['site'], s['body']) for s in sites140},
            {('0x5cfcfc2', 'getobj'), ('0x5cee3a4', 'pair_drop_140'),
             ('0x5cee721', 'refresh')})
        hits = self.got['disp148_pattern_hits']
        self.assertEqual(hits, {
            'ctor_grower': ['0x5cfea0e'],
            'handle_drop_148': ['0x5cfc8fe'],
            'reg_register': ['0x5cdc660', '0x5cdc6d0'],
        })

    def test_construction_and_release_chains(self):
        calls = self.got['call_sites']
        callers = {
            name: {(s['body']) for s in sites}
            for name, sites in calls.items()}
        self.assertEqual(callers['ctor_grower'], {'vec_build'})
        self.assertEqual(callers['vec_build'], {'registry_ctor_wrap'})
        self.assertEqual(callers['registry_ctor_wrap'],
                         {'globals_init_closure', 'globals_init_direct'})
        self.assertEqual(callers['vec_drop_glue'],
                         {'ctor_grower', 'vec_build'})
        self.assertEqual(
            {(s['site'], s['body']) for s in calls['handle_drop_148']},
            {('0x5cfc9ed', 'vec_drop_glue'),
             ('0x5cfca3d', 'vec_drop_glue')})
        self.assertEqual(callers['reg_register'],
                         {'entry_init_closure', 'entry_init_direct'})
        self.assertEqual(callers['record_once_shim'], {'lookup'})
        self.assertEqual(callers['getobj'], {'lookup'})
        self.assertEqual(self.got['rela_refs_to_drop_bodies'], [])

    def test_once_identity(self):
        loc = self.got['locations']['0x64c6fd8']
        self.assertEqual(loc, {'file': 'std/src/sys/sync/once/futex.rs',
                               'line': 91, 'col': 18})
        self.assertEqual(self.got['once_state_message'],
                         subject.ONCE_MSG)
        self.assertEqual(self.got['slots']['0x64df9f0'],
                         {'kind': 'relative', 'target': '0x5c87d50'})
        self.assertEqual(self.got['locations']['0x64c6e80']['file'],
                         'tokio/src/signal/registry.rs')


if __name__ == '__main__':
    unittest.main()
