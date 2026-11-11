from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import timeout_cache_object_fields_static as subject

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)

RECORDS = (ROOT_DIR / 'research/work-items'
           / 'RE-005-node115-timeout-cache-object-fields/records.json')


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class TimeoutCacheObjectFieldsStaticTest(unittest.TestCase):

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

    def test_layout_constants(self):
        layout = self.got['layout']
        self.assertEqual(layout['alloc_size'], '0x150')
        self.assertEqual(layout['cells'], 8)
        self.assertEqual(layout['cell_stride'], '0x20')
        self.assertEqual(layout['ctor_memset'], {'at': 'obj+0x10', 'len': '0x130'})
        self.assertEqual(self.got['draincb_claim_offsets'],
                         ['0x8', '0x28', '0x48', '0x68',
                          '0x88', '0xa8', '0xc8', '0xe8'])

    def test_count_site_census(self):
        sites = {(s['body'], s['op'], s['disp'])
                 for s in self.got['lock_count_sites']}
        self.assertEqual(sites, {
            ('getobj', 'inc', '0x140'),
            ('pair_drop_140', 'dec', '0x140'),
            ('refresh', 'dec', '0x140'),
            ('handle_drop_148', 'dec', '0x148'),
        })

    def test_global_refs_closure(self):
        refs = self.got['global_refs']
        self.assertEqual(set(refs['cache_obj']), {'refresh'})
        self.assertEqual(set(refs['cache_lock']), {'refresh'})
        self.assertEqual(set(refs['cache_key']), {'refresh'})
        self.assertEqual(set(refs['vec_ptr']), {'drain', 'lookup'})
        self.assertEqual(set(refs['vec_len']), {'drain', 'lookup'})


if __name__ == '__main__':
    unittest.main()
