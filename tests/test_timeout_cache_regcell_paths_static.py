from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT_DIR), str(ROOT_DIR / 'tools')]

import timeout_cache_regcell_paths_static as subject

TARGET = ROOT_DIR / 'artifacts/node/115/hl-node'
DATA = TARGET.read_bytes() if TARGET.exists() else b''
MATERIALISED = (
    len(DATA) == subject.TARGET_SIZE
    and hashlib.sha256(DATA).hexdigest() == subject.TARGET_SHA256)

RECORDS = (ROOT_DIR / 'research/work-items'
           / 'RE-005-node115-timeout-cache-regcell-paths/records.json')


def canonical(payload):
    return json.dumps(payload, indent=1, sort_keys=True) + '\n'


@unittest.skipUnless(
    MATERIALISED,
    'the node 115 ELF artifact is not materialised')
class TimeoutCacheRegcellPathsStaticTest(unittest.TestCase):

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
        self.assertEqual(
            layout['cell_write']['answer'],
            'no path other than the lookup writes the cell')
        self.assertEqual(layout['registry_globals']['vec_ptr'],
                         '0x64fee28')

    def test_cell_store_pattern_sites(self):
        self.assertEqual(
            [(s['site'], s['body'])
             for s in self.got['cell_store_pattern']],
            [('0x5cdf4c6', 'entry_init_closure'),
             ('0x5cdf696', 'entry_init_direct'),
             ('0x5d08ac6', 'utf8_result_body')])

    def test_invocation_chain_is_lookup_only(self):
        calls = self.got['call_sites']
        callers = {
            name: {(s['body']) for s in sites}
            for name, sites in calls.items()}
        # the value source is called from the entry-init pair only
        self.assertEqual(callers['reg_register'],
                         {'entry_init_closure', 'entry_init_direct'})
        # the shim is called from the lookup only
        self.assertEqual(callers['record_once_shim'], {'lookup'})
        # the entry-init bodies have no direct callers at all
        self.assertEqual(calls['entry_init_closure'], [])
        self.assertEqual(calls['entry_init_direct'], [])
        # the globals shims likewise have no direct callers
        self.assertEqual(calls['globals_init_closure'], [])
        self.assertEqual(calls['globals_init_direct'], [])
        # the lookup itself is entered from the refresh only
        self.assertEqual(callers['lookup'], {'refresh'})
        self.assertEqual(callers['getobj'], {'lookup'})
        self.assertEqual(
            {(s['site'], s['body']) for s in calls['once_globals']},
            {('0x5cde849', 'lookup'), ('0x5cde8a3', 'lookup'),
             ('0x5ce732a', 'driver_init'), ('0x5ce7564', 'drain')})

    def test_vtable_is_the_only_entry_init_reference(self):
        rela = self.got['rela_refs']
        self.assertEqual(rela['entry_init_closure'], ['0x64c57c0'])
        self.assertEqual(rela['entry_init_direct'], ['0x64c57b8'])
        self.assertEqual(rela['reg_register'], [])
        self.assertEqual(rela['record_once_shim'], [])
        self.assertEqual(rela['lookup'], [])
        rip = self.got['rip_refs']
        self.assertEqual(
            [(s['site'], s['body']) for s in rip['vtable_entry_init']],
            [('0x5cdf566', 'record_once_shim')])
        self.assertEqual(
            [(s['site'], s['body'])
             for s in rip['vtable_globals_init']],
            [('0x5cdf5ab', 'once_globals')])
        self.assertEqual(rip['entry_init_closure'], [])
        self.assertEqual(rip['entry_init_direct'], [])
        self.assertEqual(rip['reg_register'], [])
        self.assertEqual(rip['record_once_shim'], [])
        self.assertEqual(rip['lookup'], [])
        raw = self.got['raw_refs_outside_text']
        self.assertEqual(raw['entry_init_closure'], 1)
        self.assertEqual(raw['entry_init_direct'], 1)
        self.assertEqual(raw['reg_register'], 0)
        self.assertEqual(raw['record_once_shim'], 0)
        self.assertEqual(raw['lookup'], 0)
        vt = self.got['vtables']['vtable_entry_init']
        self.assertEqual(vt, ['0x0', '0x8', '0x8',
                              '0x5cdf630', '0x5cdf460'])

    def test_record_pointers_confined_to_lookup_and_drain(self):
        rip = self.got['rip_refs']
        for key in ('g_vec_ptr', 'g_vec_len'):
            self.assertEqual(
                {(s['body']) for s in rip[key]}, {'lookup', 'drain'})
        sc = self.got['store_census']
        # no disp-0x10/0x14 store at all in the entry-init pair,
        # the drop glue or the +0x148 drop body
        self.assertEqual(sc['entry_init_closure'], [])
        self.assertEqual(sc['entry_init_direct'], [])
        self.assertEqual(sc['vec_drop_glue'], [])
        self.assertEqual(sc['handle_drop_148'], [])
        # lookup and drain: stack spills only
        self.assertEqual(
            [(s['site'], s['base']) for s in sc['lookup']],
            [('0x5cde739', 'rsp')])
        self.assertEqual(
            [(s['site'], s['base']) for s in sc['drain']],
            [('0x5ce7531', 'rsp')])

    def test_once_identity(self):
        self.assertEqual(self.got['slots']['0x64df9f0'],
                         {'kind': 'relative', 'target': '0x5c87d50'})
        self.assertEqual(self.got['locations']['0x64c5788'],
                         {'file': 'std/src/sync/once.rs',
                          'line': 219, 'col': 20})
        self.assertEqual(self.got['locations']['0x64c57c8'],
                         {'file': 'std/src/sync/once.rs',
                          'line': 219, 'col': 49})


if __name__ == '__main__':
    unittest.main()
