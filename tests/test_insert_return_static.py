"""Tests for the RE-005 insert-return packet tool.

The tool re-derives the insert body's producer
conditions, the (rax, rdx) return shape on each arm,
the trap census, the setter's post-rebind consumption,
the notify contract and the direct-caller census from
the authenticated hl-node 115 artifact, byte by byte.
Any drift in a body hash, slot resolution, Location
static, store census, call-site census or instruction
pin must fail the suite rather than silently rewrite
the packet.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'insert_return_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-insert-return')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'insert_return_static', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL_MOD = load_tool()


def materialised():
    target = TOOL_MOD.TARGET
    if not target.is_file():
        return False
    with target.open('rb') as handle:
        return not handle.read(64).startswith(b'version https://')


@unittest.skipUnless(materialised(),
                     'hl-node artifact not materialised')
class InsertReturnPacketTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TOOL_MOD.TARGET.read_bytes()
        cls.records = TOOL_MOD.analyze(cls.data)

    def test_artifact_and_owners(self):
        self.assertEqual(self.records['artifact']['size'],
                         105896032)
        owners = self.records['owners']
        self.assertEqual(owners['insert']['bytes'], 319)
        self.assertEqual(
            owners['insert']['sha256'],
            '9b9b96ad18568130435d9442cbc897deef1bd531a6b2bab71'
            'e050997e87ef6ef')
        self.assertEqual(owners['setter']['bytes'], 599)
        self.assertEqual(
            owners['setter']['sha256'],
            '5fbfddaf7831cf129e1dc6734e16b7aa37d5e51b3355c96a'
            '8da582d905f4d8e2')
        self.assertEqual(owners['notify']['bytes'], 258)
        self.assertEqual(
            owners['notify']['sha256'],
            'c7efc9b1071af6d1e1a162ccdff36175ffd1fe4a7dbfaa962'
            '8965f187d18b8e7')
        self.assertEqual(owners['guard_shim']['bytes'], 51)
        self.assertEqual(self.records['exported_bodies'],
                         ['insert', 'setter', 'notify'])

    def test_slots_resolve(self):
        slots = self.records['slots']
        self.assertEqual(slots['0x64df770'], '0x1680bd0')
        self.assertEqual(slots['0x64df620'], '0x1680cbf')
        self.assertEqual(slots['0x64df870'], '0x1681dc0')
        self.assertEqual(slots['0x64e0820'], '0x1681e20')
        self.assertEqual(slots['0x64ecbd8'], '0x5ce82b8')
        self.assertEqual(slots['0x64ec188'], '0x5bb42e0')
        self.assertEqual(slots['0x64e0f38'], '0x5bb5650')
        self.assertEqual(slots['0x64e01f8'], '0x5bb59d0')
        self.assertEqual(slots['0x64df6b8'], '0x1680e80')
        self.assertEqual(slots['0x64df6a0'], '0x1680c30')

    def test_strings(self):
        strings = self.records['strings']
        self.assertEqual(strings['timer_already_fired']['text'],
                         'Timer already fired')
        self.assertEqual(strings['wake_io_driver']['text'],
                         'failed to wake I/O driver')
        self.assertTrue(
            strings['entry_rs']['text'].endswith(
                'runtime/time/entry.rs'))
        self.assertTrue(
            strings['wheel_rs']['text'].endswith(
                'runtime/time/wheel/mod.rs'))
        self.assertTrue(
            strings['level_rs']['text'].endswith(
                'runtime/time/wheel/level.rs'))
        self.assertTrue(
            strings['linked_list_rs']['text'].endswith(
                'util/linked_list.rs'))
        self.assertTrue(
            strings['park_rs']['text'].endswith('runtime/park.rs'))

    def test_locations(self):
        locations = self.records['locations']
        self.assertEqual(
            (locations['0x64c6170']['line'],
             locations['0x64c6170']['col']), (417, 27))
        self.assertEqual(
            (locations['0x64c6a30']['line'],
             locations['0x64c6a30']['col']), (102, 13))
        self.assertEqual(
            (locations['0x64c5900']['line'],
             locations['0x64c5900']['col']), (173, 19))
        self.assertEqual(
            (locations['0x64c5918']['line'],
             locations['0x64c5918']['col']), (173, 6))
        self.assertEqual(
            (locations['0x64c5d70']['line'],
             locations['0x64c5d70']['col']), (125, 9))
        self.assertEqual(
            (locations['0x64c6f60']['line'],
             locations['0x64c6f60']['col']), (187, 18))

    def test_store_censuses(self):
        censuses = self.records['store_censuses']
        insert = [(e['site'], e['base'], e['disp'])
                  for e in censuses['insert_all_stores']]
        self.assertEqual(
            insert,
            [('0x5cf688f', 'rsi', 16), ('0x5cf6914', 'rsp', 0),
             ('0x5cf6921', 'rsi', 8), ('0x5cf6925', 'rsi', 0),
             ('0x5cf6931', 'rcx', 0), ('0x5cf6934', 'rax', 0),
             ('0x5cf693e', 'rax', 8), ('0x5cf694c', 'r9', 1032)])
        r14 = [(e['site'], e['base'], e['disp'])
               for e in censuses['setter_post_rebind_r14_stores']]
        self.assertEqual(
            r14,
            [('0x5cea8ec', 'r14', 56), ('0x5cea8f1', 'r14', 24),
             ('0x5cea907', 'r14', 48), ('0x5cea93e', 'r14', 32),
             ('0x5cea948', 'r14', 48)])
        notify = [(e['site'], e['base'], e['disp'])
                  for e in censuses['notify_rbx_stores']]
        self.assertEqual(
            notify,
            [('0x5ce09c7', 'rbx', 16), ('0x5ce09f9', 'rbx', 32),
             ('0x5ce0a04', 'rbx', 32), ('0x5ce0a65', 'rbx', 32)])

    def test_caller_census(self):
        self.assertEqual(self.records['insert_call_sites'],
                         [{'site': '0x5cea8d0', 'kind': 'call'}])

    def test_return_table(self):
        table = self.records['return_table']
        rows = table['rows']
        self.assertEqual(len(rows), 6)
        due = rows[1]
        self.assertIn('v <= elapsed', due['condition'])
        self.assertIn('rax = 1, rdx = entry', due['outcome'])
        linked = rows[5]
        self.assertIn('rax = 0, rdx = v', linked['outcome'])
        trap_conditions = [r['condition'] for r in rows
                           if r['outcome'].startswith('no return')]
        self.assertEqual(len(trap_conditions), 4)
        self.assertIn('rax == 1', table['setter_consumption'])
        self.assertIn('v < [wheel+0x28]',
                      table['setter_consumption']['rax == 0'])
        self.assertIn('v <= [wheel+0x10]',
                      table['testable_statement'])

    def test_records_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            TOOL_MOD.OUT = out
            TOOL_MOD.generate(self.data)
            committed = json.loads(
                (PACKET / 'records.json').read_text())
            regenerated = json.loads(
                (out / 'records.json').read_text())
            self.assertEqual(regenerated, committed)
            for name in ('insert', 'setter', 'notify'):
                self.assertEqual(
                    (out / f'{name}.objdump.txt').read_bytes(),
                    (PACKET / f'{name}.objdump.txt').read_bytes())

    def test_verify_mode(self):
        result = subprocess.run(
            [sys.executable, str(TOOL)], capture_output=True,
            text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"matches": true', result.stdout)

    def test_mutation_rejected(self):
        bad_start = bytearray(self.data)
        bad_start[0x5CF6880 - 0x1000] ^= 0xFF
        with self.assertRaises(ValueError):
            TOOL_MOD.analyze(bytes(bad_start))
        bad_pin = bytearray(self.data)
        bad_pin[0x5CEA8F1 - 0x1000] ^= 0xFF
        with self.assertRaises(ValueError):
            TOOL_MOD.analyze(bytes(bad_pin))


if __name__ == '__main__':
    unittest.main()
