"""Tests for the RE-005 bucket-second-caller packet tool.

The tool re-derives the bucket body 0x5ce29a0's complete
direct-caller census, the second caller 0x5ceb06e's
owner body (its dispatch context, gating, argument
setup, inline wheel-list arm, consume phase and traps)
and the comparison with the setter's known call from
the authenticated hl-node 115 artifact, byte by byte.
Any drift in a body hash, slot resolution, Location
static, store census, call-site census, reference
census or instruction pin must fail the suite rather
than silently rewrite the packet.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'bucket_second_caller_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-bucket-second-caller')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'bucket_second_caller_static', TOOL)
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
class BucketSecondCallerPacketTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TOOL_MOD.TARGET.read_bytes()
        cls.records = TOOL_MOD.analyze(cls.data)

    def test_artifact_and_owners(self):
        self.assertEqual(self.records['artifact']['size'],
                         105896032)
        owners = self.records['owners']
        self.assertEqual(owners['caller']['bytes'], 468)
        self.assertEqual(
            owners['caller']['sha256'],
            '5b1addcef08123e292e9e2110d74cdf9516ac713d91a'
            '19fb6a988b9bee7c52a3')
        self.assertEqual(owners['caller']['start'], '0x5ceafd0')
        self.assertEqual(owners['caller']['end'], '0x5ceb1a4')
        self.assertEqual(owners['bucket']['bytes'], 214)
        self.assertEqual(
            owners['bucket']['sha256'],
            '7f1bf0ac13bf0df1287b21da22e231bf1b29ea287ea'
            '2182aa5b8433b1fef89d8')
        self.assertEqual(self.records['exported_bodies'],
                         ['caller', 'bucket'])

    def test_slots_resolve(self):
        slots = self.records['slots']
        self.assertEqual(slots['0x64df770'], '0x1680bd0')
        self.assertEqual(slots['0x64df620'], '0x1680cbf')
        self.assertEqual(slots['0x64e01f8'], '0x5bb59d0')
        self.assertEqual(slots['0x64e0f38'], '0x5bb5650')
        self.assertEqual(slots['0x64df4c0'], '0x1680cab')
        self.assertEqual(slots['0x64df730'], '0x1680e60')
        self.assertEqual(slots['0x64df870'], '0x1681dc0')
        self.assertEqual(slots['0x64e0820'], '0x1681e20')

    def test_strings(self):
        strings = self.records['strings']
        self.assertTrue(
            strings['timers_disabled']['text'].startswith(
                'A Tokio 1.x context was found'))
        self.assertEqual(strings['tail_assert']['text'],
                         'assertion failed: self.tail.is_none()')
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

    def test_locations(self):
        locations = self.records['locations']
        self.assertEqual(
            (locations['0x64c6158']['line'],
             locations['0x64c6158']['col']), (549, 30))
        self.assertEqual(
            (locations['0x64c6a48']['line'],
             locations['0x64c6a48']['col']), (130, 17))
        self.assertEqual(
            (locations['0x64c5900']['line'],
             locations['0x64c5900']['col']), (173, 19))
        self.assertEqual(
            (locations['0x64c5918']['line'],
             locations['0x64c5918']['col']), (173, 6))
        self.assertEqual(
            (locations['0x64c5930']['line'],
             locations['0x64c5930']['col']), (188, 9))

    def test_store_censuses(self):
        censuses = self.records['store_censuses']
        caller = [(e['site'], e['base'], e['disp'])
                  for e in censuses['caller_all_stores']]
        self.assertEqual(
            caller,
            [('0x5ceb00a', 'r15', 80), ('0x5ceb081', 'rcx', 8),
             ('0x5ceb08d', 'rax', 0), ('0x5ceb093', 'rsi', 0),
             ('0x5ceb0a2', 'r15', 104), ('0x5ceb0bb', 'r14', 72),
             ('0x5ceb0c0', 'r14', 40), ('0x5ceb0d7', 'r14', 64),
             ('0x5ceb0ec', 'r14', 48), ('0x5ceb0f6', 'r14', 64),
             ('0x5ceb106', 'rbx', 0), ('0x5ceb115', 'r15', 112),
             ('0x5ceb183', 'rbx', 0)])
        bucket = [(e['site'], e['base'], e['disp'])
                  for e in censuses['bucket_all_stores']]
        self.assertEqual(
            bucket,
            [('0x5ce29df', 'rdx', 8), ('0x5ce29eb', 'rcx', 0),
             ('0x5ce29f1', 'rsi', 0), ('0x5ce2a09', 'rax', 0),
             ('0x5ce2a31', 'rdi', 1032), ('0x5ce2a3d', 'rax', 8)])

    def test_bucket_call_sites(self):
        self.assertEqual(
            self.records['bucket_call_sites'],
            [{'site': '0x5cea839', 'kind': 'call'},
             {'site': '0x5ceb06e', 'kind': 'call'}])

    def test_caller_references(self):
        refs = self.records['caller_references']
        self.assertEqual(refs['caller_direct_refs'], [])
        self.assertEqual(refs['caller_rip_relative_refs'], {})
        self.assertEqual(refs['caller_addend_refs'],
                         ['0x64dfe40'])
        self.assertEqual(refs['bucket_addend_refs'], [])
        self.assertEqual(refs['bucket_rip_relative_refs'], {})
        self.assertEqual(
            refs['table_neighbourhood']['0x64dfe40'],
            '0x5ceafd0')
        # Correction census (2026-11-05): the slot is a
        # .got entry and is called through from 35
        # drop-glue bodies - the invocation path the
        # original reference census could not see.
        self.assertEqual(refs['caller_slot_section'],
                         '.got')
        self.assertEqual(refs['caller_slot_section_range'],
                         ['0x64df458', '0x64ee158'])
        sites = refs['caller_slot_call_sites']
        self.assertEqual(len(sites), 35)
        self.assertTrue(
            all(s['kind'] == 'call' for s in sites))
        self.assertTrue(
            all(s['body_bytes'] == 136 for s in sites))
        self.assertTrue(
            all(s['site_offset'] == '0xc' for s in sites))
        self.assertEqual(
            len({s['body'] for s in sites}), 35)
        self.assertEqual(sites[0]['site'], '0x1472b9c')
        self.assertEqual(sites[0]['body'], '0x1472b90')
        self.assertEqual(sites[-1]['site'], '0x5cf1d7c')
        self.assertEqual(sites[-1]['body'], '0x5cf1d70')
        self.assertIn(
            'CORRECTION',
            self.records['findings']['dispatch_context'])

    def test_call_table(self):
        table = self.records['call_table']
        rows = table['rows']
        self.assertEqual(len(rows), 5)
        trap_rows = [r for r in rows
                     if r['outcome'].startswith('no return')]
        self.assertEqual(len(trap_rows), 2)
        call_row = rows[4]
        self.assertIn('0x5ceb06e', call_row['outcome'])
        self.assertIn('[head+0x18]',
                      table['consume_phase']['callback'])
        self.assertIn('only unlinks',
                      table['testable_statement'])
        self.assertIn('0x64dfe40',
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
            for name in ('caller', 'bucket'):
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
        bad_start[0x5CEAFD0 - 0x1000] ^= 0xFF
        with self.assertRaises(ValueError):
            TOOL_MOD.analyze(bytes(bad_start))
        bad_pin = bytearray(self.data)
        bad_pin[0x5CEB06E - 0x1000] ^= 0xFF
        with self.assertRaises(ValueError):
            TOOL_MOD.analyze(bytes(bad_pin))


if __name__ == '__main__':
    unittest.main()
