"""Tests for the RE-005 orphan queue writer packet tool.

The tool re-derives, from the authenticated hl-node 115
artifact only: the orphan queue header layout and file
initial values, the 0x1c-byte record layout the SIGCHLD
reap pass consumes, the complete RIP-relative census for
every queue word (disp-final and trailing-immediate
forms), the convert/wait call census, the slot
resolutions, the x28 stride-idiom census and the
process-module Location string census. The headline
finding is negative and must stay negative: no body
other than the refresh body and the reap pass itself
materialises any orphan queue global, so no
statically-addressing writer exists. Any drift must
fail the suite rather than silently rewrite the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'orphan_queue_writer_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-orphan-queue-writer')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'orphan_queue_writer_static', TOOL)
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
class OrphanQueueWriterPacketTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TOOL_MOD.TARGET.read_bytes()
        cls.records = TOOL_MOD.analyze(cls.data)
        cls.saved = json.loads(
            (PACKET / 'records.json').read_text())

    def test_artifact(self):
        self.assertEqual(self.records['artifact']['size'],
                         105896032)
        self.assertEqual(
            self.records['artifact']['sha256'],
            'a6e2897cd051213d004802deca416e8eca62b7a8278'
            'fa39f249e98c3867b5301')

    def test_records_match_saved(self):
        self.assertEqual(self.records, self.saved)

    def test_queue_initial_values(self):
        init = self.records['queue_init']
        # lock byte free, capacity-position word zero,
        # buffer pointer is the dangling align-4 value,
        # length zero: the queue starts empty.
        self.assertEqual(init['lock_orphan'], 0)
        self.assertEqual(init['queue_word_e8'], 0)
        self.assertEqual(init['queue_base'], 4)
        self.assertEqual(init['queue_len'], 0)

    def test_queue_globals_only_in_refresh_and_reap(self):
        refresh = hex(TOOL_MOD.BODIES['refresh'])
        reap = hex(TOOL_MOD.BODIES['reap'])
        falsepos = hex(TOOL_MOD.BODIES['falsepos'])
        census = self.records['rip_census']
        for name in ('lock_orphan', 'queue_base', 'queue_len'):
            for site in census.get(name, []):
                self.assertIn(
                    site['in_body'], (refresh, reap),
                    '%s referenced from %s' % (name, site))
        # trailing-form hits for the lock outside refresh /
        # reap are exactly the slab_counter references in
        # the registry allocator bodies: the counter word
        # sits 8 bytes below the lock, so its disp-final
        # sites alias as k = 8 trailing hits for the lock.
        slab_ends = {s['disp_end']
                     for s in census['slab_counter']}
        for site in census.get('lock_orphan_trail', []):
            if site['in_body'] in (refresh, reap):
                continue
            self.assertEqual(site['k'], 8)
            self.assertIn(site['disp_end'], slab_ends)
        for site in census.get('queue_base_trail', []):
            self.assertEqual(
                site['in_body'],
                hex(TOOL_MOD.BODIES['falsepos']))
        for site in census.get('queue_len_trail', []):
            if site['in_body'] == refresh:
                self.assertEqual(site['k'], 1)
            else:
                self.assertEqual(site['in_body'], reap)
                self.assertEqual(site['k'], 8)
        # the capacity-position word's only disp-final hit
        # anywhere is the documented mid-instruction byte
        # pattern inside the unrelated constructor body
        # pinned as falsepos; its trailing-form hits are
        # arithmetic aliases of the lock sites (k = 8).
        for site in census.get('queue_word_e8', []):
            self.assertEqual(site['in_body'], falsepos)
        for site in census.get('queue_word_e8_trail', []):
            self.assertIn(site['in_body'], (refresh, reap))
            self.assertEqual(site['k'], 8)

    def test_capacity_word_reference_is_only_the_false_hit(self):
        census = self.records['rip_census']
        self.assertEqual(len(census['queue_word_e8']), 1)
        hit = census['queue_word_e8'][0]
        self.assertEqual(hit['disp_end'], '0x63ba622')
        self.assertEqual(hit['k'], 0)

    def test_no_imul_stride_in_process_bodies(self):
        sizes = {name: self.records['bodies'][name]['size']
                 for name in ('convert', 'wait', 'fdhelper',
                              'spawn')}
        for site in self.records['imul_0x1c_sites']:
            va = int(site, 16)
            for name, size in sizes.items():
                start = TOOL_MOD.BODIES[name]
                self.assertFalse(
                    start <= va < start + size,
                    'imul x28 pattern inside %s' % name)

    def test_refresh_length_test_is_trailing_form(self):
        census = self.records['rip_census']
        sites = census['queue_len_trail']
        refresh = hex(TOOL_MOD.BODIES['refresh'])
        mine = [s for s in sites if s['in_body'] == refresh]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]['k'], 1)
        self.assertEqual(mine[0]['disp_end'], '0x5cee6e7')

    def test_convert_has_no_direct_callers(self):
        # convert is reached only through its GOT slot,
        # and only from the reap pass.
        self.assertNotIn('convert',
                         self.records['call_census'])
        slot = self.records['rip_census']['convert_slot']
        bodies = {s['in_body'] for s in slot}
        self.assertEqual(bodies, {hex(TOOL_MOD.BODIES['reap'])})

    def test_wait_callers(self):
        callers = self.records['call_census']['wait']
        bodies = {}
        for site in callers:
            bodies.setdefault(site['in_body'], 0)
            bodies[site['in_body']] += 1
        self.assertEqual(bodies[hex(TOOL_MOD.BODIES['spawn'])],
                         3)
        for name in ('waituser', 'appwait_a', 'appwait_b'):
            self.assertEqual(
                bodies[hex(TOOL_MOD.BODIES[name])], 1)

    def test_waitpid_slot_only_convert_and_wait(self):
        refs = self.records['rip_census']['waitpid_slot']
        bodies = {s['in_body'] for s in refs}
        self.assertEqual(
            bodies,
            {hex(TOOL_MOD.BODIES['convert']),
             hex(TOOL_MOD.BODIES['wait'])})

    def test_stride_idiom_only_reap_in_process_region(self):
        idiom = self.records['stride_idiom_x28']
        in_region = [s for s in idiom
                     if TOOL_MOD.BODIES['reap'] <= int(s, 16)
                     < TOOL_MOD.BODIES['reap'] + 465]
        self.assertTrue(in_region)
        others = [s for s in idiom if s not in in_region]
        for site in others:
            body = TOOL_MOD.fde_of(
                TOOL_MOD.fde_table(), int(site, 16))
            self.assertNotEqual(body[0],
                                TOOL_MOD.BODIES['convert'])
            self.assertNotEqual(body[0],
                                TOOL_MOD.BODIES['wait'])

    def test_process_location_strings(self):
        strings = self.records['string_census']
        self.assertEqual(strings['process_path_count'], 1)
        self.assertEqual(strings['orphan_rs_count'], 1)

    def test_byte_pins(self):
        pins = self.records['byte_pins']
        self.assertEqual(pins['convert_pid_load']['bytes'],
                         '8b7e08')
        self.assertEqual(pins['wait_pid_load']['bytes'],
                         '458b7e08')
        self.assertEqual(pins['fdhelper_pidfd_idtype']
                         ['bytes'], 'bf03000000')


if __name__ == '__main__':
    unittest.main()
