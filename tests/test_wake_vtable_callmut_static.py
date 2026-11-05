import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from artifacts import ROOT  # noqa: E402
import wake_vtable_callmut_static as wv  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
MATERIALISED = (TARGET.exists() and not TARGET.read_bytes()[:64]
                .startswith(b'version https://git-lfs.github.com'))
WORK_ITEM = (ROOT / 'research' / 'work-items' /
             'RE-005-node115-signal-wake-vtable-callmut')
RECORDS = WORK_ITEM / 'records.json'
CENSUS = WORK_ITEM / 'census_decoded.json'


@unittest.skipUnless(MATERIALISED, 'node artifact not materialised')
class WakeVtableCallmutPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = wv.analyze(TARGET.read_bytes(), TARGET)

    def test_artifact_and_records_match(self):
        self.assertEqual(self.records['artifact']['size'], 105896032)
        self.assertEqual(
            self.records['artifact']['sha256'],
            'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
        want = json.loads(RECORDS.read_text())
        self.assertEqual(self.records, want)

    def test_body_pins(self):
        b = self.records['bodies']
        self.assertEqual(
            b['os_handler']['sha256'],
            '051d0781c488a0b64d1c7e6c84aa82da533ba070ccd7044381d179592af9f392')
        self.assertEqual(b['os_handler']['bytes'], 1343)
        self.assertEqual(
            b['entry_init']['sha256'],
            '057084c530f317622bad3c75887757a91d51d6ba4a371489a9aa93c27a581b19')
        self.assertEqual(
            b['registry_insert']['sha256'],
            '4a9c525c945cfb7bac0144b1f6f7a7542e42378e1dc6f915323dda6c92a22453')
        # Cross-checks against the #2974 packet's independently made pins.
        self.assertEqual(
            b['wake_call']['sha256'],
            'bcb6335b6c1dd826cd4f0a015c1c666eec2b950355b93d452ac871cc2eaf4bb2')
        self.assertEqual(
            b['wake_call_once']['sha256'],
            '4b20d2c88ea478a8b58a2e88649ff497e332e3416232fef73d3ba5aba39803c3')
        self.assertEqual(b['wake_call']['bytes'], 135)
        self.assertEqual(b['wake_call_once']['bytes'], 135)

    def test_vtable_slots(self):
        slots = self.records['wake_vtable']['slots']
        # +0x20 (call_mut) and +0x28 (call) name the same body.
        for off in ('+0x20', '+0x28'):
            self.assertEqual(slots[off]['rela']['type'], 8)
            self.assertEqual(slots[off]['rela']['addend'], '0x5cdcda0')
        self.assertEqual(slots['+0x18']['rela']['addend'], '0x5cdd040')
        self.assertEqual(slots['+0x8']['file_qword'], '0x10')
        self.assertEqual(slots['+0x10']['file_qword'], '0x8')
        # Boundary: the drop slot carries no static value.
        self.assertEqual(slots['+0x0']['file_qword'], '0x0')
        self.assertIsNone(slots['+0x0']['rela'])

    def test_vtable_materialisation(self):
        m = self.records['vtable_materialisation']
        self.assertEqual(m['lea_sites'], [
            '0x5cdd54f', '0x5cdd568', '0x5cdd5df', '0x5cdd695',
            '0x5cdd874'])
        self.assertTrue(m['all_in_registry_insert'])
        self.assertEqual(m['qword_occurrences_in_file'], 0)
        self.assertEqual(m['rela_addend_occurrences'], 0)

    def test_only_plus28_dispatch_in_cluster(self):
        inv = self.records['cluster_indirect_inventory']
        disp_sites = {}
        reg_sites = {}
        for name, v in inv.items():
            for d, sites in v['disp'].items():
                disp_sites.setdefault(d, []).extend(
                    (name, s) for s in sites)
            reg_sites[name] = v['reg']
        # The single vtable-slot dispatch in the whole cluster.
        self.assertEqual(disp_sites.get('0x28'),
                         [('os_handler', '0x5c67834')])
        # No call_once (+0x18) and no call_mut (+0x20) dispatch.
        self.assertNotIn('0x18', disp_sites)
        self.assertNotIn('0x20', disp_sites)
        # The raw-table helper's +0x30 hasher-field call is the
        # only other displacement-form site.
        self.assertEqual(disp_sites.get('0x30'),
                         [('raw_table_insert', '0x5cde904')])
        # Register-indirect sites: all classified non-vtable calls.
        self.assertEqual(reg_sites['os_handler'], [
            '0x5c677ab', '0x5c677c9', '0x5c677d0', '0x5c67a00'])
        self.assertEqual(reg_sites['entry_init'], ['0x5cdc510'])
        self.assertEqual(reg_sites['registry_insert'], ['0x5cdde42'])
        self.assertEqual(reg_sites['io_error_ctor'], ['0x5cdd2c1'])
        for name, sites in reg_sites.items():
            if name not in ('os_handler', 'entry_init',
                            'registry_insert', 'io_error_ctor'):
                self.assertEqual(sites, [], name)

    def test_got_resolutions(self):
        got = self.records['got']
        self.assertEqual(got['sched_yield_slot']['symbol'], 'sched_yield')
        self.assertEqual(got['sched_yield_slot']['rela_type'], 6)
        self.assertEqual(got['memmove_slot']['symbol'], 'memmove')
        self.assertEqual(got['memmove_slot']['rela_type'], 6)

    def test_registry_genuine_refs(self):
        g = self.records['registry_global']['genuine_refs']
        self.assertEqual(sorted(g), [
            '0x14353b0', '0x5c4e240', '0x5c67560', '0x5c67aa0',
            '0x5cdbf20'])
        struct = '0x64fff58'
        consumers = [b for b, tgts in g.items()
                     if any(t != '0x64fff50' for t in tgts)]
        self.assertEqual(sorted(consumers),
                         ['0x5c67560', '0x5c67aa0', '0x5cdbf20'])
        # The two neighbour bodies touch only the word below.
        self.assertEqual(g['0x5c4e240'], ['0x64fff50'])
        self.assertEqual(g['0x14353b0'], ['0x64fff50'])
        self.assertIn(struct, g['0x5c67560'])

    def test_byte_pins(self):
        p = self.records['byte_pins']
        self.assertEqual(p['handler_action_call']['bytes'], 'ff5028')
        self.assertEqual(p['handler_vtable_load']['bytes'],
                         '488b8402b8000000')
        self.assertEqual(p['handler_align_read']['bytes'], '488b5010')
        self.assertEqual(p['sched_yield_call']['bytes'], '41ffd6')
        self.assertEqual(p['memmove_call']['bytes'], 'ffd0')
        self.assertEqual(p['error_drop_call']['bytes'], 'ffd0')
        self.assertEqual(p['rawtab_fn_call']['bytes'], 'ff5030')

    def test_decoded_census_evidence(self):
        cen = json.loads(CENSUS.read_text())
        whole = cen['whole_text']
        self.assertEqual(whole['disp_0x20'], {'sites': 5184,
                                              'bodies': 2141})
        self.assertEqual(whole['disp_0x18'], {'sites': 4754,
                                              'bodies': 2773})
        self.assertEqual(whole['disp_0x28'], {'sites': 350,
                                              'bodies': 281})
        self.assertEqual(whole['reg_form'], {'sites': 72638,
                                             'bodies': 31689})
        # The raw pattern census in records is a superset.
        raw = self.records['raw_ff_census']
        self.assertGreaterEqual(raw['disp_0x20'],
                                whole['disp_0x20']['sites'])
        self.assertGreaterEqual(raw['disp_0x18'],
                                whole['disp_0x18']['sites'])
        self.assertGreaterEqual(raw['disp_0x28'],
                                whole['disp_0x28']['sites'])
        self.assertGreaterEqual(raw['reg_form'],
                                whole['reg_form']['sites'])


if __name__ == '__main__':
    unittest.main()
