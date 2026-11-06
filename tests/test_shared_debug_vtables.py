import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from shared_debug_vtables import (DISPLAY_BODY, EXPECTED_VTABLES,
                                  H13_DROP_SHA256, METHOD_STUB,
                                  PACKET, SHA256, SIZE, TAG_MASK,
                                  TARGET, analyze, hx, read)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class SharedDebugVtablesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA256:
            raise unittest.SkipTest('target digest is not the '
                                    'pinned node115 distribution')
        cls.retained = payload(PACKET / 'records.json')
        cls.payload = analyze(cls.data)

    def offset_of(self, va):
        for s in sections(self.data):
            if (s['type'] != 8 and s['address'] <= va
                    < s['address'] + s['size']):
                return s['offset'] + va - s['address']
        raise AssertionError('unmapped va')

    def mutated(self, va, delta, value):
        data = bytearray(self.data)
        data[self.offset_of(va) + delta] = value
        return bytes(data)

    def test_regeneration_matches_retained_packet(self):
        self.assertEqual(self.payload, self.retained)

    def test_manifest_matches_packet_files(self):
        lines = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split('  ', 1)
            actual = hashlib.sha256(
                (PACKET / name).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, name)

    def test_census_and_families(self):
        census = self.payload['census']
        self.assertEqual(census['vtables'], 32)
        self.assertEqual(census['distinct_drops'], 30)
        self.assertEqual(census['families'],
                         {'standalone': 18, 'extended': 13,
                          'tokio': 1})
        self.assertEqual(census['reference_sites'], 94)
        self.assertEqual(census['site_kinds'],
                         {'panic': 57, 'field_accessor': 6,
                          'enum_accessor': 10, 'store': 14,
                          'clone': 3, 'other': 4})
        bases = {v['base'] for v in self.payload['vtables']}
        self.assertEqual(bases, {hx(b) for b in EXPECTED_VTABLES})

    def test_every_vtable_is_the_same_value(self):
        for v in self.payload['vtables']:
            self.assertEqual((v['size'], v['align']), (8, 8),
                             v['base'])
            self.assertEqual(v['slots'][0]['target'], '0x5ca5610')
        for d in self.payload['drops']:
            t = d['template']
            self.assertTrue(t['tag_mask'], d['start'])
            self.assertTrue(t['mov_0x18'], d['start'])
            self.assertTrue(t['word_load'], d['start'])
            self.assertGreaterEqual(t['dealloc_refs'], 2, d['start'])

    def test_h13_cross_check(self):
        h13 = next(v for v in self.payload['vtables']
                   if v['is_h13_vtable'])
        self.assertEqual(h13['base'], '0x64005f0')
        self.assertEqual(h13['drop'], '0x15be1a0')
        drop = next(d for d in self.payload['drops']
                    if d['start'] == '0x15be1a0')
        self.assertEqual(drop['sha256'], H13_DROP_SHA256)
        sites = h13['references']['rip']
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]['kind'], 'panic')
        self.assertEqual(sites[0]['message'], 'failed to spawn thread')
        self.assertEqual(sites[0]['location']['line'], 131)

    def test_extended_family_shape(self):
        extended = [v for v in self.payload['vtables']
                    if v['family'] == 'extended']
        self.assertEqual(len(extended), 13)
        for v in extended:
            slots = {s['offset']: s['target'] for s in v['slots']}
            self.assertEqual(slots['0x20'], '0x5ca84b0', v['base'])
            self.assertEqual(slots['0x30'], '0x5ca8760', v['base'])
            self.assertEqual(slots['0x48'], '0x5ca8730', v['base'])
            sib = v['sibling_display_vtable']
            self.assertIsNotNone(sib)
            self.assertEqual(sib['base'],
                             hx(int(v['base'], 16) - 0x20))
            self.assertEqual(slots['0x28'], sib['base'])
            self.assertEqual(sib['drop'], v['drop'])
            self.assertEqual(sib['method'], '0x5ca84b0')

    def test_display_and_forwarders(self):
        disp = self.payload['display']
        self.assertEqual(disp['body'], hx(DISPLAY_BODY))
        self.assertEqual(
            read(self.data, int(disp['os_error_string_at'], 16), 10),
            b'(os error ')
        self.assertEqual(
            read(self.data, int(disp['strerror_string_at'], 16), 18),
            b'strerror_r failure')
        fwd = self.payload['forwarders']
        self.assertEqual(fwd['plus_0x30']['body'], '0x5ca8760')
        self.assertEqual(fwd['plus_0x48']['body'], '0x5ca8730')

    def test_panic_spot_checks(self):
        by_base = {v['base']: v for v in self.payload['vtables']}
        tokio = by_base['0x64c6458']['references']['rip']
        self.assertEqual(len(tokio), 7)
        for s in tokio:
            self.assertEqual(s['message'], 'failed to wake I/O driver')
            self.assertEqual(s['location']['line'], 272)
        libstd = by_base['0x64c3270']['references']['rip']
        self.assertEqual(len(libstd), 27)
        ren = by_base['0x63fe880']['references']['rip']
        self.assertEqual(ren[0]['message'], 'ren restart file error')
        self.assertEqual(ren[0]['location'],
                         {'file': 'base/src/ren.rs', 'line': 234})

    def test_mutation_of_stub_byte_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(METHOD_STUB, 0, 0x90))

    def test_mutation_of_size_cell_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x63FC2B8, 8, 9))

    def test_mutation_of_drop_tag_mask_is_rejected(self):
        drop = 0x150C590
        blob = read(self.data, drop, 209)
        at = TAG_MASK.search(blob).start()
        with self.assertRaises(ValueError):
            analyze(self.mutated(drop, at + 2, 0x04))

    def test_mutation_of_message_string_is_rejected(self):
        # 0x465bb3 is the message copy lea'd at site 0x150ba4e.
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x465BB3, 0, 0x58))

    def test_mutation_of_display_string_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze(self.mutated(0x43D45F, 0, 0x58))


if __name__ == '__main__':
    unittest.main()
