import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from cfg_byte_consumers_static import (BODIES, EXCERPTS, PACKET,
                                       PRIOR_PINS, SHA, SIZE, TARGET,
                                       analyze, generate)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


class CfgByteConsumersStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA:
            raise unittest.SkipTest('target digest is not the '
                                    'pinned node115 distribution')
        cls.retained = payload(PACKET / 'records.json')
        cls.payload = analyze(cls.data)
        cls.regenerated = generate(TARGET, tempfile.mkdtemp())

    def mutated(self, va, delta, value):
        data = bytearray(self.data)
        data[self.offset_of(va) + delta] = value
        return bytes(data)

    def offset_of(self, va):
        for s in sections(self.data):
            if (s['type'] != 8 and s['address'] <= va
                    < s['address'] + s['size']):
                return s['offset'] + va - s['address']
        raise AssertionError('unmapped va')

    def test_native_regeneration_matches_retained_packet(self):
        self.assertEqual(self.regenerated, self.retained)
        self.assertEqual(self.payload, self.retained)
        regen_dir = Path(tempfile.mkdtemp())
        generate(TARGET, regen_dir)
        names = ['records.json', 'frames.txt'] + [
            '%s.objdump.txt' % n for n in EXCERPTS]
        for name in names:
            self.assertEqual((regen_dir / name).read_bytes(),
                             (PACKET / name).read_bytes(), name)

    def test_artifact_and_body_pins(self):
        self.assertEqual(self.payload['artifact']['sha256'], SHA)
        self.assertEqual(self.payload['artifact']['size'], SIZE)
        self.assertEqual(set(self.payload['bodies']), set(BODIES))
        for role, digest in PRIOR_PINS.items():
            self.assertEqual(self.payload['bodies'][role]['sha256'],
                             digest, role)

    def test_ctor_reads_exactly_three_cfg_fields(self):
        census = self.payload['ctor_cfg_census']
        self.assertEqual(
            [(r['va'], r['disp'], r['width'], r['kind'])
             for r in census],
            [('0x5ce0207', '0x8', 1, 'compare'),
             ('0x5ce0211', '0x0', 8, 'load'),
             ('0x5ce03f6', '0x9', 1, 'compare')])
        for r in census:
            d = int(r['disp'], 16)
            self.assertFalse(d < 0xc and d + r['width'] > 0xa,
                             'no ctor access covers +0xa/+0xb')

    def test_dcfg_assembly_and_reachable_values(self):
        asm = self.payload['dcfg_assembly']
        self.assertEqual(asm['site_1']['fields']['+0x0a'],
                         'immediate 1')
        self.assertEqual(asm['site_2']['fields']['+0x0a'],
                         '[bcfg+0xe4] ^ 1')
        self.assertEqual(asm['site_1']['fields']['+0x0b'],
                         '[bcfg+0xe7]')
        self.assertEqual(asm['site_2']['fields']['+0x0b'],
                         '[bcfg+0xe7]')
        vals = self.payload['reachable_values']
        self.assertEqual(vals['bcfg+0xe4'],
                         {'wrapper_a_site_1': 1, 'wrapper_a_site_2': 0,
                          'wrapper_b': 1})
        self.assertEqual(vals['dcfg+0x0a']['site_1'], 1)
        self.assertEqual(vals['dcfg+0x0a']['site_2'], 0)
        self.assertEqual(vals['dcfg+0x0b']['site_1'], 0)
        self.assertEqual(vals['dcfg+0x0b']['site_2'], 0)
        self.assertEqual(vals['dcfg+0x08'], 1)
        self.assertEqual(vals['dcfg+0x09'], 1)

    def test_bcfg_bytes_have_one_covering_access(self):
        census = self.payload['builder_bcfg_census']
        cov = [r['va'] for r in census
               if int(r['disp'], 16) < 0xc
               and int(r['disp'], 16) + r['width'] > 0x8]
        self.assertEqual(cov, ['0x5cf962d'])
        cov_a = [r['va'] for r in census
                 if int(r['disp'], 16) < 0xc
                 and int(r['disp'], 16) + r['width'] > 0xa]
        self.assertEqual(cov_a, ['0x5cf962d'])

    def test_cfg_ctor_never_writes_the_qword_slot(self):
        stores = self.payload['cfg_ctor_store_census']
        self.assertEqual(len(stores), 23)
        for r in stores:
            d = int(r['disp'], 16)
            self.assertFalse(d < 0x10 and d + r['width'] > 0x8,
                             'no cfg_ctor store covers +0x8')
        by_disp = {r['disp']: r for r in stores}
        self.assertEqual(by_disp['0x0']['text'], 'movq $0x0,(%rbx)')
        self.assertEqual(by_disp['0xe5']['text'],
                         'movl $0x0,0xe5(%rbx)')
        self.assertEqual(by_disp['0xe5']['width'], 4)

    def test_other_consumers_make_no_covering_access(self):
        for key in ('pair_helper_census', 'cfg_drop_census'):
            for r in self.payload[key]:
                d = int(r['disp'], 16)
                self.assertFalse(
                    d < 0xc and d + r['width'] > 0x8,
                    '%s has no access covering [bcfg+0x8]' % key)

    def test_wrapper_stores(self):
        a = self.payload['wrapper_census']['wrapper_a']
        stores = [(r['va'], r['offset']) for r in a
                  if r['kind'] == 'store']
        early = [s for s in stores if int(s[0], 16) < 0x15d70c2]
        self.assertEqual(early, [('0x15d700c', '0xe5'),
                                 ('0x15d70a8', '0xe5')])
        late8 = [r['va'] for r in a if r['kind'] == 'store'
                 and int(r['offset'], 16) < 0x10
                 and int(r['offset'], 16) + r['width'] > 0x8]
        self.assertTrue(late8)
        self.assertTrue(all(int(v, 16) > 0x15d7034 for v in late8))
        b = self.payload['wrapper_census']['wrapper_b']
        self.assertEqual([(r['va'], r['offset']) for r in b
                          if r['kind'] == 'store'],
                         [('0x2ae16d6', '0xe5')])
        for rows in (a, b):
            for r in rows:
                d = int(r['offset'], 16)
                self.assertFalse(d < 0xe8 and d + r['width'] > 0xe7,
                                 'wrappers never touch [bcfg+0xe7]')

    def test_ctor_cmp_disp_counterfactual(self):
        # cmpb $0x0,0x8(%rsi): disp8 sits at byte 2 of the
        # instruction at 0x5ce0207.
        data = self.mutated(0x5ce0207, 2, 0x0a)
        with self.assertRaisesRegex(
                ValueError, 'driver_ctor cfg-access census'):
            analyze(data)

    def test_site1_flag_immediate_counterfactual(self):
        # movb $0x1,0x7a(%rsp) at 0x5cf964e: immediate at byte 4.
        data = self.mutated(0x5cf964e, 4, 0x00)
        with self.assertRaisesRegex(
                ValueError, 'site 1 dcfg\\+0xa store is the '
                            'immediate 1'):
            analyze(data)

    def test_wrapper_overwrite_counterfactual(self):
        # movw $0x101,0x5f5(%rsp) at 0x15d700c: imm16 at byte 8.
        data = self.mutated(0x15d700c, 9, 0x00)
        with self.assertRaisesRegex(
                ValueError, 'wrapper A site 1 overwrites'):
            analyze(data)

    def test_cfg_ctor_zero_dword_counterfactual(self):
        # movl $0x0,0xe5(%rbx) at 0x5cf9521: disp32 at byte 2.
        data = self.mutated(0x5cf9521, 2, 0xe7)
        with self.assertRaisesRegex(
                ValueError, 'cfg_ctor zero dword at \\+0xe5'):
            analyze(data)


if __name__ == '__main__':
    unittest.main()
