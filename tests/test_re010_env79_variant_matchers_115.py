import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import re010_env79_variant_matchers_115 as m

PACKET = (Path(__file__).resolve().parents[1] / 'research' / 'work-items'
          / 'RE-010-env79-variant-matchers-115')
GENERATED = ('summary.json', 'decoder-bindings.tsv', 'functions.tsv', 'names.tsv',
             'jump-tables.tsv', 'cases.tsv', 'unwind-cases.tsv', 'lsda-call-sites.tsv',
             'insns.tsv', 'mutants.tsv', 'matchers.rs.txt')
DECODER, FBYTES, FSTR, SLICE, COUNT = m.ENUMS[0][1:]
BODY_SHA256 = {
    FBYTES: 'c4b40bdd5ad739039734908641f1e422173ec8de0c58b54d51e3abb30220e48b',
    FSTR: '3ee611c5b44fff6a96dfa25abaa919faaa9d1b4611cb665e789b1c035fafc9c6',
    DECODER: 'e6ec82267e09b09d1eda67e1bd1e0fa2b61e1e91c8878277b5336b5d05c474ac',
}
NAMES = [n.encode() for n in (
    'Ec DummyTokyo DummyTokyo2 GaOnchain GbOnchain NodeTestnet NodeTestnet2 NodeTestnet3 '
    'NodeTestnet4 Ea Ea2 Ea3 EaMm EaTx HeavyTestnet HeavyMainnet Eb Ed Ee SoloTestnet '
    'SoloMainnet LockerTestnet LockerMainnet RpcTestnet RpcSandbox RpcMainnet RpcMainnet2 '
    'Sa Sb Sc Sd WebSandbox SoloSandbox NvTestnet NvTestnet2 NvMainnet NvMainnet2 NvMainnet3 '
    'JoinMainnet DummyNv FBinSpot FBinSpot2 FBinSpot3 FBinSpot4 FBinSpot5 FBinSpot6 FBinSpot7 '
    'FBinSpot8 FBinPerp FBinPerp2 FOkexSpot FOkexSpot2 FOkexPerp FHuobiSpot FHuobiSpot2 '
    'FHuobiSpot3 FHuobiSpot4 FHuobiPi FHuobiPerp FCobSpot FKraSpot FBybitSpot ScratchDummy '
    'ScratchCron OBinSpot FHlPerp GaHlPerp GaHlPerp2 GaHlPerp3 GbHlPerp GbHlPerp2 GbHlPerp3 '
    'GcHlPerp GcHlPerp2 GdHlPerp GdHlPerp2 GsHlPerp EaHlPerp EbHlPerp').split()]


class Env79VariantMatcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = m.BINARY.read_bytes()
        cls.img = m.Image(cls.data)
        from fde_extents import eh_frame_records
        _, cls.fdes = eh_frame_records(cls.data)

    def test_target_and_body_digests(self):
        self.assertEqual(len(self.data), 105_896_032)
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), m.SHA256)
        for start, digest in BODY_SHA256.items():
            rec = m.fde_record(self.fdes, start)
            body = self.img.read(start, rec['end'] - start)
            self.assertEqual(hashlib.sha256(body).hexdigest(), digest)

    def test_wrong_digest_is_refused_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad = root / 'bad.bin'
            bad.write_bytes(b'not the node')
            out = root / 'evidence'
            with patch.object(m, 'BINARY', bad):
                with self.assertRaises(ValueError):
                    m.generate(out)
            self.assertFalse(out.exists())

    def test_decode_lands_on_fde_end(self):
        for start, count in ((FBYTES, 1404), (FSTR, 578)):
            rec = m.fde_record(self.fdes, start)
            insns = m.coverage_sweep(self.img, start, rec['end'])
            self.assertEqual(len(insns), count)
            self.assertEqual(insns[-1].va + insns[-1].size, rec['end'])

    def test_decode_from_non_fde_start_fails(self):
        with self.assertRaises(m.Fault):
            m.fde_record(self.fdes, FSTR + 1)

    def test_decoder_bindings(self):
        for off in m.BYTES_CALL_OFFSETS:
            self.assertEqual(self.img.direct_call_target(DECODER + off), FBYTES)
        self.assertEqual(self.img.direct_call_target(DECODER + m.STR_CALL_OFFSET), FSTR)
        ins = m.decode(self.img, DECODER + m.DISPATCH_CALL_OFFSET)
        self.assertEqual(ins.op, 'callr')
        slot = DECODER + m.DISPATCH_CALL_OFFSET + ins.size + ins.a[4]
        self.assertEqual(slot, m.DISPATCH_SLOT)
        self.assertEqual(self.img.relative[slot], m.DISPATCH_TARGET)

    def test_variants_slice(self):
        self.assertEqual(len(NAMES), COUNT)
        self.assertEqual(self.img.variants(SLICE, COUNT), NAMES)

    def test_rule_cases(self):
        table = m.variant_table(NAMES, m.ALIAS_POSITIONS['ENV79'])
        self.assertEqual(len(table), 79)
        for pos, name in enumerate(NAMES):
            self.assertEqual(m.reconstructed_match(name, table), ('ok', pos))
        # Independent cross-check: the RE-015 static-config packet observed
        # discriminant 33 for NvTestnet in the config code of this enum.
        self.assertEqual(m.reconstructed_match(b'NvTestnet', table), ('ok', 33))
        self.assertEqual(m.reconstructed_match(b'nvtestnet', table),
                         ('unknown', b'nvtestnet', 0))
        self.assertEqual(m.reconstructed_match(b'', table), ('unknown', b'', 0))
        self.assertEqual(m.reconstructed_match(b'Ec\xff', table),
                         ('unknown', b'Ec\xef\xbf\xbd', 1))

    def _machine(self, kind, start):
        rec = m.fde_record(self.fdes, start)
        insns = m.coverage_sweep(self.img, start, rec['end'])
        cache = {i.va: i for i in insns}
        sites = self.img.call_sites(rec['lsda'], start) if rec['lsda'] is not None else []
        return m.Machine(self.img, kind, start, rec['end'], (SLICE, COUNT), cache, sites)

    def test_interpreter_matches_rule_on_sample(self):
        table = m.variant_table(NAMES, m.ALIAS_POSITIONS['ENV79'])
        cases = m.build_cases(NAMES)
        sample = cases[::7] + [(k, s) for k, s in cases if k == 'exact']
        for kind, start in (('bytes', FBYTES), ('str', FSTR)):
            machine = self._machine(kind, start)
            for _, s in sample:
                if kind == 'str':
                    try:
                        s.decode('utf-8')
                    except UnicodeDecodeError:
                        continue
                self.assertEqual(machine.run(s), m.reconstructed_match(s, table),
                                 f'{kind} {s!r}')

    def test_store_corruption_changes_the_variant(self):
        # visit_str leaf for `Sd`: movw $0x1e09,(%rax) at 0x14c1334; the
        # immediate's second byte is the variant (30). Flip its low bit.
        buf = bytearray(self.data)
        buf[self.img.off(0x14c1334 + 4)] ^= 0x01
        img = m.mutated_image(self.img, bytes(buf))
        rec = m.fde_record(self.fdes, FSTR)
        insns = m.coverage_sweep(img, FSTR, rec['end'])
        machine = m.Machine(img, 'str', FSTR, rec['end'], (SLICE, COUNT),
                            {i.va: i for i in insns}, [])
        self.assertEqual(machine.run(b'Sd'), ('ok', 31))

    def test_regeneration_matches_committed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'packet'
            with patch('sys.argv',
                       ['re010_env79_variant_matchers_115.py', '--out', str(out)]):
                self.assertEqual(m.main(), 0)
            for name in GENERATED:
                self.assertEqual((out / name).read_bytes(),
                                 (PACKET / name).read_bytes(),
                                 f'{name} differs from committed evidence')

    def test_manifest(self):
        manifest = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        self.assertTrue(manifest)
        for line in manifest:
            digest, name = line.split('  ', 1)
            payload = (PACKET / name).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest,
                             f'MANIFEST entry for {name} does not verify')


if __name__ == '__main__':
    unittest.main()
