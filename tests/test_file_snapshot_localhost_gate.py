import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('file_snapshot_localhost_gate', ROOT / 'tools/file_snapshot_localhost_gate.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
PACKET = ROOT / 'research/work-items/RE-012-file-snapshot-localhost-gate-94/file-snapshot-localhost-gate.json'


class SnapshotGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = mod.build()
        cls.loaded = {}
        for release in ('94', '115'):
            data, _ = mod.checked(release)
            secs = mod.sections(data)
            cls.loaded[release] = (data, secs, mod.relative_relocs(data, secs), mod.fde_extents(data, secs))

    def test_regeneration_matches_packet(self):
        self.assertEqual(mod.render(self.result), PACKET.read_bytes())
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / PACKET.name).write_bytes(PACKET.read_bytes())
            subprocess.run([sys.executable, str(ROOT / 'tools/file_snapshot_localhost_gate.py'), '--out', d, '--check'], check=True)

    def test_same_rule_in_both_captures(self):
        for release in ('94', '115'):
            t = self.result['targets'][release]
            kinds = {a['meaning']: a for a in t['anchors']}
            self.assertEqual(t['request_table']['file_snapshot_index'], 0, release)
            self.assertEqual(t['state_table']['initial_index'], 0, release)
            self.assertTrue(kinds['V4 octets == 127.0.0.1 exactly']['bytes'].endswith('7f000001'), release)
            self.assertEqual(kinds['compare with the ::1 constant']['constant'], mod.IPV6_LOOPBACK.hex(), release)
            self.assertTrue(kinds['len < 0x65?']['bytes'].endswith('65'), release)
            self.assertEqual(kinds['log Location']['source'].rsplit(':', 2)[1:],
                             [str(v) for v in mod.ANCHORS[release]['log_location']], release)
            self.assertTrue(t['logger_crit_marker'], release)
        self.assertEqual(self.result['targets']['94']['anchors'][0]['bytes'], '0fb68693000000')
        self.assertEqual(self.result['targets']['115']['anchors'][0]['bytes'], '0fb686b3000000')

    def _mutated(self, release, va, patch):
        data, secs, relocs, fdes = self.loaded[release]
        broken = bytearray(data)
        off = next(s['offset'] + va - s['addr'] for s in secs.values()
                   if s['addr'] and s['addr'] <= va < s['addr'] + s['size'])
        broken[off:off + len(patch)] = patch
        return bytes(broken), secs, relocs, fdes

    def test_loopback_range_rejected(self):
        # 127.0.0.0/8 (is_loopback) would compare one byte; a dword against 127.0.0.2 must not pass.
        for release, va in (('94', 0x27ec599), ('115', 0x2976aaf)):
            data, secs, relocs, fdes = self._mutated(release, va + 6, b'\x7f\x00\x00\x02')
            with self.assertRaises(mod.EvidenceError):
                mod.analyze(data, secs, relocs, fdes, release)

    def test_ipv6_constant_rejected(self):
        for release, va in (('94', 0x205c00), ('115', 0x453120)):
            data, secs, relocs, fdes = self._mutated(release, va + 15, b'\x02')
            with self.assertRaises(mod.EvidenceError):
                mod.analyze(data, secs, relocs, fdes, release)

    def test_length_bound_rejected(self):
        for release, va in (('94', 0x27e92cf), ('115', 0x29739f3)):
            data, secs, relocs, fdes = self._mutated(release, va + 3, b'\x66')
            with self.assertRaises(mod.EvidenceError):
                mod.analyze(data, secs, relocs, fdes, release)

    def test_inner_future_vtable_layout(self):
        vt = self.result['targets']['94']['inner_future_vtable']
        self.assertEqual(vt, {'va': '0x56c3d98', 'slot0_drop_in_place': '0x2833ed0', 'slot1_size': '0x58',
                              'slot2_align': '0x8', 'slot3_poll': '0x27f45d0'})
        self.assertEqual(int(vt['slot1_size'], 16), 0x58)          # the same size the box helper allocates
        self.assertNotIn('inner_future_vtable', self.result['targets']['115'])   # not pinned for #115

    def test_inner_vtable_size_or_align_corruption_rejected(self):
        for va in (0x56c3da0, 0x56c3da8):
            data, secs, relocs, fdes = self._mutated('94', va, b'\x10')
            with self.assertRaises(mod.EvidenceError):
                mod.analyze(data, secs, relocs, fdes, '94')

    def test_missing_template_lea_rejected(self):
        for release, va in (('94', 0x27ec5d6), ('115', 0x2976afe)):
            data, secs, relocs, fdes = self._mutated(release, va + 3, b'\x00\x00\x00\x00')
            with self.assertRaises(mod.EvidenceError):
                mod.analyze(data, secs, relocs, fdes, release)


if __name__ == '__main__':
    unittest.main()
