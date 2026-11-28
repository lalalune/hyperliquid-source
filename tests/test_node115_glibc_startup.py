import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-node115-glibc-startup'
sys.path.insert(0, str(PACKET))
spec = importlib.util.spec_from_file_location('glibc_startup_probe', PACKET/'verify.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class StartupTest(unittest.TestCase):
    def setUp(self):
        self.raw = bytes.fromhex('488b3d00000000ff150000000090')
        self.linked = bytes.fromhex('488d3d88000000ff152a01000090')
        self.target = dict(entry_va=0x100, main_va=0x18f, libc_start_main_got=0x237)
        self.obj = dict(start_section_offset=0, relocations=[
            dict(section='.text', offset=3, kind='R_X86_64_REX_GOTPCRELX', symbol='main', undefined=True, addend=-4),
            dict(section='.text', offset=9, kind='R_X86_64_GOTPCRELX', symbol='__libc_start_main', undefined=True,
                 addend=-4)])

    def test_full_extent_and_no_unjustified_byte_changes(self):
        self.assertEqual(probe.compare(self.obj, self.raw, self.target, self.linked)['raw_equal_bytes'], 10)
        with self.assertRaisesRegex(ValueError, 'Remaining startup bytes differ'):
            probe.compare(self.obj, self.raw, self.target, self.linked[:-1] + b'\x00')
        self.assertEqual(probe.compare(self.obj, self.raw, self.target, self.linked[:-1])['outcome'],
                         'different extent')

    def test_wrong_symbol_type_or_addend(self):
        for key, value in [('symbol', 'other'), ('kind', 'R_X86_64_PC32'), ('addend', 0)]:
            with self.subTest(field=key):
                obj = copy.deepcopy(self.obj)
                obj['relocations'][0][key] = value
                with self.assertRaises(ValueError):
                    probe.compare(obj, self.raw, self.target, self.linked)

    def test_wrong_signed_manifest_rejected_before_package_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            (cache/'noble').mkdir()
            (cache/'noble/InRelease').write_bytes(b'altered')
            with self.assertRaisesRegex(ValueError, 'Checksum mismatch'):
                probe.ubuntu(cache, 'noble', cache/'keyring.gpg', False)

    def test_known_target_and_retained_candidates(self):
        target, body = probe.authenticated_target(probe.entry.TARGET)
        result = json.loads((PACKET/'result.json').read_text())
        self.assertEqual(target, result['target'])
        for name, candidate in result['distributions']['noble']['objects'].items():
            with self.subTest(name=name):
                self.assertEqual(candidate['comparison']['linked_sha256'], probe.sha(body))
                self.assertEqual(candidate['comparison']['raw_equal_bytes'], 29)
        for candidate in result['distributions']['focal']['objects'].values():
            self.assertEqual(candidate['comparison'], dict(outcome='different extent', candidate_bytes=47,
                                                           target_bytes=len(body)))
