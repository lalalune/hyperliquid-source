import hashlib
import importlib.util
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import rmp_signable_path as packet

DIR = ROOT / 'research/work-items/action-wire-rmp-signable-94'
DATA = packet.TARGET.read_bytes()


class RmpSignableEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = packet.Elf(DATA)
        cls.result = packet.build(DATA)

    def changed(self, va, replacement):
        changed = bytearray(DATA)
        offset = self.elf.off(va)
        changed[offset:offset + len(replacement)] = replacement
        return bytes(changed)

    def test_census_and_anchors(self):
        r = self.result
        self.assertEqual(r['fde_count'], 121299)
        self.assertEqual(r['first_party_location_count'], 1186)
        self.assertEqual(len(r['scoped_locations']), 3)
        self.assertEqual(r['connectionId_raw_file_occurrences'], 0)
        self.assertEqual(self.elf.read(0x1f3237, 58),
                         b'/home/ubuntu/hl/code_Mainnet/l1/src/action/rmp_signable.rs')
        self.assertEqual(self.elf.read(0x58c079, 43),
                         b'called `Result::unwrap()` on an `Err` value')
        for loc in r['scoped_locations']:
            self.assertEqual((loc['line'], loc['column']), (14, 55))
            self.assertEqual(loc['path_pointer'], '0x1f3237')

    def test_fde_end_exclusive(self):
        starts, ends = packet.fde_index(self.elf)
        for _, start, end in packet.EXPECTED_LOCATIONS.values():
            self.assertEqual(packet.containing(starts, ends, start), (start, end))
            self.assertEqual(packet.containing(starts, ends, end - 1), (start, end))
            self.assertNotEqual(packet.containing(starts, ends, end), (start, end))

    def test_byte_identical_regeneration(self):
        self.assertEqual(packet.render(self.result), (DIR / 'rmp-signable-path.json').read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            for seed in ('0', '99'):
                p = subprocess.run([sys.executable, str(ROOT / 'tools/rmp_signable_path.py'),
                                    '--out', tmp], env=dict(os.environ, PYTHONHASHSEED=seed),
                                   capture_output=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual((Path(tmp) / 'rmp-signable-path.json').read_bytes(), packet.render(self.result))

    def test_digest_and_no_output_on_wrong_target(self):
        changed = self.changed(0x333f2de, b'\x90')
        with self.assertRaises(packet.EvidenceError):
            packet.build(changed)
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'wrong'; binary.write_bytes(changed)
            out = Path(tmp) / 'out'
            p = subprocess.run([sys.executable, str(ROOT / 'tools/rmp_signable_path.py'),
                                '--binary', str(binary), '--out', str(out)], capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertFalse(out.exists())

    def test_corruption_of_pinned_evidence_is_detected_even_with_new_hash(self):
        for va, replacement in ((0x333f2de, b'\x90'), (0x333f2f8, b'\x90'),
                                (0x56e9c08 + 16, struct.pack('<I', 15)),
                                (0x333f5fd + 3, b'\0\0\0\0'),
                                (0x58c079, b'X')):
            with self.subTest(va=hex(va)):
                changed = self.changed(va, replacement)
                with self.assertRaises(packet.EvidenceError):
                    packet.build(changed, expected_sha256=hashlib.sha256(changed).hexdigest())

    def test_manifest_rejects_corrupt_and_missing_files(self):
        spec = importlib.util.spec_from_file_location('packet_verify', DIR / 'verify.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        with tempfile.TemporaryDirectory() as tmp:
            clone = Path(tmp)
            for file in DIR.iterdir():
                if file.is_file(): shutil.copyfile(file, clone / file.name)
            verifier.verify(clone)
            (clone / 'objdump-excerpts.txt').write_text('tampered\n')
            with self.assertRaises(ValueError): verifier.verify(clone)
            (clone / 'MANIFEST.sha256').write_text('')
            with self.assertRaises(ValueError): verifier.verify(clone)

    @unittest.skipUnless(shutil.which('objdump'), 'objdump unavailable')
    def test_independent_disassembly_instruction_boundaries(self):
        # Start at the FDE boundary, not at the byte pattern being checked.
        p = subprocess.run(['objdump', '-d', '--start-address=0x333f240',
                            '--stop-address=0x333f686', str(packet.TARGET)],
                           check=True, capture_output=True, text=True)
        lines = {int(m.group(1), 16): m.group(2) for m in re.finditer(
            r'^[ \t]*([0-9a-f]+):[ \t]+(?:[0-9a-f]{2}[ \t]+)+[ \t]*(.*)$', p.stdout, re.M)}
        for name, (site, _) in packet.SITES.items():
            self.assertIn(site, lines, name)
        for site, mnemonic in ((0x333f2de, 'bswap'), (0x333f30d, 'movb'),
                               (0x333f36a, 'movb'), (0x333f4d2, 'cmp'),
                               (0x333f5fd, 'lea')):
            self.assertTrue(lines[site].startswith(mnemonic), lines[site])

    @unittest.skipUnless(shutil.which('readelf'), 'readelf unavailable')
    def test_location_and_helper_relocations_against_readelf(self):
        p = subprocess.run(['readelf', '-rW', str(packet.TARGET)],
                           check=True, capture_output=True, text=True)
        relocations = {int(m.group(1), 16): int(m.group(2), 16)
                       for m in re.finditer(
                           r'^([0-9a-f]{16})[ \t]+[0-9a-f]+[ \t]+R_X86_64_RELATIVE[ \t]+([0-9a-f]+)',
                           p.stdout, re.M)}
        for slot in packet.EXPECTED_LOCATIONS:
            self.assertEqual(relocations[slot], 0x1f3237)
        self.assertEqual(relocations[0x576e1d8], 0x4f59a10)
        self.assertEqual(relocations[0x576e1e0], 0x4f59e40)

    @unittest.skipUnless(shutil.which('objdump'), 'objdump unavailable')
    def test_location_xrefs_disassembled_from_fde_start(self):
        for slot, (site, start, end) in packet.EXPECTED_LOCATIONS.items():
            p = subprocess.run(['objdump', '-d', f'--start-address={start:#x}',
                                f'--stop-address={end:#x}', str(packet.TARGET)],
                               check=True, capture_output=True, text=True)
            lines = p.stdout.splitlines()
            found = [line for line in lines if re.match(rf'^[ \t]*{site:x}:[ \t]', line)]
            self.assertEqual(len(found), 1)
            self.assertRegex(found[0], rf'\blea\s+.*# {slot:x}\b')


if __name__ == '__main__':
    unittest.main()
