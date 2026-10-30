"""Target-grounded static controls for RE-012; no captured program execution."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/hl-node-startup-inventory-94'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load('hl_node_startup_inventory', ROOT / 'tools/hl_node_startup_inventory.py')
verifier = load('hl_node_startup_verify', PACKET / 'verify.py')
EXPECTED_BOUND = {
    'chain', 'serve-evm-rpc', 'serve-info', 'write-trades', 'write-fills',
    'write-raw-book-diffs', 'write-order-statuses', 'write-misc-events',
    'write-hip3-oracle-updates', 'write-system-and-core-writer-actions',
}
EXPECTED_RANGES = [
    (0x225dd90, 0x225ddf8), (0x2271d00, 0x2272c74), (0x2272c80, 0x2275a07),
    (0x2275a10, 0x227a0db), (0x22ae8a0, 0x22b107c), (0x4546ac0, 0x4546b98),
    (0x4546ba0, 0x4546c51), (0x4578bd0, 0x4578e2a), (0x4579310, 0x457acef),
    (0x4583030, 0x4583f52), (0x4583f60, 0x4583fb6), (0x4584030, 0x4584136),
    (0x4584140, 0x4584172), (0x4584180, 0x45841f7), (0x4584200, 0x4584306),
]


class StartupInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing/wrong target is a failure, not a silently skipped packet test.
        cls.data = tool.TARGET.read_bytes()
        cls.r = tool.build(cls.data)
        cls.elf = tool.Elf(cls.data)
        cls.fdes, _ = tool.frames(cls.elf)
        cls.starts = [f['start'] for f in cls.fdes]

    def mutate(self, va, replacement):
        data = bytearray(self.data)
        off = self.elf.offset(va, len(replacement))
        data[off:off + len(replacement)] = replacement
        return bytes(data)

    def test_target_counts(self):
        self.assertEqual(self.r['binary_sha256'], tool.EXPECTED_SHA256)
        self.assertEqual(self.r['counts'], {
            'locations': 53, 'location_leas': 57, 'locations_without_lea': 0,
            'scoped_fdes': 15, 'decoded_fdes_total': 121299,
            'cli_candidates': 16, 'cli_bound': 10, 'cli_unresolved': 6,
        })

    def test_exact_scope_excludes_tcp_and_info(self):
        self.assertEqual({l['file'] for l in self.r['locations']}, {'node/src/hl_node.rs'})
        self.assertEqual(len({l['slot_va'] for l in self.r['locations']}), 53)
        self.assertEqual(len({r['site_va'] for l in self.r['locations'] for r in l['references']}), 57)

    def test_fde_extents(self):
        self.assertEqual([(f['start_va'], f['end_va']) for f in self.r['fde_ranges']], EXPECTED_RANGES)
        for f in self.r['fde_ranges']:
            start, length = struct.unpack('<iI', bytes.fromhex(f['fde_bytes'])[8:16])
            self.assertEqual(f['fde_va'] + 8 + start, f['start_va'])
            self.assertEqual(f['start_va'] + length, f['end_va'])

    def test_half_open_bounds_and_whole_instruction_membership(self):
        for start, end in EXPECTED_RANGES:
            self.assertEqual(tool.containing(self.fdes, self.starts, end - 1)['start'], start)
            after = tool.containing(self.fdes, self.starts, end)
            self.assertTrue(after is None or after['start'] != start)
            self.assertIsNone(tool.containing(self.fdes, self.starts, end - 1, 7))

    def test_location_layout_and_relocations(self):
        for loc in self.r['locations']:
            length, line, col = struct.unpack_from('<QII', bytes.fromhex(loc['bytes']), 8)
            self.assertEqual((length, line, col), (48, loc['line'], loc['column']))
            slot, info, target = struct.unpack('<QQq', bytes.fromhex(loc['relocation_bytes']))
            self.assertEqual((slot, info, target), (loc['slot_va'], 8, loc['path_va']))
            self.assertEqual(self.elf.read(target, length), tool.FIRST_PARTY + tool.SCOPE_PATH.encode())

    def test_cli_bound_and_unresolved(self):
        by = {c['text']: c for c in self.r['cli_literals']}
        self.assertEqual({name for name, c in by.items() if c['status'] == 'bound'}, EXPECTED_BOUND)
        for name in EXPECTED_BOUND:
            c = by[name]
            self.assertEqual(c['qualified_anchor_count'], 1)
            self.assertTrue(any(r['length_pair'] for a in c['anchors'] for r in a['references']))
        self.assertEqual(by['data-dir']['occurrences_va'], [])
        self.assertEqual(by['run-validator']['occurrences_va'], [])
        self.assertEqual(len(by['chain']['occurrences_va']), 73)
        self.assertEqual(by['chain']['anchors'][0]['anchor_va'], 0x6f6148)
        # A globally unique filename or service label is insufficient.
        for name in ('serve-eth-rpc', 'override_gossip_config.json'):
            self.assertEqual(len(by[name]['occurrences_va']), 1)
            self.assertEqual(by[name]['status'], 'unresolved')

    def test_side_effects_are_scoped_markers(self):
        markers = self.r['side_effect_markers']
        self.assertEqual(len(markers), 11)
        self.assertIn('write-trades', markers)
        self.assertIn('@@ archiving data to s3', markers)
        self.assertIn('timeout 3 nc -zv ', markers)
        self.assertNotIn(tool.DIAGNOSTICS[1][0], markers)
        archive = self.r['diagnostics'][0]['anchors'][0]
        self.assertEqual((archive['anchor_va'], archive['occurrence_va']), (0x1f4100, 0x1f410f))
        self.assertEqual(archive['references'][0]['site_va'], 0x2275be0)

    def test_call_edge_and_numeric_limits(self):
        edge = self.r['scoped_call']
        self.assertEqual((edge['site_va'], edge['from_va'], edge['to_va'], edge['bytes']),
                         (0x22aef61, 0x22ae8a0, 0x2271d00, 'e89a2dfcff'))
        self.assertEqual(self.r['packed_numeric_observation']['little_endian_u16_halves'], [4001, 4004])
        self.assertTrue(all(p['status'] == 'unresolved' for p in self.r['port_roles']))

    def test_retained_outputs_byte_identical(self):
        for name, content in tool.generated_files(self.r).items():
            self.assertEqual((PACKET / name).read_bytes(), content, name)
        self.assertEqual(hashlib.sha256(tool.render(self.r)).hexdigest(), verifier.OUTPUT_SHA256)

    def test_wrong_digest_rejected_before_analysis(self):
        for data in (b'', b'not an ELF', self.data[:-1], self.data[:-1] + bytes([self.data[-1] ^ 1])):
            with self.subTest(length=len(data)), self.assertRaisesRegex(tool.EvidenceError, 'SHA-256'):
                tool.build(data)

    def test_cli_bad_input_does_not_write_output(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            binary = base / 'wrong-node'
            binary.write_bytes(b'bad digest')
            out = base / 'out'
            out.mkdir()
            sentinel = out / 'startup-inventory.json'
            sentinel.write_bytes(b'preserve')
            p = subprocess.run([sys.executable, str(ROOT / 'tools/hl_node_startup_inventory.py'),
                                '--binary', str(binary), '--out', str(out)], capture_output=True)
            self.assertEqual(p.returncode, 2)
            self.assertIn(b'SHA-256', p.stderr)
            self.assertEqual(sentinel.read_bytes(), b'preserve')
            self.assertFalse((out / 'byte-excerpts.txt').exists())

    def test_elf_and_mapping_bounds(self):
        for bad in (b'', b'\0' * 64, self.data[:80]):
            with self.assertRaises(ValueError):
                tool.Elf(bad)
        base, _, size, _ = self.elf.loads[0]
        self.assertEqual(len(self.elf.read(base + size - 1, 1)), 1)
        with self.assertRaises(ValueError):
            self.elf.read(base + size - 1, 2)

    def test_location_length_corruption_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'invalid scoped Location'):
            tool._inventory(self.mutate(0x569e870 + 8, b'\0' * 8))

    def test_location_zero_line_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'invalid scoped Location'):
            tool._inventory(self.mutate(0x569e870 + 16, b'\0' * 4))

    def test_location_line_change_visible(self):
        r = tool._inventory(self.mutate(0x569e870 + 16, struct.pack('<I', 187)))
        self.assertEqual(r['locations'][0]['line'], 187)
        self.assertNotEqual(tool.render(r), tool.render(self.r))

    def test_location_lea_retarget_visible(self):
        site = 0x22b06ff
        disp = struct.unpack('<i', self.elf.read(site + 3, 4))[0]
        r = tool._inventory(self.mutate(site + 3, struct.pack('<i', disp + 1)))
        self.assertEqual(r['counts']['location_leas'], 56)
        self.assertEqual(r['counts']['locations_without_lea'], 1)

    def test_zero_fde_range_rejected(self):
        f = self.r['fde_ranges'][0]
        with self.assertRaisesRegex(tool.EvidenceError, 'empty'):
            tool._inventory(self.mutate(f['fde_va'] + 12, b'\0' * 4))

    def test_cie_encoding_corruption_rejected(self):
        f = self.r['fde_ranges'][0]
        # CIE version byte, independently specified by DWARF record layout.
        with self.assertRaisesRegex(ValueError, 'CIE version'):
            tool._inventory(self.mutate(f['cie_va'] + 8, b'\xff'))

    def test_cli_literal_corruption_unbinds(self):
        r = tool._inventory(self.mutate(0x6f6148, b'C'))
        chain = next(c for c in r['cli_literals'] if c['text'] == 'chain')
        self.assertEqual(chain['status'], 'unresolved')
        self.assertEqual(r['counts']['cli_bound'], 9)

    def test_cli_length_corruption_unbinds(self):
        r = tool._inventory(self.mutate(0x4578be7 + 8, struct.pack('<I', 4)))
        chain = next(c for c in r['cli_literals'] if c['text'] == 'chain')
        self.assertEqual(chain['status'], 'unresolved')

    def test_substring_and_missing_literal_do_not_bind(self):
        leas = tool.lea_targets(self.elf)
        owner = lambda site, size=1: tool.containing(self.fdes, self.starts, site, size)
        scoped = {f['start_va'] for f in self.r['fde_ranges']}
        for text in ('hain', 'NoSuchStartupFlagXYZ', 'delegate'):
            c = tool.bind_literal(self.elf, text, 'cli', leas, owner, scoped)
            self.assertEqual(c['status'], 'unresolved')

    def test_template_boundary_corruption_unbinds(self):
        r = tool._inventory(self.mutate(0x1f40ff, b'X'))
        self.assertEqual(r['diagnostics'][0]['status'], 'unresolved')

    def test_call_opcode_corruption_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'call opcode'):
            tool._inventory(self.mutate(tool.CALL_SITE, b'\x90' * 5))

    def test_call_target_corruption_rejected(self):
        displacement = tool.CALL_FROM - tool.CALL_SITE - 5
        with self.assertRaisesRegex(tool.EvidenceError, 'direct call changed'):
            tool._inventory(self.mutate(tool.CALL_SITE + 1, struct.pack('<i', displacement)))

    def test_numeric_immediate_corruption_rejected(self):
        with self.assertRaisesRegex(tool.EvidenceError, 'numeric observation changed'):
            tool._inventory(self.mutate(tool.PORT_SITE + 6, b'\xa2'))

    def test_hashseed_and_directory_regeneration(self):
        for seed in ('0', '97'):
            with self.subTest(seed=seed), tempfile.TemporaryDirectory() as d:
                subprocess.run([sys.executable, '-B', str(ROOT / 'tools/hl_node_startup_inventory.py'),
                                '--out', d], env=dict(os.environ, PYTHONHASHSEED=seed),
                               capture_output=True, check=True)
                for name in tool.GENERATED:
                    self.assertEqual((Path(d) / name).read_bytes(), (PACKET / name).read_bytes())

    def test_objdump_all_reported_instruction_boundaries(self):
        self.assertIsNotNone(shutil.which('objdump'), 'native instruction cross-check required')
        decoded = {}
        for start, end in EXPECTED_RANGES:
            p = subprocess.run(['objdump', '-d', '--wide', f'--start-address={start:#x}',
                                f'--stop-address={end:#x}', str(tool.TARGET)],
                               capture_output=True, text=True, check=True, env=dict(os.environ, LC_ALL='C'))
            for line in p.stdout.splitlines():
                m = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)', line)
                if m:
                    decoded[int(m[1], 16)] = (bytes.fromhex(m[2]), m[3])
        refs = [(r, loc['slot_va']) for loc in self.r['locations'] for r in loc['references']]
        refs += [(r, a['anchor_va']) for c in self.r['cli_literals'] + self.r['diagnostics']
                 for a in c['anchors'] for r in a['references']]
        for r, target in refs:
            raw, asm = decoded[r['site_va']]
            self.assertEqual(raw.hex(), r['bytes'])
            self.assertRegex(asm, rf'^lea\s+.*\(%rip\).*# {target:x}\b')
            if r.get('length_pair'):
                self.assertEqual((raw + decoded[r['site_va'] + 7][0]).hex(), r['pair_bytes'])
                self.assertTrue(decoded[r['site_va'] + 7][1].startswith('mov'))
        raw, asm = decoded[tool.CALL_SITE]
        self.assertEqual(raw.hex(), 'e89a2dfcff')
        self.assertRegex(asm, r'^call\s+2271d00\b')
        raw, asm = decoded[tool.PORT_SITE]
        self.assertEqual(raw.hex(), 'c7834c070000a10fa40f')
        self.assertIn('$0xfa40fa1', asm)

    def test_readelf_scoped_extents(self):
        self.assertIsNotNone(shutil.which('readelf'), 'native FDE cross-check required')
        wanted = dict(EXPECTED_RANGES)
        found = {}
        with subprocess.Popen(['readelf', '-wF', str(tool.TARGET)], stdout=subprocess.PIPE,
                              text=True, env=dict(os.environ, LC_ALL='C')) as p:
            for line in p.stdout:
                m = re.search(r'FDE cie=.* pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
                if m and int(m[1], 16) in wanted:
                    found[int(m[1], 16)] = int(m[2], 16)
            self.assertEqual(p.wait(), 0)
        self.assertEqual(found, wanted)

    def test_manifest_requires_result_and_rejects_bad_entries(self):
        text = (PACKET / 'MANIFEST.sha256').read_text()
        self.assertIn('RESULT.md', verifier.manifest_entries(text))
        variants = [
            '\n'.join(line for line in text.splitlines() if not line.endswith('  RESULT.md')),
            text + text.splitlines()[0] + '\n',
            text + '0' * 64 + '  ../../../arbitrary-file\n',
            text.replace('  RESULT.md', '  ./RESULT.md'),
            text.replace('  RESULT.md', ' RESULT.md'),
        ]
        for changed in variants:
            with self.subTest(text=changed[-100:]), self.assertRaises(ValueError):
                verifier.manifest_entries(changed)

    def test_manifest_detects_result_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            here = Path(d) / 'research/work-items/packet'
            here.mkdir(parents=True)
            for name in verifier.MANIFEST | {'MANIFEST.sha256'}:
                dest = here / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((PACKET / name).read_bytes())
            verifier.verify_manifest(here)
            (here / 'RESULT.md').write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'RESULT.md'):
                verifier.verify_manifest(here)

    def test_verifier_under_optimized_python(self):
        p = subprocess.run([sys.executable, '-O', '-B', str(PACKET / 'verify.py')], capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertIn(b'PASS:', p.stdout)


if __name__ == '__main__':
    unittest.main()
