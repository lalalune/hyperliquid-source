import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import bridge_inventory as bi

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'

MAINNET_SITE = bytes.fromhex('4180ff03b8b1a40000b9ee6e0600480f44c8')
INTERLEAVED_SITE = bytes.fromhex('4080fd03c60061b9b1a40000baee6e0600480f44d1')


def mapping_for(payload, va=0x1000, size=0x400):
    buffer = bytearray(size)
    buffer[:len(payload)] = payload
    return bytes(buffer), bi.Mapping([(0, va, size, 5)])


class ChainSiteTests(unittest.TestCase):
    def test_decodes_seeded_shape(self):
        data, mapping = mapping_for(MAINNET_SITE)
        site = bi.decode_chain_site(data, mapping, 0x1000)
        self.assertEqual(site['selected_when_equal'], 42161)
        self.assertEqual(site['selected_otherwise'], 421614)
        self.assertEqual(site['destination_register'], 'rcx')
        self.assertEqual(site['compare_register'], 'r15b')
        self.assertEqual(site['bytes'], MAINNET_SITE.hex())

    def test_skips_interleaved_tag_store(self):
        data, mapping = mapping_for(INTERLEAVED_SITE)
        site = bi.decode_chain_site(data, mapping, 0x1000)
        self.assertEqual(site['destination_register'], 'rdx')
        self.assertEqual(site['conditional'], 'cmove')

    def test_rejects_swapped_immediates(self):
        swapped = bytearray(MAINNET_SITE)
        swapped[5:9], swapped[10:14] = MAINNET_SITE[10:14], MAINNET_SITE[5:9]
        data, mapping = mapping_for(bytes(swapped))
        with self.assertRaisesRegex(ValueError, 'expected mainnet'):
            bi.decode_chain_site(data, mapping, 0x1000)

    def test_rejects_non_register_cmove(self):
        broken = bytearray(MAINNET_SITE)
        broken[-1] = 0x08  # mod=00
        data, mapping = mapping_for(bytes(broken))
        with self.assertRaisesRegex(ValueError, 'non-register'):
            bi.decode_chain_site(data, mapping, 0x1000)

    def test_rejects_missing_compare(self):
        data, mapping = mapping_for(b'\x90' * 32)
        with self.assertRaisesRegex(ValueError, 'missing REX cmpb'):
            bi.decode_chain_site(data, mapping, 0x1000)


class XrefTests(unittest.TestCase):
    def test_resolves_movups_disp32(self):
        # movups 0x1000(%rip) at 0x2000 targeting 0x2013, then filler.
        insn = bytes.fromhex('0f1005') + struct.pack('<i', 0x2013 - 0x2027)
        data, mapping = mapping_for(b'\x90' * 0x20 + insn, va=0x2000, size=0x100)
        refs = bi.rip_relative_xrefs(data, mapping, 0x2013)
        self.assertEqual([r['instruction_va'] for r in refs], [0x2020])
        self.assertEqual(refs[0]['insn_bytes'], insn.hex())

    def test_ignores_absolute_and_wrong_target(self):
        data, mapping = mapping_for(b'\x0f\x10\x04\x25\x13\x20\x00\x00' * 4, va=0x2000)
        self.assertEqual(bi.rip_relative_xrefs(data, mapping, 0x2013), [])


class WindowScanTests(unittest.TestCase):
    def test_call_ending_at_window_end_is_found(self):
        call = b'\xe8' + struct.pack('<i', 0x100)  # call at 0x1003 -> 0x1108
        data, mapping = mapping_for(b'\x90' * 3 + call)
        self.assertEqual(bi.direct_calls(data, mapping, 0x1000, 8), [0x1108])
        self.assertEqual(bi.direct_calls(data, mapping, 0x1000, 7), [])

    def test_literal_load_ending_at_window_end_is_found(self):
        load = bytes.fromhex('0f1005') + struct.pack('<i', 0x20)  # movups at 0x1002
        data, mapping = mapping_for(b'\x90' * 2 + load)
        self.assertEqual(bi.literal_loads(data, mapping, 0x1000, 9),
                         [{'load_va': 0x1002, 'literal_va': 0x1029}])
        self.assertEqual(bi.literal_loads(data, mapping, 0x1000, 8), [])


class TableTests(unittest.TestCase):
    def test_rejects_arm_outside_function(self):
        table = struct.pack('<8i', *([0x7FFF] * 8))
        data, mapping = mapping_for(table, va=0x1000, size=0x100)
        with mock.patch.object(bi, 'STRUCT_HASH_TABLE', 0x1000), \
                mock.patch.object(bi, 'STRUCT_HASH_START', 0x1000):
            with self.assertRaisesRegex(ValueError, 'outside struct_hash'):
                bi.decode_struct_hash_table(data, mapping)

    def test_decodes_relative_entries(self):
        table = struct.pack('<8i', *([0x20] * 8))
        data, mapping = mapping_for(table, va=0x1000, size=0x100)
        with mock.patch.object(bi, 'STRUCT_HASH_TABLE', 0x1000), \
                mock.patch.object(bi, 'STRUCT_HASH_START', 0x1000):
            arms = bi.decode_struct_hash_table(data, mapping)
        self.assertEqual([a['target_va'] for a in arms], [0x1020] * 8)
        self.assertEqual([a['discriminant'] for a in arms], list(range(8)))


class ArtifactTests(unittest.TestCase):
    def test_rejects_corrupted_digest(self):
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b'\x7fELF')
            handle.flush()
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                bi.load_artifact(Path(handle.name), 94)

    def test_missing_literal_is_detected(self):
        self.assertEqual(bi.find_all(b'no literal here', b'requestWithdrawal'), [])

    @unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
    def test_end_to_end_report_is_pinned(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bi.main(['--release', '94'])
        report = json.loads(out.getvalue())
        self.assertEqual(report['artifact_sha256'], bi.TARGET_SHA256[94])
        self.assertEqual(report['literal']['va'], bi.SEED_LITERAL_OFFSET)
        self.assertEqual(len(report['chain_id_sites']), 3)
        seeded = bi.Mapping(bi.load_segments(ARTIFACT.read_bytes())).offset_to_va(bi.SEED_CHAIN_OFFSET)
        self.assertTrue(any(s['site_va'] <= seeded < s['site_va'] + s['length']
                            for s in report['chain_id_sites']))
        layout = report['struct_hash']['withdrawal_arm_layout']['field_source_offsets']
        self.assertEqual(layout['account']['offset'], 1)
        self.assertEqual(layout['destination']['offset'], 0x15)
        self.assertEqual(report['struct_hash']['withdrawal_encoder']['tags'], [6, 0, 0, 4, 4])
        arms = {a['discriminant']: a for a in report['struct_hash']['arms']}
        # Reserved (6) ends at its jmp at 0x358e7af; 0x3c97be0 belongs to arm 7's continuation.
        self.assertEqual((arms[6]['span'], arms[6]['direct_calls'], arms[6]['continuations']),
                         (0x23A, [0x3C9F240], []))
        self.assertEqual(arms[7]['direct_calls'], [0x3C97BE0])
        self.assertEqual(arms[7]['continuations'],
                         [{'branch_va': 0x358E2B6, 'start_va': 0x358E7B4, 'end_va': 0x358E85B}])
        self.assertTrue(all(arms[i]['continuations'] == [] for i in arms if i != 7))

    @unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
    def test_arm_extent_pins_fail_closed(self):
        data = ARTIFACT.read_bytes()
        mapping = bi.Mapping(bi.load_segments(data))
        arms = bi.decode_struct_hash_table(data, mapping)
        for patch, message in (
                (('LAST_ARM_JMP', 0x358E7AE), 'last arm does not end with jmp'),
                (('ARM_CONTINUATIONS', {7: [(0x358E2B6, 0x358E7B5, 0x358E85B)]}), 'does not reach'),
                (('ARM_CONTINUATIONS', {7: [(0x358E2B7, 0x358E7B4, 0x358E85B)]}), 'expected jcc'),
                (('ARM_CONTINUATIONS', {6: [(0x358E2B6, 0x358E7B4, 0x358E85B)]}), 'expected jcc'),
                (('ARM_CONTINUATIONS', {7: [(0x358E2B6, 0x358E7B4, 0x358E85C)]}), 'does not end with a call')):
            with self.subTest(patch=patch), mock.patch.object(bi, *patch):
                with self.assertRaisesRegex(ValueError, message):
                    bi.arm_windows(data, mapping, arms)

    @unittest.skipUnless(ARTIFACT.exists(), 'captured node #94 not present')
    def test_packet_regenerates_and_manifest_matches(self):
        packet = ROOT / 'research/work-items/bridge'
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bi.main(['--release', '94', '--out', tmp]), 0)
            for path in Path(tmp).iterdir():
                self.assertEqual(path.read_bytes(), (packet / 'evidence' / path.name).read_bytes(), path.name)
        # Packet files only; the manifest also pins ../../../tools and tests
        # for `shasum -c`, which edits to those files must refresh.
        for line in (packet / 'evidence/MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ', 1)
            if not name.startswith('../'):
                self.assertEqual(hashlib.sha256((packet / name).read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main()
