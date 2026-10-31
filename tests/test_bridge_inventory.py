import contextlib
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


class FunctionBoundsTests(unittest.TestCase):
    """Synthetic ELF whose first function is followed by alignment padding."""

    TEXT, HDR, FRAME = 0x1000, 0x2000, 0x3000

    def build(self, functions):
        # functions: list of (start, pc_range), one FDE record each.
        frame = bytearray()
        fde_vas = []
        for start, pc_range in functions:
            fde_va = self.FRAME + len(frame)
            body = struct.pack('<I', 0)                    # CIE pointer (unread)
            body += struct.pack('<i', start - (fde_va + 8))  # initial_location
            body += struct.pack('<I', pc_range)            # address_range
            frame += struct.pack('<I', len(body)) + body
            fde_vas.append(fde_va)
        header = bytes([1, 0x1B, 0x03, 0x3B])
        header += struct.pack('<i', self.FRAME - (self.HDR + 4))
        header += struct.pack('<I', len(functions))
        for (start, _range), fde_va in zip(functions, fde_vas):
            header += struct.pack('<i', start - self.HDR)
            header += struct.pack('<i', fde_va - self.HDR)
        names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0'
        shoff = 0x800
        data = bytearray(shoff + 5 * 64)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<Q', data, 40, shoff)
        struct.pack_into('<HHH', data, 58, 64, 5, 1)
        data[64:64 + len(names)] = names
        data[0x400:0x400 + len(header)] = header
        data[0x600:0x600 + len(frame)] = frame
        rows = [(0, 0, 0, 0, 0, 0),
                (names.index(b'.shstrtab'), 3, 0, 0, 64, len(names)),
                (names.index(b'.text'), 1, 6, self.TEXT, 0x200, 0x100),
                (names.index(b'.eh_frame_hdr'), 1, 2, self.HDR, 0x400, len(header)),
                (names.index(b'.eh_frame\0'), 1, 2, self.FRAME, 0x600, len(frame))]
        for index, row in enumerate(rows):
            struct.pack_into('<IIQQQQIIQQ', data, shoff + index * 64, *row, 0, 0, 1, 0)
        return bytes(data)

    def test_end_is_fde_extent_not_next_start(self):
        data = self.build([(0x1000, 0x10), (0x1020, 0x20)])
        # 0x1010..0x1020 is padding; the next start must not become the end.
        self.assertEqual(bi.function_bounds(data, 0x1008), (0x1000, 0x1010))

    def test_last_function_end_comes_from_fde(self):
        data = self.build([(0x1000, 0x10), (0x1020, 0x20)])
        self.assertEqual(bi.function_bounds(data, 0x1030), (0x1020, 0x1040))

    def test_precedes_first_start_still_rejected(self):
        data = self.build([(0x1000, 0x10)])
        with self.assertRaisesRegex(ValueError, 'precedes the first unwind start'):
            bi.function_bounds(data, 0x800)


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


if __name__ == '__main__':
    unittest.main()
