import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import generate, owner, validate_progress
from elf_index import entry_file_offset, sections, target_for, unwind_index


def fixture():
    data = bytearray(832)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 512)
    struct.pack_into('<HHH', data, 58, 64, 5, 1)
    names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0'
    data[64:64+len(names)] = names
    entries = [(0,0,0,0,0,0), (1,3,0,0,64,len(names)), (11,1,6,0x100,256,32),
               (17,1,2,0x200,320,20), (31,1,2,0x300,384,16)]
    # Use the actual string offsets so fixtures remain readable.
    entries[2] = (names.index(b'.text'),1,6,0x100,256,32)
    entries[3] = (names.index(b'.eh_frame_hdr'),1,2,0x200,320,20)
    entries[4] = (names.index(b'.eh_frame\0'),1,2,0x300,384,16)
    for i, e in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, 512+i*64, *e, 0,0,1,0)
    data[320:324] = bytes([1,0x1b,3,0x3b])
    struct.pack_into('<Iii', data, 328, 1, -0x100, 0x100)
    return data


class UnwindTests(unittest.TestCase):
    def test_entry_uses_source_offset_not_linked_or_rebased_address(self):
        data = fixture()
        struct.pack_into('<Q', data, 24, 0x108)
        self.assertEqual(entry_file_offset(data), 264)


    def test_data_relative_negative_start(self):
        secs, rows = unwind_index(fixture())
        self.assertEqual(rows, [{'index':0, 'start':0x100, 'fde':0x300, 'section':'.text', 'next_index_upper_bound':0x120}])

    def test_rejects_truncated_table(self):
        data = fixture()
        struct.pack_into('<I', data, 328, 100)
        with self.assertRaises(ValueError): unwind_index(data)

    def test_rejects_unknown_encoding(self):
        data = fixture(); data[323] = 0
        with self.assertRaises(ValueError): unwind_index(data)

    def test_rejects_non_executable_start(self):
        data = fixture(); struct.pack_into('<i', data, 332, 0x100)
        with self.assertRaises(ValueError): unwind_index(data)

    def test_rejects_truncated_sections(self):
        with self.assertRaises(ValueError): sections(fixture()[:600])


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.parts = json.loads((self.root / 'research/components.json').read_text())['components']
        self.progress = json.loads((self.root / 'research/progress.json').read_text())

    def test_specific_handler_before_exchange_fallback(self):
        self.assertEqual(owner('l1/exchange/handlers/14_order.rs', self.parts), 'action-dispatch')
        self.assertEqual(owner('l1/exchange/impl_trading.rs', self.parts), 'exchange')
        self.assertEqual(owner('l1/clearinghouse/oracle/reference_oracle.rs', self.parts), 'risk')

    def test_unknown_tree_rejected(self):
        with self.assertRaises(ValueError): owner('unrecognized/private.rs', self.parts)

    def test_complete_gate_without_evidence_rejected(self):
        d = copy.deepcopy(self.progress)
        d['components']['orderbook']['gates']['built'] = True
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_fabricated_denominator_rejected(self):
        d = copy.deepcopy(self.progress)
        row = d['components']['orderbook']
        row['raw_equal_bodies'] = 2; row['total_function_windows'] = 1
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_missing_component_rejected(self):
        d = copy.deepcopy(self.progress); del d['components']['visor']
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    @staticmethod
    def _elf(text_addr=0x400000):
        names = b'\0.text\0.shstrtab\0'
        shstr_off = 64 + 4 * 64
        data = bytearray(0x3000)
        data[0:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
        struct.pack_into('<HHIQQQIHHHHHH', data, 16, 2, 0x3E, 1, 0, 0, 64, 0, 64, 0, 0, 64, 4, 3)
        def sh(idx, name, typ, flags, addr, off, size):
            struct.pack_into('<IIQQQQIIQQ', data, 64 + idx * 64, name, typ, flags, addr, off, size, 0, 0, 1, 0)
        sh(1, 1, 1, 0x6, text_addr, 0x1000, 0x2000)
        sh(3, 7, 3, 0, 0, shstr_off, len(names))
        data[shstr_off:shstr_off + len(names)] = names
        return bytes(data)

    def _catalogue_root(self, tmp, elf):
        root = Path(tmp)
        for rel in ['research/components.json', 'research/progress.json',
                    'research/imported/hl-node-94.inventory.json',
                    'research/imported/hl-node-115.inventory.json',
                    'research/imported/hl-visor.inventory.json',
                    'research/imported/can1357-literal-classes.json']:
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes((self.root / rel).read_bytes())
        inv = json.loads((root / 'research/imported/hl-node-94.inventory.json').read_text())
        crate = sorted(inv['first_party_files'])[0]
        src = root / 'references/can1357-hl' / crate / 'src' / inv['first_party_files'][crate][0]
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text('// 0x401000 captured entry candidate\nfn main() {}\n')
        binary = root / 'artifacts/node/94/hl-node'
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(elf)
        manifest = json.loads((self.root / 'provenance/artifacts.json').read_text())
        (root / 'provenance').mkdir(parents=True, exist_ok=True)
        (root / 'provenance/artifacts.json').write_text(json.dumps(manifest))
        return root, manifest

    def test_generate_rejects_unpinned_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._catalogue_root(tmp, self._elf())
            with self.assertRaises(ValueError):
                generate(root)

    def test_generate_rejects_missing_manifest_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, manifest = self._catalogue_root(tmp, self._elf())
            manifest['files'] = [i for i in manifest['files']
                                 if i['path'] != 'artifacts/node/94/hl-node']
            (root / 'provenance/artifacts.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                generate(root)

    def test_generate_stamps_pinned_binary(self):
        elf = self._elf()
        with tempfile.TemporaryDirectory() as tmp:
            root, manifest = self._catalogue_root(tmp, elf)
            item = next(i for i in manifest['files'] if i['path'] == 'artifacts/node/94/hl-node')
            item['size'] = len(elf)
            item['sha256'] = hashlib.sha256(elf).hexdigest()
            (root / 'provenance/artifacts.json').write_text(json.dumps(manifest))
            result = generate(root)
            seeds = json.loads(result['research/catalogue/seed-candidates.json'])
            self.assertEqual(seeds['binary_sha256'], item['sha256'])
            mine = [s for s in seeds['items'] if s['address'] == '0x401000']
            self.assertEqual(len(mine), 1)
            self.assertTrue(mine[0]['inside_executable_section_94'])


class VisorIndexTests(unittest.TestCase):
    def test_target_for_maps_nodes_and_visor(self):
        self.assertEqual(
            target_for('94')[0],
            'artifacts/node/94/hl-node',
        )
        self.assertEqual(
            target_for('visor'),
            (
                'artifacts/visor/captured/hl-visor',
                'research/imported/hl-visor.inventory.json',
                'visor-unwind',
            ),
        )

    def test_retained_visor_inventory_matches_unwind_when_bytes_present(self):
        root = Path(__file__).resolve().parents[1]
        binary = root / 'artifacts/visor/captured/hl-visor'
        inventory = json.loads((root / 'research/imported/hl-visor.inventory.json').read_text())
        self.assertEqual(inventory['file_size'], 8305392)
        self.assertEqual(
            inventory['build_id'],
            'b55c82cd4de234f23c768e5adff1e84e6adbc9a6',
        )
        data = binary.read_bytes()
        if data.startswith(b'version https://git-lfs.github.com/spec/v1'):
            self.skipTest('visor LFS object not pulled in this checkout')
        self.assertEqual(len(data), inventory['file_size'])
        _secs, rows = unwind_index(data)
        self.assertEqual(len(rows), inventory['fde_count_eh_frame_hdr'])
