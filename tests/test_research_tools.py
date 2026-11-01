import copy


import json


from pathlib import Path


import struct


import sys


import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import (PROGRESS_END, PROGRESS_START, owner, render_readme_progress,
                       update_readme_progress, validate_progress)
from elf_index import entry_file_offset, sections, target_for, unwind_index


import hashlib


import tempfile


from catalogue import generate, owner, validate_progress


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

    def _with_duplicate_section(self, name):
        data = bytearray(fixture()) + bytearray(64)
        struct.pack_into('<HHH', data, 58, 64, 6, 1)
        names = b'\x00.shstrtab\x00.text\x00.eh_frame_hdr\x00.eh_frame\x00'
        struct.pack_into('<IIQQQQIIQQ', data, 512 + 5 * 64,
                         names.index(name), 1, 2, 0x999, 400, 20, 0, 0, 1, 0)
        return bytes(data)

    def test_rejects_duplicate_eh_frame_hdr_section(self):
        with self.assertRaisesRegex(ValueError, r'Duplicate section: \.eh_frame_hdr'):
            unwind_index(self._with_duplicate_section(b'.eh_frame_hdr'))

    def test_rejects_duplicate_eh_frame_section(self):
        with self.assertRaisesRegex(ValueError, r'Duplicate section: \.eh_frame'):
            unwind_index(self._with_duplicate_section(b'.eh_frame\x00'))


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

    def test_readme_uses_accepted_gates_for_counts_and_total(self):
        d = copy.deepcopy(self.progress)
        for row in d['components'].values():
            row['gates'] = dict.fromkeys(d['gates'], False)
        d['components']['foundation']['gates'] = dict.fromkeys(d['gates'], True)
        d['components']['visor']['gates']['mapped'] = True
        block = render_readme_progress(self.parts, d)
        self.assertIn('4.35% (4/92 accepted gates; 1/23 components complete)', block)
        self.assertIn('25.00% (1/4 accepted gates; 0/1 components complete)', block)
        self.assertIn('| 4/4 | 100% |', block)
        self.assertIn('| 1/4 | 25% |', block)
        self.assertIn('**5/96**', block)

    def test_readme_regeneration_preserves_surrounding_text(self):
        readme = f'User introduction\n{PROGRESS_START}\nStale numbers\n{PROGRESS_END}\nUser setup\n'
        result = update_readme_progress(readme, 'Current numbers')
        self.assertEqual(result, f'User introduction\n{PROGRESS_START}\nCurrent numbers\n{PROGRESS_END}\nUser setup\n')
        self.assertEqual(update_readme_progress(result, 'Current numbers'), result)

    def test_readme_rejects_missing_duplicate_and_reversed_markers(self):
        for readme in ['', PROGRESS_START, PROGRESS_END,
                       PROGRESS_START * 2 + PROGRESS_END,
                       PROGRESS_START + PROGRESS_END * 2,
                       PROGRESS_END + PROGRESS_START]:
            with self.subTest(readme=readme), self.assertRaises(ValueError):
                update_readme_progress(readme, 'Current numbers')

    def test_boolean_match_count_rejected(self):
        d = copy.deepcopy(self.progress)
        d['components']['orderbook']['raw_equal_bodies'] = True
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_fractional_match_count_rejected(self):
        d = copy.deepcopy(self.progress)
        row = d['components']['orderbook']
        row['raw_equal_bodies'] = 1.5; row['total_function_windows'] = 3
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_boolean_denominator_rejected(self):
        d = copy.deepcopy(self.progress)
        row = d['components']['orderbook']
        row['raw_equal_bodies'] = 1; row['total_function_windows'] = True
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_duplicate_component_rejected(self):
        parts = self.parts + [copy.deepcopy(self.parts[0])]
        with self.assertRaises(ValueError): validate_progress(parts, self.progress, self.root)

    def test_missing_progress_field_rejected(self):
        d = copy.deepcopy(self.progress)
        del d['components']['orderbook']['raw_equal_bodies']
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    @staticmethod
    def _elf():
        data = fixture()
        for index in (2, 3, 4):
            offset = 512 + index * 64 + 16
            address = struct.unpack_from('<Q', data, offset)[0]
            struct.pack_into('<Q', data, offset, address + 0x400f00)
        return bytes(data)

    def _catalogue_root(self, tmp, elf):
        root = Path(tmp)
        (root / 'README.md').write_text(f'{PROGRESS_START}\n{PROGRESS_END}\n')
        for rel in ['research/components.json', 'research/progress.json',
                    'research/imported/hl-node-94.inventory.json',
                    'research/imported/hl-node-115.inventory.json',
                    'research/imported/hl-visor.inventory.json',
                    'research/imported/can1357-literal-classes.json']:
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes((self.root / rel).read_bytes())
        # Synthetic ELF fixtures do not contain the real compiled-byte windows.
        progress_path = root / 'research/progress.json'
        metadata = json.loads(progress_path.read_text())
        metadata.pop('byte_window_registry', None)
        progress_path.write_text(json.dumps(metadata))
        inv = json.loads((root / 'research/imported/hl-node-94.inventory.json').read_text())
        crate = sorted(inv['first_party_files'])[0]
        src = root / 'references/can1357-hl' / crate / 'src' / inv['first_party_files'][crate][0]
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text('// 0x401000 captured entry candidate\nfn main() {}\n')
        for relative in ('artifacts/node/94/hl-node', 'artifacts/node/115/hl-node',
                         'artifacts/visor/captured/hl-visor'):
            binary = root / relative
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(elf)
        for name in ('hl-node-94', 'hl-node-115', 'hl-visor'):
            path = root / f'research/imported/{name}.inventory.json'
            inventory = json.loads(path.read_text())
            inventory['fde_count_eh_frame_hdr'] = 1
            path.write_text(json.dumps(inventory))
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
            for record in manifest['files']:
                if record['path'] in ('artifacts/node/94/hl-node', 'artifacts/node/115/hl-node',
                                      'artifacts/visor/captured/hl-visor'):
                    record['size'] = len(elf)
                    record['sha256'] = hashlib.sha256(elf).hexdigest()
            (root / 'provenance/artifacts.json').write_text(json.dumps(manifest))
            result = generate(root)
            seeds = json.loads(result['research/catalogue/seed-candidates.json'])
            self.assertEqual(seeds['binary_sha256'], item['sha256'])
            mine = [s for s in seeds['items'] if s['address'] == '0x401000']
            self.assertEqual(len(mine), 1)
            self.assertTrue(mine[0]['inside_executable_section_94'])

    def fde_root(self, claims):
        import hashlib, tempfile
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / 'research/imported').mkdir(parents=True)
        (root / 'README.md').write_text(f'{PROGRESS_START}\n{PROGRESS_END}\n')
        (root / 'references/can1357-hl').mkdir(parents=True)
        comp = {"id": "foundation", "name": "Foundation", "patterns": ["base/*"],
                "depends_on": [], "scope": "x", "first_task": "y", "artifact": "node94"}
        (root / 'research/components.json').write_text(json.dumps(
            {"components": [comp], "known_first_party_crates": ["base"]}))
        (root / 'research/progress.json').write_text(json.dumps(
            {"gates": {g: g for g in ('mapped', 'built', 'behavior', 'identity')}, "components": {"foundation":
             {"gates": {g: False for g in ('mapped', 'built', 'behavior', 'identity')}, "evidence": [], "raw_equal_bodies": 0,
              "normalized_only_bodies": 0, "total_function_windows": None}}}))
        for name, claim in claims.items():
            (root / f'research/imported/{name}.inventory.json').write_text(json.dumps(
                {"first_party_files": {}, "fde_count_eh_frame_hdr": claim}))
        (root / 'research/imported/can1357-literal-classes.json').write_text(
            json.dumps({"items": []}))
        data = bytes(fixture())
        files = []
        for relative in ('artifacts/node/94/hl-node', 'artifacts/node/115/hl-node',
                         'artifacts/visor/captured/hl-visor'):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            files.append({'path': relative, 'size': len(data),
                          'sha256': hashlib.sha256(data).hexdigest()})
        (root / 'provenance').mkdir()
        (root / 'provenance/artifacts.json').write_text(json.dumps({'files': files}))
        return root

    def test_inventory_unwind_counts_recounted(self):
        root = self.fde_root({'hl-node-94': 1, 'hl-node-115': 1, 'hl-visor': 1})
        out = generate(root)
        self.assertIn('| Node #94 | 1 |', out['docs/PROGRESS.md'])

    def test_inflated_unwind_count_rejected(self):
        root = self.fde_root({'hl-node-94': 2, 'hl-node-115': 1, 'hl-visor': 1})
        with self.assertRaises(ValueError):
            generate(root)

    def run_catalogue_main(self, root, argv):
        import catalogue
        original = (catalogue.ROOT, catalogue.generate, sys.argv)
        catalogue.ROOT = root
        catalogue.generate = lambda: {'docs/PROGRESS.md': '# Progress\u2014x\nline2\n'}
        sys.argv = ['catalogue.py'] + argv
        try:
            catalogue.main()
        finally:
            catalogue.ROOT, catalogue.generate, sys.argv = original

    def catalogue_root(self):
        import tempfile
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / 'docs').mkdir(parents=True)
        return root

    def test_catalogue_check_rejects_crlf_drift(self):
        root = self.catalogue_root()
        content = '# Progress\u2014x\nline2\n'
        (root / 'docs/PROGRESS.md').write_bytes(content.replace('\n', '\r\n').encode())
        with self.assertRaises(SystemExit):
            self.run_catalogue_main(root, ['--check'])

    def test_catalogue_write_then_check_roundtrip(self):
        root = self.catalogue_root()
        content = '# Progress\u2014x\nline2\n'
        self.run_catalogue_main(root, [])
        self.assertEqual((root / 'docs/PROGRESS.md').read_bytes(), content.encode())
        self.run_catalogue_main(root, ['--check'])

    def input_root(self, inventory94=None, literal_items=()):
        root = self.fde_root({'hl-node-94': 1, 'hl-node-115': 1, 'hl-visor': 1})
        if inventory94 is not None:
            (root / 'research/imported/hl-node-94.inventory.json').write_text(inventory94)
        (root / 'research/imported/can1357-literal-classes.json').write_text(
            json.dumps({'items': list(literal_items)}))
        return root

    def test_duplicate_inventory_key_rejected(self):
        dup = ('{"first_party_files": {"base": ["a.rs"], "base": ["b.rs"]},'
               ' "fde_count_eh_frame_hdr": 1}')
        root = self.input_root(inventory94=dup)
        with self.assertRaises(ValueError):
            generate(root)

    def test_duplicate_literal_item_rejected(self):
        item = {"crate": "base", "file": "base/a.rs",
                "literal": "attempt to add with overflow", "class": "grounded"}
        root = self.input_root(literal_items=[item, dict(item)])
        with self.assertRaises(ValueError):
            generate(root)

    def test_clean_inputs_still_generate(self):
        item = {"crate": "base", "file": "base/a.rs",
                "literal": "attempt to add with overflow", "class": "grounded"}
        root = self.input_root(literal_items=[item])
        out = generate(root)
        self.assertIn('docs/PROGRESS.md', out)

    def test_non_dict_gate_record_rejected(self):
        # A gates record that is not a dict must fail closed as a ValueError,
        # like every other malformed progress record — on base it escaped as
        # AttributeError from the .values() call in the gate check.
        d = copy.deepcopy(self.progress)
        d['components']['orderbook']['gates'] = list(d['components']['orderbook']['gates'])
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_non_list_evidence_record_rejected(self):
        # A non-list evidence value must fail closed as a ValueError, like
        # every other malformed progress record — on base it escaped as
        # TypeError from iterating the evidence value.
        d = copy.deepcopy(self.progress)
        d['components']['orderbook']['evidence'] = None
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_missing_progress_gates_rejected(self):
        # A progress record without its top-level gates key must fail closed
        # as a ValueError — on base it escaped as KeyError from the gate
        # comparison in the component loop.
        d = copy.deepcopy(self.progress); del d['gates']
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_missing_components_key_rejected(self):
        d = copy.deepcopy(self.progress); del d['components']
        with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_missing_component_id_rejected(self):
        parts = copy.deepcopy(self.parts); del parts[0]['id']
        with self.assertRaises(ValueError): validate_progress(parts, self.progress, self.root)

    def test_missing_component_depends_on_rejected(self):
        parts = copy.deepcopy(self.parts); del parts[0]['depends_on']
        with self.assertRaises(ValueError): validate_progress(parts, self.progress, self.root)

    def test_missing_component_patterns_rejected(self):
        parts = copy.deepcopy(self.parts); del parts[0]['patterns']
        with self.assertRaises(ValueError): owner('l1/exchange/handlers/14_order.rs', parts)

    def test_non_dict_progress_row_rejected(self):
        for bad in (None, 5, ['gates']):
            d = copy.deepcopy(self.progress)
            d['components']['orderbook'] = bad
            with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)

    def test_gate_schema_rejects_additional_acceptance_credit(self):
        d = copy.deepcopy(self.progress)
        d['gates']['extra'] = 'An extra milestone would allow 125% completion.'
        for row in d['components'].values():
            row['gates']['extra'] = False
        with self.assertRaisesRegex(ValueError, 'four acceptance gates'):
            validate_progress(self.parts, d, self.root)

    def test_gate_schema_rejects_missing_or_replaced_gate(self):
        for replacement in (None, 'source_imported'):
            with self.subTest(replacement=replacement):
                d = copy.deepcopy(self.progress)
                del d['gates']['identity']
                for row in d['components'].values():
                    del row['gates']['identity']
                if replacement is not None:
                    d['gates'][replacement] = 'Not target code/data/call identity.'
                    for row in d['components'].values():
                        row['gates'][replacement] = False
                with self.assertRaisesRegex(ValueError, 'four acceptance gates'):
                    validate_progress(self.parts, d, self.root)

    def test_gate_schema_accepts_canonical_names_in_any_order(self):
        d = copy.deepcopy(self.progress)
        d['gates'] = dict(reversed(list(d['gates'].items())))
        validate_progress(self.parts, d, self.root)

    def test_non_mapping_progress_components_rejected(self):
        ids = [c['id'] for c in self.parts]
        for bad in (ids, 0, None):
            d = copy.deepcopy(self.progress)
            d['components'] = bad
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_progress(self.parts, d, self.root)
        validate_progress(self.parts, self.progress, self.root)

    def test_non_dict_component_record_rejected(self):
        # The 'id'/'patterns' key-presence guards of #321/#325 assume dict
        # records: the string/list cases below carry the key, so they slip
        # past those guards and crash at the subscript instead.
        for bad in (5, None, 'id-patterns', ['id']):
            parts = copy.deepcopy(self.parts)
            parts[0] = bad
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_progress(parts, self.progress, self.root)
        validate_progress(self.parts, self.progress, self.root)

    def test_non_dict_component_record_rejected_by_owner(self):
        for bad in (123, None, 'patterns', ['patterns']):
            with self.assertRaises(ValueError): owner('l1/exchange/impl_trading.rs', [bad])
        self.assertEqual(owner('l1/exchange/impl_trading.rs', self.parts), 'exchange')

    def test_non_list_depends_on_rejected(self):
        for bad in (123, None):
            parts = copy.deepcopy(self.parts); parts[0]['depends_on'] = bad
            with self.assertRaises(ValueError): validate_progress(parts, self.progress, self.root)
        validate_progress(self.parts, self.progress, self.root)

    def test_non_string_evidence_entry_rejected(self):
        for bad in (123, {'a': 1}, ['x'], None, True):
            d = copy.deepcopy(self.progress)
            d['components']['foundation']['evidence'] = [bad]
            with self.assertRaises(ValueError): validate_progress(self.parts, d, self.root)
        d = copy.deepcopy(self.progress)
        d['components']['foundation']['evidence'] = ['research/components.json']
        validate_progress(self.parts, d, self.root)

    def test_missing_component_id_rejected_by_owner(self):
        parts = copy.deepcopy(self.parts)
        for c in parts:
            if c['id'] == 'exchange':
                del c['id']
                break
        with self.assertRaises(ValueError): owner('l1/exchange/impl_trading.rs', parts)
        self.assertEqual(owner('l1/exchange/impl_trading.rs', self.parts), 'exchange')


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
