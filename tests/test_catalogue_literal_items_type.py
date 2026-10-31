import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import generate


def elf_fixture():
    data = bytearray(832)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 512)
    struct.pack_into('<HHH', data, 58, 64, 2, 1)
    names = b'\0.shstrtab\0'
    data[64:64 + len(names)] = names
    entries = [(0, 0, 0, 0, 0, 0), (1, 3, 0, 0, 64, len(names))]
    for i, e in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, 512 + i * 64, *e, 0, 0, 1, 0)
    return bytes(data)


def make_root(tmp, literal_record):
    root = Path(tmp)
    component = {'id': 'exchange', 'name': 'Exchange', 'scope': 'Exchange scope',
                 'artifact': 'exchange', 'depends_on': [], 'patterns': ['*'],
                 'first_task': 'First task'}
    (root / 'research/imported').mkdir(parents=True)
    (root / 'research/components.json').write_text(json.dumps(
        {'components': [component], 'known_first_party_crates': []}))
    (root / 'research/progress.json').write_text(json.dumps(
        {'gates': ['g1'], 'components': {'exchange': {'gates': {'g1': False},
         'raw_equal_bodies': 0, 'normalized_only_bodies': 0,
         'total_function_windows': None, 'evidence': []}}}))
    for v in ['94', '115']:
        (root / f'research/imported/hl-node-{v}.inventory.json').write_text(json.dumps(
            {'first_party_files': {}, 'fde_count_eh_frame_hdr': 0}))
    (root / 'research/imported/hl-visor.inventory.json').write_text(json.dumps(
        {'first_party_files': {}, 'fde_count_eh_frame_hdr': 0}))
    (root / 'research/imported/can1357-literal-classes.json').write_text(
        json.dumps(literal_record))
    (root / 'references/can1357-hl').mkdir(parents=True)
    artifact = root / 'artifacts/node/94/hl-node'
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(elf_fixture())
    return root


class LiteralItemsTypeTests(unittest.TestCase):
    def test_non_list_items_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp, {'items': 42})
            with self.assertRaises(ValueError):
                generate(root)

    def test_list_items_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp, {'items': [{'class': 'grounded',
                                             'file': 'l1/foo.rs'}]})
            result = generate(root)
            catalogue = json.loads(result['research/catalogue/components.json'])
            self.assertEqual(catalogue['components'][0]['literal_counts'],
                             {'grounded': 1})


if __name__ == '__main__':
    unittest.main()
