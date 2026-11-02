"""Malformed catalogue input documents must fail with ValueError diagnostics.

generate() loads research/components.json and the node115 inventory and
dereferences their keys; validate_progress() already refuses a malformed
progress document, but the other two documents escaped as raw KeyError /
TypeError. The deep cases stage a synthetic ELF (builder idiom from
test_elf_index.py) plus a provenance manifest carrying its real size and
SHA-256, so the authenticated-binary gate passes and generate() reaches the
inventory load and the paths comprehension.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import catalogue

NAMES = b'\0.text\0.eh_frame\0.eh_frame_hdr\0.shstrtab\0'
# Name offsets inside NAMES: .text=1, .eh_frame=7, .eh_frame_hdr=17, .shstrtab=31.
HDR_VA = 0x402000
HDR_OFF = 0x3000


def build_elf(entries):
    """Minimal ELF64-LE image whose .eh_frame_hdr lists the given pairs."""
    data = bytearray(0x4000)
    data[0:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIQQQIHHHHHH', data, 16,
                     2, 0x3E, 1, 0, 0, 64, 0, 64, 0, 0, 64, 5, 4)

    def section(index, name, typ, flags, addr, off, size):
        struct.pack_into('<IIQQQQIIQQ', data, 64 + index * 64,
                         name, typ, flags, addr, off, size, 0, 0, 1, 0)

    section(1, 1, 1, 0x6, 0x400000, 0x1000, 0x2000)      # .text
    section(2, 7, 1, 0x2, 0x401000, 0x2000, 0x100)       # .eh_frame
    section(3, 17, 1, 0x2, HDR_VA, HDR_OFF, 28)          # .eh_frame_hdr
    section(4, 31, 3, 0, 0, 64 + 5 * 64, len(NAMES))     # .shstrtab
    data[64 + 5 * 64:64 + 5 * 64 + len(NAMES)] = NAMES
    data[HDR_OFF:HDR_OFF + 4] = bytes([1, 0x1b, 0x03, 0x3b])
    struct.pack_into('<i', data, HDR_OFF + 4, 0)         # eh_frame_ptr
    struct.pack_into('<I', data, HDR_OFF + 8, len(entries))
    for i, (start, fde) in enumerate(entries):
        struct.pack_into('<ii', data, HDR_OFF + 12 + i * 8, start - HDR_VA, fde - HDR_VA)
    return bytes(data)


COMPONENT = {'id': 'core', 'name': 'Core', 'scope': 'Core scope', 'artifact': 'node115',
             'first_task': 'TASK-0', 'depends_on': [], 'patterns': ['*']}
GATES = {'mapped': False, 'built': False, 'behavior': False, 'identity': False}
PROGRESS = {'gates': dict(GATES),
            'components': {'core': {'gates': dict(GATES), 'raw_equal_bodies': 0,
                                    'normalized_only_bodies': 0,
                                    'total_function_windows': 0, 'evidence': []}},
            'baseline': 'node115'}
CONFIG = {'components': [COMPONENT], 'known_first_party_crates': ['crate0']}
INVENTORY = {'fde_count_eh_frame_hdr': 0, 'first_party_files': {'crate0': ['lib.rs']}}


class CatalogueInputShapeTests(unittest.TestCase):
    def stage(self, folder, config=CONFIG, inventory=None, deep=False):
        root = Path(folder)
        (root / 'research/imported').mkdir(parents=True)
        (root / 'research/components.json').write_text(json.dumps(config))
        (root / 'research/progress.json').write_text(json.dumps(PROGRESS))
        if deep:
            elf = build_elf([])
            binary = root / 'artifacts/node/115/hl-node'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(elf)
            (root / 'provenance').mkdir()
            item = {'path': 'artifacts/node/115/hl-node', 'size': len(elf),
                    'sha256': hashlib.sha256(elf).hexdigest()}
            (root / 'provenance/artifacts.json').write_text(json.dumps({'files': [item]}))
            (root / 'research/imported/hl-node-115.inventory.json').write_text(
                json.dumps(inventory))
        return root

    def assert_generate_rejected(self, message, **kwargs):
        with tempfile.TemporaryDirectory() as folder:
            root = self.stage(folder, **kwargs)
            with self.assertRaisesRegex(ValueError, message):
                catalogue.generate(root)

    def test_config_without_components_is_invalid(self):
        self.assert_generate_rejected('Invalid components config', config={})

    def test_config_as_list_is_invalid(self):
        self.assert_generate_rejected('Invalid components config', config=[])

    def test_config_components_not_a_list_is_invalid(self):
        config = {'components': {'core': COMPONENT}, 'known_first_party_crates': []}
        self.assert_generate_rejected('Invalid components config', config=config)

    def test_config_without_known_crates_is_invalid(self):
        self.assert_generate_rejected('Invalid components config',
                                      config={'components': [COMPONENT]})

    def test_inventory_without_fde_count_is_invalid(self):
        self.assert_generate_rejected('Invalid node115 inventory', inventory={}, deep=True)

    def test_inventory_without_first_party_files_is_invalid(self):
        self.assert_generate_rejected('Invalid node115 inventory',
                                      inventory={'fde_count_eh_frame_hdr': 0}, deep=True)

    def test_valid_inputs_reach_the_coverage_gate(self):
        # Control: fully valid staged inputs pass both shape boundaries and
        # every later catalogue gate, reaching load_coverage, whose own
        # validated diagnostic answers for the unstaged byte registry.
        self.assert_generate_rejected('Missing/external byte evidence',
                                      inventory=INVENTORY, deep=True)


if __name__ == '__main__':
    unittest.main()
