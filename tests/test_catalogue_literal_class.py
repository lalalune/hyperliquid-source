import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import generate


def fixture():
    data = bytearray(832)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 512)
    struct.pack_into('<HHH', data, 58, 64, 5, 1)
    names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0'
    data[64:64 + len(names)] = names
    entries = [(0, 0, 0, 0, 0, 0), (1, 3, 0, 0, 64, len(names)), (11, 1, 6, 0x100, 256, 32),
               (17, 1, 2, 0x200, 320, 20), (31, 1, 2, 0x300, 384, 16)]
    entries[2] = (names.index(b'.text'), 1, 6, 0x100, 256, 32)
    entries[3] = (names.index(b'.eh_frame_hdr'), 1, 2, 0x200, 320, 20)
    entries[4] = (names.index(b'.eh_frame\0'), 1, 2, 0x300, 384, 16)
    for i, e in enumerate(entries):
        struct.pack_into('<IIQQQQIIQQ', data, 512 + i * 64, *e, 0, 0, 1, 0)
    data[320:324] = bytes([1, 0x1b, 3, 0x3b])
    struct.pack_into('<Iii', data, 328, 1, -0x100, 0x100)
    return data


class LiteralClassTests(unittest.TestCase):
    def input_root(self, literal_items):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / 'research/imported').mkdir(parents=True)
        (root / 'references/can1357-hl').mkdir(parents=True)
        (root / 'artifacts/node/94').mkdir(parents=True)
        comp = {"id": "foundation", "name": "Foundation", "patterns": ["base/*"],
                "depends_on": [], "scope": "x", "first_task": "y", "artifact": "node94"}
        (root / 'research/components.json').write_text(json.dumps(
            {"components": [comp], "known_first_party_crates": ["base"]}))
        (root / 'research/progress.json').write_text(json.dumps(
            {"gates": {"mapped": "m"}, "components": {"foundation":
             {"gates": {"mapped": False}, "evidence": [], "raw_equal_bodies": 0,
              "normalized_only_bodies": 0, "total_function_windows": None}}}))
        plain = json.dumps({"first_party_files": {}, "fde_count_eh_frame_hdr": 1})
        for name in ('hl-node-94', 'hl-node-115', 'hl-visor'):
            (root / f'research/imported/{name}.inventory.json').write_text(plain)
        (root / 'research/imported/can1357-literal-classes.json').write_text(
            json.dumps({"items": literal_items}))
        (root / 'artifacts/node/94/hl-node').write_bytes(bytes(fixture()))
        return root

    def test_missing_class_key_rejected(self):
        item = {"crate": "base", "file": "base/a.rs", "literal": "attempt to add with overflow"}
        with self.assertRaises(ValueError):
            generate(self.input_root([item]))

    def test_clean_inputs_still_generate(self):
        item = {"crate": "base", "file": "base/a.rs",
                "literal": "attempt to add with overflow", "class": "grounded"}
        result = generate(self.input_root([item]))
        self.assertIn('research/catalogue/components.json', result)
        self.assertIn('docs/PROGRESS.md', result)


if __name__ == '__main__':
    unittest.main()
