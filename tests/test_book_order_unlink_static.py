import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from book_order_unlink_static import (
    PACKET,
    TARGET,
    analyze,
    authenticate,
    generate,
    unlink_order,
)

ROOT = Path(__file__).resolve().parents[1]


def fresh_order(tag=4, link_a=0, link_word=0, link_b=0):
    raw = bytearray(0x110)
    raw[0:8] = tag.to_bytes(8, 'little')
    raw[8:16] = link_a.to_bytes(8, 'little')
    raw[0x10:0x18] = link_word.to_bytes(8, 'little')
    raw[0x18:0x20] = link_b.to_bytes(8, 'little')
    raw[0xb0] = 4
    raw[0xd2] = 7
    raw[0xe0] = 9
    raw[0xf0] = 3
    raw[0xf8] = 0x11
    raw[0x108] = 0x22
    return raw


class BookOrderUnlinkStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != 105_896_032:
            raise unittest.SkipTest('node 115 target is not materialized')
        cls.data = TARGET.read_bytes()
        authenticate(cls.data)
        cls.report = analyze(cls.data)

    def test_native_contract_and_regeneration(self):
        self.assertEqual(self.report['scope']['measured_denominator_bytes'], 1720)
        self.assertEqual(self.report['twin_difference']['differing_bytes'], 42)
        self.assertEqual(
            self.report['locations']['link_137']['file'],
            'l1/src/book/book_orders.rs',
        )
        self.assertEqual(self.report['locations']['link_137']['line'], 137)
        self.assertEqual(self.report['locations']['link_145']['line'], 145)
        self.assertEqual(self.report['locations']['level']['line'], 32)
        self.assertEqual(
            self.report['unwrap_message'],
            'called `Result::unwrap()` on an `Err` value',
        )
        retained = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(
            self.report,
            {key: value for key, value in retained.items() if key != 'source_exports'},
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'packet'
            generate(TARGET, output)
            retained_files = sorted(
                path.name for path in PACKET.iterdir()
                if path.name not in {'MANIFEST.sha256', 'README.md'}
            )
            self.assertEqual(
                retained_files,
                sorted(path.name for path in output.iterdir()),
            )
            for name in retained_files:
                self.assertEqual(
                    (PACKET / name).read_bytes(),
                    (output / name).read_bytes(),
                    name,
                )

    def test_corrupted_vacant_tag_is_rejected(self):
        mutated = bytearray(self.data)
        # Owner-relative cmp rbp, 2 immediate at unlink_a + 0x2c.
        site = 0x58DFBC0 + 0x2C
        mutated[site - 0x1000 + 3] ^= 0xFF
        with self.assertRaises(ValueError):
            analyze(bytes(mutated))

    def test_model_boundaries(self):
        elements = [fresh_order(tag=2), fresh_order()]
        counter, head, quantity = [5], [1], [20]
        self.assertEqual(
            unlink_order(elements, counter, head, 0, 8, quantity, None, 0, 4)[0],
            'vacant',
        )
        self.assertEqual(
            unlink_order(elements, counter, head, 9, 8, quantity, None, 0, 4)[0],
            'vacant',
        )
        self.assertEqual(counter[0], 5)
        self.assertEqual(quantity[0], 20)

        elements = [fresh_order()]
        elements[0][0xe0] = 3
        counter, head, quantity = [0], [7], [3]
        kind, detail = unlink_order(
            elements, counter, head, 0, 0x55, quantity, None, 1, 4)
        self.assertEqual(kind, 'returned')
        self.assertEqual(int.from_bytes(elements[0][0:8], 'little'), 2)
        self.assertEqual(int.from_bytes(elements[0][8:16], 'little'), 7)
        self.assertEqual(head[0], 0)
        self.assertEqual(quantity[0], 0)
        self.assertFalse(detail['underflow_helper'])
        self.assertEqual(detail['event']['argument'], 0x55)
        self.assertEqual(detail['event']['kind'], 3)
        self.assertEqual(detail['output'][-1], 0)
        self.assertEqual(detail['output'][0], 4)

        elements = [fresh_order()]
        counter, head, quantity = [4], [1], [2]
        kind, detail = unlink_order(
            elements, counter, head, 0, 0, quantity, None, 0, 1)
        self.assertEqual(kind, 'returned')
        self.assertTrue(detail['underflow_helper'])
        self.assertEqual(quantity[0], 0)

        elements = [fresh_order()]
        counter, head, quantity = [2], [5], [40]
        self.assertEqual(
            unlink_order(elements, counter, head, 0, 0, quantity, None, 3, 3)[0],
            'event_full',
        )
        self.assertEqual(quantity[0], 40)

        elements = [fresh_order()]
        elements[0][0xb7] = 0x80
        level = bytearray(0x80)
        counter, head, quantity = [1], [0], [20]
        kind, detail = unlink_order(
            elements, counter, head, 0, 0, quantity, level, 0, 2)
        self.assertEqual(kind, 'negative_field')
        self.assertEqual(int.from_bytes(level[0x70:0x78], 'little'), 0)
        self.assertIn('event', detail)

        elements = [fresh_order(tag=0x10, link_a=2, link_word=0, link_b=6),
                    fresh_order()]
        level = bytearray(0x80)
        level[0x70] = 12
        level[0x78] = 1
        counter, head, quantity = [2], [9], [30]
        kind, detail = unlink_order(
            elements, counter, head, 0, 0, quantity, level, 0, 1)
        self.assertEqual(kind, 'returned')
        self.assertEqual(int.from_bytes(level[0:8], 'little'), 0)
        self.assertEqual(int.from_bytes(level[8:16], 'little'), 6)
        self.assertEqual(int.from_bytes(level[0x10:0x18], 'little'), 0x10)
        self.assertEqual(int.from_bytes(level[0x18:0x20], 'little'), 2)
        self.assertEqual(int.from_bytes(level[0x70:0x78], 'little'), 3)
        self.assertEqual(detail['output'][-1], 0x10 ^ 1)

        elements = [
            fresh_order(tag=1, link_a=1, link_word=5, link_b=1),
            fresh_order(),
        ]
        level = bytearray([1]) * 0x80
        counter, head, quantity = [3], [0], [40]
        kind, detail = unlink_order(
            elements, counter, head, 0, 0, quantity, level, 0, 1)
        self.assertEqual(kind, 'returned')
        self.assertEqual(int.from_bytes(elements[1][0x10:0x18], 'little'), 5)
        self.assertEqual(int.from_bytes(elements[1][0:8], 'little'), 1)
        self.assertEqual(detail['output'][-1], 0)

        elements = [fresh_order(tag=1, link_a=1), fresh_order(tag=2)]
        level = bytearray(0x80)
        kind, _detail = unlink_order(
            elements, counter, head, 0, 0, quantity, level, 0, 1)
        self.assertEqual(kind, 'link_absent')

        elements = [fresh_order()]
        elements[0][0x10] = 0x42
        elements[0][0x18] = 0x07
        elements[0][0xd8] = 1
        elements[0][0xdc] = 0x63
        level = bytearray(0x80)
        level[0x20] = 1
        counter, head, quantity = [1], [0], [20]
        kind, detail = unlink_order(
            elements, counter, head, 0, 0, quantity, level, 0, 1)
        self.assertEqual(kind, 'side_call')
        self.assertEqual(level[0x20], 0x42)
        self.assertEqual(detail['side_call']['field_f0'], 3)
        self.assertEqual(detail['side_call']['field_dc'], 0x63)
        self.assertEqual(int.from_bytes(level[0x70:0x78], 'little'), 0)

    def test_rust_model(self):
        rustc = shutil.which('rustc')
        if rustc is None:
            self.skipTest('rustc is not installed')
        source = ROOT / 'src/node115-book-order-unlink/lib.rs'
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'book-order-unlink-test'
            compiled = subprocess.run(
                [rustc, '--edition=2021', '--test', '-D', 'warnings',
                 str(source), '-o', str(binary)],
                text=True, capture_output=True, check=False)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run(
                [str(binary)], text=True, capture_output=True, check=False)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)


if __name__ == '__main__':
    unittest.main()
