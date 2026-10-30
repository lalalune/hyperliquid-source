"""Tools whose parsers read GNU binutils text must refuse other objdump/readelf builds.

A fake LLVM objdump/readelf (or none) is placed on PATH. Each tool must stop with
the detection reason before it runs a listing, FDE or relocation command, so no
non-GNU output can reach a parser. These controls run with or without GNU tools.
"""
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import evm_amount_scale  # noqa: E402
import spot_wei_scale  # noqa: E402
import truncated_debug_static  # noqa: E402
import wei_buffered_cap  # noqa: E402

BINARY = ROOT / 'artifacts/node/94/hl-node'
LISTING_TOOLS = {
    'evm_amount_scale': (evm_amount_scale, evm_amount_scale.SCALE, evm_amount_scale.SCALE_END),
    'spot_wei_scale': (spot_wei_scale, 0x3760790, 0x376081c),
    'wei_buffered_cap': (wei_buffered_cap, 0x2723c70, 0x27240a3),
}
FAKE = """#!/bin/sh
echo "$0 $*" >> {log}
if [ "$1" = "--version" ]; then echo "Apple LLVM version 17.0.0"; exit 0; fi
exit 0
"""


class FakeBinutils(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bin = self.dir / 'bin'
        self.bin.mkdir()
        self.log = self.dir / 'calls.log'
        self.log.touch()
        for name in ('objdump', 'readelf'):
            tool = self.bin / name
            tool.write_text(FAKE.format(log=self.log))
            tool.chmod(tool.stat().st_mode | stat.S_IXUSR)

    def tearDown(self):
        self.tmp.cleanup()

    def calls(self):
        return [line.split(' ', 1)[1] for line in self.log.read_text().splitlines()]

    def test_listing_tools_refuse_non_gnu_objdump(self):
        for name, (module, start, end) in LISTING_TOOLS.items():
            with self.subTest(tool=name), mock.patch.dict(os.environ, {'PATH': str(self.bin)}):
                with self.assertRaisesRegex(
                        module.EvidenceError,
                        r"objdump is not GNU binutils \(got 'Apple LLVM version 17\.0\.0'\)"):
                    module.disassemble(BINARY, start, end)
        self.assertEqual(self.calls(), ['--version'] * len(LISTING_TOOLS))

    def test_listing_tools_refuse_missing_objdump(self):
        empty = self.dir / 'empty'
        empty.mkdir()
        for name, (module, start, end) in LISTING_TOOLS.items():
            with self.subTest(tool=name), mock.patch.dict(os.environ, {'PATH': str(empty)}):
                with self.assertRaisesRegex(module.EvidenceError, 'objdump not found on PATH'):
                    module.disassemble(BINARY, start, end)

    @unittest.skipUnless(BINARY.exists(), 'pinned node #94 binary not present')
    def test_truncated_debug_refuses_non_gnu_before_writing(self):
        out = self.dir / 'out'
        with mock.patch.dict(os.environ, {'PATH': str(self.bin)}):
            with self.assertRaisesRegex(
                    ValueError, r"readelf is not GNU binutils \(got 'Apple LLVM version 17\.0\.0'\)"):
                truncated_debug_static.generate(BINARY, out)
        self.assertEqual(self.calls(), ['--version'])
        self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
