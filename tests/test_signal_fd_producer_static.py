"""Tests for the RE-005 signal-fd producer packet.

The tool re-derives, from the authenticated hl-node
115 artifact only: that the fd word at 0x64fee24 is
one end of a Unix socketpair created exactly once
by the get_or_init closure 0x5cfcec0 of the global
signal state at 0x64fee20 (vendored tokio,
signal/unix.rs:71:53), through the socketpair
wrapper 0x475b160 whose only call site is that
closure; that the closure completes the 24-byte
value with a SIGRTMAX-sized table of 32-byte
entries built by 0x5ce1320; that the lazy accessor
0x5cdf582 reaches the closure only through std
call_once_force 0x5c87d50 and the Once vtable at
0x64c5760; and that the fd word has exactly one
reader in the whole .text -- signal_attach
0x5ce71f0.  Any drift in a body hash, census,
relocation resolution or instruction pin must fail
the suite rather than silently rewrite the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'signal_fd_producer_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-signal-fd-producer')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'signal_fd_producer_static', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL_MOD = load_tool()


def materialised():
    target = TOOL_MOD.TARGET
    if not target.is_file():
        return False
    with target.open('rb') as handle:
        return not handle.read(64).startswith(b'version https://')


@unittest.skipUnless(materialised(),
                     'hl-node artifact not materialised')
class SignalFdProducerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TOOL_MOD.TARGET.read_bytes()
        cls.records = TOOL_MOD.analyze(cls.data)

    def test_artifact(self):
        self.assertEqual(self.records['artifact']['size'],
                         TOOL_MOD.TARGET_SIZE)
        self.assertEqual(self.records['artifact']['sha256'],
                         TOOL_MOD.TARGET_SHA256)

    def test_records_match_disk(self):
        on_disk = json.loads(
            (PACKET / 'records.json').read_text())
        self.assertEqual(self.records, on_disk)

    def test_global_born_uninitialised(self):
        words = self.records['global_state']['initial_u32']
        self.assertEqual(words[:6], ['0x0'] * 6)
        self.assertEqual(words[6], '0x3')   # Once state: incomplete
        self.assertEqual(words[7], '0x0')

    def test_producer_is_socketpair(self):
        got = self.records['got_resolutions']
        self.assertEqual(got['0x64eb078'],
                         {'kind': 'dynsym',
                          'symbol': 'socketpair'})
        calls = self.records['censuses']['e8_calls']
        self.assertEqual(calls['0x475b160'], ['0x5cfced2'])

    def test_closure_reached_only_via_vtable(self):
        calls = self.records['censuses']['e8_calls']
        self.assertEqual(calls['0x5cfcec0'],
                         ['0x5cdf50c', '0x5cdf6dc'])
        self.assertEqual(calls['0x5c87d50'], [])
        self.assertEqual(self.records['vtable'],
                         {'base': '0x64c5760',
                          'plus_0x18': '0x5cdf6c0',
                          'plus_0x20': '0x5cdf4f0'})
        self.assertEqual(
            self.records['got_resolutions']['0x64df9f0'],
            {'kind': 'relative', 'target': '0x5c87d50'})

    def test_fd_word_single_reader(self):
        rip = self.records['censuses']['rip']
        self.assertEqual(rip['disp_final']['0x64fee24'],
                         ['0x5ce7213'])
        self.assertEqual(rip['disp_final']['0x64fee2c'], [])
        self.assertEqual(rip['disp_final']['0x64fee34'], [])
        trailing = rip['disp_imm_trailing']
        self.assertTrue(all(not v for v in trailing.values()))
        self.assertEqual(self.records['censuses']['imm64'],
                         {'0x64fee20': 0, '0x64fee24': 0,
                          '0x64fee38': 0})

    def test_table_consumers(self):
        rip = self.records['censuses']['rip']['disp_final']
        self.assertEqual(rip['0x64fee28'],
                         ['0x5cde7c8', '0x5ce745d'])
        self.assertEqual(rip['0x64fee30'],
                         ['0x5cde7bf', '0x5ce744d', '0x5ce756c'])
        self.assertEqual(rip['0x64fee38'],
                         ['0x5cde79e', '0x5cde7ef',
                          '0x5ce7205', '0x5ce743e'])

    def test_source_location_is_tokio_signal_unix(self):
        loc = self.records['locations']['init_unwrap_location']
        self.assertTrue(loc['file'].endswith(
            'z_vendor/tokio/src/signal/unix.rs'))
        self.assertEqual((loc['line'], loc['col']), (71, 53))
        once = self.records['locations']['once_panic_location']
        self.assertTrue(once['file'].endswith(
            'library/std/src/sync/once.rs'))
        self.assertEqual((once['line'], once['col']), (219, 20))

    def test_owner_bodies(self):
        for name, rec in self.records['owners'].items():
            self.assertEqual(
                rec['bytes'],
                int(rec['end'], 16) - int(rec['start'], 16),
                name)
            self.assertEqual(len(rec['sha256']), 64, name)


if __name__ == '__main__':
    unittest.main()
