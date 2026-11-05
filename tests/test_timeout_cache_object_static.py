"""Tests for the RE-005 timeout cache object packet tool.

The tool re-derives, from the authenticated hl-node 115
artifact only: the identity of the object the park
slow-path refresh body caches (the vendored tokio signal
registry's SIGCHLD entry object), the refresh/lookup/
getter/reap-pass call census, the cache globals' RIP-
relative reference census, the cached object's Arc
layout pins, the slot resolutions, the panic Locations
and the registry messages. Any drift in a body hash,
slot resolution, Location, call census, byte pin or
message must fail the suite rather than silently
rewrite the packet.
"""

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'timeout_cache_object_static.py'
PACKET = (ROOT / 'research' / 'work-items' /
          'RE-005-node115-timeout-cache-object')


def load_tool():
    spec = importlib.util.spec_from_file_location(
        'timeout_cache_object_static', TOOL)
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
class TimeoutCacheObjectPacketTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = TOOL_MOD.TARGET.read_bytes()
        cls.records = TOOL_MOD.analyze(cls.data)

    def test_artifact(self):
        self.assertEqual(self.records['artifact']['size'],
                         105896032)
        self.assertEqual(
            self.records['artifact']['sha256'],
            'a6e2897cd051213d004802deca416e8eca62b7a8278'
            'fa39f249e98c3867b5301')

    def test_records_match_packet(self):
        stored = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(self.records, stored)

    def test_refresh_is_sole_lookup_caller(self):
        census = self.records['call_census']
        self.assertEqual(
            census['lookup'],
            [{'site': '0x5cee6f9', 'kind': 'call',
              'in_body': '0x5cee650'}])
        self.assertEqual(
            census['getobj'],
            [{'site': '0x5cde802', 'kind': 'call',
              'in_body': '0x5cde710'}])
        self.assertEqual(
            [(r['site'], r['kind'], r['in_body'])
             for r in census['refresh']],
            [('0x5ce01cb', 'jmp', '0x5ce0160'),
             ('0x5ce08be', 'jmp', '0x5ce0850'),
             ('0x5cfdfef', 'call', '0x5cfdd00')])
        self.assertEqual(
            [(r['site'], r['in_body']) for r in census['notify']],
            [('0x5cee6c4', '0x5cee650'),
             ('0x5cee793', '0x5cee650')])

    def test_cache_globals_only_in_refresh(self):
        rip = self.records['rip_refs']
        for name in ('lock_refresh', 'cache_obj', 'cache_key'):
            bodies = {r['in_body'] for r in rip[name]}
            self.assertEqual(bodies, {'0x5cee650'}, name)
        for name in ('queue_base', 'queue_len'):
            bodies = {r['in_body'] for r in rip[name]}
            self.assertEqual(bodies, {'0x5cee900'}, name)

    def test_signal_number_pin(self):
        # 17 is the SIGCHLD signal number passed to the
        # lookup, and the refusal mask names the five
        # forbidden signals 4, 8, 9, 11, 19.
        self.assertEqual(self.records['pins']['0x5cee6f1'],
                         'be11000000')
        mask = 0x80b10
        refused = [s for s in range(1, 20)
                   if mask & (1 << s)]
        self.assertEqual(refused, [4, 8, 9, 11, 19])
        self.assertEqual(
            self.records['messages']['0x44ce8e'],
            'Refusing to register signal ')

    def test_object_layout_pins(self):
        bodies = self.records['pinned_bodies']
        self.assertEqual(bodies['refresh']['size'], 679)
        self.assertEqual(bodies['getobj']['size'], 127)
        self.assertEqual(self.records['pins']['0x5cfcfbb'],
                         '488b9038010000')
        self.assertEqual(self.records['pins']['0x5cfcfc2'],
                         'f048ff8040010000')
        self.assertEqual(self.records['pins']['0x5ce8870'],
                         'be50010000')

    def test_locations(self):
        locs = self.records['locations']
        self.assertTrue(
            locs['0x64c6e80']['path'].endswith(
                'z_vendor/tokio/src/signal/registry.rs'))
        self.assertEqual(locs['0x64c6e80']['line'], 73)
        self.assertTrue(
            locs['0x64c6498']['path'].endswith(
                'z_vendor/tokio/src/process/unix/orphan.rs'))
        self.assertEqual(locs['0x64c6498']['line'], 118)

    def test_slots(self):
        slots = self.records['slots']
        self.assertEqual(slots['0x64dfe78'],
                         {'kind': 'glob_dat', 'value': 'close'})
        self.assertEqual(slots['0x64ec8a0'],
                         {'kind': 'glob_dat', 'value': 'waitpid'})
        self.assertEqual(slots['0x64e01e8']['value'], '5ce57c0')
        self.assertEqual(slots['0x64ecc58']['value'], '5ce8860')

    def test_manifest(self):
        import hashlib
        manifest = (PACKET / 'MANIFEST.sha256').read_text()
        listed = {}
        for line in manifest.splitlines():
            digest, name = line.split('  ', 1)
            listed[name] = digest
        for name, digest in listed.items():
            raw = (PACKET / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             digest, name)


if __name__ == '__main__':
    unittest.main()
