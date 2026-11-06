import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from tokio_waker_table import (ALLOC_SIZE, CLONE, DATA_OFF,
                               DEBUG_DROP, DEBUG_STUB, DEBUG_VTABLE,
                               DEBUG_VTABLE_SITES, DESTROY, DRIVER_WAKE,
                               DROP_SHIM, FLAG_FROM_BASE, FLAG_FROM_DATA,
                               FMT_SHIM, PACKET, PANIC_HELPER, SHA256,
                               SIZE, TARGET, TARGET_FROM_BASE,
                               TARGET_FROM_DATA, WAKE_BY_REF,
                               WAKE_CONSUME, WAKE_FWD, WAKER_TABLE,
                               analyze, hx, read)
from elf_index import sections


def payload(path):
    return json.loads(Path(path).read_text())


def offset_of(data, va):
    for s in sections(data):
        if (s['type'] != 8 and s['address'] <= va
                < s['address'] + s['size']):
            return s['offset'] + va - s['address']
    raise AssertionError('unmapped va')


class TokioWakerTableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.exists() or TARGET.stat().st_size != SIZE:
            raise unittest.SkipTest('pinned node115 target is not '
                                    'materialised')
        cls.data = TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != SHA256:
            raise unittest.SkipTest('target digest is not the '
                                    'pinned node115 distribution')
        cls.retained = payload(PACKET / 'records.json')
        cls.payload = analyze(cls.data)

    def mutated(self, va, delta, value):
        data = bytearray(self.data)
        data[offset_of(self.data, va) + delta] = value
        return bytes(data)

    def test_regeneration_matches_retained_packet(self):
        self.assertEqual(self.payload, self.retained)

    def test_manifest_matches_packet_files(self):
        lines = (PACKET / 'MANIFEST.sha256').read_text().splitlines()
        self.assertTrue(lines)
        for line in lines:
            digest, name = line.split('  ', 1)
            actual = hashlib.sha256(
                (PACKET / name).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, name)

    def test_debug_vtable_is_standalone(self):
        vt = self.payload['debug_vtable']
        self.assertEqual(vt['base'], hx(DEBUG_VTABLE))
        self.assertEqual(vt['drop'], hx(DEBUG_DROP))
        self.assertEqual(vt['size'], 8)
        self.assertEqual(vt['align'], 8)
        self.assertEqual(vt['debug_slot']['target'], hx(DEBUG_STUB))
        self.assertEqual(self.payload['answers']['extent_corrected'],
                         '0x20')
        self.assertEqual(vt['references'],
                         [hx(s) for s in DEBUG_VTABLE_SITES])

    def test_waker_table_field_order(self):
        fields = self.payload['raw_waker_vtable']['fields']
        self.assertEqual([f['field'] for f in fields],
                         ['clone', 'wake', 'wake_by_ref', 'drop'])
        self.assertEqual([f['target'] for f in fields],
                         [hx(CLONE), hx(WAKE_FWD), hx(WAKE_BY_REF),
                          hx(DROP_SHIM)])
        self.assertEqual([f['cell'] for f in fields],
                         [hx(WAKER_TABLE + 8 * i) for i in range(4)])
        self.assertEqual(self.payload['raw_waker_vtable']
                         ['references'], ['0x5cee5a7'])

    def test_offset_identities(self):
        self.assertEqual(FLAG_FROM_DATA + DATA_OFF, FLAG_FROM_BASE)
        self.assertEqual(TARGET_FROM_DATA + DATA_OFF,
                         TARGET_FROM_BASE)
        alloc = self.payload['allocation']
        self.assertEqual(alloc['size'], hx(ALLOC_SIZE))
        self.assertEqual(alloc['data_pointer_at'], hx(DATA_OFF))
        self.assertEqual(alloc['woken_flag_at'], hx(FLAG_FROM_BASE))
        self.assertEqual(alloc['wake_target_at'],
                         hx(TARGET_FROM_BASE))
        self.assertEqual(alloc['destroy'], hx(DESTROY))

    def test_wake_path_and_panic_format(self):
        wp = self.payload['wake_path']
        self.assertEqual(wp['consume_body'], hx(WAKE_CONSUME))
        self.assertEqual(wp['driver_wake_body'], hx(DRIVER_WAKE))
        self.assertEqual(wp['panic']['message'],
                         'failed to wake I/O driver')
        self.assertEqual(wp['panic']['line'], 272)
        pf = self.payload['panic_format_path']
        self.assertEqual(pf['helper'], hx(PANIC_HELPER))
        self.assertEqual(pf['slot_used'], '0x18')
        self.assertTrue(self.payload['raw_waker_vtable']['wake']
                        ['consumes_strong_ref'])
        self.assertFalse(self.payload['raw_waker_vtable']
                         ['wake_by_ref']['touches_count'])

    def test_mutation_of_clone_inc_is_rejected(self):
        # lock incq -0x80(%rdi): f0 48 ff 47 80 -> flip the opcode
        bad = self.mutated(CLONE, 2, 0xFE)
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_mutation_of_wake_by_ref_flag_is_rejected(self):
        # xchg %al,0x150(%rdi): ... 50 01 00 00 -> bump the offset
        blob = read(self.data, WAKE_BY_REF, 0x88)
        at = blob.find(b'\x50\x01\x00\x00')
        self.assertGreaterEqual(at, 0)
        bad = self.mutated(WAKE_BY_REF, at, 0x51)
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_mutation_of_destroy_size_is_rejected(self):
        # mov $0x300,%esi: be 00 03 00 00 -> change the size
        blob = read(self.data, DESTROY, 0x185)
        at = blob.find(b'\xbe\x00\x03\x00\x00')
        self.assertGreaterEqual(at, 0)
        bad = self.mutated(DESTROY, at + 2, 0x04)
        with self.assertRaises(ValueError):
            analyze(bad)

    def test_mutation_of_fmt_shim_slot_is_rejected(self):
        # mov 0x18(%rcx),%rcx: 48 8b 49 18 -> move the slot
        bad = self.mutated(FMT_SHIM, 3, 0x10)
        with self.assertRaises(ValueError):
            analyze(bad)


if __name__ == '__main__':
    unittest.main()
