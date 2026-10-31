"""RE-001 consumer downstream: pinned record, tamper controls, determinism."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import bincode_varint as bv  # noqa: E402
import consumer_downstream as cd  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-001-consumer-downstream-94'
OUTPUT_SHA256 = '884c1413e5942e6415fc7a864be44e8ccf534583ad36056aca3bcf9714f542ae'
_DATA = None


def data():
    global _DATA
    if _DATA is None:
        _DATA = bv.TARGET.read_bytes()
    return _DATA


def mutate(va, new):
    buf = bytearray(data())
    offset = bv.va_to_off(bv.sections(data()), va)
    buf[offset:offset + len(new)] = new
    return bytes(buf)


def scan_mutated(buf):
    return cd.scan(buf, expected_sha256=hashlib.sha256(buf).hexdigest())


def relocation_offset(slot):
    secs = bv.sections(data())
    r = secs['.rela.dyn']
    for offset in range(r['offset'], r['offset'] + r['size'], 24):
        if struct.unpack_from('<Q', data(), offset)[0] == slot:
            return offset
    raise AssertionError(f'no relocation for {slot:#x}')


class Pinned(unittest.TestCase):
    def test_committed_record(self):
        self.assertEqual((PACKET / 'records.json').read_bytes(),
                         cd.render(cd.scan(data())).encode())

    def test_exact_values(self):
        r = cd.scan(data())
        self.assertEqual([(f['start_va'], f['size']) for f in r['functions']],
                         [('0x1346100', 130), ('0x157b810', 44)])
        self.assertEqual([o['slot_va'] for o in r['functions'][0]['operands']],
                         ['0x576e030', '0x576dfd8'])
        self.assertEqual([o['relocation']['target_va'] for o in r['functions'][0]['operands']],
                         ['0x54c5620', '0x54c06b0'])
        self.assertEqual(r['functions'][1]['operands'][0]['slot_va'], '0x57706e0')
        self.assertEqual(r['functions'][1]['operands'][0]['relocation']['target_va'], '0x4ecdcf0')

    def test_cli_check(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/consumer_downstream.py'),
                                 '--check', str(PACKET / 'records.json')],
                                check=True, capture_output=True)
        self.assertEqual(result.stdout, b'Consumer downstream extents reproduce exactly.\n')


class Negative(unittest.TestCase):
    def test_digest(self):
        buf = bytearray(data())
        buf[0x100] ^= 1
        with self.assertRaisesRegex(bv.EvidenceError, 'SHA-256'):
            cd.scan(bytes(buf))

    def test_anchor_byte(self):
        with self.assertRaisesRegex(bv.EvidenceError, '0x134610d'):
            scan_mutated(mutate(0x134610D, bytes.fromhex('41bf02000000')))

    def test_slot_addend(self):
        offset = relocation_offset(0x576E030)
        buf = bytearray(data())
        struct.pack_into('<q', buf, offset + 16, 0x54C5621)
        with self.assertRaisesRegex(bv.EvidenceError, '0x576e030'):
            scan_mutated(bytes(buf))

    def test_operand_retarget(self):
        offset = bv.va_to_off(bv.sections(data()), 0x157B836)
        buf = bytearray(data())
        struct.pack_into('<i', buf, offset + 2, 0x57706E1 - (0x157B836 + 6))
        with self.assertRaisesRegex(bv.EvidenceError, '0x157b836: rip operand'):
            scan_mutated(bytes(buf))


class Determinism(unittest.TestCase):
    def test_hashseed(self):
        outs = {subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/consumer_downstream.py')],
                               env=dict(os.environ, PYTHONHASHSEED=seed), check=True,
                               capture_output=True).stdout for seed in ('0', '7', '4242')}
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)


if __name__ == '__main__':
    unittest.main()

