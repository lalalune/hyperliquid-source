"""Target-bound node115 entry (_start) and Rust main handoff, with byte counterfactuals."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import entry_start_static as subject
from elf_index import sections


class EntryStartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not subject.TARGET.is_file() or subject.TARGET.stat().st_size != subject.SIZE:
            raise unittest.SkipTest('materialized node115 required')
        cls.data = subject.TARGET.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != subject.SHA:
            raise ValueError('wrong capture')
        cls.secs = sections(cls.data)
        cls.report = subject.analyze(cls.data)

    def offset(self, va):
        s = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def mutate(self, va, value=None):
        b = bytearray(self.data)
        o = self.offset(va)
        b[o] = b[o] ^ 1 if value is None else value
        return b

    def test_full_native_regeneration_and_retained_records(self):
        self.assertEqual(self.report, json.loads((subject.PACKET / 'records.json').read_text()))
        self.assertEqual(sum(x['bytes'] for x in self.report['owners']), 77)
        self.assertEqual(self.report['entry_va'], '0x1419300')
        for owner in self.report['owners']:
            self.assertTrue(owner['has_fde'])
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            subject.generate(subject.TARGET, out)
            for p in out.iterdir():
                self.assertEqual(p.read_bytes(), (subject.PACKET / p.name).read_bytes(), p.name)

    def test_resolved_handoff_targets_and_argument_map(self):
        h = self.report['start_handoff']
        self.assertEqual(h['callee'], '__libc_start_main@GLIBC_2.34')
        self.assertEqual(h['relocation'], 'R_X86_64_GLOB_DAT')
        self.assertEqual(h['arguments']['rdi_main'], '0x2cef8f0')
        m = self.report['main_shim']
        self.assertEqual(m['callee'], 'std::rt::lang_start_internal')
        self.assertEqual(m['relocation'], 'R_X86_64_RELATIVE')
        self.assertEqual((m['callee_body'], m['arguments']['main_dyn_fn_data'],
                          m['arguments']['main_dyn_fn_vtable']),
                         ('0x5c99970', '0x2cd8370', '0x6440b48'))
        # The displacement decode is reproduced independently of the record.
        self.assertEqual(subject.rip_target(self.data, 0x1419318, 3), 0x2cef8f0)
        self.assertEqual(subject.rip_target(self.data, 0x141931f, 2), 0x64df458)
        self.assertEqual(subject.rip_target(self.data, 0x2cef90f, 2), 0x64e6c30)

    def test_real_opcode_and_rip_displacement_counterfactuals(self):
        # One flipped opcode byte in either function is rejected.
        for site, _ in subject.START_ANCHORS + subject.MAIN_ANCHORS:
            with self.assertRaisesRegex(ValueError, 'opcode changed'):
                subject.analyze(self.mutate(site))
        # A flipped displacement byte retargets the resolved call/lea and is rejected.
        for site, opcode_len, pattern in [(0x1419318, 3, '_start RIP target'),
                                          (0x141931f, 2, '_start RIP target'),
                                          (0x2cef8f7, 3, 'main RIP target'),
                                          (0x2cef902, 3, 'main RIP target'),
                                          (0x2cef90f, 2, 'main RIP target')]:
            with self.assertRaisesRegex(ValueError, pattern):
                subject.analyze(self.mutate(site + opcode_len))
    def test_body_digest_pins_bytes_outside_opcode_anchors(self):
        # The recorded per-function sha256 covers bytes the opcode/RIP checks skip
        # (e.g. unanalyzed operand bytes). Patch START_RIP so the RIP gate passes
        # and the body-digest gate is the one that rejects the altered disp byte.
        changed = self.mutate(0x141931b)  # first displacement byte of lea rdi
        retargeted = subject.rip_target(changed, 0x1419318, 3)
        saved = subject.START_RIP[0x1419318]
        subject.START_RIP[0x1419318] = ('main', retargeted)
        try:
            with self.assertRaisesRegex(ValueError, 'instruction bytes changed'):
                subject.analyze(changed)
        finally:
            subject.START_RIP[0x1419318] = saved

    def test_entry_point_and_relocation_controls(self):
        # A changed ELF e_entry no longer names _start.
        bad = bytearray(self.data)
        struct.pack_into('<Q', bad, 24, subject.START[0] + 1)
        with self.assertRaisesRegex(ValueError, 'e_entry is not'):
            subject.analyze(bad)
        # Relocation slots for the two callees must keep type, symbol and addend.
        sec = next(s for s in self.secs if s['name'] == '.rela.dyn')
        offsets = {struct.unpack_from('<Q', self.data, p)[0]: p
                   for p in range(sec['offset'], sec['offset'] + sec['size'], 24)}
        changed = bytearray(self.data)
        changed[offsets[subject.LIBC_SLOT] + 8] ^= 1  # perturb r_info (type/symbol)
        with self.assertRaisesRegex(ValueError, 'libc_start_main'):
            subject.analyze(changed)
        changed = bytearray(self.data)
        changed[offsets[subject.LANG_SLOT] + 16] ^= 1  # perturb RELATIVE addend
        with self.assertRaisesRegex(ValueError, 'lang_start_internal relocation changed'):
            subject.analyze(changed)

    def test_public_identity_gate_precedes_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'bad'
            out = Path(directory) / 'out'
            p.write_bytes(self.mutate(0x1419300))
            for path in [p, subject.ROOT / 'artifacts/visor/captured/hl-visor']:
                with self.assertRaisesRegex(ValueError, 'pinned node115'):
                    subject.generate(path, out)
            p.write_bytes(self.data[:4096])
            with self.assertRaisesRegex(ValueError, 'pinned node115'):
                subject.generate(p, out)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
