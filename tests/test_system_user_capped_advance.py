"""Instruction-grounded controls for the static node #94 capped advance bind.

No captured machine code is executed. The interpreter below implements the
small decoded instruction vocabulary separately from the high-level model.
Structural corruptions use a private copy-on-write mmap, never a second
whole-binary bytearray and never a write to the artifact.
"""

from contextlib import contextmanager
import itertools
import json
import mmap
from pathlib import Path
import random
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import system_user_capped_advance as bind  # noqa: E402


def interpret(program, old, offset, extra):
    """Execute decoded operations in a tiny abstract register/memory machine.

    This is an instruction-level Python evaluator, not native execution or a
    substitute for a separately authorized differential harness.
    """
    m = bind.MASK
    regs = dict(rax=0xfeedface, rsi=offset, rdi=0x1000, rcx=0xdeadbeef, rsp=0x2000)
    mem = {0x1000: old, 0x1008: extra}
    cf = zf = False
    ip = program[0].va
    by_va = {i.va: i for i in program}
    stores = []
    stage = None

    def get(arg):
        if isinstance(arg, int):
            return arg
        if arg == 'qword [rdi]':
            return mem[regs['rdi']]
        if arg == 'qword [rdi+0x8]':
            return mem[regs['rdi'] + 8]
        return regs[arg]

    def put(dest, value):
        if dest == 'qword [rdi]':
            mem[regs['rdi']] = value & m
            stores.append((regs['rdi'], value & m))
        elif dest == 'al':
            regs['rax'] = (regs['rax'] & ~0xff) | (value & 0xff)
        elif dest == 'eax':
            regs['rax'] = value & 0xffffffff
        else:
            regs[dest] = value & m

    for _ in range(len(program) + 1):
        ins = by_va[ip]
        ip = ins.after
        op, args = ins.op, ins.args
        if op == 'push':
            regs['rsp'] -= 8
            mem[regs['rsp']] = get(args[0])
        elif op == 'pop':
            put(args[0], mem[regs['rsp']])
            regs['rsp'] += 8
        elif op in ('mov', 'lea'):
            put(args[0], get(args[1]))
        elif op == 'add':
            result = get(args[0]) + get(args[1])
            cf, zf = result > m, (result & m) == 0
            put(args[0], result)
            stage = 'old_plus_offset' if args[0] == 'rsi' else 'plus_extra'
        elif op == 'inc':
            result = (get(args[0]) + 1) & m
            zf = result == 0  # INC preserves CF.
            put(args[0], result)
            stage = 'plus_one'
        elif op == 'cmp':
            left, right = get(args[0]), get(args[1])
            cf, zf = left < right, left == right
        elif op in ('jb', 'je', 'jbe'):
            taken = {'jb': cf, 'je': zf, 'jbe': cf or zf}[op]
            if taken:
                ip = args[0]
        elif op == 'cmovb':
            if cf:
                put(args[0], get(args[1]))
        elif op == 'call_slot':
            assert args == (bind.SLOT,) and regs['rdi'] == bind.LOCATION
            assert not stores and mem[0x1000] == old and mem[0x1008] == extra
            assert regs['rsp'] == 0x1ff8
            return dict(outcome='transfer', stage=stage, stored=None)
        elif op == 'ret':
            assert regs['rsp'] == 0x2000 and mem[0x1008] == extra
            assert len(stores) == 1 and stores[0][0] == 0x1000
            return dict(outcome='return', stored=mem[0x1000], rax=regs['rax'], al=regs['rax'] & 0xff)
        else:
            raise AssertionError('Unexpected decoded operation')
    raise AssertionError('Unexpected cycle or missing terminal instruction')


class CappedAdvanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = bind.TARGET.open('rb')
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_READ)
        if len(cls.data) != bind.SIZE or bind.sha(cls.data) != bind.SHA256:
            cls.data.close()
            cls.handle.close()
            raise ValueError('Tests require the authenticated node #94 artifact')
        cls.image = bind.Image(cls.data)
        cls.records, cls.program = bind.analyze_structure(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def mutated(self, va, raw):
        off = self.image.offset(va, len(raw))
        with mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_COPY) as data:
            data[off:off + len(raw)] = raw
            yield data

    def rejects_structure(self, va, raw, message):
        with self.mutated(va, raw) as data:
            with self.assertRaisesRegex(ValueError, message):
                bind.analyze_structure(data)

    def relocation_file_offset(self, slot):
        row = next(r for r in self.records['relocations'] if int(r['slot_va'], 16) == slot)
        return self.image.by_name[row['section']]['offset'] + int(row['section_offset'], 16)

    def test_full_packet_verifies(self):
        self.assertEqual(bind.verify_packet(), self.records)

    def test_regenerates_byte_identically_without_external_tools(self):
        with tempfile.TemporaryDirectory() as tmp, patch('subprocess.run', side_effect=AssertionError('External process')):
            out = Path(tmp)
            bind.generate(out)
            for name in (*bind.GENERATED, 'verify.py', 'MANIFEST.sha256'):
                self.assertEqual((out / name).read_bytes(), (bind.PACKET / name).read_bytes(), name)
            self.assertEqual(bind.verify_packet(out), self.records)

    def test_readme_counts_and_all_generated_prose_equal_json(self):
        recorded = json.loads((bind.PACKET / 'records.json').read_text())
        self.assertEqual((bind.PACKET / 'README.md').read_text(), bind.render_readme(recorded))
        c = recorded['counts']
        self.assertEqual(c['instructions'], len(self.program))
        self.assertEqual(c['conditional_branches'], len(recorded['control_flow']['branches']))
        self.assertEqual(c['returns'], len(recorded['control_flow']['return_sites']))
        self.assertEqual(c['callees'], len(recorded['callees']))
        self.assertEqual(c['direct_e8_callers'], len(recorded['caller_census']['direct_e8_sites']))
        self.assertEqual(c['direct_e9_callers'], len(recorded['caller_census']['direct_e9_sites']))
        self.assertEqual(c['pointer_slots'], len(recorded['caller_census']['pointer_slots']))
        self.assertEqual(c['overflow_checks'], len(recorded['rule']['checked_stages']))
        self.assertEqual(c['vectors'], len(recorded['rule']['vectors']))

    def test_full_decode_covers_fde_without_padding(self):
        self.assertEqual(b''.join(i.raw for i in self.program), bind.BODY)
        self.assertEqual(self.program[-1].after, bind.END)
        self.assertEqual(self.program[0].va, bind.START)
        self.assertTrue(0x3000000 <= bind.START < 0x4000000)
        for left, right in zip(self.program, self.program[1:]):
            self.assertEqual(left.after, right.va)

    def test_hand_worked_vectors_agree_with_model_and_decoded_instructions(self):
        for vector in self.records['rule']['vectors']:
            inputs = vector['inputs']
            values = (inputs['old'], inputs['offset'], inputs['extra'])
            with self.subTest(label=vector['label']):
                self.assertEqual(bind.model(*values), vector['expected'])
                self.assertEqual(interpret(self.program, *values), vector['expected'])

    def test_boundary_cross_product_and_deterministic_unsigned_cases(self):
        edge = (0, 1, 28, 29, 30, 31, 255, 256, bind.MASK - 1, bind.MASK)
        rng = random.Random(94)
        inputs = itertools.chain(itertools.product(edge, repeat=3),
                                 (tuple(rng.getrandbits(64) for _ in range(3)) for _ in range(500)))
        for values in inputs:
            self.assertEqual(interpret(self.program, *values), bind.model(*values), values)

    def test_low_byte_write_does_not_zero_upper_rax(self):
        self.assertEqual(interpret(self.program, 255, 0, 0),
                         dict(outcome='return', stored=30, rax=0x11e, al=30))

    def test_each_overflow_exits_before_object_write(self):
        for inputs, stage in (((bind.MASK, 1, 0), 'old_plus_offset'),
                              ((bind.MASK, 0, 0), 'plus_one'),
                              ((0, 0, bind.MASK), 'plus_extra')):
            self.assertEqual(interpret(self.program, *inputs),
                             dict(outcome='transfer', stage=stage, stored=None))

    def test_model_rejects_out_of_domain_inputs(self):
        for values in ((-1, 0, 0), (0, 1 << 64, 0), (0, 0, 1.0), (True, 0, 0)):
            with self.assertRaises(ValueError):
                bind.model(*values)

    def test_wrong_digest_fails_public_entrypoint(self):
        # A same-size sparse temporary file avoids copying the binary.
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'wrong-target'
            with bad.open('wb') as handle:
                handle.truncate(bind.SIZE)
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                with bind.mapped(bad):
                    self.fail('Wrong digest accepted')

    def test_wrong_size_fails_public_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'short-target'
            bad.write_bytes(b'\x7fELF')
            with self.assertRaisesRegex(ValueError, 'size mismatch'):
                with bind.mapped(bad):
                    self.fail('Wrong size accepted')

    def test_changed_valid_instruction_rejected_beyond_digest_gate(self):
        # mov al,30 -> mov al,31 is valid x86 but a different rule.
        self.rejects_structure(bind.START + 0x25, b'\x1f', 'Function body changed')

    def test_unknown_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported instruction'):
            bind.decode_window(b'\x90' + bind.BODY[1:])

    def test_truncated_instruction_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Truncated instruction'):
            bind.decode_window(bind.BODY[:-1])

    def test_branch_into_instruction_rejected(self):
        body = bytearray(bind.BODY)
        body[5] = 0x35  # jb into the Location LEA's second byte.
        with self.assertRaisesRegex(ValueError, 'instruction boundary'):
            bind.decode_window(body)

    def test_changed_call_displacement_rejected(self):
        raw = bytearray(self.image.read(bind.START + 0x41, 6))
        raw[2] ^= 1
        self.rejects_structure(bind.START + 0x41, raw, 'Function body changed')

    def test_shifted_fde_start_rejected_beyond_digest_gate(self):
        field = self.image.by_name['.eh_frame']['address'] + 0x1b9f64 + 8
        before = struct.unpack('<i', self.image.read(field, 4))[0]
        self.rejects_structure(field, struct.pack('<i', before + 1), 'function FDE')

    def test_shortened_fde_extent_rejected(self):
        field = self.image.by_name['.eh_frame']['address'] + 0x1b9f64 + 12
        self.rejects_structure(field, struct.pack('<i', len(bind.BODY) - 1), 'FDE association')

    def test_changed_cie_association_rejected(self):
        field = self.image.by_name['.eh_frame']['address'] + 0x1b9f64 + 4
        delta = struct.unpack('<I', self.image.read(field, 4))[0]
        self.rejects_structure(field, struct.pack('<I', delta - 1), 'preceding CIE')

    def test_changed_padding_rejected(self):
        self.rejects_structure(bind.END, b'\x90', 'Padding changed')

    def test_changed_callee_body_rejected(self):
        self.rejects_structure(bind.CALLEE, b'\x90', 'Body SHA-256 changed')

    def test_wrong_callee_relocation_target_rejected(self):
        offset = self.relocation_file_offset(bind.SLOT)
        # .rela.dyn VA equals file offset in this artifact; resolve via section.
        section = self.image.by_name['.rela.dyn']
        va = section['address'] + offset - section['offset'] + 16
        self.rejects_structure(va, struct.pack('<q', bind.CALLEE + 1), 'relocation changed')

    def test_wrong_relocation_type_rejected(self):
        offset = self.relocation_file_offset(bind.SLOT)
        section = self.image.by_name['.rela.dyn']
        va = section['address'] + offset - section['offset'] + 8
        self.rejects_structure(va, struct.pack('<Q', 1), 'relocation changed')

    def test_wrong_source_relocation_rejected(self):
        offset = self.relocation_file_offset(bind.LOCATION)
        section = self.image.by_name['.rela.dyn']
        va = section['address'] + offset - section['offset'] + 16
        self.rejects_structure(va, struct.pack('<q', bind.PATH_VA + 1), 'relocation changed')

    def test_changed_location_line_rejected(self):
        self.rejects_structure(bind.LOCATION + 16, struct.pack('<I', 4), 'Location layout changed')

    def test_changed_source_path_rejected(self):
        self.rejects_structure(bind.PATH_VA + len(bind.SOURCE_PREFIX), b'x', 'source path changed')

    def test_full_text_direct_scan_is_empty(self):
        self.assertEqual(bind.scan_direct(self.data, self.image.by_name['.text'], {bind.START}), [])

    def test_direct_scan_handles_both_opcodes_signed_displacements_and_truncation(self):
        # Include a scan starting inside opaque bytes: this deliberately
        # demonstrates why nonempty results are only byte-pattern candidates.
        base = 0x1000
        raw = b'\xaa\xe8' + struct.pack('<i', -6) + b'\xe9' + struct.pack('<i', -11) + b'\xe8\x00'
        text = dict(address=base, offset=0, size=len(raw))
        found = bind.scan_direct(raw, text, {base})
        self.assertEqual(found, [dict(site_va='0x1001', opcode='0xe8', target_va='0x1000'),
                                 dict(site_va='0x1006', opcode='0xe9', target_va='0x1000')])

    def test_retained_semantic_corruption_rejected_even_with_updated_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / 'packet'
            shutil.copytree(bind.PACKET, packet)
            rec = json.loads((packet / 'records.json').read_text())
            rec['rule']['cap'] += 1
            (packet / 'records.json').write_text(json.dumps(rec, indent=2) + '\n')
            (packet / 'MANIFEST.sha256').write_bytes(bind.manifest_bytes(packet))
            with self.assertRaisesRegex(ValueError, 'Generated evidence mismatch'):
                bind.verify_packet(packet)

    def test_readme_count_corruption_rejected_even_with_updated_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / 'packet'
            shutil.copytree(bind.PACKET, packet)
            readme = (packet / 'README.md').read_text().replace('23 instructions', '24 instructions')
            self.assertNotEqual(readme, (packet / 'README.md').read_text())
            (packet / 'README.md').write_text(readme)
            (packet / 'MANIFEST.sha256').write_bytes(bind.manifest_bytes(packet))
            with self.assertRaisesRegex(ValueError, 'Generated evidence mismatch: README'):
                bind.verify_packet(packet)

    def test_manifest_whitelist_rejects_path_escape_and_extra_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / 'packet'
            shutil.copytree(bind.PACKET, packet)
            original = (packet / 'MANIFEST.sha256').read_text()
            for bad in ('../escape', '/absolute', 'unexpected.txt'):
                (packet / 'MANIFEST.sha256').write_text(original + '0' * 64 + '  ' + bad + '\n')
                with self.assertRaisesRegex(ValueError, 'Non-whitelisted'):
                    bind.check_manifest(packet)

    def test_manifest_duplicate_missing_and_wrong_hash_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            packet = Path(tmp) / 'packet'
            shutil.copytree(bind.PACKET, packet)
            original = (packet / 'MANIFEST.sha256').read_text().splitlines()
            for lines, message in ((original + original[:1], 'duplicate'),
                                   (original[1:], 'Incomplete'),
                                   (['0' * 64 + original[0][64:]] + original[1:], 'hash mismatch')):
                (packet / 'MANIFEST.sha256').write_text('\n'.join(lines) + '\n')
                with self.assertRaisesRegex(ValueError, message):
                    bind.check_manifest(packet)


if __name__ == '__main__':
    unittest.main()
