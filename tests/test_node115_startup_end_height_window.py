"""Operative static-byte controls; never execute or interpret captured code.

The CLI always requires the complete target identity. These tests deliberately
call the inner guard below that admission to distinguish a real instruction,
CFI, relocation or data rejection from a generic digest failure.
"""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-012-node115-startup-end-height-window'
SPEC = importlib.util.spec_from_file_location('startup_window_collect', PACKET / 'collect.py')
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class StartupWindowEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = collector.read_target(ROOT / 'artifacts/node/115/hl-node')
        cls.image = collector.Image(cls.data)
        cls.obligations = collector.obligations()

    def changed(self, address, replacement):
        data = bytearray(self.data)
        offset = self.image.offset(address, len(replacement))
        data[offset:offset + len(replacement)] = replacement
        return data

    def test_admission_precedes_output_and_tool_selection(self):
        changed = bytearray(self.data)
        changed[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'not-created'
            with patch.object(collector, 'select_tool') as tool, patch.object(collector.subprocess, 'run') as child:
                with self.assertRaisesRegex(ValueError, 'node115 identity mismatch'):
                    collector.collect(changed, destination)
                tool.assert_not_called()
                child.assert_not_called()
            self.assertFalse(destination.exists())

    def test_capture_as_decoder_is_rejected_without_spawning(self):
        with patch.object(collector.os, 'access', return_value=True), patch.object(collector.subprocess, 'run') as child:
            with self.assertRaisesRegex(ValueError, 'captured binary is not an objdump provider'):
                collector.select_tool(str(ROOT / 'artifacts/node/115/hl-node'))
            child.assert_not_called()

    def test_inner_accepts_original_with_exact_scope(self):
        self.assertEqual(collector.validate_inner(self.data), {
            'bodies': 6, 'bytes': 5492, 'rows': 1294, 'semantic_control_sites': 54,
            'transfers': 281, 'rip_edges': 69, 'relative_bindings': 22,
            'imports': 1, 'data_spans': 13, 'relocation_records_scanned': 61001,
        })

    def test_all_named_semantic_byte_controls_reach_their_own_guard(self):
        changed = bytearray(self.data)
        for entry in self.obligations['semantic_controls']:
            pc, raw = int(entry['pc'], 16), bytes.fromhex(entry['raw'])
            for delta in sorted({0, len(raw) - 1}):
                with self.subTest(site=entry['id'], pc=entry['pc'], byte=delta):
                    offset = self.image.offset(pc + delta, 1)
                    changed[offset] ^= 1
                    expected = f'instruction {entry["id"]} at {pc:#x}'
                    with self.assertRaisesRegex(ValueError, '^' + re.escape(expected) + '$'):
                        collector.validate_inner(changed)
                    changed[offset] ^= 1

    def test_near_width_and_drain_file_height_call_changes_are_detected(self):
        # Turn the two-byte JO into a six-byte near JO with the same destination.
        # This preserves the textual branch destination but changes its extent.
        pc, target = 0x543db50, 0x543db84
        changed = self.changed(pc, b'\x0f\x80' + struct.pack('<i', target - pc - 6))
        with self.assertRaisesRegex(ValueError, '^instruction P006 at 0x543db50$'):
            collector.validate_inner(changed)
        # A complete real drain CALL now points to file-height instead of front-next.
        pc = 0x543db95
        changed = self.changed(pc, b'\xe8' + struct.pack('<i', 0x595b520 - pc - 5))
        with self.assertRaisesRegex(ValueError, '^instruction P039 at 0x543db95$'):
            collector.validate_inner(changed)

    def test_cfi_records_and_index_are_not_only_body_hashes(self):
        seen = set()
        for body in self.obligations['bodies']:
            for kind in ('fde', 'cie'):
                va = int(body[kind + '_va'], 16)
                if (va, kind) in seen:
                    continue
                seen.add((va, kind))
                raw = bytes.fromhex(body[kind + '_raw'])
                for delta in sorted({4, len(raw) - 1}):
                    with self.subTest(kind=kind, va=hex(va), byte=delta):
                        changed = self.changed(va + delta, bytes([raw[delta] ^ 1]))
                        with self.assertRaisesRegex(ValueError, 'full ' + kind.upper() + ' raw bytes'):
                            collector.validate_inner(changed)
        s = self.image.section('.eh_frame_hdr')
        raw = self.image.read(s[3], s[5])
        wanted = int(self.obligations['bodies'][0]['start'], 16)
        for i in range(struct.unpack_from('<I', raw, 8)[0]):
            if s[3] + struct.unpack_from('<i', raw, 12 + 8 * i)[0] == wanted:
                va = s[3] + 16 + 8 * i
                original = self.image.read(va, 4)
                changed = self.changed(va, bytes([original[0] ^ 1]) + original[1:])
                with self.assertRaisesRegex(ValueError, 'FDE-header binding'):
                    collector.validate_inner(changed)
                break
        else:
            self.fail('selected FDE index absent in authenticated target')

    def test_relative_symbol_type_addend_and_overlay_controls(self):
        for record in self.obligations['relative_bindings']:
            va = int(record['record_va'], 16)
            for delta in (8, 12, 16):
                with self.subTest(slot=record['slot'], field=delta):
                    byte = self.image.read(va + delta, 1)[0]
                    changed = self.changed(va + delta, bytes([byte ^ 1]))
                    # Type 8->9 is refused by the width taxonomy; symbol/addend
                    # reach the selected record obligation instead.
                    message = 'unsupported RELA width/type' if delta == 8 else 'RELATIVE record/overlap'
                    with self.assertRaisesRegex(ValueError, message):
                        collector.validate_inner(changed)
        first = self.obligations['relative_bindings'][0]
        va = int(first['record_va'], 16)
        changed = self.changed(va, struct.pack('<Q', 0x543db64))
        with self.assertRaisesRegex(ValueError, 'relocation overlays selected code'):
            collector.validate_inner(changed)
        # A second record partially covers an already-bound slot.
        section = self.image.section('.rela.dyn')
        used = {int(r['record_va'], 16) for r in self.obligations['relative_bindings']}
        spare = next(v for v in range(section[3], section[3] + section[5], 24) if v not in used)
        changed = self.changed(spare, struct.pack('<QQq', int(first['slot'], 16) + 1, 8, 0))
        with self.assertRaisesRegex(ValueError, 'RELATIVE record/overlap'):
            collector.validate_inner(changed)

    def test_data_and_import_raw_bindings(self):
        for va, entry in self.obligations['data'].items():
            raw = bytes.fromhex(entry['raw'])
            with self.subTest(data=va):
                changed = self.changed(int(va, 16) + len(raw) - 1, bytes([raw[-1] ^ 1]))
                with self.assertRaisesRegex(ValueError, 'data anchor'):
                    collector.validate_inner(changed)
        imported = self.obligations['imports'][0]
        for key, delta, message in [('plt', 2, 'PLT raw stub'), ('symbol_va', 4, 'import symbol bytes'),
                                    ('name_va', 0, 'import name bytes')]:
            va = int(imported[key], 16) + delta
            changed = self.changed(va, bytes([self.image.read(va, 1)[0] ^ 1]))
            with self.subTest(import_field=key), self.assertRaisesRegex(ValueError, message):
                collector.validate_inner(changed)
        r = imported['relocation']
        va = int(r['record_va'], 16) + 12
        changed = self.changed(va, bytes([self.image.read(va, 1)[0] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'import relocation'):
            collector.validate_inner(changed)

    def test_elf_mapping_ambiguity_and_offset_disagreement(self):
        start = int(self.obligations['bodies'][0]['start'], 16)
        changed = bytearray(self.data)
        so = struct.unpack_from('<Q', changed, 40)[0]
        index = next(i for i, s in enumerate(self.image.sh) if s[1] != 8 and s[2] & 2 and
                     s[3] <= start < s[3] + s[5])
        struct.pack_into('<Q', changed, so + index * 64 + 24, self.image.sh[index][4] + 1)
        with self.assertRaisesRegex(ValueError, 'offset disagreement'):
            collector.validate_inner(changed)
        changed = bytearray(self.data)
        po = struct.unpack_from('<Q', changed, 32)[0]
        load = next(p for p in self.image.ph if p[0] == 1 and p[3] <= start < p[3] + p[5])
        other = next(i for i, p in enumerate(self.image.ph) if p[0] != 1)
        struct.pack_into('<IIQQQQQQ', changed, po + other * 56, *load)
        with self.assertRaisesRegex(ValueError, 'nonunique or missing PT_LOAD/section mapping'):
            collector.validate_inner(changed)

    def test_missing_duplicate_and_resegmented_native_rows(self):
        body = self.obligations['bodies'][0]
        start = int(body['start'], 16)
        raw = (PACKET / f'native/{start:x}.objdump.txt').read_bytes()
        lines = raw.splitlines(keepends=True)
        i = next(i for i, line in enumerate(lines) if collector.ROW.match(line.decode()))
        for altered in (b''.join(lines[:i] + lines[i+1:]), b''.join(lines[:i] + [lines[i]] + lines[i:])):
            with self.assertRaisesRegex(ValueError, 'partition disagreement'):
                collector.decode_export(altered, self.image, body, self.obligations)
        # Correct contiguous bytes are not sufficient if decoder instruction
        # boundaries change: combine the first two rows into one fake row.
        a, b = [collector.ROW.match(lines[j].decode()) for j in (i, i+1)]
        merged = f' {a[1]}:\t{a[2]} {b[2]}\tfake-row\n'.encode()
        altered = b''.join(lines[:i] + [merged] + lines[i+2:])
        with self.assertRaisesRegex(ValueError, 'boundary/width disagreement'):
            collector.decode_export(altered, self.image, body, self.obligations)

    def test_native_failure_preserves_streams_and_exit_before_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / 'fake-provider'
            tool.write_bytes(b'not executed')
            out = Path(directory) / 'fresh'
            version = subprocess.CompletedProcess([], 0, b'GNU objdump test provider\n', b'')
            failed = subprocess.CompletedProcess([], 9, b'partial native output\n', b'actual decoder failure\n')
            with patch.object(collector, 'select_tool', return_value=(tool, collector.digest(tool.read_bytes()))), \
                    patch.object(collector.subprocess, 'run', side_effect=[version, failed]):
                with self.assertRaisesRegex(ValueError, 'GNU tool failure/nonempty stderr'):
                    collector.collect(self.data, out)
            commands = json.loads((out / 'commands.json').read_text())
            self.assertEqual(commands[-1]['exit_code'], 9)
            self.assertEqual((out / commands[-1]['stdout_file']).read_bytes(), failed.stdout)
            self.assertEqual((out / commands[-1]['stderr_file']).read_bytes(), failed.stderr)
            self.assertFalse((out / 'records.json').exists())

    def test_complete_six_body_native_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'fresh'
            result = collector.collect(self.data, out)
            self.assertEqual(result['facts']['bytes'], 5492)
            self.assertEqual(result['facts']['rows'], 1294)
            self.assertEqual(collector.compare_packet(out)['exact_native_files'], 12)

    def test_provenance_exception_is_narrow_and_paths_are_not_metadata_commands(self):
        names = ['records.json', 'commands.json', 'objdump-version.txt', 'objdump-version.stderr']
        names += [f'native/{int(b["start"], 16):x}.{suffix}' for b in self.obligations['bodies']
                  for suffix in ('objdump.txt', 'stderr')]
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            for name in names:
                (out / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(PACKET / name, out / name)
            record = json.loads((out / 'records.json').read_text())
            record['tool_sha256'] = '0' * 64
            (out / 'records.json').write_text(json.dumps(record))
            self.assertTrue(collector.compare_packet(out)['semantic_records_equal'])
            record['transfers'][0]['raw'] = '90'
            (out / 'records.json').write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, 'record mismatch'):
                collector.compare_packet(out)
            shutil.copyfile(PACKET / 'records.json', out / 'records.json')
            commands = json.loads((out / 'commands.json').read_text())
            commands[0]['stdout_file'] = '../must-not-read'
            (out / 'commands.json').write_text(json.dumps(commands))
            with self.assertRaisesRegex(ValueError, 'command identity'):
                collector.compare_packet(out)
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            collector.load_json('{"a":1,"a":2}')


if __name__ == '__main__':
    unittest.main()
