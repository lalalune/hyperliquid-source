"""Corruption controls against the actual node #94 static observation."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from artifacts import ROOT, check
import heartbeat_status
from heartbeat_status import direct_callers, mapped, relocations, static_controls


class HeartbeatStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = ROOT / 'artifacts/node/94/hl-node'
        item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == 'artifacts/node/94/hl-node')
        check(binary, item)
        cls.data = binary.read_bytes()

    def test_real_target_controls(self):
        self.assertEqual(len(static_controls(self.data)), 18)
        self.assertEqual(len(relocations(self.data)), 5)

    def test_real_branch_data_and_consumer_corruptions(self):
        # Invoke controls below the whole-artifact hash gate, so each rejection
        # demonstrates the relevant evidence check rather than only SHA mismatch.
        for va in [0x4726AC9, 0x4726B42, 0x4726B4A, 0x4726B54,
                   0x4726BC3, 0x4726C26, 0x4726C87, 0x4726CD3,
                   0x20ACD8, 0x6FB82A, 0x1447181, 0x4876FE3]:
            with self.subTest(va=hex(va)):
                changed = bytearray(self.data)
                offset, _ = mapped(changed, va, 1)
                changed[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'control changed'):
                    static_controls(changed)

    def test_real_elapsed_relocation_retarget_is_rejected(self):
        changed = bytearray(self.data)
        # Locate the authenticated RELA triple without assuming its file offset.
        import struct
        needle = struct.pack('<QQq', 0x576E8C0, 8, 0x1447130)
        offset = changed.find(needle)
        self.assertGreaterEqual(offset, 0)
        changed[offset + 16] ^= 1
        with self.assertRaisesRegex(ValueError, 'relocation targets changed'):
            relocations(changed)

    def test_callers_are_decoded_direct_calls_not_address_mentions(self):
        self.assertEqual(direct_callers([
            ' 4876fd9:\te8 72 fa ea ff       \tcall   4726a50 <label>',
            ' 487734c:\te8 ff f6 ea ff       \tcall   4726a50 <label>',
            ' 4726a50: 55 push %rbp',
            ' 123: ff d3 call *%rbx # 4726a50',
        ]), [0x4876FD9, 0x487734C])


_FRAMES = '\n'.join(
    '0000000000000000 0000000000000000 0000000000000000 FDE cie=0000000000000000 '
    f'pc={a:016x}..{b:016x}'
    for a, b in [(0x4726A50, 0x4726D2C), (0x4876F90, 0x48774B0), (0x1447130, 0x14472A0)]) + '\n'
_RELOCATIONS = ('000000000576e488  0000000000000006 R_X86_64_GLOB_DAT '
                '0000000000000000 memcmp@GLIBC_2.2.5 + 0\n')
_FULL_TEXT = io.StringIO(
    ' 4876fd9:\te8 72 fa ea ff       \tcall   4726a50 <label>\n'
    ' 487734c:\te8 ff f6 ea ff       \tcall   4726a50 <label>\n')


class _FakePopen:
    """Records constructor kwargs; serves canned full-.text disassembly."""

    instances = []

    def __init__(self, cmd, **kwargs):
        self.kwargs = kwargs
        self.stdout = io.StringIO(_FULL_TEXT.getvalue())
        _FakePopen.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def wait(self):
        return 0


class HeartbeatOutputPinTests(unittest.TestCase):
    """The observed/ packet is pinned byte-for-byte by MANIFEST.sha256, so the
    writes in run() must not depend on the host's default encoding or newline
    translation: on a Windows text-mode host a bare write_text rewrites every
    LF as CRLF and all six pinned hashes break. run() is driven here with
    stubbed tool output so the pin is exercised without the LFS binary."""

    def test_outputs_are_byte_pinned(self):
        writes, tool_calls = [], []
        real_write_text = Path.write_text

        def recording_write_text(path, data, *args, **kwargs):
            writes.append((path.name, kwargs))
            return real_write_text(path, data, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'hl-node'
            binary.write_bytes(b'fixture')
            output = root / 'observed'

            def fake_check_output(cmd, **kwargs):
                tool_calls.append(kwargs)
                if cmd[0] == 'readelf' and '-wf' in cmd:
                    return _FRAMES
                if cmd[0] == 'readelf':
                    return _RELOCATIONS
                return f'{binary}:\tfile format elf64-x86-64\n  4726a50:\t55\tpush %rbp\n'

            with mock.patch.object(heartbeat_status, 'check', lambda path, item: None), \
                    mock.patch.object(heartbeat_status, 'static_controls', lambda data: []), \
                    mock.patch.object(heartbeat_status, 'relocations', lambda data: [
                        {'slot_va': '0x576e488', 'type': 6, 'symbol_index': 1, 'addend': '0x0'}]), \
                    mock.patch.object(heartbeat_status, 'mapped', lambda data, va, size: (0, bytes(size))), \
                    mock.patch.object(heartbeat_status.subprocess, 'check_output', fake_check_output), \
                    mock.patch.object(heartbeat_status.subprocess, 'Popen', _FakePopen), \
                    mock.patch.object(Path, 'write_text', recording_write_text):
                result = heartbeat_status.run(binary, output)

            self.assertEqual(result['fde_record_count'], 3)
            names = {name for name, _ in writes}
            self.assertEqual(names, {'relocations.txt', 'status.objdump.txt',
                                     'consumer.objdump.txt', 'elapsed-helper.objdump.txt',
                                     'frames.txt', 'records.json'})
            for name, kwargs in writes:
                with self.subTest(write=name):
                    self.assertEqual(kwargs.get('encoding'), 'utf-8')
                    self.assertEqual(kwargs.get('newline'), '\n')
            self.assertEqual(len(_FakePopen.instances), 1)
            for kwargs in tool_calls + [_FakePopen.instances[0].kwargs]:
                with self.subTest(tool_call=kwargs):
                    self.assertEqual(kwargs.get('encoding'), 'utf-8')
            frames = (output / 'frames.txt').read_bytes()
            self.assertEqual(hashlib.sha256(frames).hexdigest(),
                             hashlib.sha256(_FRAMES.encode('utf-8')).hexdigest())
            for path in sorted(output.iterdir()):
                self.assertNotIn(b'\r', path.read_bytes(), path.name)
            records = json.loads((output / 'records.json').read_text())
            self.assertEqual(records['fde_record_count'], 3)
            self.assertTrue((output / 'records.json').read_bytes().endswith(b'\n'))
            status = (output / 'status.objdump.txt').read_text()
            self.assertIn('<authenticated-node94>', status)
            self.assertNotIn(str(binary), status)
