"""Unit tests for tools/target_cpu_features.py (synthetic ELFs, no LFS required)."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from target_cpu_features import classify_functions, decode_one, scan_text
from fde_extents import eh_frame_records
from elf_index import sections

TEXT, HDR, FRAME = 0x1000, 0x2000, 0x3000
OFFSET = {TEXT: 0x400, HDR: 0x500, FRAME: 0x600}
SHOFF = 0x800


def sdata4(value):
    return struct.pack('<i', value)


def build_elf(bodies):
    """bodies: list of (start_va, bytes). Each becomes one FDE in .text."""
    frame, layout = bytearray(), {'cie': None, 'fde': []}

    def record(make_body):
        start = len(frame)
        body = make_body(FRAME + start + 4)
        body += b'\0' * (-len(body) % 4)
        frame.extend(struct.pack('<I', len(body)) + body)
        return start

    def cie_body(va):
        head = struct.pack('<I', 0) + b'\1zR\0' + bytes([1, 0x78, 16])
        return head + b'\1\x1b'

    layout['cie'] = record(cie_body)
    cie_va = FRAME + layout['cie']
    for start_va, blob in bodies:
        def body(va, start_va=start_va, size=len(blob), cie_va=cie_va):
            out = struct.pack('<I', va - cie_va) + sdata4(start_va - (va + 4)) + struct.pack('<I', size)
            return out + b'\0'
        layout['fde'].append(record(body))
    frame.extend(b'\0' * 4)

    rows = sorted((va, FRAME + off) for (va, _), off in zip(bodies, layout['fde']))
    header = bytes([1, 0x1b, 3, 0x3b]) + sdata4(FRAME - (HDR + 4)) + struct.pack('<I', len(rows))
    for start_va, fde_va in rows:
        header += sdata4(start_va - HDR) + sdata4(fde_va - HDR)

    text_size = max(va + len(blob) for va, blob in bodies) - TEXT + 16
    text = bytearray(b'\xcc' * text_size)
    for va, blob in bodies:
        off = va - TEXT
        text[off:off + len(blob)] = blob

    data = bytearray(SHOFF + 5 * 64)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, SHOFF)
    struct.pack_into('<HHH', data, 58, 64, 5, 1)
    names = b'\0.shstrtab\0.text\0.eh_frame_hdr\0.eh_frame\0'
    data[64:64 + len(names)] = names
    data[OFFSET[TEXT]:OFFSET[TEXT] + len(text)] = text
    data[OFFSET[HDR]:OFFSET[HDR] + len(header)] = header
    data[OFFSET[FRAME]:OFFSET[FRAME] + len(frame)] = frame
    table = [
        (0, 0, 0, 0, 0, 0),
        (names.index(b'.shstrtab'), 3, 0, 0, 64, len(names)),
        (names.index(b'.text'), 1, 6, TEXT, OFFSET[TEXT], len(text)),
        (names.index(b'.eh_frame_hdr'), 1, 2, HDR, OFFSET[HDR], len(header)),
        (names.index(b'.eh_frame\0'), 1, 2, FRAME, OFFSET[FRAME], len(frame)),
    ]
    for index, row in enumerate(table):
        struct.pack_into('<IIQQQQIIQQ', data, SHOFF + index * 64, *row, 0, 0, 1, 0)
    return bytes(data)


class DecodeOneTests(unittest.TestCase):
    def test_cpuid(self):
        length, cls, map_id, opcode, pp = decode_one(b'\x0f\xa2', 0, 2)
        self.assertEqual((length, cls, map_id, opcode), (2, 'cpuid', 1, 0xA2))

    def test_tzcnt_is_soft(self):
        length, cls, *_ = decode_one(b'\xf3\x0f\xbc\xc8', 0, 4)
        self.assertEqual((length, cls), (4, 'tzcnt_lzcnt'))

    def test_lzcnt_is_soft(self):
        length, cls, *_ = decode_one(b'\xf3\x0f\xbd\xc8', 0, 4)
        self.assertEqual((length, cls), (4, 'tzcnt_lzcnt'))

    def test_legacy_adox_is_not_bmi2(self):
        # F3 0F 38 F6 is ADX ADOX, not BMI2 MULX.
        length, cls, *_ = decode_one(b'\xf3\x0f\x38\xf6\xc8', 0, 5)
        self.assertEqual(cls, 'other')

    def test_vex_mulx_is_bmi2(self):
        # C4 E2 F3 F6 C8 = VEX.0F38.W0 F3 mulx eax, ecx, eax (synthetic).
        length, cls, *_ = decode_one(bytes.fromhex('c4e2f3f6c8'), 0, 5)
        self.assertEqual(cls, 'bmi2')

    def test_vex_andn_is_bmi1(self):
        length, cls, *_ = decode_one(bytes.fromhex('c4e278f2c1'), 0, 5)
        self.assertEqual(cls, 'bmi1')

    def test_vpaddd_is_avx(self):
        # C5 F1 FC C1 = vpaddd xmm0, xmm1, xmm1
        length, cls, *_ = decode_one(bytes.fromhex('c5f1fcc1'), 0, 4)
        self.assertEqual(cls, 'avx')

    def test_unknown_vex_is_vex_other_not_avx(self):
        # C5 FF FF C1: VEX map 1 opcode FF is group-5, no SIMD form.
        length, cls, *_ = decode_one(bytes.fromhex('c5ff ffc1'.replace(' ', '')), 0, 4)
        self.assertEqual(cls, 'vex_other')

    def test_cpuid_with_rex_prefix(self):
        length, cls, *_ = decode_one(b'\x48\x0f\xa2', 0, 3)
        self.assertEqual((length, cls), (3, 'cpuid'))


class ScanTests(unittest.TestCase):
    def _scan(self, bodies):
        data = build_elf(bodies)
        secs = sections(data)
        _, fdes = eh_frame_records(data, secs)
        for f in fdes:
            f['section'] = '.text'
        return scan_text(data, fdes, secs)

    def test_isa_function_without_cpuid(self):
        # one function: tzcnt + vpaddd, no cpuid
        body = bytes.fromhex('f30fbcc8') + bytes.fromhex('c5f1fcc1') + b'\xc3'
        fn_hits, stats, undecoded = self._scan([(TEXT, body)])
        rows, dispatchers, soft = classify_functions(fn_hits)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['disposition'], 'no_same_function_cpuid')
        self.assertEqual(dispatchers, [])
        self.assertEqual(soft, [])

    def test_same_function_cpuid(self):
        body = b'\x0f\xa2' + bytes.fromhex('c5f1fcc1') + b'\xc3'
        fn_hits, stats, undecoded = self._scan([(TEXT, body)])
        rows, dispatchers, soft = classify_functions(fn_hits)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['disposition'], 'same_function_cpuid')

    def test_cpuid_only_is_dispatcher(self):
        body = b'\x0f\xa2' + b'\xc3'
        fn_hits, stats, undecoded = self._scan([(TEXT, body)])
        rows, dispatchers, soft = classify_functions(fn_hits)
        self.assertEqual(rows, [])
        self.assertEqual(len(dispatchers), 1)

    def test_soft_tzcnt_does_not_require_isa_row(self):
        body = b'\xf3\x0f\xbc\xc8' + b'\xc3'
        fn_hits, stats, undecoded = self._scan([(TEXT, body)])
        rows, dispatchers, soft = classify_functions(fn_hits)
        self.assertEqual(rows, [])
        self.assertEqual(len(soft), 1)

    def test_corruption_endbr_replacement(self):
        # A 33-byte extent of endbr64+nop must not create an ISA hit.
        body = b'\xf3\x0f\x1e\xfa' * 4 + b'\x90\x90\x90\xc3'
        fn_hits, stats, undecoded = self._scan([(TEXT, body)])
        self.assertEqual(fn_hits, {})

    def test_two_functions_split(self):
        f1 = bytes.fromhex('c5f1fcc1') + b'\xc3'  # avx
        f2 = b'\x0f\xa2' + b'\xc3'                 # cpuid only
        fn_hits, stats, undecoded = self._scan([(TEXT, f1), (TEXT + 0x40, f2)])
        rows, dispatchers, soft = classify_functions(fn_hits)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(dispatchers), 1)


if __name__ == '__main__':
    unittest.main()
