"""Missing .rela.dyn must fail closed in foundation_millis.analyze().

analyze() reads its relocation table through a bare ``named['.rela.dyn']``
lookup, so an ELF without that section escapes the module's require() /
ValueError contract as a KeyError traceback. This mirrors the
foundation_hour missing-section fix: route the lookup through a helper
that raises ValueError. The synthetic ELF below carries the full
pinned-window gauntlet up to the relocation lookup (five one-byte
windows, the error-call / format-reference displacements and the error
message bytes), so the missing-section case is reached, not an earlier
gate. A second test keeps .rela.dyn present (empty) and expects the
analysis to proceed past the lookup into the later calendar-table gate,
proving the lookup itself passes.
"""
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_millis as millis

EH = 0x500000
CODE = 0x13C8000
CODE_END = 0x14509C1
MSG = 0x1E1000
REQUIRED = [0x13C8E25, 0x13C8EEB, 0x13C8EF3, 0x13C8F2D, 0x14509BA]
MESSAGE = b'from_unix_millis: out-of-range input '


def build_elf(with_rela):
    eh = bytearray(512)
    windows = []
    for i, start in enumerate(REQUIRED):
        fde = b'\x00' * 8 + struct.pack('<i', start - (EH + i * 64 + 8)) + struct.pack('<I', 1)
        cie = b'\x22' * 16
        eh[i * 64:i * 64 + 16] = fde
        eh[i * 64 + 32:i * 64 + 48] = cie
        windows.append({
            'name': f'w{i}', 'start_va': hex(start), 'end_va_exclusive': hex(start + 1),
            'body_sha256': hashlib.sha256(b'\x90').hexdigest(),
            'fde_offset': hex(i * 64), 'fde_hex': fde.hex(),
            'cie_offset': hex(i * 64 + 32), 'cie_hex': cie.hex(),
        })
    code = bytearray(CODE_END - CODE)
    for start in REQUIRED:
        code[start - CODE] = 0x90
    struct.pack_into('<i', code, 0x13C8EF4 - CODE, 0x14509A0 - (0x13C8EF3 + 5))
    struct.pack_into('<i', code, 0x14509BD - CODE, 0x1E1152 - (0x14509BA + 7))
    msg = bytearray(0x200)
    msg[0x153:0x153 + len(MESSAGE)] = MESSAGE
    strtab = b'\x00.eh_frame\x00.text\x00.msg\x00.rela.dyn\x00.shstrtab\x00'
    names = {'': 0, '.eh_frame': 1, '.text': 11, '.msg': 17, '.rela.dyn': 22, '.shstrtab': 32}
    # File layout: 64-byte header, section contents, then section headers.
    eh_off = 64
    code_off = eh_off + len(eh)
    msg_off = code_off + len(code)
    str_off = msg_off + len(msg)
    shoff = str_off + len(strtab)
    entries = [
        ('', 0, 0, 0, 0, 0),
        ('.eh_frame', 1, 0, EH, eh_off, len(eh)),
        ('.text', 1, 6, CODE, code_off, len(code)),
        ('.msg', 1, 0, MSG, msg_off, len(msg)),
    ]
    if with_rela:
        entries.append(('.rela.dyn', 1, 0, 0x600000, shoff, 0))
    entries.append(('.shstrtab', 3, 0, 0, str_off, len(strtab)))
    blob = bytearray(shoff)
    blob[eh_off:eh_off + len(eh)] = eh
    blob[code_off:code_off + len(code)] = code
    blob[msg_off:msg_off + len(msg)] = msg
    blob[str_off:str_off + len(strtab)] = strtab
    header = bytearray(64)
    header[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, len(entries), len(entries) - 1)
    blob[:64] = header
    for name, typ, flags, addr, off, size in entries:
        blob += struct.pack('<IIQQQQIIQQ', names[name], typ, flags, addr, off, size, 0, 0, 1, 0)
    records = {
        'target_sha256': millis.SHA256, 'windows': windows,
        'relative_slots': {}, 'calendar_source_locations': [], 'calendar_tables': [],
    }
    return bytes(blob), records, windows


class MissingRelaDynTests(unittest.TestCase):
    def analyze(self, with_rela):
        data, records, windows = build_elf(with_rela)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        packet = Path(tmp.name)
        for w in windows:
            (packet / (w['name'] + '.objdump.txt')).write_text(
                f"{int(w['start_va'], 16):x}: 90 \n")
        old = millis.PACKET
        millis.PACKET = packet
        self.addCleanup(setattr, millis, 'PACKET', old)
        return millis.analyze(data, records)

    def test_missing_rela_dyn_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Missing section'):
            self.analyze(with_rela=False)

    def test_present_rela_dyn_passes_the_lookup(self):
        # Empty table: no slots to check, so analysis reaches the later
        # calendar-table LEA gate instead of the section lookup.
        with self.assertRaisesRegex(ValueError, 'Calendar table LEA boundary'):
            self.analyze(with_rela=True)


if __name__ == '__main__':
    unittest.main()
