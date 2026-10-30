"""Missing .rela.dyn must fail closed in foundation_duration_guards.analyze().

analyze() reads its relocation table through a bare ``named['.rela.dyn']``
lookup, so an ELF without that section escapes the module's require() /
ValueError contract as a KeyError traceback. This mirrors the
foundation_millis missing-.rela.dyn fix: route the lookup through a
helper that raises ValueError. The synthetic ELF below carries the full
anchor gauntlet up to and past the relocation lookup (the 522-byte
window with sign-mask / finite-threshold reads, exact instruction
anchors, RIP-relative references, branch displacements, the clamp bound
and the assertion texts), so the missing-section case is reached, not
an earlier gate, and the present-section case runs to a full result.
"""
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import foundation_duration_guards as guards

EH = 0x500000
START, END = 0x392FAB0, 0x392FCBA
CLAMP = 0x20A700
ASSERT = 0x219D00

EXACT = [(0x392FB04, 'f2 0f 5f d1'), (0x392FC40, 'f2 0f 5f d1'),
         (0x392FB1E, '66 0f 2e c8'), (0x392FC5A, '66 0f 2e c8'),
         (0x392FB60, '66 0f 2e c1'), (0x392FC78, '66 0f 2e c1')]
RIP_PRE = [(0x392FB08, 8, 4, 0x20A730), (0x392FC44, 8, 4, 0x20A730)]
BRANCHES = [(0x392FAFE, 0x392FB1A, '7f'), (0x392FC3A, 0x392FC56, '7f'),
            (0x392FB18, 0x392FB2C, '77'), (0x392FC54, 0x392FC64, '77'),
            (0x392FB26, 0x392FC88, '0f82'), (0x392FC62, 0x392FC88, '72'),
            (0x392FB64, 0x392FCA1, '0f82'), (0x392FC7C, 0x392FCA1, '72')]
RIP_POST = [(0x392FC88, 7, 3, 0x219D71), (0x392FC8F, 7, 3, 0x566AB58),
            (0x392FCA1, 7, 3, 0x219F59), (0x392FCA8, 7, 3, 0x566AE58),
            (0x392FC9B, 6, 2, 0x576E108), (0x392FCB4, 6, 2, 0x576E108)]


def build_elf(with_rela):
    body = bytearray(END - START)

    def put(va, raw):
        body[va - START:va - START + len(raw)] = raw

    for va in (0x392FAE4, 0x392FC20):
        put(va + 2, struct.pack('<Q', guards.SIGN - 1))
    for va in (0x392FAF1, 0x392FC2D):
        put(va + 2, struct.pack('<Q', guards.MAX_FINITE))
    for va, raw in EXACT:
        put(va, bytes.fromhex(raw))
    for va, length, offset, target in RIP_PRE:
        put(va + offset, struct.pack('<i', target - (va + length)))
    for va, length, offset, target in RIP_POST:
        put(va + offset, struct.pack('<i', target - (va + length)))
    # Row boundaries: every anchor, plus the end of each exact row and
    # each branch row, so branch displacement parsing matches its width.
    bounds = {START, END}
    for va, _ in EXACT:
        bounds.add(va)
        bounds.add(va + 4)
    for va, _, opcode in BRANCHES:
        bounds.add(va)
        bounds.add(va + (2 if len(bytes.fromhex(opcode)) == 1 else 6))
    for va, _, _, _ in RIP_PRE + RIP_POST:
        bounds.add(va)
    bounds = sorted(b for b in bounds if START <= b <= END)
    for va, target, opcode in BRANCHES:
        row_len = bounds[bounds.index(va) + 1] - va
        op = bytes.fromhex(opcode)
        put(va, op)
        if row_len == 2:
            put(va + len(op), struct.pack('<b', target - (va + row_len)))
        else:
            put(va + len(op), struct.pack('<i', target - (va + row_len)))
    fde = b'\x00' * 8 + struct.pack('<i', START - (EH + 8)) + struct.pack('<I', END - START)
    cie = b'\x33' * 16
    eh = bytearray(256)
    eh[0:16] = fde
    eh[32:48] = cie
    clamp = bytearray(0x100)
    clamp[0x30:0x38] = struct.pack('<Q', guards.ONE)
    assertion = bytearray(0x300)
    for va, message in ((0x219D71, b'assertion failed: self >= 0.'),
                        (0x219F59, b'assertion failed: self.0 >= 0.')):
        assertion[va - ASSERT:va - ASSERT + len(message)] = message
    strtab = b'\x00.eh_frame\x00.text\x00.clamp\x00.assert\x00.rela.dyn\x00.shstrtab\x00'
    names = {'': 0, '.eh_frame': 1, '.text': 11, '.clamp': 17, '.assert': 24,
             '.rela.dyn': 32, '.shstrtab': 42}
    eh_off = 64
    text_off = eh_off + len(eh)
    clamp_off = text_off + len(body)
    assert_off = clamp_off + len(clamp)
    str_off = assert_off + len(assertion)
    shoff = str_off + len(strtab)
    entries = [('', 0, 0, 0, 0, 0),
               ('.eh_frame', 1, 0, EH, eh_off, len(eh)),
               ('.text', 1, 6, START, text_off, len(body)),
               ('.clamp', 1, 0, CLAMP, clamp_off, len(clamp)),
               ('.assert', 1, 0, ASSERT, assert_off, len(assertion))]
    if with_rela:
        entries.append(('.rela.dyn', 1, 0, 0x600000, shoff, 0))
    entries.append(('.shstrtab', 3, 0, 0, str_off, len(strtab)))
    blob = bytearray(shoff)
    blob[eh_off:eh_off + len(eh)] = eh
    blob[text_off:text_off + len(body)] = body
    blob[clamp_off:clamp_off + len(clamp)] = clamp
    blob[assert_off:assert_off + len(assertion)] = assertion
    blob[str_off:str_off + len(strtab)] = strtab
    header = bytearray(64)
    header[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', header, 40, shoff)
    struct.pack_into('<HHH', header, 58, 64, len(entries), len(entries) - 1)
    blob[:64] = header
    for name, typ, flags, addr, off, size in entries:
        blob += struct.pack('<IIQQQQIIQQ', names[name], typ, flags, addr, off, size, 0, 0, 1, 0)
    lines = []
    for lo, hi in zip(bounds, bounds[1:]):
        row = bytes(body[lo - START:hi - START])
        lines.append(f"{lo:x}: {' '.join(f'{b:02x}' for b in row)} ")
    records = {
        'target_sha256': guards.SHA256, 'start_va': hex(START),
        'end_va_exclusive': hex(END),
        'body_sha256': hashlib.sha256(bytes(body)).hexdigest(),
        'fde_offset': '0x0', 'fde_hex': fde.hex(),
        'cie_offset': '0x20', 'cie_hex': cie.hex(),
        'relative_slots': {}, 'source_locations': [],
    }
    return bytes(blob), records, '\n'.join(lines) + '\n'


class MissingRelaDynTests(unittest.TestCase):
    def analyze(self, with_rela):
        data, records, objdump = build_elf(with_rela)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        packet = Path(tmp.name)
        (packet / 'function.objdump.txt').write_text(objdump)
        old = guards.PACKET
        guards.PACKET = packet
        self.addCleanup(setattr, guards, 'PACKET', old)
        return guards.analyze(data, records)

    def test_missing_rela_dyn_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'Missing section'):
            self.analyze(with_rela=False)

    def test_present_rela_dyn_runs_to_a_result(self):
        result = self.analyze(with_rela=True)
        self.assertEqual(result['window']['start_va'], hex(START))


if __name__ == '__main__':
    unittest.main()
