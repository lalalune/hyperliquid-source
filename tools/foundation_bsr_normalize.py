#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 bsr/normalize evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The bsr-undefined input ([rdi] == 0xffffffff) is excluded from the rule, and
no behavior is claimed for it.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x55c9800, 0x55c9830
NEXT_START, NEXT_END = 0x55c9830, 0x55c9989
CALLER_START, CALLER_END = 0x55caf70, 0x55cc408
CALL_SITES = [0x55cb6fb, 0x55cb7f0, 0x55cbde5, 0x55cc00a]
CALL_BYTES = {
    0x55cb6fb: bytes.fromhex('e800e1ffff'),
    0x55cb7f0: bytes.fromhex('e80be0ffff'),
    0x55cbde5: bytes.fromhex('e816daffff'),
    0x55cc00a: bytes.fromhex('e8f1d7ffff'),
}
BODY = bytes.fromhex('89c883fa01741d8b1783c2010fbdca89cfc1e70885c07407c1e208d3ea01d789f029f8c385c90f95c00fb6c0c1e008c3')
# Raw FDE records at .eh_frame offsets, decoded below (zR pcrel sdata4).
FDE = bytes.fromhex('10000000f03c2d00f44561043000000000000000')
NEXT_FDE = bytes.fromhex('50000000043d2d001046610459010000005f0e108d024c0e188c03490e208604410e288305026c0e20410e184a0e10420e0842c3c6cccd500e28830586048c038d02024b0a0e20410e18460e10420e08440b0000')
CALLER_FDE = bytes.fromhex('70000000003e2d00545c61049814000000420e108f02460e188e03420e208d044a0e288c05410e308606410e3883074a0e900303dc010e98034c0ea003730e9803410e90030354060e98034d0ea0036a0e9803410e90030334050a0e38410e30410e28420e20420e18420e10420e084a0b000000')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def normalize(mem_word, esi, edx, ecx):
    """Return the window's 32-bit result, or None for the bsr-undefined input.

    All comparisons and arithmetic are 32-bit: edx is compared as low32,
    ecx is tested as low32 (saved into eax at entry), esi is loaded via
    mov %esi,%eax, and the loaded word is a 32-bit load from [rdi].
    bsr is undefined when (mem_word + 1) mod 2**32 == 0, i.e. mem_word
    == 0xffffffff; that input returns None and no behavior is claimed.
    """
    if (edx & 0xFFFFFFFF) == 1:
        return 0x100 if (ecx & 0xFFFFFFFF) != 0 else 0
    w = (mem_word + 1) & 0xFFFFFFFF
    if w == 0:
        return None
    t = w.bit_length() - 1
    base = (t << 8) & 0xFFFFFFFF
    if (ecx & 0xFFFFFFFF) != 0:
        base = (base + (((w << 8) & 0xFFFFFFFF) >> t)) & 0xFFFFFFFF
    return ((esi & 0xFFFFFFFF) - base) & 0xFFFFFFFF


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    body = read(START, END - START)
    require(body == BODY, 'Bsr/normalize window changed')
    # Padding is exactly zero bytes: the next FDE starts immediately at END.
    eh = by_name['.eh_frame']
    for offset, raw, start, end in [(0x2d3cec, FDE, START, END),
                                    (0x2d3d00, NEXT_FDE, NEXT_START, NEXT_END),
                                    (0x2d3dfc, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # CIE pointer field points back to the CIE at section offset 0.
        require(struct.unpack_from('<I', record, 4)[0] == offset + 4,
                'FDE CIE pointer changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    # Instruction-level locks at fixed body offsets.
    require(body[0:2] == bytes.fromhex('89c8'), 'mov ecx,eax changed')
    require(body[2:5] == bytes.fromhex('83fa01'), 'cmp $1,edx changed')
    require(body[5:7] == bytes.fromhex('741d'), 'je target changed')
    require(body[7:9] == bytes.fromhex('8b17'), 'mov (rdi),edx changed')
    require(body[9:12] == bytes.fromhex('83c201'), 'add $1,edx changed')
    require(body[12:15] == bytes.fromhex('0fbdca'), 'bsr edx,ecx changed')
    require(body[15:17] == bytes.fromhex('89cf'), 'mov ecx,edi changed')
    require(body[17:20] == bytes.fromhex('c1e708'), 'shl $8,edi changed')
    require(body[20:22] == bytes.fromhex('85c0'), 'test eax,eax changed')
    require(body[22:24] == bytes.fromhex('7407'), 'je target changed')
    require(body[24:27] == bytes.fromhex('c1e208'), 'shl $8,edx changed')
    require(body[27:29] == bytes.fromhex('d3ea'), 'shr cl,edx changed')
    require(body[29:31] == bytes.fromhex('01d7'), 'add edx,edi changed')
    require(body[31:33] == bytes.fromhex('89f0'), 'mov esi,eax changed')
    require(body[33:35] == bytes.fromhex('29f8'), 'sub edi,eax changed')
    require(body[35:36] == b'\xc3', 'main-path ret changed')
    require(body[36:38] == bytes.fromhex('85c9'), 'test ecx,ecx changed')
    require(body[38:41] == bytes.fromhex('0f95c0'), 'setne al changed')
    require(body[41:44] == bytes.fromhex('0fb6c0'), 'movzbl al,eax changed')
    require(body[44:47] == bytes.fromhex('c1e008'), 'shl $8,eax changed')
    require(body[47:48] == b'\xc3', 'flag-path ret changed')

    # No relocation record of any type names this window as addend.
    for secname in ('.rela.dyn', '.rela.plt'):
        sec = by_name[secname]
        require(sec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(sec['address'], sec['size'])
        for off in range(0, len(raw), 24):
            _address, _info, addend = struct.unpack_from('<QQq', raw, off)
            require(addend != START, 'Unexpected naming relocation')

    # This byte-pattern scan is explicitly NOT a complete xref census. Linear
    # disassembly from the caller FDE start validates the retained sites.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    hits = []
    for i in range(len(code) - 5):
        if code[i] == 0xe8:
            rel = struct.unpack_from('<i', code, i + 1)[0]
            if text['address'] + i + 5 + rel == START:
                hits.append(text['address'] + i)
    require(hits == CALL_SITES, 'Direct caller set changed')
    for site, call_bytes in CALL_BYTES.items():
        require(read(site, 5) == call_bytes, 'Call bytes changed')
    caller_txt = (ROOT / 'research/work-items/foundation-bsr-normalize-94'
                  / 'caller.objdump.txt').read_text()
    for site, call_bytes in CALL_BYTES.items():
        line = f'{site:x}:\t' + ' '.join(f'{b:02x}' for b in call_bytes)
        require(line in caller_txt, 'Retained caller line changed')

    return dict(window=hex(START), fde_end=hex(END), next_fde=hex(NEXT_START),
                caller_fde_end=hex(CALLER_END),
                direct_callers=[hex(s) for s in CALL_SITES],
                body_sha256=hashlib.sha256(body).hexdigest(),
                padding='none')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', metavar='EVIDENCE')
    parser.add_argument('--binary', default=str(TARGET))
    args = parser.parse_args()
    data = Path(args.binary).read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    found = analyze(data)
    if args.check:
        retained = json.loads(Path(args.check).read_text())
        for key, value in retained.items():
            if key in found:
                require(found[key] == value, 'Retained evidence mismatch: ' + key)
    print('Foundation bsr-normalize evidence reproduces exactly.')


if __name__ == '__main__':
    main()
