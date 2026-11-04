#!/usr/bin/env python3
'''RE-012: node #115 CLI info literal and the FDE of its only referrer.

Reads artifacts/node/115/hl-node in place. The target is never executed,
copied or relocated. From the pinned bytes alone this checker re-derives:

  1. the NUL-terminated ASCII literal info in .rodata at VA 0x4312f2;
  2. every direct RIP-relative reference to that VA in .text over the
     documented 32-prefix LEA/MOV/CALL/JMP opcode set: exactly one, at VA
     0x63d4d18 with bytes 48 8d 35 d3 c5 05 fa 48 89 df c7 84 24. The first
     seven bytes are lea rsi,[rip+0xfa05c5d3], so the instruction resolves to
     the literal address;
  3. the .eh_frame FDE that contains that instruction. Its half-open extent is
     start plus the encoded range from the FDE record itself, never the next
     unwind-table start: [0x63d4bbe, 0x63d5428).

Every value recorded in
research/work-items/RE-012-node115-cli-info-literal/evidence.json must equal
the re-derived value, and the corruption controls require the comparator to
reject an altered byte string, FDE start, FDE end, literal address, reference
count, in-FDE offset and token. The target SHA-256 is verified before analysis
and again afterwards.

Nothing here is inferred from symbol names, comments or upstream sources, and
no behaviour of the captured code is executed or claimed.
'''

import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
PACKET = ROOT / 'research' / 'work-items' / 'RE-012-node115-cli-info-literal'
EVIDENCE = PACKET / 'evidence.json'

TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

TOKEN = b'info'
TOKEN_VA = 0x4312F2
REFERENCE_VA = 0x63D4D18
REFERENCE_BYTES = bytes.fromhex('488d35d3c505fa4889dfc78424')
INSTRUCTION_LENGTH = 7
FDE_START = 0x63D4BBE
FDE_END = 0x63D5428

METADATA = {
    'task': 'RE-012',
    'component': 'node-runtime',
    'question': 'Which node #115 .text instruction references the CLI literal info at 0x4312f2, and what is the authenticated FDE extent of that instruction?',
    'claim_status': 'observation',
    'target_path': 'artifacts/node/115/hl-node',
}

PREFIXES = (
    b'\x48\x8d\x05', b'\x48\x8d\x0d', b'\x48\x8d\x15', b'\x48\x8d\x1d',
    b'\x48\x8d\x25', b'\x48\x8d\x2d', b'\x48\x8d\x35', b'\x48\x8d\x3d',
    b'\x4c\x8d\x05', b'\x4c\x8d\x0d', b'\x4c\x8d\x15', b'\x4c\x8d\x1d',
    b'\x4c\x8d\x25', b'\x4c\x8d\x2d', b'\x4c\x8d\x35', b'\x4c\x8d\x3d',
    b'\x48\x8b\x05', b'\x48\x8b\x0d', b'\x48\x8b\x15', b'\x48\x8b\x1d',
    b'\x48\x8b\x25', b'\x48\x8b\x2d', b'\x48\x8b\x35', b'\x48\x8b\x3d',
    b'\x4c\x8b\x05', b'\x4c\x8b\x0d', b'\x4c\x8b\x15', b'\x4c\x8b\x1d',
    b'\xff\x15', b'\xff\x25',
)

POINTER_SIZE = {0x00: 8, 0x02: 2, 0x03: 4, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8}
REQUIRED_SECTIONS = ('.text', '.rodata', '.eh_frame')


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def require_digest(digest, stage):
    if digest != TARGET_SHA256:
        raise AssertionError('%s target digest is %s, pinned %s' % (stage, digest, TARGET_SHA256))
    return digest


def parse_sections(data):
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise AssertionError('target is not a little-endian ELF64 file')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    shnum = struct.unpack_from('<H', data, 0x3C)[0]
    shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    if shentsize < 64 or shnum == 0 or shstrndx >= shnum:
        raise AssertionError('implausible section table header')
    if shoff + shnum * shentsize > len(data):
        raise AssertionError('section table overruns the file')
    raw = []
    for index in range(shnum):
        entry = shoff + index * shentsize
        name_off, sh_type = struct.unpack_from('<II', data, entry)
        flags, addr, offset, size = struct.unpack_from('<QQQQ', data, entry + 8)
        raw.append((name_off, sh_type, flags, addr, offset, size))
    string_off = raw[shstrndx][4]
    string_size = raw[shstrndx][5]
    strings = data[string_off:string_off + string_size]
    sections = {}
    for name_off, sh_type, flags, addr, offset, size in raw:
        nul = strings.find(b'\x00', name_off)
        if nul < 0:
            raise AssertionError('section name is not NUL-terminated')
        name = strings[name_off:nul].decode('utf-8', 'replace')
        section = {'type': sh_type, 'flags': flags, 'addr': addr, 'offset': offset, 'size': size}
        if name in REQUIRED_SECTIONS and name in sections:
            raise AssertionError('duplicate required section name %s' % name)
        sections.setdefault(name, section)
    return sections


def allocated_section(sections, name):
    section = sections.get(name)
    if section is None:
        raise AssertionError('target has no %s section' % name)
    if section['addr'] == 0 or section['size'] == 0:
        raise AssertionError('%s has an empty address range' % name)
    return section


def section_offset(sections, va):
    for section in sections.values():
        if not section['flags'] & 0x2:
            continue
        if section['size'] == 0:
            continue
        if section['addr'] <= va < section['addr'] + section['size']:
            return section['offset'] + (va - section['addr'])
    raise AssertionError('VA 0x%x is outside every allocated section' % va)


def count_literals(data, section, token):
    start = section['offset']
    end = start + section['size']
    count = 0
    position = data.find(token, start, end)
    while position >= 0:
        after = data[position + len(token)] if position + len(token) < len(data) else 0
        before = data[position - 1] if position > start else 0
        if after == 0 and not 0x20 <= before <= 0x7E:
            count += 1
        position = data.find(token, position + 1, end)
    return count


def scan_references(text, text_va, wanted):
    hits = set()
    for prefix in PREFIXES:
        position = text.find(prefix)
        while position >= 0:
            field = position + len(prefix)
            if field + 4 <= len(text):
                displacement = struct.unpack_from('<i', text, field)[0]
                if text_va + field + 4 + displacement == wanted:
                    hits.add(text_va + position)
            position = text.find(prefix, position + 1)
    return sorted(hits)


def read_uleb(data, pos, end):
    value = 0
    shift = 0
    while pos < end:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    raise AssertionError('truncated ULEB128 at 0x%x' % pos)


def read_sleb(data, pos, end):
    value = 0
    shift = 0
    while pos < end:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                value -= 1 << shift
            return value, pos
    raise AssertionError('truncated SLEB128 at 0x%x' % pos)


def decode_address(data, pos, end, encoding, section_va, base):
    fmt = encoding & 0x0F
    if encoding & 0x80:
        raise AssertionError('indirect pointer encoding 0x%02x is not supported' % encoding)
    application = encoding & 0x70
    if application not in (0x00, 0x10):
        raise AssertionError('pointer application 0x%02x is not supported' % encoding)
    if fmt not in POINTER_SIZE:
        raise AssertionError('pointer format 0x%02x is not supported' % fmt)
    size = POINTER_SIZE[fmt]
    if pos + size > end:
        raise AssertionError('encoded pointer at 0x%x overruns its record' % pos)
    raw = data[pos:pos + size]
    if fmt in (0x0A, 0x0B):
        value = struct.unpack('<h' if size == 2 else '<i', raw)[0]
    elif fmt == 0x0C:
        value = struct.unpack('<q', raw)[0]
    elif size == 8:
        value = struct.unpack('<Q', raw)[0]
    elif size == 4:
        value = struct.unpack('<I', raw)[0]
    else:
        value = struct.unpack('<H', raw)[0]
    if encoding & 0x10:
        value += section_va + (pos - base)
    return value, pos + size


def decode_range(data, pos, end, encoding):
    fmt = encoding & 0x0F
    if fmt not in POINTER_SIZE:
        raise AssertionError('range format 0x%02x is not supported' % fmt)
    size = POINTER_SIZE[fmt]
    if pos + size > end:
        raise AssertionError('encoded range at 0x%x overruns its record' % pos)
    raw = data[pos:pos + size]
    if fmt in (0x0A, 0x0B):
        value = struct.unpack('<h' if size == 2 else '<i', raw)[0]
    elif fmt == 0x0C:
        value = struct.unpack('<q', raw)[0]
    elif size == 8:
        value = struct.unpack('<Q', raw)[0]
    elif size == 4:
        value = struct.unpack('<I', raw)[0]
    else:
        value = struct.unpack('<H', raw)[0]
    if value <= 0:
        raise AssertionError('non-positive FDE range at 0x%x' % pos)
    return value, pos + size


def parse_cie(data, pos, end, section_va, base):
    if pos >= end:
        raise AssertionError('empty CIE record')
    version = data[pos]
    pos += 1
    nul = data.find(b'\x00', pos, end)
    if nul < 0:
        raise AssertionError('CIE augmentation string is not NUL-terminated')
    augmentation = data[pos:nul].decode('ascii', 'replace')
    pos = nul + 1
    if version >= 4:
        pos += 2
    _, pos = read_uleb(data, pos, end)
    _, pos = read_sleb(data, pos, end)
    if version == 1:
        pos += 1
    else:
        _, pos = read_uleb(data, pos, end)
    encoding = 0x00
    has_length = augmentation.startswith('z')
    if has_length:
        length, pos = read_uleb(data, pos, end)
        aug_end = pos + length
        if aug_end > end:
            raise AssertionError('CIE augmentation data overruns its record')
        for char in augmentation[1:]:
            if char == 'R':
                encoding = data[pos]
                pos += 1
            elif char == 'L':
                pos += 1
            elif char == 'P':
                pointer = data[pos]
                pos += 1 + POINTER_SIZE.get(pointer & 0x0F, 0)
            elif char in 'SBG':
                continue
            else:
                break
        pos = aug_end
    if pos > end:
        raise AssertionError('CIE record overruns')
    return {'encoding': encoding, 'has_length': has_length}


def parse_fdes(data, section):
    base = section['offset']
    section_va = section['addr']
    limit = base + section['size']
    cies = {}
    extents = []
    pos = base
    while pos + 4 <= limit:
        record = pos
        length = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            length = struct.unpack_from('<Q', data, pos)[0]
            pos += 8
        record_end = pos + length
        if record_end > limit or record_end <= pos:
            raise AssertionError('FDE record at 0x%x overruns .eh_frame' % record)
        cie_pointer = struct.unpack_from('<I', data, pos)[0]
        field = pos
        pos += 4
        if cie_pointer == 0:
            cies[record] = parse_cie(data, pos, record_end, section_va, base)
        else:
            cie_offset = field - cie_pointer
            cie = cies.get(cie_offset)
            if cie is None:
                raise AssertionError('FDE at 0x%x refers to unknown CIE 0x%x' % (record, cie_offset))
            start, pos = decode_address(data, pos, record_end, cie['encoding'], section_va, base)
            span, pos = decode_range(data, pos, record_end, cie['encoding'])
            if cie['has_length']:
                _, pos = read_uleb(data, pos, record_end)
            extents.append((start, start + span))
        pos = record_end
    return extents


def compare(recorded, expected):
    if not isinstance(recorded, dict):
        raise AssertionError('evidence.json must hold a JSON object')
    if set(recorded) != set(expected):
        missing = sorted(set(expected) - set(recorded))
        extra = sorted(set(recorded) - set(expected))
        raise AssertionError('evidence schema mismatch; missing %s; unrecorded %s' % (missing, extra))
    for key in sorted(expected):
        if recorded[key] != expected[key]:
            raise AssertionError('evidence field %s is %r, target bytes give %r' % (key, recorded[key], expected[key]))


def corruption_controls(expected):
    compare(expected, expected)
    mutants = [
        ('reference_bytes_hex', '488d35d3c505fa4889dfc78425'),
        ('fde_start', '0x63d4bbd'),
        ('fde_end', '0x63d5429'),
        ('token', 'infp'),
        ('token_va', '0x4312f3'),
        ('direct_reference_count', 2),
        ('reference_offset_in_fde', 347),
    ]
    for key, value in mutants:
        mutated = dict(expected)
        mutated[key] = value
        if mutated == expected:
            raise AssertionError('control %s does not change the record' % key)
        try:
            compare(mutated, expected)
        except AssertionError:
            continue
        raise AssertionError('comparator accepted an altered %s' % key)
    try:
        require_digest('0' * 64, 'control')
    except AssertionError:
        return
    raise AssertionError('digest guard accepted a wrong digest')


def main():
    if not TARGET.is_file():
        raise AssertionError('missing pinned target: %s' % TARGET)
    before = require_digest(sha256_file(TARGET), 'pre-analysis')
    if not EVIDENCE.is_file():
        raise AssertionError('missing packet evidence: %s' % EVIDENCE)
    data = TARGET.read_bytes()
    require_digest(hashlib.sha256(data).hexdigest(), 'in-memory')

    sections = parse_sections(data)
    rodata = allocated_section(sections, '.rodata')
    text_section = allocated_section(sections, '.text')
    eh_frame = allocated_section(sections, '.eh_frame')

    token_offset = section_offset(sections, TOKEN_VA)
    if data[token_offset:token_offset + len(TOKEN)] != TOKEN:
        raise AssertionError('VA 0x%x does not hold %r' % (TOKEN_VA, TOKEN))
    if data[token_offset + len(TOKEN)] != 0:
        raise AssertionError('literal at 0x%x is not NUL-terminated' % TOKEN_VA)
    occurrences = count_literals(data, rodata, TOKEN)
    if occurrences != 1:
        raise AssertionError('expected one NUL-terminated info literal in .rodata, found %d' % occurrences)

    text_va = text_section['addr']
    text = data[text_section['offset']:text_section['offset'] + text_section['size']]
    references = scan_references(text, text_va, TOKEN_VA)
    if len(references) != 1:
        raise AssertionError('expected one direct reference to 0x%x, found %d' % (TOKEN_VA, len(references)))
    if references[0] != REFERENCE_VA:
        raise AssertionError('direct reference is at 0x%x, pinned 0x%x' % (references[0], REFERENCE_VA))
    reference_offset = text_section['offset'] + (REFERENCE_VA - text_va)
    observed = data[reference_offset:reference_offset + len(REFERENCE_BYTES)]
    if observed != REFERENCE_BYTES:
        raise AssertionError('reference bytes are %s, pinned %s' % (observed.hex(), REFERENCE_BYTES.hex()))
    displacement = struct.unpack_from('<i', data, reference_offset + 3)[0]
    target_va = REFERENCE_VA + INSTRUCTION_LENGTH + displacement
    if target_va != TOKEN_VA:
        raise AssertionError('instruction at 0x%x resolves to 0x%x, not 0x%x' % (REFERENCE_VA, target_va, TOKEN_VA))
    if REFERENCE_VA + INSTRUCTION_LENGTH > text_va + text_section['size']:
        raise AssertionError('reference instruction overruns .text')

    extents = parse_fdes(data, eh_frame)
    if len(extents) < 100000:
        raise AssertionError('implausible FDE count from .eh_frame: %d' % len(extents))
    containing = [item for item in extents if item[0] <= REFERENCE_VA < item[1]]
    if len(containing) != 1:
        raise AssertionError('expected exactly one FDE containing 0x%x, found %d' % (REFERENCE_VA, len(containing)))
    fde_start, fde_end = containing[0]
    if (fde_start, fde_end) != (FDE_START, FDE_END):
        raise AssertionError('FDE extent is [0x%x, 0x%x), pinned [0x%x, 0x%x)' % (fde_start, fde_end, FDE_START, FDE_END))

    after = require_digest(sha256_file(TARGET), 'post-analysis')
    if after != before:
        raise AssertionError('target digest changed during analysis')

    derived = {
        'target_sha256': before,
        'target_size_bytes': len(data),
        'token': TOKEN.decode('ascii'),
        'token_va': '0x%x' % TOKEN_VA,
        'token_section': '.rodata',
        'token_nul_terminated': True,
        'token_occurrences_in_rodata': occurrences,
        'reference_va': '0x%x' % REFERENCE_VA,
        'reference_bytes_hex': observed.hex(),
        'reference_instruction_length': INSTRUCTION_LENGTH,
        'reference_displacement': displacement,
        'reference_target_va': '0x%x' % target_va,
        'direct_reference_count': len(references),
        'fde_start': '0x%x' % fde_start,
        'fde_end': '0x%x' % fde_end,
        'fde_size_bytes': fde_end - fde_start,
        'reference_offset_in_fde': REFERENCE_VA - fde_start,
        'fde_containing_count': len(containing),
        'fde_count': len(extents),
        'captured_code_executed': False,
    }
    expected = dict(METADATA)
    expected.update(derived)

    recorded = json.loads(EVIDENCE.read_text(encoding='utf-8'))
    compare(recorded, expected)
    corruption_controls(expected)

    print(json.dumps({'derived': derived, 'packet': str(EVIDENCE.relative_to(ROOT))}, indent=2, sort_keys=True))
    print('OK: node #115 CLI literal info -> reference 0x%x -> FDE [0x%x, 0x%x)' % (REFERENCE_VA, fde_start, fde_end))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
