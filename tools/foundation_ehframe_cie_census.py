#!/usr/bin/env python3
'''Node #115 .eh_frame CIE identity and FDE start/extent census checker.

The checker reads artifacts/node/115/hl-node in place. The captured target is
never copied, executed, emulated or reached over a network. After the size and
SHA-256 authenticate, it re-derives the CIE records, the per-CIE FDE counts,
the terminator offset and the FDE start-address/extent census directly from
the pinned .eh_frame bytes and compares every derived value with the recorded
packet research/work-items/RE-001-node115-ehframe-cie-census/evidence.json.

Usage:
  python3 tools/foundation_ehframe_cie_census.py            verify the packet
  python3 tools/foundation_ehframe_cie_census.py --derive   print derived values

Exit 0 means every recorded value matched the target bytes. A mismatch, a
missing packet or a corrupted input exits 1 with a reason on stderr.
'''

import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
EVIDENCE = (ROOT / 'research' / 'work-items'
            / 'RE-001-node115-ehframe-cie-census' / 'evidence.json')
TARGET_SIZE = 105896032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
EH_FRAME_VA = 0xca6ed8
EH_FRAME_SIZE = 7803772
TEXT_VA = 0x1419300
TEXT_SIZE = 83719936
MASK64 = (1 << 64) - 1
NUL = bytes([0])
ELF_MAGIC = bytes([0x7f, 0x45, 0x4c, 0x46])


class CheckError(Exception):
    pass


def uleb(buf, off):
    result = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise CheckError('truncated ULEB128 at 0x%x' % off)
        byte = buf[off]
        off += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, off
        shift += 7
        if shift > 63:
            raise CheckError('oversized ULEB128 ending at 0x%x' % off)


def sleb(buf, off):
    result = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise CheckError('truncated SLEB128 at 0x%x' % off)
        byte = buf[off]
        off += 1
        result |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                result -= 1 << shift
            return result, off
        if shift > 63:
            raise CheckError('oversized SLEB128 ending at 0x%x' % off)


def read_encoded(buf, off, enc, field_va):
    fmt = enc & 0x0f
    app = enc & 0x70
    if fmt == 0x01:
        val = struct.unpack_from('<Q', buf, off)[0]
        off += 8
    elif fmt == 0x02:
        val = struct.unpack_from('<H', buf, off)[0]
        off += 2
    elif fmt == 0x03:
        val = struct.unpack_from('<I', buf, off)[0]
        off += 4
    elif fmt == 0x04:
        val = struct.unpack_from('<Q', buf, off)[0]
        off += 8
    elif fmt == 0x09:
        val, off = sleb(buf, off)
    elif fmt == 0x0a:
        val = struct.unpack_from('<h', buf, off)[0]
        off += 2
    elif fmt == 0x0b:
        val = struct.unpack_from('<i', buf, off)[0]
        off += 4
    elif fmt == 0x0c:
        val = struct.unpack_from('<q', buf, off)[0]
        off += 8
    else:
        raise CheckError('unsupported DW_EH_PE format 0x%02x at 0x%x' % (fmt, off))
    if app == 0x10:
        val = (val + field_va) & MASK64
    elif app != 0x00:
        raise CheckError('unsupported DW_EH_PE application 0x%02x' % app)
    return val, off


def elf_sections(data):
    if data[:4] != ELF_MAGIC:
        raise CheckError('target is not an ELF file')
    if data[4] != 2 or data[5] != 1:
        raise CheckError('target is not ELF64 little-endian')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    shnum = struct.unpack_from('<H', data, 0x3c)[0]
    shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
    if shentsize != 64:
        raise CheckError('unexpected section header size %d' % shentsize)
    if shnum <= 0 or shstrndx >= shnum:
        raise CheckError('invalid section header table')
    headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        name, stype, flags, addr, offset, size = struct.unpack_from(
            '<IIQQQQ', data, base)
        headers.append({'name_offset': name, 'type': stype, 'flags': flags,
                        'addr': addr, 'offset': offset, 'size': size})
    strtab = headers[shstrndx]
    sections = {}
    for header in headers:
        start = strtab['offset'] + header['name_offset']
        try:
            stop = data.index(NUL, start)
        except ValueError:
            raise CheckError('unterminated section name at 0x%x' % start)
        header['name'] = data[start:stop].decode('latin-1')
        sections.setdefault(header['name'], header)
    return sections


def parse_eh_frame(buf, eh_va):
    cies = []
    by_offset = {}
    fdes = []
    pos = 0
    terminator = None
    total = len(buf)
    while pos + 4 <= total:
        length = struct.unpack_from('<I', buf, pos)[0]
        if length == 0:
            terminator = pos
            break
        if length == 0xffffffff:
            raise CheckError('64-bit .eh_frame record at 0x%x' % pos)
        body = pos + 4
        end = body + length
        if end > total:
            raise CheckError('record at 0x%x overruns .eh_frame' % pos)
        raw = buf[pos:end]
        ident = struct.unpack_from('<I', buf, body)[0]
        if ident == 0:
            cur = body + 4
            version = buf[cur]
            cur += 1
            try:
                stop = buf.index(NUL, cur)
            except ValueError:
                raise CheckError('unterminated CIE augmentation at 0x%x' % cur)
            augmentation = buf[cur:stop].decode('latin-1')
            cur = stop + 1
            code_align, cur = uleb(buf, cur)
            data_align, cur = sleb(buf, cur)
            ra_register, cur = uleb(buf, cur)
            fde_encoding = None
            lsda_encoding = None
            personality_encoding = None
            personality_va = None
            if augmentation[:1] == 'z':
                _, cur = uleb(buf, cur)
                cursor = cur
                for char in augmentation[1:]:
                    if char == 'R':
                        fde_encoding = buf[cursor]
                        cursor += 1
                    elif char == 'L':
                        lsda_encoding = buf[cursor]
                        cursor += 1
                    elif char == 'P':
                        personality_encoding = buf[cursor]
                        cursor += 1
                        personality_va, cursor = read_encoded(
                            buf, cursor, personality_encoding, eh_va + cursor)
                    elif char == 'S':
                        continue
                    else:
                        break
            entry = {
                'section_offset': '0x%x' % pos,
                'version': version,
                'augmentation': augmentation,
                'code_align': code_align,
                'data_align': data_align,
                'ra_register': ra_register,
                'fde_encoding': ('0x%02x' % fde_encoding
                                 if fde_encoding is not None else None),
                'lsda_encoding': ('0x%02x' % lsda_encoding
                                  if lsda_encoding is not None else None),
                'personality_encoding': ('0x%02x' % personality_encoding
                                         if personality_encoding is not None else None),
                'personality_va': ('0x%x' % personality_va
                                   if personality_va is not None else None),
                'record_hex': raw.hex(),
                'record_sha256': hashlib.sha256(raw).hexdigest(),
                'fde_count': 0,
            }
            cies.append(entry)
            by_offset[pos] = entry
        else:
            cie_offset = body - ident
            cie = by_offset.get(cie_offset)
            if cie is None:
                raise CheckError('FDE at 0x%x references unparsed CIE at 0x%x'
                                 % (pos, cie_offset))
            cursor = body + 4
            enc = int(cie['fde_encoding'], 16) if cie['fde_encoding'] else 0
            start_va, cursor = read_encoded(buf, cursor, enc, eh_va + cursor)
            fmt = enc & 0x0f
            if fmt == 0:
                fmt = 0x03
            size, cursor = read_encoded(buf, cursor, fmt, 0)
            if cie['augmentation'][:1] == 'z':
                aug_len, cursor = uleb(buf, cursor)
                cursor += aug_len
            cie['fde_count'] += 1
            fdes.append({'cie_offset': '0x%x' % cie_offset,
                         'start_va': start_va, 'size': size})
        pos = end
    return cies, fdes, terminator


def derive(data):
    sections = elf_sections(data)
    if '.eh_frame' not in sections:
        raise CheckError('target has no .eh_frame section')
    if '.text' not in sections:
        raise CheckError('target has no .text section')
    eh = sections['.eh_frame']
    text = sections['.text']
    if eh['addr'] != EH_FRAME_VA:
        raise CheckError('.eh_frame VA 0x%x != pinned 0x%x' % (eh['addr'], EH_FRAME_VA))
    if eh['size'] != EH_FRAME_SIZE:
        raise CheckError('.eh_frame size %d != pinned %d' % (eh['size'], EH_FRAME_SIZE))
    if eh['offset'] + eh['size'] > len(data):
        raise CheckError('.eh_frame extent overruns the target file')
    if text['addr'] != TEXT_VA or text['size'] != TEXT_SIZE:
        raise CheckError('.text bounds differ from the pinned 0x%x/0x%x'
                         % (TEXT_VA, TEXT_SIZE))
    eh_bytes = data[eh['offset']:eh['offset'] + eh['size']]
    cies, fdes, terminator = parse_eh_frame(eh_bytes, eh['addr'])
    if not cies:
        raise CheckError('no CIE records derived from .eh_frame')
    if not fdes:
        raise CheckError('no FDE records derived from .eh_frame')
    counted = sum(cie['fde_count'] for cie in cies)
    if counted != len(fdes):
        raise CheckError('per-CIE FDE counts total %d, records %d'
                         % (counted, len(fdes)))

    starts = [fde['start_va'] for fde in fdes]
    counts = Counter(starts)
    distinct = sorted(counts)
    duplicates = sorted(va for va, count in counts.items() if count > 1)
    text_lo = text['addr']
    text_hi = text['addr'] + text['size']
    in_text = sum(1 for va in starts if text_lo <= va < text_hi)
    ordered = sorted((fde['start_va'], fde['size']) for fde in fdes)
    overlaps = 0
    covered = 0
    previous_end = -1
    for start, size in ordered:
        if start < previous_end:
            overlaps += 1
        covered += size
        if start + size > previous_end:
            previous_end = start + size

    identities = {}
    for cie in cies:
        key = (cie['version'], cie['augmentation'], cie['code_align'],
               cie['data_align'], cie['ra_register'], cie['fde_encoding'],
               cie['lsda_encoding'], cie['personality_encoding'],
               cie['personality_va'])
        slot = identities.setdefault(key, {
            'version': key[0], 'augmentation': key[1], 'code_align': key[2],
            'data_align': key[3], 'ra_register': key[4],
            'fde_encoding': key[5], 'lsda_encoding': key[6],
            'personality_encoding': key[7], 'personality_va': key[8],
            'cie_records': 0, 'fdes': 0})
        slot['cie_records'] += 1
        slot['fdes'] += cie['fde_count']

    return {
        'task': 'RE-001',
        'question': ('Which CIE records support the node #115 .eh_frame, and what '
                     'start-address and extent census do their FDEs give?'),
        'target_sha256': TARGET_SHA256,
        'target_size': TARGET_SIZE,
        'eh_frame': {
            'va': '0x%x' % eh['addr'],
            'file_offset': '0x%x' % eh['offset'],
            'size': eh['size'],
            'cie_records': len(cies),
            'fde_records': len(fdes),
            'terminator_offset': ('0x%x' % terminator
                                  if terminator is not None else None),
        },
        'text': {'va': '0x%x' % text['addr'], 'size': text['size']},
        'cies': cies,
        'cie_identities': [identities[key] for key in sorted(identities, key=str)],
        'fde_census': {
            'record_count': len(fdes),
            'distinct_start_va': len(distinct),
            'duplicate_start_count': len(duplicates),
            'duplicate_starts_sample': ['0x%x' % va for va in duplicates[:10]],
            'starts_in_text': in_text,
            'starts_outside_text': len(fdes) - in_text,
            'extent_bytes_total': covered,
            'overlapping_extent_count': overlaps,
            'lowest_start_va': '0x%x' % distinct[0],
            'highest_start_va': '0x%x' % distinct[-1],
            'distinct_start_sha256': hashlib.sha256(
                chr(10).join('%x' % va for va in distinct).encode('ascii')).hexdigest(),
        },
    }


def compare(derived, recorded, path):
    if isinstance(derived, dict):
        if not isinstance(recorded, dict):
            raise CheckError('recorded %s is not an object' % path)
        for key, value in derived.items():
            if key not in recorded:
                raise CheckError('recorded %s is missing field %r' % (path, key))
            compare(value, recorded[key], path + key + '.')
    elif isinstance(derived, list):
        if not isinstance(recorded, list):
            raise CheckError('recorded %s is not a list' % path)
        if len(recorded) != len(derived):
            raise CheckError('recorded %s has %d entries, derived %d'
                             % (path, len(recorded), len(derived)))
        for index, value in enumerate(derived):
            compare(value, recorded[index], path + str(index) + '.')
    elif recorded != derived:
        raise CheckError('recorded %s = %r, derived %r' % (path, recorded, derived))


def negative_controls(report):
    def cie_digest(candidate):
        candidate['cies'][0]['record_sha256'] = '0' * 64

    def cie_count(candidate):
        candidate['cies'][1]['fde_count'] += 1

    def extent_total(candidate):
        candidate['fde_census']['extent_bytes_total'] += 1

    def terminator(candidate):
        candidate['eh_frame']['terminator_offset'] = '0x0'

    def lowest_start(candidate):
        candidate['fde_census']['lowest_start_va'] = '0x1400000'

    controls = [('cie record digest', cie_digest),
                ('per-cie fde count', cie_count),
                ('extent total', extent_total),
                ('terminator offset', terminator),
                ('lowest start va', lowest_start)]
    for name, mutate in controls:
        candidate = json.loads(json.dumps(report))
        mutate(candidate)
        try:
            compare(report, candidate, '')
        except CheckError:
            continue
        raise CheckError('corruption control %r was not rejected' % name)
    try:
        authenticate(TARGET_SIZE + 1, TARGET_SHA256)
    except CheckError:
        pass
    else:
        raise CheckError('corruption control for the target size was not rejected')
    try:
        authenticate(TARGET_SIZE, '0' * 64)
    except CheckError:
        pass
    else:
        raise CheckError('corruption control for the target digest was not rejected')


def authenticate(size, digest):
    if size != TARGET_SIZE:
        raise CheckError('target size %d != pinned %d' % (size, TARGET_SIZE))
    if digest != TARGET_SHA256:
        raise CheckError('target digest %s != pinned %s' % (digest, TARGET_SHA256))


def main(argv):
    derive_only = '--derive' in argv
    if not TARGET.is_file():
        raise CheckError('missing pinned target %s' % TARGET)
    data = TARGET.read_bytes()
    authenticate(len(data), hashlib.sha256(data).hexdigest())
    report = derive(data)
    if derive_only:
        print(json.dumps(report, indent=2))
        return 0
    if not EVIDENCE.is_file():
        raise CheckError('missing recorded packet %s' % EVIDENCE)
    recorded = json.loads(EVIDENCE.read_text(encoding='utf-8'))
    compare(report, recorded, '')
    negative_controls(report)
    print('PACKET OK: %s matches the derived .eh_frame census'
          % EVIDENCE.parent.name)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except CheckError as error:
        sys.stderr.write('CHECK FAILED: ' + str(error) + chr(10))
        sys.exit(1)
