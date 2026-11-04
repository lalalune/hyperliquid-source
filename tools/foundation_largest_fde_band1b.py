#!/usr/bin/env python3
'''Node #115 RE-001 committed checker for packet RE-001-node115-largest-fde-band1b.

Question: which complete FDE is the largest whose entry lies in the .text band
0x1b00000..0x2000000, and what are its exact extent and body digest?

Reads artifacts/node/115/hl-node in place; the pinned target is never executed,
copied or modified. Every recorded value is re-derived from its bytes and
compared with the constants below. The leading 160 window bytes match the
length used by the focused proof, so the packet excerpts and this checker
agree on one head length.
'''

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

TARGET_REL = Path('artifacts') / 'node' / '115' / 'hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
BAND_LO = 0x1B00000
BAND_HI = 0x2000000
BAND_FDE_COUNT = 3437
TEXT_VA = 0x1419300
TEXT_OFFSET = 0x1418300
TEXT_SIZE = 83719936
EH_VA = 0xCA6ED8
EH_OFFSET = 0xCA6ED8
EH_SIZE = 7803772
CIE_COUNT = 3
FDE_COUNT = 135313
CHOSEN_START = 0x1D7F620
CHOSEN_END = 0x1D9243F
CHOSEN_BYTES = 77343
CHOSEN_FILE_OFFSET = 0x1D7E620
CHOSEN_SHA256 = '7183b9de5bf56bb92e9ac042d79d2bae620eaad91c549e5ef9601b575b605bc2'
FDE_RECORD_OFFSET = 0x408068
CIE_RECORD_OFFSET = 0x39672C
CIE_AUGMENTATION = 'zPLR'
CIE_FDE_ENCODING = 0x1B
HEAD_BYTES = 160
FRAMES_LINE = (
    '010aef40 0000006c 0039672c FDE cie=0039672c '
    'pc=0000000001d7f620..0000000001d9243f'
)
CANDIDATES = (
    (0x1D7F620, 0x1D9243F, 77343, '7183b9de5bf56bb92e9ac042d79d2bae620eaad91c549e5ef9601b575b605bc2'),
    (0x1D793E0, 0x1D7F619, 25145, 'b61907d78b96b2451f187bebbc48e32745b259fd8921bc0d28b1938f819ab1c2'),
    (0x1BEB080, 0x1BF03EB, 21355, '85c3db1daf89c42beba525091139f13c9a45a8ad8849c3694406c04d28b43850'),
    (0x1C14A50, 0x1C19BD5, 20869, '4ff2702e4e47268f5b971bbe44bff19a9cb559468ee2d555a483c572b105533f'),
    (0x1C1E610, 0x1C23558, 20296, '8477bbf45c0e169511f7b2e7636436048823b98b39df4e6b23d24e87133a6ef1'),
    (0x1F5E410, 0x1F62ECC, 19132, '1389818585a4c12e0c2a852ff75abacfa690577a7057f0506761f9e4abe61d39'),
    (0x1E7A3E0, 0x1E7EB37, 18263, 'df6a429f13c852a2906963ac6895c559765f50bc8b51719272bc85dd195f83a0'),
    (0x1E54850, 0x1E58F97, 18247, '7e47475d565ecf25c168155992404dcc779ba06b56c787a075e333cd90f7aaad'),
    (0x1F7E100, 0x1F82681, 17793, '6a8a64a57bd3c13c758bacecab6bdee9cac9d503780013cd0eed4fb0b588f38e'),
    (0x1ED4320, 0x1ED86ED, 17357, 'ddd97f4db968be2e4c7fe76d994086f5c61ef0c9646cbef0d924268d7d705d34'),
)


def hexs(data):
    return ' '.join('{:02x}'.format(byte) for byte in data)


def uleb(buf, pos):
    result = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, pos
        shift += 7
        assert shift < 64, 'ULEB128 too long'


def sleb(buf, pos):
    result = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            if byte & 0x40:
                result -= 1 << shift
            return result, pos
        assert shift < 64, 'SLEB128 too long'


def read_raw(buf, pos, fmt):
    if fmt == 0x00:
        return int.from_bytes(buf[pos:pos + 8], 'little'), pos + 8
    if fmt == 0x01:
        return uleb(buf, pos)
    if fmt == 0x02:
        return int.from_bytes(buf[pos:pos + 2], 'little'), pos + 2
    if fmt == 0x03:
        return int.from_bytes(buf[pos:pos + 4], 'little'), pos + 4
    if fmt == 0x04:
        return int.from_bytes(buf[pos:pos + 8], 'little'), pos + 8
    if fmt == 0x09:
        return sleb(buf, pos)
    if fmt == 0x0A:
        return int.from_bytes(buf[pos:pos + 2], 'little', signed=True), pos + 2
    if fmt == 0x0B:
        return int.from_bytes(buf[pos:pos + 4], 'little', signed=True), pos + 4
    if fmt == 0x0C:
        return int.from_bytes(buf[pos:pos + 8], 'little', signed=True), pos + 8
    raise AssertionError('unsupported DW_EH_PE format 0x{:02x}'.format(fmt))


def raw_size(fmt):
    if fmt in (0x02, 0x0A):
        return 2
    if fmt in (0x03, 0x0B):
        return 4
    if fmt in (0x00, 0x04, 0x0C):
        return 8
    raise AssertionError('variable or unsupported encoding 0x{:02x}'.format(fmt))


def decode_pointer(buf, pos, enc, field_va):
    value, pos = read_raw(buf, pos, enc & 0x0F)
    application = enc & 0x70
    if application == 0x10:
        value += field_va
    elif application != 0x00:
        raise AssertionError('unsupported DW_EH_PE application 0x{:02x}'.format(enc))
    return value, pos


def read_sections(blob):
    assert blob[:4] == bytes((0x7F, 0x45, 0x4C, 0x46)), 'target is not an ELF file'
    assert blob[4] == 2 and blob[5] == 1, 'expected ELF64 little-endian target'
    shoff = int.from_bytes(blob[0x28:0x30], 'little')
    shentsize = int.from_bytes(blob[0x3A:0x3C], 'little')
    shnum = int.from_bytes(blob[0x3C:0x3E], 'little')
    shstrndx = int.from_bytes(blob[0x3E:0x40], 'little')
    assert shentsize == 64, 'unexpected section header size {}'.format(shentsize)
    assert shnum > 0 and shstrndx < shnum, 'invalid section header counts'
    headers = []
    for index in range(shnum):
        raw = blob[shoff + index * shentsize:shoff + (index + 1) * shentsize]
        assert len(raw) == shentsize, 'truncated section header {}'.format(index)
        headers.append({
            'name': int.from_bytes(raw[0:4], 'little'),
            'addr': int.from_bytes(raw[16:24], 'little'),
            'offset': int.from_bytes(raw[24:32], 'little'),
            'size': int.from_bytes(raw[32:40], 'little'),
        })
    strtab = headers[shstrndx]
    names = blob[strtab['offset']:strtab['offset'] + strtab['size']]
    out = {}
    for header in headers:
        end = names.index(0, header['name'])
        out[names[header['name']:end].decode('ascii')] = header
    return out


def parse_cie(body):
    assert body[0:4] == bytes(4), 'CIE id field is not zero'
    version = body[4]
    end = body.index(0, 5)
    augmentation = body[5:end].decode('latin-1')
    pos = end + 1
    code_align, pos = uleb(body, pos)
    data_align, pos = sleb(body, pos)
    if version == 1:
        return_register = body[pos]
        pos += 1
    else:
        return_register, pos = uleb(body, pos)
    info = {
        'version': version,
        'augmentation': augmentation,
        'code_align': code_align,
        'data_align': data_align,
        'return_register': return_register,
        'lsda_encoding': None,
        'fde_encoding': None,
        'personality': None,
    }
    if augmentation.startswith('z'):
        aug_len, pos = uleb(body, pos)
        aug_data = body[pos:pos + aug_len]
        assert len(aug_data) == aug_len, 'truncated CIE augmentation data'
        cursor = 0
        for char in augmentation[1:]:
            if char == 'L':
                info['lsda_encoding'] = aug_data[cursor]
                cursor += 1
            elif char == 'R':
                info['fde_encoding'] = aug_data[cursor]
                cursor += 1
            elif char == 'P':
                encoding = aug_data[cursor]
                cursor += 1
                size = raw_size(encoding & 0x0F)
                info['personality'] = (encoding, hexs(aug_data[cursor:cursor + size]))
                cursor += size
            elif char == 'S':
                pass
            else:
                raise AssertionError('unsupported CIE augmentation {!r}'.format(char))
        assert cursor == aug_len, 'CIE augmentation length mismatch'
    return info


def parse_fde(body, rec_start, body_start, sec_va, cie, cie_off):
    encoding = cie['fde_encoding']
    assert encoding is not None, 'CIE without an FDE pointer encoding'
    field_va = sec_va + rec_start + 8
    start, pos = decode_pointer(body, 4, encoding, field_va)
    span, pos = read_raw(body, pos, encoding & 0x0F)
    return {
        'start': start,
        'end': start + span,
        'range': span,
        'record_offset': rec_start,
        'body_offset': body_start,
        'cie_record_offset': cie_off,
        'cie': cie,
    }


def parse_eh_frame(section_bytes, section_va):
    cies = {}
    fdes = []
    pos = 0
    total = len(section_bytes)
    while pos + 4 <= total:
        rec_start = pos
        length = int.from_bytes(section_bytes[pos:pos + 4], 'little')
        pos += 4
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            length = int.from_bytes(section_bytes[pos:pos + 8], 'little')
            pos += 8
        body_start = pos
        body = section_bytes[body_start:body_start + length]
        assert len(body) == length, 'truncated .eh_frame record at 0x{:x}'.format(rec_start)
        cie_ptr = int.from_bytes(body[0:4], 'little')
        if cie_ptr == 0:
            cies[rec_start] = parse_cie(body)
        else:
            cie_off = body_start - cie_ptr
            assert cie_off in cies, 'FDE at 0x{:x} references unknown CIE 0x{:x}'.format(
                rec_start, cie_off)
            fdes.append(parse_fde(body, rec_start, body_start, section_va, cies[cie_off], cie_off))
        pos = body_start + length
    return cies, fdes


def parse_record_at(section_bytes, section_va, cies, offset):
    length = int.from_bytes(section_bytes[offset:offset + 4], 'little')
    assert length not in (0, 0xFFFFFFFF), 'record at 0x{:x} has no inline body'.format(offset)
    body_start = offset + 4
    body = section_bytes[body_start:body_start + length]
    assert len(body) == length, 'truncated record at 0x{:x}'.format(offset)
    cie_ptr = int.from_bytes(body[0:4], 'little')
    assert cie_ptr != 0, 'record at 0x{:x} is a CIE, not an FDE'.format(offset)
    cie_off = body_start - cie_ptr
    assert cie_off in cies, 'unknown CIE 0x{:x} for record at 0x{:x}'.format(cie_off, offset)
    record = parse_fde(body, offset, body_start, section_va, cies[cie_off], cie_off)
    return record, 4 + length


def analyze(blob):
    '''Re-derive the recorded facts from the pinned bytes; return (facts, context).'''
    digest = hashlib.sha256(blob).hexdigest()
    assert digest == TARGET_SHA256, 'target digest mismatch: {}'.format(digest)
    assert len(blob) == TARGET_SIZE, 'target size mismatch: {}'.format(len(blob))
    sections = read_sections(blob)
    assert '.text' in sections and '.eh_frame' in sections, 'missing required sections'
    text = sections['.text']
    eh = sections['.eh_frame']
    assert (text['addr'], text['offset'], text['size']) == (TEXT_VA, TEXT_OFFSET, TEXT_SIZE)
    assert (eh['addr'], eh['offset'], eh['size']) == (EH_VA, EH_OFFSET, EH_SIZE)
    sec = blob[eh['offset']:eh['offset'] + eh['size']]
    assert len(sec) == eh['size'], 'truncated .eh_frame section'
    cies, fdes = parse_eh_frame(sec, eh['addr'])
    band = [f for f in fdes if BAND_LO <= f['start'] < BAND_HI and f['range'] > 0]
    usable = [f for f in band if f['start'] >= text['addr']
              and f['end'] <= text['addr'] + text['size']]
    assert usable, 'no complete in-.text FDE inside the recorded band'
    usable.sort(key=lambda f: (-f['range'], f['start']))
    chosen = usable[0]
    code_off = text['offset'] + (chosen['start'] - text['addr'])
    code = blob[code_off:code_off + chosen['range']]
    assert len(code) == chosen['range'], 'window outside the pinned target'
    record, record_bytes = parse_record_at(sec, eh['addr'], cies, FDE_RECORD_OFFSET)
    assert (record['start'], record['end']) == (chosen['start'], chosen['end']), \
        'record at 0x{:x} is not the chosen FDE'.format(FDE_RECORD_OFFSET)
    frames_line = '{:08x} {:08x} {:08x} FDE cie={:08x} pc={:016x}..{:016x}'.format(
        eh['offset'] + chosen['record_offset'], record_bytes,
        chosen['cie_record_offset'], chosen['cie_record_offset'],
        chosen['start'], chosen['end'])
    facts = {
        'target_sha256': digest,
        'target_size': len(blob),
        'text': {'va': text['addr'], 'offset': text['offset'], 'size': text['size']},
        'eh_frame': {'va': eh['addr'], 'offset': eh['offset'], 'size': eh['size']},
        'cie_count': len(cies),
        'fde_count': len(fdes),
        'band': [BAND_LO, BAND_HI],
        'band_fde_count': len(band),
        'chosen': {
            'start': chosen['start'],
            'end': chosen['end'],
            'bytes': chosen['range'],
            'file_offset': code_off,
            'sha256': hashlib.sha256(code).hexdigest(),
            'fde_record_offset': chosen['record_offset'],
            'cie_record_offset': chosen['cie_record_offset'],
            'cie_augmentation': chosen['cie']['augmentation'],
            'cie_fde_encoding': chosen['cie']['fde_encoding'],
        },
        'frames_line': frames_line,
        'head_hex': hexs(code[:HEAD_BYTES]),
        'candidates': [
            {
                'start': f['start'],
                'end': f['end'],
                'bytes': f['range'],
                'sha256': hashlib.sha256(
                    blob[text['offset'] + (f['start'] - text['addr']):
                         text['offset'] + (f['end'] - text['addr'])]).hexdigest(),
            }
            for f in usable[:10]
        ],
    }
    context = {'fdes': fdes, 'cies': cies, 'record_bytes': record_bytes}
    return facts, context


def window_bytes(blob, facts):
    start = facts['text']['offset'] + (facts['chosen']['start'] - facts['text']['va'])
    return blob[start:start + facts['chosen']['bytes']]


def check(facts):
    assert facts['target_sha256'] == TARGET_SHA256, 'target digest mismatch'
    assert facts['target_size'] == TARGET_SIZE, 'target size mismatch'
    assert facts['text'] == {'va': TEXT_VA, 'offset': TEXT_OFFSET, 'size': TEXT_SIZE}
    assert facts['eh_frame'] == {'va': EH_VA, 'offset': EH_OFFSET, 'size': EH_SIZE}
    assert facts['cie_count'] == CIE_COUNT, 'CIE count mismatch'
    assert facts['fde_count'] == FDE_COUNT, 'FDE count mismatch'
    assert facts['band'] == [BAND_LO, BAND_HI], 'band bounds mismatch'
    assert facts['band_fde_count'] == BAND_FDE_COUNT, 'band census mismatch'
    chosen = facts['chosen']
    assert chosen['start'] == CHOSEN_START, 'chosen start mismatch'
    assert chosen['end'] == CHOSEN_END, 'chosen end mismatch'
    assert chosen['bytes'] == CHOSEN_BYTES, 'chosen extent mismatch'
    assert chosen['file_offset'] == CHOSEN_FILE_OFFSET, 'chosen file offset mismatch'
    assert chosen['sha256'] == CHOSEN_SHA256, 'chosen body digest mismatch'
    assert chosen['fde_record_offset'] == FDE_RECORD_OFFSET, 'FDE record offset mismatch'
    assert chosen['cie_record_offset'] == CIE_RECORD_OFFSET, 'CIE record offset mismatch'
    assert chosen['cie_augmentation'] == CIE_AUGMENTATION, 'CIE augmentation mismatch'
    assert chosen['cie_fde_encoding'] == CIE_FDE_ENCODING, 'CIE FDE encoding mismatch'
    assert facts['frames_line'] == FRAMES_LINE, 'frames row mismatch'
    assert len(facts['head_hex'].split()) == HEAD_BYTES, 'head hex length mismatch'
    observed = tuple(
        (c['start'], c['end'], c['bytes'], c['sha256']) for c in facts['candidates'])
    assert observed == CANDIDATES, 'candidate census mismatch'


def corruption_controls(blob, facts, context):
    fdes = context['fdes']
    clipped = [f for f in fdes if BAND_LO <= f['start'] < CHOSEN_START and f['range'] > 0]
    assert len(clipped) != BAND_FDE_COUNT, 'band-boundary control failed'
    fake = [dict(f, range=(1 if f['start'] == CHOSEN_START else f['range']))
            for f in fdes if BAND_LO <= f['start'] < BAND_HI and f['range'] > 0]
    fake.sort(key=lambda f: (-f['range'], f['start']))
    assert fake[0]['start'] != CHOSEN_START, 'extent control failed'
    mutated = bytearray(window_bytes(blob, facts))
    mutated[len(mutated) // 2] ^= 0xFF
    assert hashlib.sha256(bytes(mutated)).hexdigest() != CHOSEN_SHA256, \
        'body-mutation control failed'
    tampered = FRAMES_LINE.replace('010aef40', '010aef41', 1)
    assert tampered != FRAMES_LINE, 'frames-row control is inert'
    assert facts['frames_line'] != tampered, 'frames-row control failed'
    assert context['record_bytes'] == 0x6C, 'FDE record byte count mismatch'


def main():
    repo = Path(__file__).resolve().parents[1]
    target = repo / TARGET_REL
    assert target.is_file(), 'missing pinned target {}'.format(target)
    blob = target.read_bytes()
    facts, context = analyze(blob)
    check(facts)
    corruption_controls(blob, facts, context)
    print('target {} bytes {} sha256 {}'.format(
        target, len(blob), facts['target_sha256']))
    print('band 0x{:x}..0x{:x} holds {} FDEs'.format(
        BAND_LO, BAND_HI, facts['band_fde_count']))
    print('chosen pc=0x{:x}..0x{:x} bytes={} file_offset=0x{:x} sha256={}'.format(
        facts['chosen']['start'], facts['chosen']['end'], facts['chosen']['bytes'],
        facts['chosen']['file_offset'], facts['chosen']['sha256']))
    print('frames row: {}'.format(facts['frames_line']))
    print('head bytes: {}'.format(facts['head_hex']))
    print('largest-fde-band1b checker OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
