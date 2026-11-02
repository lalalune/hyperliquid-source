#!/usr/bin/env python3
"""Owned stdlib data probe. No imports from the repository, subprocess or network.

Encoded xref/call candidates are not validated instruction boundaries. This is
preparation for a bounded hosted decode, not a semantic equivalence claim.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
NEEDLE = b'data did not match any variant of untagged enum JsonRpcResult'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def cie_encoding(cie):
    """Decode only supported version-1 zR/zPLR records, with bounded reads.

    Field interpretation checked against LLVM lld ELF/EhFrame.cpp; this is an
    independently authored reader, not imported/copied implementation code.
    """
    require(cie[8] == 1, 'Unsupported CIE version')
    end = cie.find(b'\0', 9)
    require(end > 9, 'CIE augmentation string bounds')
    augmentation = cie[9:end].decode('ascii')
    require(augmentation in ('zR', 'zPLR'), 'Unsupported augmentation string')
    pos = end + 1

    def leb():
        nonlocal pos
        value = shift = 0
        for _ in range(10):
            require(pos < len(cie), 'CIE LEB bounds')
            byte = cie[pos]
            pos += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
            shift += 7
        raise ValueError('CIE LEB too long')

    leb()  # Code alignment, value not used to decode pointer encoding.
    leb()  # Signed data alignment: only its bounded encoded length is needed.
    require(pos < len(cie), 'CIE return register bounds')
    pos += 1  # Version 1 has a one-byte return-address register.
    length = leb()
    limit = pos + length
    require(limit <= len(cie), 'CIE augmentation data bounds')
    fields = {'augmentation': augmentation}
    for char in augmentation[1:]:
        require(pos < limit, 'CIE augmentation field bounds')
        value = cie[pos]
        pos += 1
        if char == 'P':
            require(value == 0x9b and pos + 4 <= limit, 'Unsupported personality pointer encoding')
            fields['personality_pointer_encoding'] = hex(value)
            pos += 4
        elif char == 'L':
            fields['lsda_pointer_encoding'] = hex(value)
        elif char == 'R':
            fields['fde_pointer_encoding'] = value
    require(pos == limit and fields['fde_pointer_encoding'] == 0x1b, 'FDE pointer encoding or augmentation length mismatch')
    return fields


def probe(data):
    require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == TARGET, 'Target identity mismatch')
    require(data[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', data, 18)[0] == 62, 'Not supported ELF64 x86-64')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', data, 58)
    require(size == 64 and 0 < names_index < count and shoff + count * size <= len(data), 'Section bounds')
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * size) for i in range(count)]
    names_row = rows[names_index]
    names = data[names_row[4]:names_row[4] + names_row[5]]
    sections = {}
    for row in rows:
        end = names.find(b'\0', row[0])
        require(0 <= row[0] <= end < len(names), 'Section name bounds')
        name = names[row[0]:end].decode('ascii')
        require(name not in sections, 'Duplicate section name')
        require(row[1] == 8 or row[4] + row[5] <= len(data), 'Section data bounds')
        sections[name] = row

    def at_va(va, length):
        hits = [r for r in rows if r[1] != 8 and r[2] & 2 and r[3] <= va and va + length <= r[3] + r[5]]
        require(len(hits) == 1, 'Ambiguous or unmapped allocated VA')
        r = hits[0]
        off = r[4] + va - r[3]
        return off, data[off:off + length]

    text = sections['.text']
    require(text[2] & 6 == 6, 'Non-executable text')
    code = data[text[4]:text[4] + text[5]]
    literals = []
    offset = 0
    while (offset := data.find(NEEDLE, offset)) >= 0:
        owners = [(name, r) for name, r in sections.items() if r[1] != 8 and r[4] <= offset and offset + len(NEEDLE) <= r[4] + r[5]]
        require(len(owners) == 1, 'Literal section ownership')
        name, r = owners[0]
        require(r[2] & 2 and not r[2] & 5, 'Literal is not readonly allocated data')
        literals.append({'file_offset': hex(offset), 'va': hex(r[3] + offset - r[4]), 'section': name, 'bytes': len(NEEDLE)})
        offset += 1
    require(len(literals) == 1, 'Expected one exact diagnostic')
    target = int(literals[0]['va'], 16)
    hdr, frame = sections['.eh_frame_hdr'], sections['.eh_frame']
    hpos = hdr[4]
    require(data[hpos:hpos + 4] == b'\x01\x1b\x03\x3b', 'Unsupported unwind header')
    n = struct.unpack_from('<I', data, hpos + 8)[0]
    require(0 < n and 12 + n * 8 <= hdr[5], 'Unwind table bounds')
    entries = [tuple(hdr[3] + v for v in struct.unpack_from('<ii', data, hpos + 12 + 8 * i)) for i in range(n)]
    require(all(a[0] < b[0] for a, b in zip(entries, entries[1:])), 'Unwind starts not strictly ordered')
    starts = [row[0] for row in entries]

    def fde_candidate(va):
        ordinal = bisect.bisect_right(starts, va) - 1
        require(ordinal >= 0, 'No preceding unwind start')
        start, fde_va = entries[ordinal]
        off, raw = at_va(fde_va, 16)
        length, distance, delta, extent = struct.unpack('<IIii', raw)
        require(12 <= length < 4096 and frame[4] <= off < off + length + 4 <= frame[4] + frame[5], 'FDE bounds')
        cie_off = off + 4 - distance
        require(frame[4] <= cie_off < off, 'CIE back-reference')
        cie_length, cie_id = struct.unpack_from('<II', data, cie_off)
        require(cie_id == 0 and cie_off + 4 + cie_length <= frame[4] + frame[5], 'CIE bounds/id')
        cie = data[cie_off:cie_off + 4 + cie_length]
        encoding = cie_encoding(cie)
        require(fde_va + 8 + delta == start and start <= va < start + extent and extent > 0, 'FDE actual extent does not cover candidate')
        body_off, body = at_va(start, extent)
        return {'start_va': hex(start), 'end_va': hex(start + extent), 'bytes': extent,
                'file_offset': hex(body_off), 'body_sha256': hashlib.sha256(body).hexdigest(),
                'unwind_index_row': ordinal, 'fde_va': hex(fde_va), 'fde_file_offset': hex(off),
                'fde_hex': data[off:off + 4 + length].hex(), 'cie_file_offset': hex(cie_off),
                'cie_hex': cie.hex(), 'fde_pointer_encoding': '0x1b (pcrel signed-4-byte)',
                'cie_fields': encoding,
                'limits': 'Actual unwind record extent, not complete CFG/exception closure or source ownership'}

    xrefs = []
    for match in re.finditer(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = match.start()
        if i + 7 > len(code):
            continue
        va = text[3] + i
        if va + 7 + struct.unpack_from('<i', code, i + 3)[0] == target:
            xrefs.append({'candidate_va': hex(va), 'bytes': code[i:i + 7].hex(),
                          'target_va': hex(target), 'instruction_boundary_validated': False,
                          'fde': fde_candidate(va)})
    require(xrefs, 'No direct RIP-relative LEA candidate; expand only by a reviewed plan')
    functions = {int(row['fde']['start_va'], 16) for row in xrefs}
    calls = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            va = text[3] + pos
            destination = va + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination in functions:
                calls.append({'candidate_va': hex(va), 'bytes': code[pos:pos + 5].hex(),
                              'destination_va': hex(destination), 'instruction_boundary_validated': False,
                              'fde': fde_candidate(va)})
        pos += 1
    return {'status': 'DATA_ONLY_REMAP_CANDIDATES_NOT_NATIVE_VALIDATED', 'target_sha256': TARGET,
            'target_bytes': len(data), 'literal': literals[0], 'diagnostic': NEEDLE.decode(),
            'text_bytes': text[5], 'unwind_index_rows': n, 'encoded_lea_candidates': xrefs,
            'encoded_direct_call_candidates': calls, 'repository_imports': False,
            'native_decoder_run': False, 'captured_execution': False,
            'limits': 'Encoded patterns can occur inside other instructions or data; hosted native decoding must qualify every edge and semantic claim.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    record = probe(args.binary.read_bytes())
    args.output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'status': record['status'], 'literal': record['literal'],
                      'unwind_rows': record['unwind_index_rows'],
                      'encoded_lea_candidates': len(record['encoded_lea_candidates']),
                      'encoded_direct_call_candidates': len(record['encoded_direct_call_candidates'])}, indent=2))


if __name__ == '__main__':
    main()
