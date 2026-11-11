#!/usr/bin/env python3
"""Replay one captured #115 fsync boundary statically; never execute the target."""
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TARGET = 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x6019690, 0x601976c


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sections(data):
    require(data[:7] == b'\x7fELF\x02\x01\x01', 'ELF64 little endian required')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    size, count, names = struct.unpack_from('<HHH', data, 58)
    require(size == 64 and names < count, 'section table shape')
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * size)
            for i in range(count)]
    n = rows[names]
    strings = data[n[4]:n[4] + n[5]]
    result = {}
    for row in rows:
        end = strings.index(b'\0', row[0])
        name = strings[row[0]:end].decode('ascii')
        require(name not in result, 'duplicate section')
        if row[1] != 8:
            require(row[4] + row[5] <= len(data), 'section out of file')
        result[name] = row
    return result


def code_checks(body):
    require(len(body) == END - START, 'boundary length')
    # Exact instruction encodings at aligned addresses, not substring searches.
    patterns = {
        0x6019699: '4889f5', 0x601969d: '4889fb',
        0x60196a4: '8b7e4c', 0x60196bc: '85c07838',
        0x60196c0: '31c0c703000000006689430448c7430800000000',
        0x60196e8: '4889d8', 0x60196f1: 'c3',
        0x6019705: '4889df8b08488d55284c89ee',
        0x6019715: '48b85768696c65206673',
        0x601971f: 'c644241b00', 0x6019724: '4889442410',
        0x6019729: '48c74424080b000000', 0x6019732: 'c744241773796e63',
    }
    for va, hexbytes in patterns.items():
        expected = bytes.fromhex(hexbytes)
        require(body[va - START:va - START + len(expected)] == expected,
                f'instruction mismatch at {va:#x}')
    calls = {}
    for va, dest in [(0x60196b7, 0x63f1640), (0x60196f8, 0x63f0ad0),
                     (0x601973a, 0x6018080), (0x6019751, 0x63f0d80),
                     (0x601975b, 0x63f0d70)]:
        offset = va - START
        require(body[offset] == 0xe8, 'direct call opcode')
        actual = va + 5 + struct.unpack_from('<i', body, offset + 1)[0]
        require(actual == dest, f'call destination at {va:#x}')
        calls[hex(va)] = hex(actual)
    return calls


def observe(data):
    sec = sections(data)
    def region(name):
        row = sec[name]
        return data[row[4]:row[4] + row[5]]
    def at(va, length, name):
        row = sec[name]
        require(row[3] <= va and va + length <= row[3] + row[5], 'VA outside section')
        off = row[4] + va - row[3]
        return data[off:off + length]
    text = sec['.text']
    require(text[2] & 4, 'boundary must be executable')
    body = at(START, END - START, '.text')
    calls = code_checks(body)
    fde = region('.eh_frame')[0x7550ec:0x75512c]
    length, cie_delta, pc_delta, extent = struct.unpack_from('<IIiI', fde)
    require(length == 0x3c and cie_delta == 0x24ec0, 'FDE header')
    fde_pc = sec['.eh_frame'][3] + 0x7550ec + 8 + pc_delta
    require((fde_pc, extent) == (START, END - START), 'FDE extent')
    cie_off = 0x7550ec + 4 - cie_delta
    require(cie_off == 0x730230, 'CIE coordinate')
    require(struct.unpack_from('<I', region('.eh_frame'), cie_off + 4)[0] == 0, 'CIE id')
    dynsym, dynstr = region('.dynsym'), region('.dynstr')
    matches = []
    rel = region('.rela.plt')
    for offset in range(0, len(rel), 24):
        got, info, addend = struct.unpack_from('<QQq', rel, offset)
        sym = info >> 32
        name_offset = struct.unpack_from('<I', dynsym, sym * 24)[0]
        name = dynstr[name_offset:dynstr.index(b'\0', name_offset)]
        if name == b'fsync':
            matches.append((got, info & 0xffffffff, addend, sym))
    require(matches == [(0x64ee770, 7, 0, 401)], 'fsync JUMP_SLOT')
    plt = at(0x63f1640, 6, '.plt')
    require(plt[:2] == b'\xff\x25', 'PLT jump')
    require(0x63f1646 + struct.unpack_from('<i', plt, 2)[0] == 0x64ee770, 'PLT to GOT')
    return {
        'target': TARGET, 'sha256': hashlib.sha256(data).hexdigest(),
        'start_va': hex(START), 'end_va_exclusive': hex(END),
        'file_offset': hex(text[4] + START - text[3]), 'bytes': len(body),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'fde_section_offset': '0x7550ec', 'cie_section_offset': hex(cie_off),
        'fde_sha256': hashlib.sha256(fde).hexdigest(), 'direct_calls': calls,
        'fsync_plt': '0x63f1640', 'fsync_got': '0x64ee770',
        'fsync_dynsym': 401, 'relocation_type': 'R_X86_64_JUMP_SLOT',
        'fd_source': '[entry_rsi+0x4c]', 'negative_branch': '0x60196f8',
        'error_helper': '0x6018080', 'error_literal': 'While fsync',
        'validated_boundaries': 1, 'gate_requested': False,
    }


def verify(data, expected):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'target SHA-256')
    actual = observe(data)
    require(actual == expected, 'record differs from authenticated observation')
    return actual


if __name__ == '__main__':
    actual = verify((ROOT / TARGET).read_bytes(), json.loads((HERE / 'boundary.json').read_text()))
    print(json.dumps(actual, indent=2, sort_keys=True))
