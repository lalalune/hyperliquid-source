#!/usr/bin/env python3
"""Authenticate a bounded static cleanup handoff. Never execute the capture."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

def need(value, message):
    if not value:
        raise ValueError(message)

class Image:
    def __init__(self, data):
        self.data = data
        need(data[:6] == b'\x7fELF\x02\x01', 'ELF64 little-endian required')
        phoff = struct.unpack_from('<Q', data, 32)[0]
        entsize, count = struct.unpack_from('<HH', data, 54)
        need(entsize == 56 and phoff + count * entsize <= len(data), 'program headers')
        self.loads = []
        for i in range(count):
            t, flags, off, va, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', data, phoff + i * entsize)
            if t == 1:
                need(off + filesz <= len(data), 'truncated segment')
                self.loads.append((va, off, filesz))
        shoff = struct.unpack_from('<Q', data, 40)[0]
        size, count, names = struct.unpack_from('<HHH', data, 58)
        need(size == 64 and names < count and shoff + size * count <= len(data), 'section headers')
        rows = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + size * i) for i in range(count)]
        ns = rows[names]
        strings = data[ns[4]:ns[4] + ns[5]]
        self.sections = {}
        for row in rows:
            name = strings[row[0]:].split(b'\0')[0].decode('ascii')
            if name in ('.eh_frame', '.rela.dyn'):
                need(name not in self.sections, 'duplicate section')
                self.sections[name] = row
        need(len(self.sections) == 2, 'missing sections')

    def offset(self, va, size):
        hits = [off + va - start for start, off, n in self.loads if start <= va and va + size <= start + n]
        need(size >= 0 and len(hits) == 1, 'nonunique load mapping')
        return hits[0]

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def frames(self):
        section = self.sections['.eh_frame']
        off, end = section[4], section[4] + section[5]
        rows = []
        while off + 4 <= end:
            length = struct.unpack_from('<I', self.data, off)[0]
            if not length:
                break
            need(length != 0xffffffff and off + length + 4 <= end, 'frame length')
            if length >= 12 and struct.unpack_from('<I', self.data, off + 4)[0]:
                pc = section[3] + off + 8 - section[4] + struct.unpack_from('<i', self.data, off + 8)[0]
                n = struct.unpack_from('<I', self.data, off + 12)[0]
                rows.append((pc, pc + n, off, length + 4))
            off += length + 4
        return rows

    def relocation(self, slot):
        row = self.sections['.rela.dyn']
        need(row[9] == 24 and row[5] % 24 == 0, 'RELA layout')
        hits = []
        for off in range(row[4], row[4] + row[5], 24):
            va, info, addend = struct.unpack_from('<QQq', self.data, off)
            if va == slot:
                hits.append((info, addend))
        return hits

def structure(data, evidence):
    """Checks below capture identity, also used by per-clause corruption tests."""
    img = Image(data)
    for pin in evidence['clauses']:
        raw = bytes.fromhex(pin['raw'])
        need(img.read(int(pin['va'], 16), len(raw)) == raw, 'clause: ' + pin['name'])
    for row in evidence['frames']:
        start, end = int(row['start'], 16), int(row['end'], 16)
        hits = [f for f in img.frames() if f[0] < end and start < f[1]]
        need(len(hits) == 1 and hits[0][:2] == (start, end), 'FDE extent')
        off, size = hits[0][2:]
        need(off == row['file_offset'] and data[off:off + size].hex() == row['raw'], 'FDE record')
        off = row['cie_file_offset']
        need(data[off:off + len(bytes.fromhex(row['cie_raw']))].hex() == row['cie_raw'], 'CIE record')
    for row in evidence['relocations']:
        need(img.relocation(int(row['slot'], 16)) == [(8, int(row['target'], 16))], 'unique RELATIVE writer')
    # Independently decode the two selected conditional edges and actual RIP slot.
    need(0x2b79aeb + 6 + struct.unpack('<i', img.read(0x2b79aed, 4))[0] == 0x2b79b7d, 'nonerror edge')
    need(0x2b79af8 + 2 + struct.unpack('<b', img.read(0x2b79af9, 1))[0] == 0x2b79b06, 'zero-capacity edge')
    need(0x2b79b00 + 6 + struct.unpack('<i', img.read(0x2b79b02, 4))[0] == 0x64df4a0, 'cleanup call slot')
    need(0x2b79b0a + 2 + struct.unpack('<b', img.read(0x2b79b0b, 1))[0] == 0x2b79b4e, 'return join')
    return img

def verify(data, evidence):
    need(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == SHA, 'capture identity')
    return structure(data, evidence)

if __name__ == '__main__':
    evidence = json.loads((HERE / 'evidence.json').read_text())
    verify(TARGET.read_bytes(), evidence)
    print(json.dumps({'capture_sha256': SHA, 'clauses_checked': len(evidence['clauses']), 'frames_checked': len(evidence['frames']), 'relocations_checked': len(evidence['relocations']), 'captured_execution': False}, sort_keys=True))
