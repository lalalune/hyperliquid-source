#!/usr/bin/env python3
"""Digest-bound static method-registration/lookup edges; never target execution."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
BASE = '56c0ec672bd8fdcfaa80f2db700a61e6240b3663'
RANGES = {
    'lookup-owner': (0x2027610, 0x2028519),
    'registration-context': (0x27ab650, 0x27abc18),
    'block-number-registration': (0x1f6d8a0, 0x1f6d97d),
    'insertion': (0x2a484d0, 0x2a48720),
    'insertion-probe': (0x2a48ad0, 0x2a48c6a),
    'method-callback': (0x1f702c0, 0x1f704a8),
    'callback-direct-callee': (0x27b8410, 0x27b86e8),
}
NATIVE_WINDOWS = {
    'lookup-owner': ((0x2027621, 0x2027660), (0x20278eb, 0x20278ee),
                     (0x2027c31, 0x2027dcb), (0x2027fed, 0x20280d3)),
    'registration-context': ((0x27ab65a, 0x27ab67e),),
    'block-number-registration': ((0x1f6d8a0, 0x1f6d97d),),
    'insertion': ((0x2a484dd, 0x2a485d8),),
    'insertion-probe': ((0x2a48ade, 0x2a48b09), (0x2a48c0c, 0x2a48c6a)),
    'method-callback': ((0x1f702c0, 0x1f702fe),),
    'callback-direct-callee': ((0x27b8410, 0x27b8427),),
}
RELATIVE = {0x5770950: 0x2a484d0, 0x5691990: 0x1f9b760,
            0x56919a8: 0x1f997c0, 0x56919b0: 0x1f702c0,
            0x56919b8: 0x1f702c0}
LOCAL_WINDOWS = (
    (0x2027c31, 0x2027dcb), (0x2027fed, 0x20280d3),
    (0x1f6d8ad, 0x1f6d934), (0x2a484dd, 0x2a485d8),
    (0x1f702d1, 0x1f702fe), (0x27ab667, 0x27ab67e),
    (0x2a48ade, 0x2a48b09), (0x2a48c1d, 0x2a48c6a),
)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


class Image:
    def __init__(self, data, authenticate=True):
        if authenticate:
            need(len(data) == SIZE and sha(data) == DIGEST, 'target identity')
        need(data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian')
        need(struct.unpack_from('<HH', data, 16) == (3, 62), 'AMD64 PIE')
        self.data = data
        po, so = struct.unpack_from('<QQ', data, 32)
        ps, pn, ss, sn, names_index = struct.unpack_from('<HHHHH', data, 54)
        need(ps == 56 and ss == 64 and names_index < sn, 'ELF header strides')
        need(po + ps * pn <= len(data) and so + ss * sn <= len(data), 'ELF tables')
        self.loads = [struct.unpack_from('<IIQQQQQQ', data, po + ps * i)
                      for i in range(pn)]
        headers = [struct.unpack_from('<IIQQQQIIQQ', data, so + ss * i)
                   for i in range(sn)]
        ns = headers[names_index]
        names = data[ns[4]:ns[4] + ns[5]]
        self.sections = {}
        for h in headers:
            end = names.find(b'\0', h[0])
            need(end >= h[0], 'section name')
            name = names[h[0]:end].decode('ascii')
            need(name not in self.sections or name == '', 'duplicate named section')
            self.sections[name] = h

    def offset(self, va, length, code=False):
        need(length > 0, 'positive mapped length')
        found = [p for p in self.loads if p[0] == 1 and p[3] <= va
                 and va + length <= p[3] + p[5] and (not code or p[1] & 1)]
        need(len(found) == 1, 'unique file-backed PT_LOAD')
        p = found[0]
        off = p[2] + va - p[3]
        need(off + length <= len(self.data), 'file-backed read bound')
        return off

    def at(self, va, length):
        off = self.offset(va, length)
        return self.data[off:off + length]

    def section(self, name):
        need(name in self.sections, 'missing section ' + name)
        return self.sections[name]

    def relas(self, slots, require_all=True):
        found = {}
        for s in self.sections.values():
            if s[1] != 4:
                continue
            need(s[9] == 24 and s[5] % 24 == 0, 'RELA stride')
            for off in range(s[4], s[4] + s[5], 24):
                va, info, addend = struct.unpack_from('<QQq', self.data, off)
                if va in slots:
                    need(va not in found, 'duplicate selected RELA')
                    found[va] = {'type': info & 0xffffffff, 'symbol_index': info >> 32,
                                 'addend': addend, 'file_offset': off,
                                 'raw': self.data[off:off + 24].hex()}
        need(not require_all or found.keys() == slots, 'missing selected RELA')
        return found

    def frame(self, start, end):
        h, f = self.section('.eh_frame_hdr'), self.section('.eh_frame')
        raw = self.data[h[4]:h[4] + h[5]]
        need(raw[:4] == bytes.fromhex('011b033b'), 'unwind index encoding')
        count = struct.unpack_from('<I', raw, 8)[0]
        need(12 + count * 8 <= len(raw), 'unwind index length')
        found = []
        for i in range(count):
            pc, fv = struct.unpack_from('<ii', raw, 12 + 8 * i)
            if h[3] + pc == start:
                found.append((i, h[3] + fv))
        need(len(found) == 1, 'selected exact unwind index')
        index, fva = found[0]
        off = self.offset(fva, 16)
        length, back, delta, extent = struct.unpack_from('<IIiI', self.data, off)
        need(13 <= length < 0xffffffff and f[4] <= off
             and off + length + 4 <= f[4] + f[5], 'FDE declared length')
        need((fva + 8 + delta, fva + 8 + delta + extent) == (start, end), 'FDE PC interval')
        co = off + 4 - back
        need(f[4] <= co and co + 8 <= off, 'CIE backreference')
        cl, cid = struct.unpack_from('<II', self.data, co)
        need(cid == 0 and co + cl + 4 <= off, 'CIE header')
        cie = self.data[co:co + cl + 4]
        need(cie[8] == 1, 'CIE version')
        nul = cie.index(0, 9)
        aug = cie[9:nul].decode('ascii')
        need(aug in ('zR', 'zPLR'), 'CIE augmentation kind')
        pos = nul + 1
        for _ in range(2):
            while cie[pos] & 0x80:
                pos += 1
            pos += 1
        pos += 1  # Version-1 return register.
        size = cie[pos]
        need(size < 128 and pos + 1 + size <= len(cie), 'CIE augmentation length')
        pos += 1
        for ch in aug[1:]:
            if ch == 'P':
                need(cie[pos] == 0x9b, 'CIE personality encoding')
                pos += 5
            elif ch == 'L':
                need(cie[pos] == 0x1b, 'CIE LSDA encoding')
                pos += 1
            elif ch == 'R':
                need(cie[pos] == 0x1b, 'CIE FDE PC encoding')
                pos += 1
        body = self.at(start, end - start)
        self.offset(start, end - start, code=True)
        return {'start': hex(start), 'end': hex(end), 'bytes': end - start,
                'body_sha256': sha(body), 'body_file_offset': self.offset(start, end - start),
                'index_file_offset': h[4] + 12 + index * 8,
                'index_raw': raw[12 + index * 8:20 + index * 8].hex(),
                'fde_va': hex(fva), 'fde_file_offset': off,
                'fde_raw': self.data[off:off + length + 4].hex(),
                'cie_file_offset': co, 'cie_raw': cie.hex(), 'cie_augmentation': aug}


def native_rows(text):
    rows = []
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$', line)
        if m:
            rows.append((int(m[1], 16), bytes.fromhex(m[2]), m[3].strip()))
    return rows


def partition(image, text, start, end):
    rows, cursor = native_rows(text), start
    for va, raw, _ in rows:
        need(va == cursor and raw and va + len(raw) <= end, 'native partition')
        need(raw == image.at(va, len(raw)), 'native byte agreement')
        cursor += len(raw)
    need(cursor == end, 'complete native extent')
    return rows


def bindings(image, witnesses):
    # No whole-image or whole-body hash here: private controls reach this seam.
    for key, value in witnesses.items():
        va = int(key, 16)
        need(image.at(va, len(bytes.fromhex(value))) == bytes.fromhex(value), 'witness:' + key)
    need(image.at(0x3f05a2, 15) == b'eth_blockNumber', 'method literal')
    need(image.at(0x5691990, 48) == struct.pack('<6Q', 0, 8, 8, 0, 0, 0), 'raw callback table')
    need(not image.relas({0x5691998, 0x56919a0}, require_all=False),
         'unrelocated callback size/alignment')
    relas = image.relas(set(RELATIVE) | {0x576e378})
    for slot, addend in RELATIVE.items():
        r = relas[slot]
        need((r['type'], r['symbol_index'], r['addend']) == (8, 0, addend), 'RELATIVE:' + hex(slot))
    r = relas[0x576e378]
    need((r['type'], r['symbol_index'], r['addend']) == (6, 11, 0), 'bcmp relocation')
    sym, strings = image.section('.dynsym'), image.section('.dynstr')
    off = sym[4] + 11 * 24
    raw = image.data[off:off + 24]
    name, info, other, shndx, value, size = struct.unpack('<IBBHQQ', raw)
    begin = strings[4] + name
    end = image.data.index(0, begin, strings[4] + strings[5])
    need(image.data[begin:end] == b'bcmp' and shndx == value == size == 0, 'undefined bcmp symbol')
    return {'selected_relocations': {hex(k): v for k, v in sorted(relas.items())},
            'comparator_symbol': {'index': 11, 'name': 'bcmp', 'symbol_file_offset': off,
                                  'symbol_raw': raw.hex(), 'name_file_offset': begin,
                                  'info': info, 'other': other, 'undefined': True},
            'callback_table': {'va': '0x5691990', 'raw': image.at(0x5691990, 48).hex()},
            'method_literal': {'va': '0x3f05a2', 'raw': 'eth_blockNumber'.encode().hex()},
            'witness_count': len(witnesses)}


def collect(target, witnesses, objdump='objdump'):
    image = Image(target.read_bytes())
    files, extents, decoded_witnesses = {}, {}, {}
    with tempfile.TemporaryDirectory(prefix='rpc-lookup-static-') as tmp:
        inert = Path(tmp) / 'node.elf'
        inert.write_bytes(image.data)
        inert.chmod(0o400)
        for name, (start, end) in RANGES.items():
            exports, windows = [], []
            for first, last in NATIVE_WINDOWS[name]:
                need(start <= first < last <= end, 'corridor in complete FDE')
                args = ['-d', '-w', '-M', 'intel', '--insn-width=16',
                        f'--start-address={first:#x}', f'--stop-address={last:#x}', 'node.elf']
                text = subprocess.check_output([objdump] + args, cwd=tmp, text=True)
                rows = partition(image, text, first, last)
                for va, raw, _ in rows:
                    key = hex(va)
                    if key in witnesses:
                        need(key not in decoded_witnesses and raw.hex() == witnesses[key],
                             'unique decoded instruction witness:' + key)
                        decoded_witnesses[key] = raw.hex()
                exports.append(text)
                windows.append({'start': hex(first), 'end': hex(last), 'bytes': last - first,
                                'rows': len(rows), 'command': ['objdump'] + args})
            text = ''.join(exports)
            files[name + '.gnu.txt'] = text.encode()
            extents[name] = dict(image.frame(start, end), native_windows=windows,
                                 native_sha256=sha(text.encode()))
        need(inert.read_bytes() == image.data, 'inert image changed')
    need(decoded_witnesses == witnesses, 'all witnesses decoded in retained corridors')
    record = {'schema': 1, 'base': BASE, 'target': {'bytes': SIZE, 'sha256': DIGEST},
              'ranges': extents, 'bindings': bindings(image, witnesses),
              'objdump_version': subprocess.check_output([objdump, '--version'], text=True).splitlines()[0],
              'captured_execution': False, 'instruction_evaluation': False,
              'new_recovered_byte_credit': 0, 'component_gate_requested': False}
    files['records.json'] = encode(record)
    return files


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, default=Path('artifacts/node/94/hl-node'))
    p.add_argument('--witnesses', type=Path, default=Path(__file__).with_name('WITNESSES.json'))
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--objdump', default='objdump')
    a = p.parse_args()
    need(not a.output.exists(), 'preserve existing output')
    files = collect(a.target, json.loads(a.witnesses.read_text()), a.objdump)
    a.output.mkdir(parents=True)
    for name, data in files.items():
        (a.output / name).write_bytes(data)
    print('Seven FDE identities and eleven selected native corridors collected; no target execution.')


if __name__ == '__main__':
    main()
