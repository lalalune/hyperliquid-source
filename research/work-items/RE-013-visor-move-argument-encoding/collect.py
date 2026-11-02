#!/usr/bin/env python3
"""Read and disassemble six complete Visor bodies; never execute target code.

Uses the repository's MIT ELF/FDE parsers. The byte-partition/LOCK convention
follows prior MIT static packets; no external/unlicensed source is incorporated.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = 'artifacts/visor/captured/hl-visor'
SHA = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
SIZE = 8305392
RANGES = {
    'move-request': (0x3a15d0, 0x3a1777),
    'coordinator': (0x323b60, 0x323d0c),
    'collector': (0x3e1920, 0x3e1bea),
    'blank-filter': (0x3a98d0, 0x3a9b67),
    'quote': (0x6516e0, 0x651be4),
    'join': (0x371b60, 0x371d8b),
}
CONTEXT = {
    'publication-first-request': (0x417026, 0x417046),
    'publication-second-request': (0x41707d, 0x417098),
    'quiet-option-selection': (0x3d8ee8, 0x3d8f36),
}
GNU = '/opt/homebrew/opt/binutils/bin/objdump'
LLVM = '/usr/bin/objdump'

def require(test, why):
    if not test:
        raise ValueError(why)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def loads(data):
    require(data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian')
    off = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    require(size == 56 and off + size * count <= len(data), 'program headers')
    result = []
    for i in range(count):
        typ, flags, file, va, _, n, memory, align = struct.unpack_from('<IIQQQQQQ', data, off + i * size)
        if typ == 1:
            require(file + n <= len(data) and n <= memory, 'PT_LOAD bounds')
            result.append((file, va, n))
    return result

def offset(data, va, length=1):
    matches = [off + va - base for off, base, size in loads(data)
               if base <= va and va + length <= base + size]
    require(len(matches) == 1, 'unique file-backed PT_LOAD')
    return matches[0]

def read(data, va, length):
    off = offset(data, va, length)
    return data[off:off + length]

def relas(data, selected):
    secs = sections(data)
    def one(name):
        found = [s for s in secs if s['name'] == name]
        require(len(found) == 1, 'unique section:' + name)
        return found[0]
    sec, syms, names = one('.rela.dyn'), one('.dynsym'), one('.dynstr')
    require(sec['size'] % 24 == 0, 'RELA size')
    rows = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, target = struct.unpack_from('<QQq', data, off)
        if slot in selected:
            require(slot not in rows, 'duplicate RELA')
            rows[slot] = {'slot': hex(slot), 'kind': info & 0xffffffff,
                          'symbol': info >> 32, 'addend': hex(target),
                          'file_offset': off, 'hex': data[off:off + 24].hex()}
            if info >> 32:
                si = syms['offset'] + (info >> 32) * 24
                require(si + 24 <= syms['offset'] + syms['size'], 'dynsym bounds')
                ni = names['offset'] + struct.unpack_from('<I', data, si)[0]
                ne = data.find(b'\0', ni, names['offset'] + names['size'])
                require(names['offset'] <= ni <= ne, 'dynstr bounds')
                rows[slot]['import'] = {'name': data[ni:ne].decode('ascii'),
                    'symbol_offset': si, 'symbol_hex': data[si:si + 24].hex(),
                    'name_offset': ni, 'name_hex': data[ni:ne + 1].hex()}
    require(set(rows) == set(selected), 'missing RELA')
    return [rows[k] for k in sorted(rows)]

def pins():
    return json.loads((HERE / 'pins.json').read_text())

def contract(data):
    p = pins()
    for name, row in p['instructions'].items():
        raw = bytes.fromhex(row['hex'])
        require(read(data, int(row['va'], 16), len(raw)) == raw, 'instruction:' + name)
    for name, row in p['data'].items():
        raw = bytes.fromhex(row['hex'])
        require(read(data, int(row['va'], 16), len(raw)) == raw, 'data:' + name)
    rows = relas(data, {int(k, 16) for k in p['relocations']})
    for row in rows:
        expected = p['relocations'][row['slot']]
        require([row['kind'], row['symbol'], row['addend']] == expected,
                'relocation:' + row['slot'])
    require(next(r for r in rows if r['slot'] == '0x7e4b68')['import']['name'] == 'memcpy', 'memcpy import')
    return rows

def fdes(data):
    secs = sections(data)
    _, records = eh_frame_records(data, secs)
    hdr = next(s for s in secs if s['name'] == '.eh_frame_hdr')
    raw = data[hdr['offset']:hdr['offset'] + hdr['size']]
    require(raw[:4] == bytes.fromhex('011b033b'), 'FDE index encoding')
    count = struct.unpack_from('<I', raw, 8)[0]
    require(12 + count * 8 == len(raw), 'FDE index size')
    index = [(hdr['address'] + a, hdr['address'] + p) for a, p in struct.iter_unpack('<ii', raw[12:])]
    result = {}
    for name, (a, b) in RANGES.items():
        found = [f for f in records if f['start'] == a]
        require(len(found) == 1 and found[0]['end'] == b, 'FDE extent:' + name)
        f = found[0]
        require([p for start, p in index if start == a] == [f['fde']], 'FDE index:' + name)
        fl = struct.unpack('<I', read(data, f['fde'], 4))[0] + 4
        cl = struct.unpack('<I', read(data, f['cie'], 4))[0] + 4
        result[name] = {'record': f, 'fde_hex': read(data, f['fde'], fl).hex(),
                        'cie_hex': read(data, f['cie'], cl).hex()}
    return result

def parse(text, start, end):
    rows = []
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$', line)
        if m and start <= int(m[1], 16) < end:
            rows.append((int(m[1], 16), bytes.fromhex(m[2]), m[3]))
    at = start
    for va, raw, _ in rows:
        require(va == at, 'native gap/overlap')
        at += len(raw)
    require(at == end, 'incomplete native extent')
    return rows

def partition(rows):
    result = []
    i = 0
    while i < len(rows):
        va, raw, asm = rows[i]
        if raw == b'\xf0' and asm == 'lock':
            require(i + 1 < len(rows) and rows[i + 1][0] == va + 1, 'dangling LOCK')
            raw += rows[i + 1][1]
            asm += ' ' + rows[i + 1][2]
            i += 1
        result.append((va, raw, asm))
        i += 1
    return result

def native(data, text, start, end):
    rows = parse(text, start, end)
    require(b''.join(raw for _, raw, _ in rows) == read(data, start, end - start), 'native bytes')
    return partition(rows)

def decode(data, snapshot, tool, provider, a, b):
    flags = ['-d', '-M', 'intel', '--insn-width=16'] if provider == 'gnu' else ['--disassemble', '--x86-asm-syntax=intel']
    text = subprocess.check_output([tool, *flags, f'--start-address={a:#x}', f'--stop-address={b:#x}', snapshot.name], cwd=snapshot.parent, text=True)
    return text, native(data, text, a, b)

def collect(binary, out, gnu=GNU, llvm=LLVM):
    require(not out.exists(), 'existing output refused')
    data = binary.read_bytes()
    require(len(data) == SIZE and digest(data) == SHA, 'target identity')
    rel = contract(data)
    fs = fdes(data)
    out.mkdir(parents=True, exist_ok=False)
    result = {'target_sha256': SHA, 'target_bytes': SIZE, 'ranges': {}, 'context': {},
              'relocations': rel, 'pins_sha256': digest((HERE / 'pins.json').read_bytes()),
              'parser_hashes': {str(p): digest((ROOT / p).read_bytes()) for p in ['tools/elf_index.py', 'tools/fde_extents.py']},
              'versions': {p: subprocess.check_output([t, '--version'], text=True).splitlines()[0] for p, t in [('gnu', gnu), ('llvm', llvm)]}}
    transfers = ['owner\taddress\tinstruction']
    with tempfile.TemporaryDirectory(prefix='visor-move-static-') as tmp:
        snapshot = Path(tmp) / 'visor.elf'
        snapshot.write_bytes(data)
        snapshot.chmod(0o400)
        require(digest(snapshot.read_bytes()) == SHA, 'snapshot before')
        for name, (a, b) in {**RANGES, **CONTEXT}.items():
            exports = {}
            rows = {}
            for provider, tool in [('gnu', gnu), ('llvm', llvm)]:
                text, rows[provider] = decode(data, snapshot, tool, provider, a, b)
                raw = text.encode()
                stored = raw if provider == 'gnu' else gzip.compress(raw, mtime=0)
                filename = name + '.' + provider + '.txt' + ('.gz' if provider == 'llvm' else '')
                (out / filename).write_bytes(stored)
                exports[provider] = {'file': filename, 'raw_sha256': digest(raw), 'stored_sha256': digest(stored)}
            require([(v, raw) for v, raw, _ in rows['gnu']] == [(v, raw) for v, raw, _ in rows['llvm']], 'native partition')
            boundaries = {v for v, _, _ in rows['gnu']}
            for va, raw, asm in rows['gnu']:
                if asm.split()[0].startswith(('call', 'jmp', 'j', 'ret')) or raw == b'\x0f\x0b':
                    transfers.append(name + '\t' + hex(va) + '\t' + asm)
                # Validate local direct branch targets; no execution/reachability claim.
                dest = None
                if raw[:1] in (b'\xe8', b'\xe9') and len(raw) == 5:
                    dest = va + 5 + struct.unpack('<i', raw[1:])[0]
                elif len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
                    dest = va + 2 + struct.unpack('<b', raw[1:])[0]
                elif len(raw) == 6 and raw[0] == 15 and 0x80 <= raw[1] <= 0x8f:
                    dest = va + 6 + struct.unpack('<i', raw[2:])[0]
                if dest is not None and a <= dest < b:
                    require(dest in boundaries, 'branch interior')
            record = {'start': hex(a), 'end': hex(b), 'bytes': b - a,
                      'rows': len(rows['gnu']), 'sha256': digest(read(data, a, b - a)), 'exports': exports}
            if name in RANGES:
                record['unwind'] = fs[name]
                result['ranges'][name] = record
            else:
                result['context'][name] = record
        require(digest(snapshot.read_bytes()) == SHA, 'snapshot after')
    (out / 'transfers.tsv').write_text('\n'.join(transfers) + '\n')
    (out / 'records.json').write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
    return result

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--gnu', default=GNU)
    p.add_argument('--llvm', default=LLVM)
    a = p.parse_args()
    r = collect(ROOT / TARGET, a.out, a.gnu, a.llvm)
    print(json.dumps({'full_fdes': len(r['ranges']), 'bytes': sum(x['bytes'] for x in r['ranges'].values()), 'rows': sum(x['rows'] for x in r['ranges'].values())}))
