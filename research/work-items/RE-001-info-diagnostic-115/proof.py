"""Narrow static node115 Location binding; never executes the captured ELF."""
from pathlib import Path
import hashlib
import json
import re
import struct
import subprocess

TARGET = Path('artifacts/node/115/hl-node')
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
LOCATION = 0x6441ad8
SOURCE = b'info_server/src/abci_state_info_handler.rs'
EXTENT = (0x29691a0, 0x2969331)
SITES = ((0x29692a8, bytes.fromhex('488d3d2988ad03')),
         (0x29692b5, bytes.fromhex('488d3d1c88ad03')))

def require(ok, message):
    if not ok:
        raise ValueError(message)

def authenticate(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256,
            'target identity')

def unpack(fmt, data, offset):
    require(offset >= 0 and offset + struct.calcsize(fmt) <= len(data), 'truncated ELF field')
    return struct.unpack_from(fmt, data, offset)

class Image:
    def __init__(self, data):
        self.data = data
        require(data[:7] == b'\x7fELF\x02\x01\x01', 'ELF format')
        require(unpack('<H', data, 18)[0] == 62, 'ELF machine')
        phoff, shoff = unpack('<QQ', data, 32)
        phents, phnum, shents, shnum = unpack('<HHHH', data, 54)
        require(phents == 56 and shents == 64 and phnum > 0 and shnum > 0, 'ELF table dimensions')
        self.ph = [unpack('<IIQQQQQQ', data, phoff + i*phents) for i in range(phnum)]
        self.sh = [unpack('<IIQQQQIIQQ', data, shoff + i*shents) for i in range(shnum)]

    def offset(self, va, size, executable=False):
        require(size > 0, 'mapping size')
        matches = []
        for p in self.ph:
            if p[0] == 1 and (not executable or p[1] & 1) and p[3] <= va and va+size <= p[3]+p[5]:
                q = p[2]+va-p[3]
                require(q+size <= len(self.data), 'truncated mapped bytes')
                matches.append(q)
        require(len(matches) == 1, 'mapping not uniquely file-backed')
        return matches[0]

    def relocations(self, va):
        found = []
        for s in self.sh:
            if s[1] != 4:
                continue
            require(s[9] == 24 and s[5] % 24 == 0, 'RELA dimensions')
            require(s[4]+s[5] <= len(self.data), 'truncated RELA table')
            for q in range(s[4], s[4]+s[5], 24):
                row = unpack('<QQq', self.data, q)
                if row[0] == va:
                    found.append((q, row))
        require(len(found) == 1, 'Location relocation missing or duplicate')
        return found[0]

def binding(data):
    image = Image(data)
    relocation_file, (destination, info, source_va) = image.relocations(LOCATION)
    require(info == 8 and source_va >= 0, 'not symbol-zero R_X86_64_RELATIVE')
    q = image.offset(LOCATION, 24)
    raw_pointer, length, line, column = unpack('<QQII', data, q)
    require((raw_pointer, length, line, column) == (0, len(SOURCE), 664, 120), 'Location fields')
    source_file = image.offset(source_va, length)
    require(data[source_file:source_file+length] == SOURCE, 'source path')
    image.offset(EXTENT[0], EXTENT[1]-EXTENT[0], executable=True)
    refs = []
    for va, expected in SITES:
        require(EXTENT[0] <= va and va+7 <= EXTENT[1], 'xref containment')
        file = image.offset(va, 7, executable=True)
        raw = data[file:file+7]
        require(raw == expected and raw[:3] == b'\x48\x8d\x3d', 'xref bytes')
        target = va+7+unpack('<i', raw, 3)[0]
        require(target == LOCATION, 'RIP-relative destination')
        refs.append({'va': hex(va), 'file': hex(file), 'bytes': raw.hex(), 'target': hex(target)})
    return {'source': SOURCE.decode(), 'line': line, 'column': column,
            'source_va': hex(source_va), 'source_file': hex(source_file),
            'location_va': hex(LOCATION), 'location_file': hex(q),
            'relocation_file': hex(relocation_file), 'relocation_info': info,
            'relocation_addend': hex(source_va), 'location_bytes': data[q:q+24].hex(),
            'extent': [hex(n) for n in EXTENT], 'xrefs': refs}

def frame_binding(text):
    ranges = []
    for line in text.splitlines():
        match = re.search(r'\bFDE\b.*\bpc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)', line)
        if match:
            ranges.append(tuple(int(x, 16) for x in match.groups()))
    for va, _ in SITES:
        owners = [pair for pair in ranges if pair[0] <= va < pair[1]]
        require(owners == [EXTENT], 'FDE missing, ambiguous or changed')

def instruction_binding(text):
    for va, expected in SITES:
        lines = re.findall(r'^\s*'+format(va, 'x')+r':\s+((?:[0-9a-fA-F]{2}\s+)+)\s*(\S+)[^\n]*', text, re.M)
        require(len(lines) == 1, 'native instruction missing or duplicate')
        raw, mnemonic = lines[0]
        require(bytes.fromhex(raw) == expected and mnemonic == 'lea', 'native instruction mismatch')

def prove():
    data = TARGET.read_bytes()
    authenticate(data)
    result = binding(data)
    commands = [ ['readelf', '--debug-dump=frames-interp', str(TARGET)],
                 ['objdump', '-d', '--start-address='+hex(EXTENT[0]),
                  '--stop-address='+hex(EXTENT[1]), str(TARGET)] ]
    frames, native = [subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=90).stdout for cmd in commands]
    frame_binding(frames)
    instruction_binding(native)
    result.update(target=str(TARGET), sha256=SHA256, size=SIZE, commands=commands,
                  tools={tool: subprocess.run([tool, '--version'], check=True, capture_output=True,
                                              text=True, timeout=10).stdout.splitlines()[0]
                         for tool in ['readelf', 'objdump']},
                  limitations='Two selected aligned LEAs and one source Location/FDE only; no helper identity, semantic ownership, request behavior, runtime reachability, equivalence or gate completion. Static only.')
    return result

if __name__ == '__main__':
    result = prove()
    Path(__file__).with_name('proof.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps(result, indent=2, sort_keys=True))
