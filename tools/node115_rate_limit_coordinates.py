"""Static, digest-bound RE-001 source-Location coordinates; never runs the target.

New independently authored tooling. Captured bytes retain their upstream rights.
An unwind range is not a recovered function identity or a semantic proof.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
SOURCE = b'net_utils/src/rate_limiter.rs'
LOCATION = 0x64b6f68
STARTS = (0x59db700, 0x59db990)
LENGTH = 653
REFS = (0x59db91d, 0x59dbbad)
LEAS = ('488d3544b6ad00', '488d35b4b3ad00')
CALLEE = 0x57d32a0


def require(condition, message):
    if not condition:
        raise ValueError(message)


def authenticate(data):
    require(len(data) == SIZE, 'target size')
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'target digest')


class Elf:
    def __init__(self, data):
        self.data = data
        require(data[:6] == b'\x7fELF\x02\x01', 'ELF64 little-endian')
        e = self.unpack('<16sHHIQQQIHHHHHH', 0)
        require(e[2] == 62 and e[9] == 56 and e[11] == 64, 'ELF layout')
        self.loads = [self.unpack('<IIQQQQQQ', e[5] + i * 56)
                      for i in range(e[10])]
        self.loads = [s for s in self.loads if s[0] == 1]
        sections = [self.unpack('<IIQQQQIIQQ', e[6] + i * 64)
                    for i in range(e[12])]
        require(e[13] < len(sections), 'section name table')
        s = sections[e[13]]
        names = self.bytes(s[4], s[5])
        self.sections = {}
        for s in sections:
            require(s[0] < len(names), 'section name index')
            name = names[s[0]:].split(b'\0', 1)[0].decode('ascii')
            require(name not in self.sections, 'duplicate section')
            self.sections[name] = s

    def bytes(self, offset, size):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset,
                'file range')
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.bytes(offset, struct.calcsize(fmt)))

    def offset(self, va, size=1):
        matches = [s for s in self.loads
                   if s[3] <= va and size <= s[5] - (va - s[3])]
        require(len(matches) == 1, 'unique file-backed VA')
        s = matches[0]
        return va - s[3] + s[2]

    def relocations(self):
        s = self.sections['.rela.dyn']
        require(s[9] == 24 and s[5] % 24 == 0, 'RELA layout')
        return [(at, *self.unpack('<QQq', at))
                for at in range(s[4], s[4] + s[5], 24)]


def check_location(elf, relocations):
    records = [r for r in relocations if r[1] == LOCATION]
    require(len(records) == 1, 'unique Location relocation')
    at, dest, info, addend = records[0]
    require(info == 8, 'R_X86_64_RELATIVE and symbol zero')
    path_offset = elf.offset(addend, len(SOURCE))
    require(elf.bytes(path_offset, len(SOURCE)) == SOURCE, 'source path')
    loc_offset = elf.offset(dest, 24)
    raw = elf.bytes(loc_offset, 24)
    pointer, length, line, column = struct.unpack('<QQII', raw)
    require((length, line, column) == (len(SOURCE), 131, 20), 'Location fields')
    return {'va': hex(dest), 'file_offset': hex(loc_offset), 'raw': raw.hex(),
            'stored_pointer': hex(pointer), 'relocation_file_offset': hex(at),
            'relocation_raw': elf.bytes(at, 24).hex(), 'info': info,
            'path_va': hex(addend), 'path_file_offset': hex(path_offset),
            'path': SOURCE.decode(), 'length': length, 'line': line, 'column': column}


def check_frames(frames):
    rows = [(m[0], int(m[1], 16), int(m[2], 16))
            for m in re.finditer(r'^.* FDE .*?pc=([0-9a-f]+)\.\.([0-9a-f]+).*$',
                                 frames, re.M)]
    selected = []
    for lo, ref in zip(STARTS, REFS):
        matches = [r for r in rows if r[1] <= ref < r[2]]
        require(len(matches) == 1, 'unique containing FDE')
        require(matches[0][1:] == (lo, lo + LENGTH), 'exact FDE extent')
        selected.append(matches[0][0])
    return selected


def check_native(elf, index, disassembly):
    lo, ref = STARTS[index], REFS[index]
    offset = elf.offset(ref, 12)
    raw = elf.bytes(offset, 12)
    require(raw[:7].hex() == LEAS[index], 'LEA bytes')
    require(ref + 7 + struct.unpack('<i', raw[3:7])[0] == LOCATION, 'LEA destination')
    require(raw[7] == 0xe8, 'direct call opcode')
    require(ref + 12 + struct.unpack('<i', raw[8:12])[0] == CALLEE, 'direct call target')
    for va, instruction, mnemonic in ((ref, raw[:7], 'lea'), (ref + 7, raw[7:], 'call')):
        lines = re.findall(r'^\s*' + format(va, 'x') + r':\s+((?:[0-9a-f]{2} )+)\s*(.*)$',
                           disassembly, re.M)
        require(len(lines) == 1, 'unique native instruction boundary')
        rendered, text = lines[0]
        require(bytes.fromhex(rendered) == instruction and text.startswith(mnemonic),
                'native decode bytes and mnemonic')
    return {'start_va': hex(lo), 'end_va': hex(lo + LENGTH), 'extent_bytes': LENGTH,
            'body_sha256': hashlib.sha256(elf.bytes(elf.offset(lo, LENGTH), LENGTH)).hexdigest(),
            'reference_va': hex(ref), 'reference_file_offset': hex(offset),
            'lea_and_call_bytes': raw.hex(), 'direct_call_target': hex(CALLEE)}


def run(target=TARGET):
    data = Path(target).read_bytes()
    authenticate(data)
    elf = Elf(data)
    location = check_location(elf, elf.relocations())
    frames = subprocess.check_output(['readelf', '--debug-dump=frames', str(target)],
                                     text=True, timeout=90)
    frame_rows = check_frames(frames)
    native, regions = {}, []
    for i, lo in enumerate(STARTS):
        text = subprocess.check_output(['objdump', '-d', '-Mintel', f'--start-address={lo}',
                                        f'--stop-address={lo + LENGTH}', str(target)],
                                       text=True, timeout=30)
        # Remove only the input-path banner, retaining original native lines.
        text = '\n'.join(line for line in text.splitlines()
                         if not line.endswith('file format elf64-x86-64')) + '\n'
        native[f'native-{lo:x}.txt'] = text
        regions.append(check_native(elf, i, text))
    result = {'target_sha256': DIGEST, 'target_size': SIZE, 'location': location,
              'fde_rows': frame_rows, 'regions': regions,
              'counts': {'source_locations': 1, 'native_references': 2, 'unwind_extents': 2},
              'limits': 'Selected references only, not all xrefs; FDEs are unwind extents, not semantic function identities. Shared callee contract, algorithm, source ownership, caller closure and runtime behavior unresolved. No target execution or progress gate.'}
    return result, native


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result, native = run(args.target)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'proof.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    for name, text in native.items():
        (args.out / name).write_text(text)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
