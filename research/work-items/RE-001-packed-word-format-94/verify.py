#!/usr/bin/env python3
"""Offline byte/FDE/edge verification. Never executes the captured program."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def require(ok, why):
    if not ok:
        raise ValueError(why)


class Elf:
    def __init__(self, data):
        self.data = data
        require(data[:6] == b'\x7fELF\x02\x01', 'ELF64 LE identity')
        off = struct.unpack_from('<Q', data, 40)[0]
        stride, count, names = struct.unpack_from('<HHH', data, 58)
        require(stride >= 64 and count and names < count and off + stride * count <= len(data), 'section table bounds')
        rows = [struct.unpack_from('<IIQQQQIIQQ', data, off + stride * i) for i in range(count)]
        n = rows[names]
        strings = data[n[4]:n[4] + n[5]]
        self.sections = {}
        for row in rows:
            end = strings.find(b'\0', row[0])
            require(end >= row[0], 'section name')
            name = strings[row[0]:end].decode()
            require(name not in self.sections, 'duplicate section name')
            require(row[1] == 8 or row[4] + row[5] <= len(data), 'section file bounds')
            self.sections[name] = row

    def offset(self, va, size):
        rows = [r for r in self.sections.values() if r[1] != 8 and r[3] <= va and va + size <= r[3] + r[5]]
        require(len(rows) == 1, 'unambiguous file-backed VA')
        return rows[0][4] + va - rows[0][3]

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def frame(self, relative):
        sec = self.sections['.eh_frame']
        va = sec[3] + relative
        length, back = struct.unpack('<II', self.read(va, 8))
        require(length >= 12 and relative + length + 4 <= sec[5], 'FDE bounds')
        cie = va + 4 - back
        require(self.read(cie, 24) == bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'), 'supported zR pcrel-sdata4 CIE')
        delta, extent = struct.unpack('<iI', self.read(va + 8, 8))
        return dict(offset=hex(relative), start=hex(va + 8 + delta), end=hex(va + 8 + delta + extent), raw=self.read(va, length + 4).hex())

    def binding(self, slot):
        found = []
        for name in ('.rela.dyn', '.rela.plt'):
            sec = self.sections[name]
            require(sec[9] == 24 and sec[5] % 24 == 0, 'RELA entry size')
            for off in range(sec[4], sec[4] + sec[5], 24):
                dst, info, addend = struct.unpack_from('<QQq', self.data, off)
                if dst == slot:
                    found.append((info, addend))
        require(len(found) == 1, 'unique selected relocation')
        info, addend = found[0]
        dyn = self.sections['.dynsym']
        names = list(self.sections.values())
        # The section link indexes original table order, retained by insertion order.
        st = names[dyn[6]]
        sym = struct.unpack_from('<IBBHQQ', self.data, dyn[4] + (info >> 32) * dyn[9])
        strings = self.data[st[4]:st[4] + st[5]]
        end = strings.index(b'\0', sym[0])
        return dict(slot=hex(slot), type=info & 0xffffffff, symbol=strings[sym[0]:end].decode(), addend=addend)


def structural(data, record):
    elf = Elf(data)
    for row in record['ranges']:
        start, end = int(row['start'], 16), int(row['end'], 16)
        require(hashlib.sha256(elf.read(start, end - start)).hexdigest() == row['sha256'], 'range byte hash')
    for row in record['frames']:
        require(elf.frame(int(row['offset'], 16)) == row, 'FDE record/range')
    for row in record['direct_edges']:
        va = int(row['site'], 16)
        raw = elf.read(va, 5)
        require(raw[0] in (0xe8, 0xe9), 'direct edge opcode')
        target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        require(hex(target) == row['target'] and raw.hex() == row['raw'], 'direct edge target')
    for row in record['indirect_calls']:
        va = int(row['site'],16)
        raw = bytes.fromhex(row['raw'])
        require(elf.read(va,len(raw)) == raw, 'indirect call bytes')
        require(raw in (bytes.fromhex('ffd1'),bytes.fromhex('ffd5'),bytes.fromhex('41ffd4'))
                or (len(raw) == 6 and raw[:2] == bytes.fromhex('ff15')), 'selected indirect call encoding')
    for row in record['rip_references']:
        va = int(row['site'],16)
        raw = bytes.fromhex(row['raw'])
        require(elf.read(va,len(raw)) == raw, 'RIP reference bytes')
        offset = row['displacement_offset']
        target = va + len(raw) + int.from_bytes(raw[offset:offset+4], 'little', signed=True)
        require(hex(target) == row['target'], 'RIP reference target')
    for row in record['bindings']:
        require(elf.binding(int(row['slot'], 16)) == row, 'dynamic binding')
    for row in record['branch_edges']:
        va = int(row['site'], 16)
        raw = bytes.fromhex(row['raw'])
        require(elf.read(va, len(raw)) == raw, 'branch bytes')
        displacement = int.from_bytes(raw[1:] if len(raw) == 2 else raw[2:], 'little', signed=True)
        require(hex(va + len(raw) + displacement) == row['target'], 'branch target')
    for row in record['data']:
        require(elf.read(int(row['va'], 16), len(bytes.fromhex(row['raw']))).hex() == row['raw'], 'selected data bytes')
    for row in record['nobits_globals']:
        sec = elf.sections[row['section']]
        va = int(row['va'], 16)
        require(sec[1] == 8 and sec[3] <= va and va + row['width'] <= sec[3] + sec[5], 'NOBITS global membership')
    # Independently check every retained disassembly line against the mapped bytes.
    count = 0
    covered = set()
    for name in ('formatter.objdump.txt',):
        for line in (HERE / name).read_text().splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)', line)
            if match:
                va = int(match[1], 16)
                raw = bytes.fromhex(match[2])
                require(elf.read(va, len(raw)) == raw, 'retained instruction bytes')
                extent = set(range(va, va + len(raw)))
                require(not (covered & extent), 'duplicate disassembly byte coverage')
                covered.update(extent)
                count += 1
    require(count == record['retained_instruction_lines'], 'instruction line count')
    for frame in record['frames']:
        require(set(range(int(frame['start'], 16), int(frame['end'], 16))) <= covered,
                'complete selected FDE byte coverage')
    return elf


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--negative-controls', action='store_true')
    args = parser.parse_args()
    data = args.binary.read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA, 'node94 full identity')
    record = json.loads((HERE / 'evidence.json').read_text())
    elf = structural(data, record)
    result = dict(identity='passed', structural='passed', instruction_lines=record['retained_instruction_lines'], captured_binary_executed=False)
    if args.negative_controls:
        controls = []
        # Full identity was checked above. Deliberately bypass only that gate so
        # each mutation reaches the downstream structural check it should test.
        cases = [('packed-field-shift', 0x151f256), ('table-bound', 0x151f267),
                 ('unsigned-small-group-guard', 0x151f284), ('first-decimal-multiplier', 0x151f296),
                 ('first-callback-slot', 0x151f2bf), ('early-AL-test', 0x151f2cd),
                 ('suffix-threshold', 0x151f39b), ('last-callback-EAX-copy', 0x151f437),
                 ('table-byte', 0x250675),
                 ('formatter-FDE-range', elf.sections['.eh_frame'][3] + 0x14fec + 12),
                 ('indirect-format-relocation', None)]
        for label, va in cases:
            changed = bytearray(data)
            if va is not None:
                offset = elf.offset(va, 1)
            else:
                sec = elf.sections['.rela.dyn']
                offsets = [off for off in range(sec[4], sec[4] + sec[5], 24)
                           if struct.unpack_from('<Q', data, off)[0] == 0x576e008]
                require(len(offsets) == 1, 'control relocation selection')
                offset = offsets[0] + 8
            changed[offset] ^= 1
            try:
                structural(changed, record)
            except (ValueError, IndexError, struct.error) as error:
                controls.append(dict(control=label, rejected=True, reason=str(error)))
            else:
                raise ValueError('mutation escaped: ' + label)
        result['negative_controls'] = controls
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
