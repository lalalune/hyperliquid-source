#!/usr/bin/env python3
"""Static node115 proposer bindings. This module never executes captured code."""
import argparse
import bisect
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-008-proposer-selection-115'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
MAIN = 0x595cb30
# Complete FDEs, not arbitrary instruction snippets. Larger generic implementations
# are recorded as boundaries, not assigned an unproved semantic identity.
STARTS = (
    MAIN, 0x595c3a0, 0x595e5c0,
    0x4dce7b0, 0x4dce480, 0x57f2b50, 0x57f35c0,
    0x4d38fd0, 0x4d391b0, 0x51f5470, 0x51f5620,
    0x5b7fca0, 0x543ec80, 0x5133940, 0x4dc0200, 0x57f54e0,
    0x5acae30, 0x5acbdf0, 0x53eaec0, 0x53ddc30,
    0x53e5db0, 0x4f3d890, 0x4f415f0, 0x4f411b0,
    0x63f0210, 0x63f0680, 0x63f0690, 0x63f06a0,
)
DATA_SPANS = ((0x9383de, 17), (0x9383ef, 6), (0x430c2a, 73),
              (0x43d23c, 47), (0x451210, 16), (0x450170, 16), (0x4592b0, 8))



def digest(data):
    return hashlib.sha256(data).hexdigest()


class Elf:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.cies, self.fdes = eh_frame_records(data, self.sections)
        self.relas = []
        self.symbols = {}
        shoff = struct.unpack_from('<Q', data, 40)[0]
        stride, count = struct.unpack_from('<HH', data, 58)
        headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * stride)
                   for i in range(count)]
        for sec in self.sections:
            if sec['type'] != 4:
                continue
            h = headers[self.sections.index(sec)]
            symbols = headers[h[6]]
            names = headers[symbols[6]]
            for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                address, info, addend = struct.unpack_from('<QQq', data, off)
                symbol = info >> 32
                name = None
                if symbol:
                    symoff = symbols[4] + symbol * symbols[9]
                    noff = struct.unpack_from('<I', data, symoff)[0]
                    begin = names[4] + noff
                    name = data[begin:data.index(b'\0', begin)].decode('ascii')
                self.relas.append(dict(address=address, kind=info & 0xffffffff,
                                       addend=addend, symbol=name, file_offset=off))

    def section(self, va, size=1):
        found = [s for s in self.sections
                 if s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(found) != 1:
            raise ValueError(f'ambiguous/unmapped span {va:#x}+{size}')
        return found[0]

    def read(self, va, size):
        sec = self.section(va, size)
        if sec['type'] == 8:
            return bytes(size)
        off = sec['offset'] + va - sec['address']
        return self.data[off:off + size]

    def fde(self, va):
        found = [f for f in self.fdes if f['start'] == va]
        if len(found) != 1:
            raise ValueError(f'nonunique FDE start {va:#x}')
        return found[0]

    def record(self, va):
        length = struct.unpack('<I', self.read(va, 4))[0]
        return self.read(va, length + 4).hex()

    def relas_at(self, start, size):
        return [r for r in self.relas if r['address'] < start + size
                and start < r['address'] + 8]


def decoder():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def body(elf, fde):
    raw = elf.read(fde['start'], fde['end'] - fde['start'])
    insns = list(decoder().disasm(raw, fde['start']))
    if sum(i.size for i in insns) != len(raw):
        raise ValueError('incomplete decoding')
    starts = {i.address for i in insns}
    rows, edges, reads = [], [], {}
    for i in insns:
        rows.append([i.address, i.bytes.hex(), i.mnemonic, i.op_str])
        if i.group(CS_GRP_CALL) or i.group(CS_GRP_JUMP):
            item = dict(site=i.address, kind=i.mnemonic, operand=i.op_str)
            if i.operands[0].type == X86_OP_IMM:
                dest = i.operands[0].imm
                item['target'] = dest
                if fde['start'] <= dest < fde['end'] and dest not in starts:
                    raise ValueError('branch enters instruction interior')
            edges.append(item)
        for op in i.operands:
            if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                continue
            address = i.address + i.size + op.mem.disp
            size = op.size if i.mnemonic != 'lea' else 1
            sec = elf.section(address, size)
            row = dict(address=address, size=size, section=sec['name'],
                       hex=elf.read(address, size).hex(),
                       relocations=elf.relas_at(address, size))
            reads[(address, size)] = row
            if i.group(CS_GRP_CALL) or i.group(CS_GRP_JUMP):
                edges[-1]['slot'] = address
                edges[-1]['slot_word'] = int.from_bytes(elf.read(address, 8), 'little')
                edges[-1]['relocations'] = elf.relas_at(address, 8)
                relative = [r for r in edges[-1]['relocations'] if r['address'] == address and r['kind'] == 8]
                if len(relative) == 1:
                    # The file's zero-filled GOT word is not the relocated value.
                    # This is a linked VA addend, not an observed runtime pointer.
                    edges[-1]['linked_target'] = relative[0]['addend']
    return dict(**fde, length=len(raw), sha256=digest(raw), hex=raw.hex(),
                fde_hex=elf.record(fde['fde']), cie_hex=elf.record(fde['cie']),
                instructions=rows, edges=edges, rip_operands=list(reads.values()))


def incoming(elf):
    """Enumerate E8/E9 and FF15/FF25 slot candidates, then decode boundaries."""
    candidates = set()
    slots = {r['address'] for r in elf.relas if r['kind'] == 8 and r['addend'] == MAIN}
    for sec in elf.sections:
        if not sec['flags'] & 4 or sec['type'] == 8:
            continue
        data = elf.read(sec['address'], sec['size'])
        for opcode in (b'\xe8', b'\xe9'):
            pos = data.find(opcode)
            while pos >= 0:
                if pos + 5 <= len(data):
                    target = sec['address'] + pos + 5 + struct.unpack_from('<i', data, pos + 1)[0]
                    if target == MAIN:
                        candidates.add(sec['address'] + pos)
                pos = data.find(opcode, pos + 1)
        for opcode in (b'\xff\x15', b'\xff\x25'):
            pos = data.find(opcode)
            while pos >= 0:
                if pos + 6 <= len(data):
                    slot = sec['address'] + pos + 6 + struct.unpack_from('<i', data, pos + 2)[0]
                    if slot in slots:
                        candidates.add(sec['address'] + pos)
                pos = data.find(opcode, pos + 1)
    fdes = [f for f in elf.fdes if any(f['start'] <= a < f['end'] for a in candidates)]
    rows = []
    for f in fdes:
        b = body(elf, f)
        sites = [e for e in b['edges'] if e.get('target') == MAIN or e.get('slot') in slots]
        if sites:
            rows.append(dict(sites=sites, body=b))
    return rows


def capture(data):
    elf = Elf(data)
    bodies = [body(elf, elf.fde(a)) for a in STARTS]
    tables = []
    for start in (0x4d38fd0, 0x4d391b0):
        target_body = next(b for b in bodies if b['start'] == start)
        row = next(r for r in target_body['rip_operands'] if r['section'] == '.rodata')
        address = row['address']
        raw = elf.read(address, 16)
        targets = [address + x for x in struct.unpack('<4i', raw)]
        boundaries = {i[0] for i in target_body['instructions']}
        if not all(t in boundaries for t in targets):
            raise ValueError('history jump table target outside instruction boundaries')
        tables.append(dict(address=address, hex=raw.hex(), targets=targets))
    return dict(schema=1, target_sha256=digest(data), target_size=len(data),
                fde_count=len(elf.fdes), cie_count=len(elf.cies), bodies=bodies,
                incoming=incoming(elf),
                naming_relocations=[r for r in elf.relas if r['kind'] == 8 and r['addend'] in STARTS],
                history_jump_tables=tables,
                data_spans=[dict(address=a, length=n, hex=elf.read(a,n).hex(),
                                 relocations=elf.relas_at(a,n)) for a,n in DATA_SPANS])


def verify(data, expected):
    if digest(data) != SHA256:
        raise ValueError('wrong complete target digest')
    actual = capture(data)
    if actual != expected:
        raise ValueError('static bindings differ: bytes/FDE/CFG/data/callers/relocations')
    return dict(target_sha256=SHA256, body_count=len(actual['bodies']),
                bytes=sum(b['length'] for b in actual['bodies']),
                main_bytes=actual['bodies'][0]['length'],
                main_calls=sum(e['kind'] == 'call' for e in actual['bodies'][0]['edges']),
                bound_incoming_sites=sum(len(c['sites']) for c in actual['incoming']),
                caller_fdes=len(actual['incoming']),
                caveat='Static closure, not captured execution or indirect reachability proof')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=TARGET)
    args = parser.parse_args()
    with gzip.open(PACKET / 'bindings.json.gz', 'rt') as f:
        expected = json.load(f)
    print(json.dumps(verify(args.target.read_bytes(), expected), indent=2))


if __name__ == '__main__':
    main()
