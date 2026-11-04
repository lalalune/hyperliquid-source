#!/usr/bin/env python3
"""Digest-bound static evidence for node115 TC reduction; never executes target code."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elf_index import sections
from fde_extents import eh_frame_records
ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-008-tc-parallel-abort-115'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CORE = (0x5b37b70, 0x5b3bd10, 0x564c120, 0x564c4b0, 0x564b510, 0x5aac2c0, 0x5b3dde0)
CONTEXT = (0x5942cc0, 0x5960390, 0x59defb0, 0x59eedf0, 0x59ee480,
           0x5bbd780, 0x5bbc210, 0x56365d0, 0x5b12050, 0x6355830, 0x635de30,
           0x595e5c0, 0x4dffc40, 0x595bc40, 0x595fd20, 0x4da8e80, 0x57e8bd0)
ANCHORS = {
    'inline-cancel-read':0x5b37ba0, 'pointer-cancel-read':0x5b3bd40,
    'inline-success-store':0x5b37ba8, 'pointer-success-store':0x5b3bd48,
    'inline-half':0x5b37bb8, 'pointer-half':0x5b3bd58,
    'inline-minimum-branch':0x5b37bbe, 'pointer-minimum-branch':0x5b3bd5e,
    'inline-worker-count':0x5b37d8c, 'pointer-worker-count':0x5b3bea3,
    'inline-worker-maximum':0x5b37d9c, 'pointer-worker-maximum':0x5b3beb3,
    'inline-underflow':0x5b37db6, 'pointer-underflow':0x5b3becd,
    'inline-stride':0x564c183, 'pointer-stride':0x564c503,
    'inline-value-offset':0x564c18c, 'pointer-value-pointer':0x564c50f,
    'inline-stop':0x564c1ad, 'pointer-stop':0x564c52d,
    'inline-flag-write':0x564c3a2, 'pointer-flag-write':0x564c722,
    'inline-post-read':0x564c435, 'pointer-post-read':0x564c7b5,
    'closure-allocation':0x5942cf6, 'closure-round-offset':0x5942cef,
    'closure-key-tail':0x5942d2a, 'closure-message-tag':0x5942d38,
    'closure-failure-tag':0x5942d5d, 'closure-success-tag':0x5942d58,
    'caller-maximum':0x5960624, 'caller-round-branch':0x5960700,
    'caller-quorum-branch':0x5960720, 'caller-nested-check':0x5960730,
    'entry-clear-flag':0x564b51b, 'entry-representation':0x564b550,
    'flat-capacity-branch':0x5b3de29, 'flat-minimum':0x5b3de61,
    'flat-count-size':0x5b3de97, 'outer-tls-offset':0x5aac31b,
}

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


def incoming(elf, targets):
    """Raw opcode candidates are admitted only after full containing-FDE decode."""
    targets = set(targets)
    slots = {r['address'] for r in elf.relas
             if r['kind'] == 8 and r['addend'] in targets}
    candidates = set()
    for sec in elf.sections:
        if not sec['flags'] & 4 or sec['type'] == 8:
            continue
        raw = elf.read(sec['address'], sec['size'])
        for opcode, width, wanted in ((b'\xe8', 5, targets), (b'\xe9', 5, targets),
                                      (b'\xff\x15', 6, slots), (b'\xff\x25', 6, slots)):
            pos = raw.find(opcode)
            while pos >= 0:
                if pos + width <= len(raw):
                    dest = sec['address'] + pos + width + struct.unpack_from('<i', raw, pos + len(opcode))[0]
                    if dest in wanted:
                        candidates.add(sec['address'] + pos)
                pos = raw.find(opcode, pos + 1)
    admitted, covered = [], set()
    for f in elf.fdes:
        if not any(f['start'] <= a < f['end'] for a in candidates):
            continue
        b = body(elf, f)
        sites = [e for e in b['edges'] if e.get('target') in targets or e.get('slot') in slots]
        if sites:
            admitted.append(dict(start=f['start'], sites=sites, body=b))
            covered.update(e['site'] for e in sites)
    return dict(callers=admitted, rejected_raw_candidates=sorted(candidates - covered),
                scope='E8/E9 and FF15/FF25 only; no complete indirect reachability claim')


def anchor_facts(elf):
    facts={}
    for name,address in ANCHORS.items():
        i=next(decoder().disasm(elf.read(address,15),address))
        facts[name]=dict(address=address,hex=i.bytes.hex(),mnemonic=i.mnemonic,
                         immediates=[o.imm for o in i.operands if o.type==X86_OP_IMM],
                         memory_displacements=[o.mem.disp for o in i.operands if o.type==X86_OP_MEM])
    return facts


def capture(data):
    elf = Elf(data)
    bodies = [body(elf, elf.fde(a)) for a in CORE + CONTEXT]
    inc = incoming(elf, CORE + (0x5942cc0,))
    # First-order outgoing targets remain boundaries. Binding a complete callee
    # does not assign its semantics or recursively close its runtime.
    destinations = {e.get('linked_target', e.get('target'))
                    for b in bodies for e in b['edges']
                    if e['kind'] == 'call' or (e['kind'] == 'jmp' and
                       not b['start'] <= e.get('target', b['start']) < b['end'])}
    tls_writers=[r for r in elf.relas_at(0x64b7070,8) if r['address']==0x64b7070 and r['kind']==8]
    if len(tls_writers)!=1: raise ValueError('no-TLS adapter data writer')
    destinations.add(tls_writers[0]['addend'])
    boundaries = []
    for address in sorted(d for d in destinations if d is not None):
        exact = [f for f in elf.fdes if f['start'] == address]
        if len(exact) == 1:
            f = exact[0]
            raw = elf.read(address, f['end'] - address)
            boundaries.append(dict(address=address, fde=f, hex=raw.hex(), sha256=digest(raw),
                                   fde_hex=elf.record(f['fde']), cie_hex=elf.record(f['cie'])))
        else:
            # PLT stubs are 16-byte linked slots, not invented FDEs.
            sec = elf.section(address)
            n = min(16, sec['address'] + sec['size'] - address)
            raw = elf.read(address, n)
            ins = list(decoder().disasm(raw, address))
            refs = []
            for i in ins:
                for op in i.operands:
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        a = i.address + i.size + op.mem.disp
                        refs.append(dict(address=a, relocations=elf.relas_at(a, op.size)))
            boundaries.append(dict(address=address, section=sec['name'], exact_fdes=len(exact),
                                   hex=raw.hex(), sha256=digest(raw), rip_operands=refs))
    # Bind full panic descriptors and the selected embedded vendored source path;
    # read actual RELATIVE addends, never treat on-disk zero words as pointers.
    data_spans = []
    for address, length in ((0x64bcbd8,24),(0x64bcbf0,24),(0x64bcb00,24),
                            (0x93ebae,19),(0x93ed0f,47),(0x443234,64),(0x64b7070,8)):
        data_spans.append(dict(address=address, length=length, hex=elf.read(address,length).hex(),
                               relocations=elf.relas_at(address,length)))
    for descriptor in (0x64bcbd8, 0x64bcbf0, 0x64bcb00):
        writers = [r for r in elf.relas_at(descriptor,8) if r['address']==descriptor and r['kind']==8]
        if len(writers)!=1:
            raise ValueError('panic source descriptor writer')
        address=writers[0]['addend'];length=int.from_bytes(elf.read(descriptor+8,8),'little')
        data_spans.append(dict(address=address,length=length,hex=elf.read(address,length).hex(),
                               relocations=elf.relas_at(address,length)))
    all_lsda=sorted({f['lsda'] for f in elf.fdes if f['lsda'] is not None})
    lsda_ranges=[]
    for address in sorted({b['lsda'] for b in bodies if b['lsda'] is not None}):
        sec=elf.section(address)
        next_addresses=[a for a in all_lsda if address<a<sec['address']+sec['size']]
        end=min(next_addresses) if next_addresses else sec['address']+sec['size']
        raw=elf.read(address,end-address)
        lsda_ranges.append(dict(address=address,end=end,hex=raw.hex(),sha256=digest(raw),
                                boundary='next referenced LSDA or section end; unwind semantics unclaimed'))
    return dict(schema=1, target_sha256=digest(data), target_size=len(data),
                fde_count=len(elf.fdes), cie_count=len(elf.cies), relocation_count=len(elf.relas),
                bodies=bodies, incoming=inc, outgoing_boundaries=boundaries,
                naming_relocations=[r for r in elf.relas if r['kind'] == 8 and r['addend'] in CORE + CONTEXT],
                data_spans=data_spans, lsda_ranges=lsda_ranges,
                data_indirect_edge=dict(data_slot=0x64b7070,consumer_site=0x4f0c248,
                                         writer=tls_writers[0],scope='actual adapter call [rsi]; TLS initializer semantics remain opaque'),
                anchor_facts=anchor_facts(elf),
                fde_overlaps={str(b['start']):[f for f in elf.fdes if f['start']<b['end'] and b['start']<f['end']]
                              for b in bodies})


def verify(data, expected):
    if digest(data) != SHA256:
        raise ValueError('wrong complete target digest')
    actual = capture(data)
    if actual != expected:
        raise ValueError('bytes/FDE/CIE/CFG/relocations/data/caller bindings differ')
    return dict(target_sha256=SHA256, core_fdes=len(CORE),
                core_bytes=sum(b['length'] for b in actual['bodies'] if b['start'] in CORE),
                context_fdes=len(CONTEXT), incoming_fdes=len(actual['incoming']['callers']),
                incoming_sites=sum(len(c['sites']) for c in actual['incoming']['callers']),
                opaque_boundary_count=len(actual['outgoing_boundaries']))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, default=TARGET)
    args = p.parse_args()
    with gzip.open(PACKET / 'bindings.json.gz', 'rt') as f:
        expected = json.load(f)
    print(json.dumps(verify(args.target.read_bytes(), expected), indent=2))


if __name__ == '__main__':
    main()
