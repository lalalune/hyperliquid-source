#!/usr/bin/env python3
"""Statically recover the node94 plain AwsName recognizer and rendering leaves.

No captured instructions are executed. A deliberately restricted abstract
interpreter propagates constants and symbolic input-byte XOR expressions along
straight-line comparison chains. Branch predicates become exact byte equality
constraints, independently of the formatter's spelling pool.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PARSER = 0x164cdb0
RENDERER = 0x164c750
PRIOR_TABLE = 0x5668288


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Image:
    def __init__(self, blob):
        require(hashlib.sha256(blob).hexdigest() == DIGEST, 'input SHA-256 mismatch')
        self.blob = blob
        self.sections = sections(blob)
        _, fdes = eh_frame_records(blob, self.sections)
        self.fdes = {f['start']: f for f in fdes}
        self.relocations = {}
        rs = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        require(len(rs) == 1 and rs[0]['size'] % 24 == 0, 'invalid RELA section')
        s = rs[0]
        for p in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', blob, p)
            if info == 8:
                require(slot not in self.relocations, 'duplicate relative relocation')
                self.relocations[slot] = (p, addend)

    def offset(self, address, size):
        require(type(address) is int and type(size) is int and size > 0, 'invalid byte range')
        matches = [s for s in self.sections if s['type'] != 8 and
                   s['address'] <= address and address + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'byte range has no unique file-backed section')
        return matches[0]['offset'] + address - matches[0]['address']

    def read(self, address, size):
        off = self.offset(address, size)
        return self.blob[off:off + size]

    def exact(self, address, expected):
        require(self.read(address, len(expected)) == expected, f'encoding mismatch at {address:#x}')

    def s32(self, address):
        return struct.unpack('<i', self.read(address, 4))[0]

    def rel32(self, address, size):
        return address + size + self.s32(address + size - 4)

    def function(self, start):
        require(start in self.fdes, 'missing FDE')
        f = self.fdes[start]
        body = self.read(start, f['end'] - start)
        return {'start': hex(start), 'end': hex(f['end']), 'fde': hex(f['fde']),
                'file_offset': hex(self.offset(start, len(body))), 'size': len(body),
                'sha256': hashlib.sha256(body).hexdigest()}


# Expressions are byte lanes. A lane is a frozenset of XOR terms; integer terms
# are XOR constants and ('input', offset) is an uninterpreted byte. OR is kept as
# a separate tuple of expressions, because OR==0 requires every child==0.
def constant(value, width):
    return tuple(frozenset([value >> (8 * i) & 255]) - {0} for i in range(width))


def numeric(value):
    require(isinstance(value, tuple) and all(isinstance(x, frozenset) for x in value), 'not a scalar constant')
    out = 0
    for i, terms in enumerate(value):
        require(all(type(t) is int for t in terms), 'arithmetic on symbolic input')
        byte = 0
        for term in terms:
            byte ^= term
        out |= byte << (8 * i)
    return out


def resize(value, width):
    require(isinstance(value, tuple) and all(isinstance(x, frozenset) for x in value), 'unsupported expression resize')
    return (value + constant(0, width))[:width]


def xor(a, b, width):
    return tuple(x ^ y for x, y in zip(resize(a, width), resize(b, width)))


def constraints(value, length):
    """Prove expression==0 is exactly one full-length string equality."""
    todo = list(value[1:]) if isinstance(value, list) and value[0] == 'or' else [value]
    result = {}
    while todo:
        v = todo.pop()
        if isinstance(v, list) and v[0] == 'or':
            todo.extend(v[1:])
            continue
        for terms in v:
            byte = 0
            variables = []
            for term in terms:
                if type(term) is int:
                    byte ^= term
                else:
                    require(term[0] == 'input', 'unknown symbolic variable')
                    variables.append(term[1])
            if not variables:
                require(byte == 0, 'unsatisfiable constant equality')
                continue
            require(len(variables) == 1, 'unsupported relation between input bytes')
            index = variables[0]
            require(0 <= index < length, 'comparison reads beyond length bucket')
            require(index not in result or result[index] == byte, 'inconsistent overlapping loads')
            result[index] = byte
    require(set(result) == set(range(length)), 'predicate does not constrain every input byte')
    return bytes(result[i] for i in range(length))


class Chain:
    """Recognize the finite instruction forms actually present in this one body.

    This is not an x86 emulator or a general disassembler. All memory operands
    must be input-relative, all arithmetic must be on constants, and every
    conditional success must terminate in a proven scalar return.
    """
    def __init__(self, im, end, length):
        self.im, self.end, self.length = im, end, length
        self.regs = {}
        self.flag = None
        self.flag_site = None
        self.rows = []
        self.instructions = {}
        self.reads = []

    def record(self, address, size, operation):
        require(PARSER <= address < address + size <= self.end, 'instruction outside parser FDE')
        row = {'va': hex(address), 'bytes': self.im.read(address, size).hex(), 'operation': operation}
        require(address not in self.instructions or self.instructions[address] == row, 'conflicting instruction decode')
        self.instructions[address] = row

    def reg(self, r, width):
        require(r in self.regs, f'read of unknown register {r}')
        return resize(self.regs[r], width)

    def setreg(self, r, value, width):
        # The only sub-32-bit write in the predicate chains is OR into CX; its
        # old upper lanes are irrelevant to the ensuing 16-bit zero flag.
        self.regs[r] = value if width == 8 or isinstance(value, list) else resize(value, 8)

    def memory(self, displacement, width, site):
        require(0 <= displacement and displacement + width <= self.length, 'input load outside length bucket')
        self.reads.append({'site': hex(site), 'offset': displacement, 'width': width})
        return tuple(frozenset([('input', displacement + i)]) for i in range(width))

    def terminal(self, address):
        raw = self.im.read(address, 3)
        if raw[0] == 0xb0 and raw[2] == 0xc3:
            self.record(address, 2, 'return-byte'); self.record(address + 2, 1, 'ret')
            return raw[1]
        if raw == bytes.fromhex('31c0c3'):
            self.record(address, 2, 'return-zero'); self.record(address + 2, 1, 'ret')
            return 0
        raise ValueError(f'nonterminal branch target {address:#x}')

    def accept(self, site, target, failure, kind):
        require(self.flag is not None and self.flag_site is not None, 'unsupported zero-flag producer')
        text = constraints(self.flag, self.length)
        code = self.terminal(target) if type(target) is int else target[0]
        self.rows.append({'length': self.length, 'predicate_site': hex(site),
                          'zero_flag_site': hex(self.flag_site),
                          'success_va': hex(target) if type(target) is int else hex(site),
                          'unequal_successor': hex(failure) if failure is not None else None,
                          'result': code, 'text_hex': text.hex(), 'predicate': kind,
                          'text': text.decode('ascii')})

    def run(self, pc):
        seen = set()
        while True:
            require(pc not in seen, 'unexpected loop in comparison chain')
            seen.add(pc)
            raw = self.im.read(pc, min(16, self.end - pc))
            if raw[0] == 0xb0 or raw[:3] == bytes.fromhex('31c0c3'):
                failure = self.terminal(pc)
                return failure
            # Two compiler-folded final comparisons encode both outcomes.
            if raw.startswith(bytes.fromhex('0f95c0c0e0020c48c3')):
                self.record(pc, 3, 'setne-al'); self.record(pc+3, 3, 'shift-al-2')
                self.record(pc+6, 2, 'or-al-72'); self.record(pc+8, 1, 'ret')
                self.accept(pc, (raw[7],), None, 'zero => 72; nonzero => 76')
                return raw[7] | (1 << raw[5])
            if raw.startswith(bytes.fromhex('0f94c1b04c28c8c3')):
                self.record(pc, 3, 'sete-cl'); self.record(pc+3, 2, 'mov-al-76')
                self.record(pc+5, 2, 'sub-al-cl'); self.record(pc+7, 1, 'ret')
                self.accept(pc, (raw[4]-1,), None, 'zero => 75; nonzero => 76')
                return raw[4]
            if raw[:2] in [b'\x0f\x84', b'\x0f\x85'] or raw[0] in [0x74, 0x75]:
                long = raw[0] == 0x0f
                size = 6 if long else 2
                eq = raw[1] == 0x84 if long else raw[0] == 0x74
                target = pc + size + (struct.unpack_from('<i', raw, 2)[0] if long else struct.unpack_from('<b', raw, 1)[0])
                self.record(pc, size, 'je' if eq else 'jne')
                if eq:
                    self.accept(pc, target, pc + size, 'exact equality')
                    pc += size
                    continue
                self.accept(pc, pc + size, target, 'exact equality')
                return self.terminal(target)
            p = 0; width = 4
            if raw[0] in [0x48, 0x66]:
                width = 8 if raw[0] == 0x48 else 2
                p += 1
            op = raw[p]; p += 1
            require(width != 2 or op in [0x81, 0x09], 'unsupported 16-bit instruction form')
            if 0xb8 <= op <= 0xbf:
                size = 8 if width == 8 else 4
                value = int.from_bytes(raw[p:p+size], 'little'); p += size
                self.setreg(op-0xb8, constant(value,width),width)
                self.record(pc,p,'mov-immediate'); pc += p; continue
            if op in [0x05,0x35]:
                v = int.from_bytes(raw[p:p+4],'little',signed=width==8); p += 4
                if op == 0x05:
                    self.setreg(0,constant((numeric(self.reg(0,width))+v) % (1 << (width*8)),width),width)
                else:
                    self.setreg(0,xor(self.reg(0,width),constant(v,width),width),width)
                self.flag = None
                self.record(pc,p,'add-constant' if op==0x05 else 'xor-immediate');pc+=p;continue
            load_width = width
            if op == 0x0f:
                op2 = raw[p]; p += 1
                require(op2 in [0xb6,0xb7], 'unsupported two-byte opcode')
                load_width = 1 if op2==0xb6 else 2
            require(op in [0x8b,0x31,0x33,0x39,0x81,0x83,0x09,0x8d,0x0f], f'unsupported opcode {op:#x} at {pc:#x}')
            modrm=raw[p];p+=1;mod=modrm>>6;reg=(modrm>>3)&7;rm=modrm&7
            disp=0
            require(rm != 4, 'SIB not supported in predicate chains')
            if mod == 1:
                disp=struct.unpack_from('<b',raw,p)[0];p+=1
            elif mod == 2:
                disp=struct.unpack_from('<i',raw,p)[0];p+=4
            require(mod != 0 or rm != 5, 'RIP-relative operand in predicate chain')
            if op == 0x8d:
                require(mod in [1,2], 'unexpected LEA form')
                value=numeric(self.reg(rm,width))+disp
                self.setreg(reg,constant(value%(1<<(width*8)),width),width)
                self.record(pc,p,'lea-constant');pc+=p;continue
            if op in [0x81,0x83]:
                size=1 if op==0x83 else 2 if width==2 else 4
                v=int.from_bytes(raw[p:p+size],'little',signed=(op==0x83 or width==8));p+=size
                if mod==3:
                    require(width != 2, 'unsupported partial-register arithmetic')
                    require(reg in [0,6], 'unsupported immediate register operation')
                    value=constant(v,width)
                    if reg==0:value=constant((numeric(self.reg(rm,width))+v)%(1<<(width*8)),width)
                    else:value=xor(self.reg(rm,width),value,width)
                    self.setreg(rm,value,width)
                    self.flag = None
                else:
                    require(reg==7 and rm==7, 'unsupported immediate memory operation')
                    self.flag=xor(self.memory(disp,width,pc),constant(v,width),width)
                    self.flag_site=pc
                self.record(pc,p,'immediate-compare' if mod!=3 else 'constant-operation');pc+=p;continue
            if mod != 3:
                require(rm==7, 'memory base is not input pointer')
                operand=self.memory(disp,load_width,pc)
            else:
                operand=self.reg(rm,width)
            if op in [0x8b,0x0f]:
                require(mod!=3, 'unexpected register MOV')
                self.setreg(reg,resize(operand,width),width)
            elif op==0x33:
                self.setreg(reg,xor(self.reg(reg,width),operand,width),width)
                self.flag=None
            elif op==0x31:
                require(mod==3, 'XOR would modify input')
                self.setreg(rm,xor(operand,self.reg(reg,width),width),width)
                self.flag=None
            elif op==0x39:
                self.flag=xor(operand,self.reg(reg,width),width)
                self.flag_site=pc
            elif op==0x09:
                require(mod==3, 'OR would modify input')
                self.flag=['or',operand,self.reg(reg,width)]
                self.flag_site=pc
                self.setreg(rm,self.flag,width)
            self.record(pc,p,{0x8b:'load',0x0f:'zero-extend-load',0x33:'xor-load',0x31:'xor-register',0x39:'compare',0x09:'or-zero-predicate'}[op]);pc+=p


def parser(im):
    f=im.fdes[PARSER]; end=f['end']
    im.exact(PARSER,bytes.fromhex('4883c6fe4883fe0b0f87'))
    failure=im.rel32(PARSER+8,6)
    im.exact(PARSER+14,bytes.fromhex('488d05'))
    table=im.rel32(PARSER+14,7)
    im.exact(PARSER+21,bytes.fromhex('48630cb04801c1ffe1'))
    low=(-struct.unpack('<b',im.read(PARSER+3,1))[0])&255
    count=im.read(PARSER+7,1)[0]+1
    header=[(PARSER,4,'length-minus-two'),(PARSER+4,4,'unsigned-length-bound'),
            (PARSER+8,6,'ja-failure'),(PARSER+14,7,'table-address'),
            (PARSER+21,4,'load-signed-relative-slot'),(PARSER+25,3,'add-table-base'),(PARSER+28,2,'jump-slot')]
    coverage={};rows=[];buckets=[];reads=[]
    invalid=Chain(im,end,0).terminal(failure)
    for i in range(count):
        entry=table+im.s32(table+4*i)
        require(PARSER<=entry<end,'length table target outside FDE')
        chain=Chain(im,end,i+low)
        status=chain.run(entry)
        require(status==invalid,'inconsistent rejection sentinel')
        for a,r in chain.instructions.items():
            require(a not in coverage or coverage[a]==r,'conflicting chain boundary')
            coverage[a]=r
        rows.extend(chain.rows);reads.extend(chain.reads)
        buckets.append({'length':i+low,'slot':hex(table+4*i),'entry':hex(entry),'accepted':len(chain.rows),'rejection':status})
    for a,size,label in header:
        coverage[a]={'va':hex(a),'bytes':im.read(a,size).hex(),'operation':label}
    rows.sort(key=lambda r:r['result'])
    require([r['result'] for r in rows]==list(range(invalid)),'success results do not partition values below sentinel')
    require(len({r['text_hex'] for r in rows})==len(rows),'shadowed duplicate recognition predicate')
    cursor=PARSER
    for a,r in sorted(coverage.items()):
        require(a==cursor,'uncovered or overlapping parser instructions')
        cursor+=len(bytes.fromhex(r['bytes']))
    require(cursor==end,'uncovered parser tail')
    return {'table':hex(table),'minimum_length':low,'maximum_length':low+count-1,
            'failure_va':hex(failure),'failure_value':invalid,'rows':rows,'buckets':buckets,
            'instructions':[r for _,r in sorted(coverage.items())],
            'reads':sorted({(r['site'],r['offset'],r['width']) for r in reads},key=lambda r:int(r[0],16))}


def renderer(im):
    f=im.fdes[RENDERER];end=f['end']
    count,remainder=divmod(end-RENDERER-22,21)
    require(count>0 and remainder==0,'renderer FDE does not contain complete leaves')
    im.exact(RENDERER,bytes.fromhex('4889f00fb60f488d15'))
    table=im.rel32(RENDERER+6,7)
    im.exact(RENDERER+13,bytes.fromhex('48630c8a4801d1ffe1'))
    rows=[];arms=[]
    for tag in range(count):
        slot=table+4*tag;arm=table+im.s32(slot)
        require(RENDERER+22<=arm and arm+21<=end,'renderer arm outside FDE')
        im.exact(arm,bytes.fromhex('488d35'));im.exact(arm+7,b'\xba')
        im.exact(arm+12,bytes.fromhex('4889c7ff25'))
        textva=im.rel32(arm,7);length=struct.unpack('<I',im.read(arm+8,4))[0]
        sink=im.rel32(arm+15,6)
        require(sink in im.relocations,'unresolved rendering sink relocation')
        relocation,target=im.relocations[sink]
        require(any(sec['type'] != 8 and sec['flags'] & 4 and
                    sec['address'] <= target < sec['address'] + sec['size']
                    for sec in im.sections), 'rendering sink outside executable sections')
        text=im.read(textva,length)
        rows.append({'tag':tag,'slot':hex(slot),'arm':hex(arm),'bytes':im.read(arm,21).hex(),
                     'text_va':hex(textva),'length':length,'text_hex':text.hex(),'text':text.decode('ascii'),
                     'tail_slot':hex(sink),'relocation_file_offset':hex(relocation),'tail_target':hex(target)})
        arms.append(arm)
    require(sorted(arms)==list(range(RENDERER+22,end,21)),'renderer leaves do not partition full FDE')
    require(len({r['tail_slot'] for r in rows})==1,'renderer leaves disagree on sink')
    return {'table':hex(table),'entry_bytes':im.read(RENDERER,22).hex(),'input_domain':'valid tags only; no range check in body','rows':rows}


def collect(im):
    p=parser(im);r=renderer(im)
    require(len(p['rows'])==len(r['rows']),'recognizer/rendering cardinality disagreement')
    require(int(r['table'],16)+4*len(r['rows'])==int(p['table'],16),'dispatch table adjacency mismatch')
    for a,b in zip(p['rows'],r['rows']):
        require(a['result']==b['tag'] and a['text_hex']==b['text_hex'],'recognizer/rendering disagreement')
    shared=0
    new_pool=[]; old_pool=[]
    for row in r['rows']:
        slot=PRIOR_TABLE+16*row['tag']
        require(slot in im.relocations,'missing prior table relocation')
        _,pointer=im.relocations[slot]
        length=struct.unpack('<Q',im.read(slot+8,8))[0]
        require(length==row['length'] and im.read(pointer,length).hex()==row['text_hex'],
                'prior inventory and code-derived spelling disagree')
        if pointer==int(row['text_va'],16):
            shared+=1
        else:
            new_pool.append((int(row['text_va'],16),length))
            old_pool.append((pointer,length))
    def pool_span(parts):
        parts=sorted(parts)
        require(bool(parts),'no separate spelling pool')
        cursor=parts[0][0]
        for start,size in parts:
            require(start==cursor,'separate spelling pool is not contiguous')
            cursor+=size
        raw=im.read(parts[0][0],cursor-parts[0][0])
        return {'start':hex(parts[0][0]),'end':hex(cursor),'size':len(raw),
                'sha256':hashlib.sha256(raw).hexdigest()}
    new_span=pool_span(new_pool);old_span=pool_span(old_pool)
    require(new_span['sha256']==old_span['sha256'],'separate spelling pools differ')
    prior={'base':hex(PRIOR_TABLE),'entries_compared':len(r['rows']),
           'same_pointer':shared,'equal_text_at_different_pointer':len(r['rows'])-shared,
           'new_spelling_pool':new_span,'prior_spelling_pool':old_span,
           'role':'comparison with existing inventory only; its table is not re-exported'}
    return {'target':'node94','sha256':DIGEST,'coordinate_system':'ELF linked virtual addresses; file offsets explicitly labeled',
            'functions':[im.function(PARSER),im.function(RENDERER)],'parser':p,'renderer':r,
            'prior_table_comparison':prior,
            'counts':{'recognizer_predicates':len(p['rows']),'renderer_leaves':len(r['rows']),
                      'length_buckets':len(p['buckets']),'parser_instructions':len(p['instructions']),
                      'parser_covered_bytes':sum(len(bytes.fromhex(x['bytes'])) for x in p['instructions']),
                      'renderer_covered_bytes':len(bytes.fromhex(r['entry_bytes']))+sum(len(bytes.fromhex(x['bytes'])) for x in r['rows'])},
            'limits':['Static equality constraints, not captured execution or runtime differential tests.',
                      'Only the two named FDE bodies and their selected tables are decoded.',
                      'Rendering sink is relocation-bound but not reconstructed; its effects and errors remain external.',
                      'No component gate, Rust build, caller closure, or whole-node equivalence claim.']}


def write_outputs(record,out):
    out.mkdir(parents=True,exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n',encoding='utf-8',newline='\n')
    lines=['length\tslot\tentry\taccepted\trejection']
    for row in record['parser']['buckets']:
        lines.append('\t'.join(str(row[k]) for k in ['length','slot','entry','accepted','rejection']))
    (out/'length-dispatch.tsv').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')
    lines=['result\tlength\tpredicate_site\tsuccess_va\trender_arm\tpool_va\ttext_hex']
    for p,r in zip(record['parser']['rows'],record['renderer']['rows']):
        lines.append('\t'.join(str(x) for x in [p['result'],p['length'],p['predicate_site'],p['success_va'],r['arm'],r['text_va'],p['text_hex']]))
    (out/'conversion-paths.tsv').write_text('\n'.join(lines)+'\n',encoding='utf-8',newline='\n')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args()
    im=Image((ROOT/'artifacts/node/94/hl-node').read_bytes())
    record=collect(im);write_outputs(record,args.out)
    print(json.dumps(record['counts'],sort_keys=True))


if __name__=='__main__':
    main()
