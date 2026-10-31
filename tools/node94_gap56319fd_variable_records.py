#!/usr/bin/env python3
"""Static record-transfer and conditional batch bounds for node #94 0x56319fd.

Only GNU objdump runs, on the 1,269-byte raw span. Finite symbolic lifting
preserves ordered overlapping WORD writes; no target/emulator or concrete-state
loop execution occurs. Runtime record validity and callers remain unqualified.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x56319fd, 0x5631ef2
OUTER, SEED, INNER, TAIL, EXIT = 0x5631a68, 0x5631b19, 0x5631b40, 0x5631e9b, 0x5631ea0
SAVED = ['rax', 'rbx', 'rcx', 'rdx', 'rbp', 'rsi', 'rdi'] + [f'r{i}' for i in range(8, 16)]
INPUTS = ['r8', 'r9', 'r10', 'r11']
OUTPUTS = ['rsi', 'rbx', 'rcx', 'rdi']
WORDS = ['rbp', 'rdx', 'r12', 'r13']
M7, M10, U64 = 0x2492492492492493, 0xcccccccccccccccd, 1 << 64


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Terms:
    """Hash-consed, width-explicit symbolic expressions, not an emulator."""
    def __init__(self):
        self.nodes, self.index = [], {}

    def node(self, op, width, args=(), **fields):
        value = dict(op=op, width=width, args=list(args), **fields)
        key = json.dumps(value, sort_keys=True)
        if key not in self.index:
            self.index[key] = len(self.nodes)
            self.nodes.append(value)
        return self.index[key]

    def var(self, name):
        return self.node('variable', 64, name=name)

    def const(self, value, width=64):
        return self.node('constant', width, value=value % (1 << width))

    def width(self, term):
        return self.nodes[term]['width']

    def zext(self, value, width=64):
        source = self.nodes[value]
        if source['width'] == width:
            return value
        require(source['width'] < width, 'Invalid zero extension')
        if source['op'] == 'zero_extend':
            return self.zext(source['args'][0], width)
        return self.node('zero_extend', width, [value])

    def extract(self, value, low, width):
        source = self.nodes[value]
        require(low + width <= source['width'], 'Invalid bit extraction')
        if low == 0 and width == source['width']:
            return value
        if source['op'] == 'zero_extend' and low + width <= self.width(source['args'][0]):
            return self.extract(source['args'][0], low, width)
        return self.node('extract', width, [value], low=low)

    def offset(self, base, displacement):
        if not displacement:
            return base
        source = self.nodes[base]
        if source['op'] == 'offset':
            return self.offset(source['args'][0], source['displacement'] + displacement)
        return self.node('offset', 64, [base], displacement=displacement)

    def op(self, op, *args):
        require(all(self.width(a) == 64 for a in args), 'Expected 64-bit operands')
        return self.node(op, 64, args)

    def load(self, width, address):
        return self.node('load', width, [address], byte_order='little')

    def shift(self, op, value, count):
        # SHLX/SHRX and 64-bit SHR mask their count to six bits.
        count_node = self.nodes[count]
        if count_node['op'] == 'constant':
            count = self.const(count_node['value'] & 63)
        elif count_node['op'] == 'and' and self.nodes[count_node['args'][1]].get('value', 64) <= 63:
            pass  # A preceding AND with 7 already establishes the count bound.
        else:
            count = self.op('and', count, self.const(63))
        return self.op(op, value, count)

class Lift:
    """Finite static lifting of one phase; loops remain CFG edges."""
    def __init__(self, terms, registers, memory=None):
        self.t = terms
        self.r = dict(registers)
        self.memory = dict(memory or {})
        self.trace, self.stores, self.bsf_inputs = [], [], []
        self.compare = None

    def register(self, name):
        if name in ('ah', 'al'):
            value = self.t.extract(self.r['rax'], 8 if name == 'ah' else 0, 8)
        else:
            aliases = {'eax': ('rax', 32), 'ebx': ('rbx', 32), 'ecx': ('rcx', 32),
                       'edx': ('rdx', 32), 'ax': ('rax', 16)}
            if name in aliases:
                root, width = aliases[name]
            elif re.fullmatch(r'r\d+[dwb]', name):
                root, width = name[:-1], {'d': 32, 'w': 16, 'b': 8}[name[-1]]
            else:
                root, width = name, 64
            require(root in self.r, 'Unsupported register ' + name)
            value = self.r[root] if width == 64 else self.t.extract(self.r[root], 0, width)
        self.event['register_reads'].append(dict(register=name, value=value))
        return value

    def assign(self, name, value):
        aliases = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx'}
        root = aliases.get(name, name[:-1] if re.fullmatch(r'r\d+d', name) else name)
        if root != name:
            require(self.t.width(value) <= 32, 'Oversized 32-bit register assignment')
            value = self.t.zext(value)
        require(root in self.r and self.t.width(value) == 64, 'Unsupported register assignment')
        self.r[root] = value
        self.event['register_writes'].append(dict(register=root, value=value))

    def address(self, operand):
        match = re.search(r'\[([^]]+)\]', operand)
        require(match is not None, 'Missing memory address')
        pieces = match[1].split('+')
        value = None
        for piece in pieces:
            if '*' in piece:
                reg, scale = piece.split('*')
                term = self.t.op('multiply_low', self.register(reg), self.t.const(int(scale, 0)))
            elif re.fullmatch(r'0x[0-9a-f]+|[0-9]+', piece):
                require(value is not None, 'Unexpected absolute address')
                value = self.t.offset(value, int(piece, 0))
                continue
            else:
                term = self.register(piece)
            value = term if value is None else self.t.op('add', value, term)
        return value

    def read_memory(self, width, address):
        value = self.memory.get((width, address))
        if value is None:
            value = self.t.load(width, address)
        self.event['memory_reads'].append(dict(width=width, address=address, value=value))
        return value

    def operand(self, operand):
        match = re.fullmatch(r'(BYTE|WORD|QWORD) PTR \[.*\]', operand)
        if match:
            return self.read_memory({'BYTE': 8, 'WORD': 16, 'QWORD': 64}[match[1]], self.address(operand))
        if re.fullmatch(r'0x[0-9a-f]+|[0-9]+', operand):
            return self.t.const(int(operand, 0))
        return self.register(operand)

    def store(self, width, address, value):
        require(self.t.width(value) == width, 'Store width differs from value')
        self.memory[width, address] = value
        record = dict(va=self.event['va'], width=width, address=address, value=value)
        self.event['memory_writes'].append(record)
        self.stores.append(record)

    def run(self, rows):
        for row in rows:
            parts = row['assembly'].split(None, 1)
            op = parts[0]
            args = parts[1].split(',') if len(parts) == 2 else []
            self.event = dict(va=row['va'], assembly=row['assembly'], register_reads=[],
                              register_writes=[], memory_reads=[], memory_writes=[])
            if op in ('mov', 'movabs', 'movzx'):
                value = self.operand(args[1])
                if op == 'movzx':
                    value = self.t.zext(value, 32)
                if args[0].startswith(('BYTE PTR', 'WORD PTR', 'QWORD PTR')):
                    width = {'BYTE': 8, 'WORD': 16, 'QWORD': 64}[args[0].split()[0]]
                    self.store(width, self.address(args[0]), value)
                else:
                    self.assign(args[0], value)
            elif op == 'push':
                value = self.operand(args[0])
                self.assign('rsp', self.t.offset(self.register('rsp'), -8))
                self.store(64, self.r['rsp'], value)
            elif op == 'pop':
                value = self.read_memory(64, self.register('rsp'))
                self.assign(args[0], value)
                self.assign('rsp', self.t.offset(self.r['rsp'], 8))
            elif op == 'lea':
                self.assign(args[0], self.address(args[1]))
            elif op in ('add', 'sub', 'and', 'or'):
                left, right = self.register(args[0]), self.operand(args[1])
                if args[0] == 'rsp' and op in ('add', 'sub'):
                    require(self.t.nodes[right]['op'] == 'constant', 'Nonconstant stack adjustment')
                    value = self.t.offset(left, self.t.nodes[right]['value'] * (1 if op == 'add' else -1))
                else:
                    value = self.t.op(op, left, right)
                self.assign(args[0], value)
                self.compare = None
            elif op == 'mul':
                left, right = self.register('rax'), self.operand(args[0])
                self.assign('rax', self.t.op('multiply_low', left, right))
                self.assign('rdx', self.t.op('multiply_high_unsigned', left, right))
                self.compare = None
            elif op in ('shlx', 'shrx', 'shr'):
                dest, value, count = (args[0], self.register(args[0]), self.operand(args[1])) if op == 'shr' else (args[0], self.register(args[1]), self.register(args[2]))
                self.assign(dest, self.t.shift('left' if op == 'shlx' else 'logical_right', value, count))
                if op == 'shr':
                    self.compare = None
            elif op == 'bsf':
                value = self.register(args[1])
                self.bsf_inputs.append(dict(va=row['va'], nonzero_term=value))
                self.assign(args[0], self.t.op('trailing_zero_count_nonzero', value))
                self.compare = None
            elif op == 'cmp':
                self.compare = (self.operand(args[0]), self.operand(args[1]))
                self.event['comparison'] = list(self.compare)
            elif op == 'cmova':
                require(self.compare is not None, 'CMOVA has no bound CMP')
                old, source = self.register(args[0]), self.operand(args[1])
                self.assign(args[0], self.t.node('if_unsigned_above', 64, [*self.compare, source, old]))
            elif op in ('je', 'jb', 'ja', 'jmp'):
                if op != 'jmp':
                    require(self.compare is not None, 'Branch has no bound CMP')
                    self.event['condition'] = dict(relation={'je': 'equal', 'jb': 'unsigned_below', 'ja': 'unsigned_above'}[op], operands=list(self.compare))
            elif op == 'ret':
                self.event['return_target'] = self.read_memory(64, self.register('rsp'))
                self.assign('rsp', self.t.offset(self.r['rsp'], 8))
            elif op in ('nop', 'data16'):
                require(row['bytes'] in ('90', '66662e0f1f840000000000'), 'Unqualified NOP encoding')
                self.event['effect'] = 'Architectural NOP: no data memory access or register change'
            else:
                require(op == 'endbr64', 'Unsupported instruction ' + row['assembly'])
            self.trace.append(self.event)
        return self


def parse_native(raw, code):
    rows, cursor = [], START
    for line in raw.splitlines():
        fields = line.split('\t', 2)
        if len(fields) != 3 or not re.fullmatch(r'\s*[0-9a-f]+:', fields[0]):
            continue
        va, encoded = int(fields[0].strip()[:-1], 16), bytes.fromhex(fields[1])
        assembly = ' '.join(fields[2].strip().split())
        require(va == cursor and 1 <= len(encoded) <= 15, 'Noncontiguous native instruction')
        require(encoded == code[va - START:va - START + len(encoded)], 'Native bytes differ from input')
        require('(bad)' not in assembly and not assembly.startswith('.byte'), 'Rejected native instruction')
        rows.append(dict(va=va, bytes=encoded.hex(), size=len(encoded), assembly=assembly))
        cursor += len(encoded)
    require(cursor == END and len(code) == END - START, 'Incomplete candidate decode')
    return rows


def decode(code, objdump='objdump'):
    with tempfile.TemporaryDirectory(prefix='hl-gap-contract-') as temporary:
        directory = Path(temporary)
        (directory / 'slice.bin').write_bytes(code)
        argv = [objdump, '-D', '-b', 'binary', '-m', 'i386:x86-64', '-w', '-Mintel',
                '--adjust-vma=' + hex(START), 'slice.bin']
        result = subprocess.run(argv, cwd=directory, capture_output=True, text=True,
                                encoding='utf-8', check=True)
    return parse_native(result.stdout, code), result.stdout, argv


def cfg(rows):
    starts = {r['va'] for r in rows}
    successors, branches, returns = {}, [], []
    leaders = {START}
    for row in rows:
        at, following = row['va'], row['va'] + row['size']
        op = row['assembly'].split()[0]
        if op == 'ret':
            require(row['bytes'] == 'c3', 'Unexpected return encoding')
            targets = []
            returns.append(at)
        elif op in ('je', 'jb', 'ja', 'jmp'):
            encoded = bytes.fromhex(row['bytes'])
            if encoded[0] == 0xe9:
                require(len(encoded) == 5 and op == 'jmp', 'Unexpected JMP encoding')
                displacement = struct.unpack_from('<i', encoded, 1)[0]
            else:
                require(len(encoded) == 6 and encoded[:2] == {'je': b'\x0f\x84', 'jb': b'\x0f\x82', 'ja': b'\x0f\x87'}.get(op), 'Unexpected branch encoding')
                displacement = struct.unpack_from('<i', encoded, 2)[0]
            target = following + displacement
            require(target == int(row['assembly'].split()[1], 16), 'Encoded/native branch mismatch')
            targets = [target] if op == 'jmp' else [target, following]
            leaders.update(targets)
            branches.append(dict(va=at, op=op, target=target, fallthrough=None if op == 'jmp' else following))
        else:
            require(op not in ('call', 'ud2', 'hlt', 'int3') and not op.startswith(('j', 'loop')), 'Unresolved control transfer')
            targets = [following]
        require(all(t in starts for t in targets), 'Non-instruction control target')
        successors[at] = targets
    reached, pending = set(), [START]
    while pending:
        at = pending.pop()
        if at not in reached:
            reached.add(at)
            pending.extend(successors[at])
    require(reached == starts, 'Unreachable candidate instructions')
    require(returns == [END - 1], 'Unexpected candidate return')
    require([(b['op'], b['target']) for b in branches] == [('je', EXIT), ('jb', EXIT), ('jb', EXIT), ('jb', EXIT), ('ja', INNER), ('jmp', OUTER)], 'Contract control structure changed')
    blocks = []
    for begin, end in zip(sorted(leaders), sorted(leaders)[1:] + [END]):
        members = [r for r in rows if begin <= r['va'] < end]
        blocks.append(dict(start=begin, end=end, instructions=len(members), successors=successors[members[-1]['va']]))
    return dict(instructions=len(rows), statically_reachable=len(reached), blocks=blocks,
                branches=branches, returns=returns)


def unsigned_min(t, left, right):
    return t.node('if_unsigned_above', 64, [left, right, right, left])


def divide7_expression(t, value):
    high = t.op('multiply_high_unsigned', value, t.const(M7))
    half = t.shift('logical_right', t.op('sub', value, high), t.const(1))
    return t.shift('logical_right', t.op('add', high, half), t.const(2))


def divide10_expression(t, value):
    return t.shift('logical_right', t.op('multiply_high_unsigned', t.const(M10), value), t.const(3))


def division_support(rows):
    """Bind exact source operands; the quantified algebra is in PROOF.md."""
    by_va = {r['va']: r for r in rows}
    expected = {0x5631a7a: '48ba9324499224499224', 0x5631a84: '48f7e2',
                0x5631a87: '4929d7', 0x5631a8a: '49d1ef', 0x5631a8d: '4c01fa',
                0x5631a90: '48c1ea02', 0x5631acc: '48b8cdcccccccccccccc',
                0x5631ad6: '48f7e2', 0x5631ad9: '48c1ea03'}
    require(all(by_va[a]['bytes'] == b for a, b in expected.items()), 'Reciprocal division source operands changed')
    require(7 * M7 == U64 + 5 and 10 * M10 == 8 * U64 + 2, 'Reciprocal constant identity failed')
    cases = [dict(remainder=r, delta=d, correction=d + (r-d)//2)
             for r in range(7) for d in (0, 1)]
    require(all(0 <= c['correction'] <= 3 for c in cases), 'Divide-seven remainder correction range failed')
    return dict(raw_source_rows=[by_va[a] for a in expected],
                N=U64, M7=M7, seven_M7_minus_N=5, M10=M10,
                ten_M10_minus_eight_N=2, output_high_half_shift=3,
                divide_seven_remainder_delta_cases=cases,
                divide_ten_fractional_upper_bound='9/10 + 1/40 = 37/40 < 1',
                meaning='Exact all-u64 floor(d/7) and floor(r/10), by the stated algebra in PROOF.md; source expressions are separately checked.',
                automatic_general_theorem_verifier=False)


def table_record(t, table, word):
    index = t.shift('logical_right', word, t.const(53))
    address = t.op('add', table, t.op('multiply_low', index, t.const(4)))
    return dict(index=index, address=address, payload=t.load(16, address),
                shift=t.zext(t.load(8, t.offset(address, 2))),
                advance=t.zext(t.load(8, t.offset(address, 3))))


def contract(rows):
    graph = cfg(rows)
    support = division_support(rows)
    t = Terms()
    initial = {r: t.var('entry.' + r) for r in SAVED + ['rsp']}
    qbase, stack = initial['rdi'], initial['rsp']
    select = lambda lo, hi: [r for r in rows if lo <= r['va'] < hi]
    prologue = Lift(t, initial).run(select(START, OUTER))
    work = t.offset(stack, -184)
    require(prologue.r['rsp'] == work, 'Working stack is not entry RSP minus184')
    require(len(prologue.stores) == 22 and
            {(s['width'], s['address']) for s in prologue.stores} ==
            {(64, t.offset(stack, -8*n)) for n in range(1, 23)}, 'Prologue save frame changed')
    lane_regs = INPUTS + OUTPUTS + WORDS
    for i, reg in enumerate(lane_regs + ['r14']):
        require(prologue.r[reg] == t.load(64, t.offset(qbase, i*8)), 'Physical state input layout changed')
    for displacement, state_offset in ((8, 0x28), (16, 0x30), (24, 0x38), (32, 0x70), (40, 0x68)):
        require(prologue.memory[64, t.offset(work, displacement)] == t.load(64, t.offset(qbase, state_offset)), 'Fixed output-end/lower-bound frame mapping changed')
    require(prologue.memory[64, t.offset(work, 56)] == qbase, 'Saved state base changed')
    state_reads = [r for e in prologue.trace for r in e['memory_reads']]
    require(len(state_reads) == 15 and all(r['width'] == 64 and r['address'] in
            {t.offset(qbase, n) for n in range(0, 0x78, 8)} for r in state_reads), 'Prologue reads beyond the state block')

    logical = {kind: [t.var(f'current.{kind}{i}') for i in range(4)]
               for kind in ('input', 'output', 'word')}
    table = t.var('current.table')
    current = dict(prologue.r)
    for regs, kind in ((INPUTS, 'input'), (OUTPUTS, 'output'), (WORDS, 'word')):
        current.update(zip(regs, logical[kind]))
    current['r14'] = table
    ends = [prologue.memory[64, t.offset(work, n)] for n in (8, 16, 24, 32)]
    lower = prologue.memory[64, t.offset(work, 40)]
    remainders = [t.op('sub', end, cursor) for end, cursor in zip(ends, logical['output'])]
    minimum = unsigned_min(t, remainders[1], remainders[0])
    for remainder in remainders[2:]:
        minimum = unsigned_min(t, minimum, remainder)
    quotient = unsigned_min(t, divide7_expression(t, t.op('sub', logical['input'][0], lower)),
                            divide10_expression(t, minimum))
    outer = Lift(t, current, prologue.memory).run(select(OUTER, SEED))
    quotient_row = next(e for e in outer.trace if e['va'] == 0x5631ae0)
    require(quotient_row['register_writes'] == [dict(register='r15', value=quotient)], 'Actual quotient does not match divide7/divide10 and four-output minimum')
    stop = t.op('add', t.op('add', logical['output'][3], t.op('multiply_low', quotient, t.const(4))), quotient)
    require(outer.r['r15'] == stop, 'Actual stop is not output3 plus5q')
    require(all(outer.r[r] == current[r] for r in lane_regs + ['r14', 'rsp']), 'Outer guards clobber lane state')
    require(outer.stores == [dict(va=0x5631a68, width=64, address=work, value=logical['word'][1])], 'Outer spill changed')
    outer_reads = [r for e in outer.trace for r in e['memory_reads']]
    require(len(outer_reads) == 6 and all(r['width'] == 64 and r['address'] in
            {t.offset(work, n) for n in (0, 8, 16, 24, 32, 40)} for r in outer_reads), 'Pre-guard access is not only fixed frame state')
    guards = [e['condition'] for e in outer.trace if 'condition' in e]
    expected_guards = [dict(relation='equal', operands=[stop, logical['output'][3]])]
    expected_guards += [dict(relation='unsigned_below', operands=[logical['input'][i+1], logical['input'][i]]) for i in range(3)]
    require(guards == expected_guards, 'Zero-quotient/input-order guard changed')
    seed = Lift(t, outer.r, outer.memory).run(select(SEED, INNER))
    require(seed.stores == [dict(va=SEED, width=64, address=t.offset(work, 48), value=stop)], 'Stop-save or alignment phase memory effect changed')
    require(not [r for e in seed.trace for r in e['memory_reads']] and
            all(seed.r[r] == outer.r[r] for r in lane_regs + ['r14', 'rsp']),
            'Alignment phase performs an unqualified read or clobber')

    body = Lift(t, seed.r, seed.memory).run(select(INNER, TAIL))
    stores = [s for s in body.stores if s['width'] == 16]
    require(len(stores) == 20 and len(body.stores) == 21, 'Inner body must have twenty WORD writes and one input0 save')
    require(body.stores[0] == dict(va=INNER, width=64, address=work, value=logical['input'][0]), 'Input0 save before payload-register reuse changed')
    words, outputs = list(logical['word']), list(logical['output'])
    events, lanes = [], []
    require(len(body.bsf_inputs) == 4, 'Unexpected BSF domain')
    for round_index in range(5):
        for lane in range(4):
            fields = table_record(t, table, words[lane])
            observed = stores[round_index*4+lane]
            require(observed['address'] == outputs[lane] and observed['value'] == fields['payload'], 'WORD payload/address transfer differs from the four-byte record')
            byte_writes = [dict(address=outputs[lane], value=t.extract(fields['payload'], 0, 8)),
                           dict(address=t.offset(outputs[lane], 1), value=t.extract(fields['payload'], 8, 8))]
            events.append(dict(**observed, lane=lane, round=round_index, record=fields,
                               little_endian_byte_effects=byte_writes,
                               next_cursor=t.op('add', outputs[lane], fields['advance'])))
            words[lane] = t.shift('left', words[lane], fields['shift'])
            outputs[lane] = events[-1]['next_cursor']
    for lane in range(4):
        require(body.r[OUTPUTS[lane]] == outputs[lane], 'Cursor advance is not the independent unsigned record byte3')
        trailing = t.op('trailing_zero_count_nonzero', words[lane])
        retreat = t.shift('logical_right', trailing, t.const(3))
        updated_input = t.op('sub', logical['input'][lane], retreat)
        updated_word = t.shift('left', t.op('or', t.load(64, updated_input), t.const(1)),
                               t.op('and', trailing, t.const(7)))
        require(body.bsf_inputs[lane]['nonzero_term'] == words[lane], 'BSF does not consume the five-shift result')
        require(body.r[INPUTS[lane]] == updated_input and body.r[WORDS[lane]] == updated_word, 'Input0 restore or full-width refill transfer changed')
        lanes.append(dict(lane=lane, before_input=logical['input'][lane], before_output=logical['output'][lane],
                          before_word=logical['word'][lane], output_end=ends[lane],
                          after_input=updated_input, after_output=outputs[lane], after_word=updated_word,
                          required_nonzero_BSF_term=words[lane], refill_retreat_range=[0, 7],
                          raw_output_advance_range=[0, 1275], conditional_output_advance_range=[5, 10]))
    expected_reads = []
    for event in events:
        address = event['record']['address']
        expected_reads += [(16, address), (8, t.offset(address, 2)), (8, t.offset(address, 3))]
    expected_reads += [(64, work)] + [(64, lane['after_input']) for lane in lanes]
    expected_reads += [(64, t.offset(work, 48))]  # final CMP of the saved stop
    actual_reads = [(r['width'], r['address']) for e in body.trace for r in e['memory_reads']]
    require(actual_reads == expected_reads, 'Inner reads differ from record fields, input0 restore, four refills and stop comparison')
    conditions = [e['condition'] for e in body.trace if 'condition' in e]
    require(conditions == [dict(relation='unsigned_above', operands=[stop, outputs[3]])], 'Inner continuation is not saved stop above updated output3')
    require(body.r['r14'] == table and body.r['rsp'] == work, 'Body clobbers table base or frame')
    tail = Lift(t, body.r, body.memory).run(select(TAIL, EXIT))
    require(not tail.stores and all(tail.r[r] == body.r[r] for r in lane_regs + ['r14', 'rsp']), 'Outer backedge changes live state')
    protected = [8, 16, 24, 32, 40] + list(range(56, 184, 8))
    for phase in (outer, seed, body, tail):
        require(all(phase.memory[64, t.offset(work, n)] == prologue.memory[64, t.offset(work, n)] for n in protected), 'Protected output ends/input lower/state base/saved registers changed')

    exit_memory = dict(prologue.memory)
    for n in (0, 48):
        exit_memory[64, t.offset(work, n)] = t.var(f'exit.scratch{n}')
    epilogue = Lift(t, current, exit_memory).run(select(EXIT, END))
    require(len(epilogue.stores) == 12, 'State writeback count changed')
    for i, store in enumerate(epilogue.stores):
        require(store['width'] == 64 and store['address'] == t.offset(qbase, i*8)
                and store['value'] == current[lane_regs[i]], 'Normal-return state layout/value changed')
    require(all(epilogue.r[r] == initial[r] for r in SAVED), 'Saved GPR restoration changed')
    require(epilogue.r['rsp'] == t.offset(stack, 8), 'RET stack effect changed')
    phases = dict(prologue=prologue, outer_guards=outer, stop_and_alignment=seed,
                  inner_body=body, outer_backedge=tail, normal_return=epilogue)
    require(sum(len(p.trace) for p in phases.values()) == len(rows), 'Some source rows were not lifted')
    require({k: len(p.trace) for k, p in phases.items()} == dict(prologue=42, outer_guards=44,
            stop_and_alignment=5, inner_body=196, outer_backedge=1, normal_return=36),
            'Fixed complete phase instruction domain changed')
    return dict(cfg=graph, division_support=support, terms=t.nodes,
                phases={k: p.trace for k, p in phases.items()},
                phase_rows={k: len(p.trace) for k, p in phases.items()},
                fixed_output_end_terms=ends, input_lower_bound_term=lower,
                raw_output_remainder_terms=remainders, quotient_term=quotient, stop_term=stop,
                outer_guard_conditions=guards, inner_continue_condition=conditions[0],
                table_record=dict(entry_stride_bytes=4, top_index_bits=11, index_shift=53,
                                  payload_bytes=[0, 1], shift_byte=2, unsigned_advance_byte=3,
                                  relative_read_envelope_bytes=8192, actual_runtime_contents_recovered=False),
                ordered_WORD_write_events=events,
                memory_composition='Apply ordered 16-bit little-endian store events; within-lane overlap for advance1 is preserved, not assumed disjoint. No atomicity claim.',
                lanes=lanes, normal_return_writebacks=epilogue.stores,
                exit_cutpoint=dict(mutable_frame_offsets=[0, 48], protected_frame_offsets=protected,
                                   note='Stop slot48 may hold the initial duplicateQ or an earlier stop; dead POP is arbitrary before protectedQ recovery.'),
                restored_GPRs=SAVED, RFLAGS_preservation_claimed=False,
                mathematical_batch_contract=dict(q='min(floor(u64(I0-L)/7),floor(min_j u64(Ej-Oj)/10))',
                    zero_q='stop==O3 iff q==0, before table/refill/output-lane accesses',
                    zero_q_criterion='u64(I0-L)<7 or at least oneu64(Ej-Oj)<10',
                    conditional_premises=['record advance1..2', 'nonzero BSF operands',
                        'genuine nonwrapping output regions and readable input window',
                        'immutable table and code; stack/return/context/input/output separation'],
                    inner_bodies='1<=J<=q for q>0 and passing input-order guards',
                    last_written_byte='Oi0+2*(5J-1)+1 <= Oi0+10J-1 < Oi0+10q <= Ei',
                    refill_cursor='initialIi-7J >= initialI0-7q >= L; read end <= initialI3+8',
                    all_premises_established_for_original_callers=False,
                    quantified_argument='PROOF.md; no automatic general machine-equivalence theorem'))


DOMAIN = {
    'raw_transfer': 'Entry at the selected candidate, original available x86-64 instructions, fixed code, valid state block [Q,Q+120) and nonwrapping stack/return [S-184,S+8); normal call/return state is assumed, not established by stack readability.',
    'zero_guard': 'First-outer q0 or failed input-order guard performs no table/refill/output-lane access; only state/frame accesses and state writeback. No buffer/table premise is inferred or needed for an unused access.',
    'output_windows': 'For the entered batch, Oj<=Ej and [Oj,Ej) are genuine nonwrapping writable lane regions. E0/E1/E2 are fixed initial output1/2/3; E3 is initial state+0x70. Their allocation/end meaning is an unverified caller premise.',
    'input_window': 'L<=initialI0<=initialI1<=initialI2<=initialI3 and immutable nonwrapping [L,initialI3+8) is readable. The three cross-input comparisons are actual guards; L<=I0 and allocation bounds are not checked by the candidate.',
    'table': 'Immutable readable nonwrapping [T,T+8192), index0..2047. Selected advance bytes are1..2 for the capacity/progress theorem; raw bytes are0..255, without a machine validation of this premise.',
    'BSF': 'Each of four post-five-shift BSF operands is nonzero in every entered body. Advance1..2 does not imply this; zero has an undefined architectural destination and is outside the proof.',
    'separation': 'State, active stack/return, immutable code, runtime table, input window and writable output windows have the required separation. Different output lanes are disjoint; successive WORD writes within one lane may overlap for advance1 and are preserved in order.',
    'limits': 'No recovered runtime table/producer/caller, original source type/ABI/function/algorithm identity, general arbitrary-state safety, whole-call termination, Rust implementation, binary equivalence, function denominator or progress gate is claimed.',
}


def inspect_target(binary, objdump='objdump'):
    with binary.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        require(sha(data) == DIGEST, 'Node #94 SHA-256 mismatch')
        matches = [s for s in sections(data) if s['type'] != 8 and s['flags'] & 4
                   and s['address'] <= START < END <= s['address'] + s['size']]
        require(len(matches) == 1, 'Candidate needs one file-backed executable mapping')
        offset = matches[0]['offset'] + START - matches[0]['address']
        code = bytes(data[offset:offset + END - START])
        rows, raw, argv = decode(code, objdump)
        result = contract(rows)
        require(sha(data) == DIGEST, 'Admitted node bytes changed during analysis')
        version = subprocess.run([objdump, '--version'], check=True, capture_output=True,
                                 text=True, encoding='utf-8').stdout.splitlines()[0]
        report = dict(target_sha256=DIGEST, target_bytes=len(data),
                      source_base='1f8c67c63ca4794c9689235471c60297f8a5c985',
                      coordinates='linked ELF virtual addresses; source file offset separately recorded',
                      candidate=dict(start=START, end=END, bytes=len(code), file_offset=offset, sha256=sha(code)),
                      claim='Conditional static four-byte-record transfer and per-batch bounds, not source reconstruction or equivalence.',
                      domain=DOMAIN, native=dict(version=version, argv=argv, raw_sha256=sha(raw.encode())),
                      source_tool_sha256=sha(Path(__file__).read_bytes()),
                      source_dependency_sha256={'tools/elf_index.py': sha((ROOT/'tools/elf_index.py').read_bytes())},
                      boundary_context='PR981 supplies the earlier candidate/FDE context. This tool independently decodes maintained base bytes and does not import its unmerged analyzer.',
                      source_binding='One admitted ELF descriptor/mmap and pre/post full hashes; native tools receive only copied1269B raw bytes. Transient in-place-write atomicity is not claimed.',
                      captured_execution_or_emulation=False, **result)
    return report, rows, raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--objdump', default='objdump')
    args = parser.parse_args()
    report, rows, raw = inspect_target(args.binary, args.objdump)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    outputs = {'REPORT.json': json.dumps(report, indent=2)+'\n',
               'instructions.json': json.dumps(rows, indent=2)+'\n', 'native.objdump': raw}
    for name, content in outputs.items():
        (args.output_dir/name).write_text(content)
    (args.output_dir/'OUTPUT-MANIFEST.json').write_text(json.dumps(
        {name: sha(content.encode()) for name, content in outputs.items()}, indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output_dir), candidate_bytes=END-START,
                          instructions=len(rows), WORD_store_sites=20,
                          runtime_table_contents_recovered=False, captured_execution_or_emulation=False)))


if __name__ == '__main__':
    main()
