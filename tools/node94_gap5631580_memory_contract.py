#!/usr/bin/env python3
"""Static, conditional memory contract for node #94 candidate 0x5631580.

Only GNU objdump runs, on a 1,149-byte raw slice. The captured executable is
never executed. Symbolic terms describe straight-line instruction transfers;
no concrete state, loop, pointer dereference or captured code is evaluated.
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
START, END = 0x5631580, 0x56319fd
OUTER, SEED, INNER, TAIL, EXIT = 0x56315de, 0x5631669, 0x56316c0, 0x563199b, 0x56319ae
SAVED = ['rax', 'rbx', 'rcx', 'rdx', 'rbp', 'rsi', 'rdi'] + [f'r{i}' for i in range(8, 16)]
INPUTS = ['r8', 'r9', 'r10', 'r11']
OUTPUTS = ['rsi', 'rbx', 'rcx', 'rdi']
WORDS = ['rbp', 'rdx', 'r12', 'r13']
CELLS = ['r15', 'r9', 'r10', 'r11']


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

    def table_cell(self, table, word):
        index = self.shift('logical_right', word, self.const(53))
        return self.zext(self.load(16, self.op('add', table, self.op('multiply_low', index, self.const(2)))))


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
            root = name[:-1] if re.fullmatch(r'r\d+d', name) else name
            require(root in self.r, 'Unsupported register ' + name)
            value = self.r[root] if root == name else self.t.extract(self.r[root], 0, 32)
        self.event['register_reads'].append(dict(register=name, value=value))
        return value

    def assign(self, name, value):
        root = name[:-1] if re.fullmatch(r'r\d+d', name) else name
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


def contract(rows):
    """Derive and check phase transfers against width-explicit postconditions."""
    graph = cfg(rows)
    t = Terms()
    initial = {r: t.var('entry.' + r) for r in SAVED + ['rsp']}
    q, stack = initial['rdi'], initial['rsp']
    select = lambda lo, hi: [r for r in rows if lo <= r['va'] < hi]
    prologue = Lift(t, initial).run(select(START, OUTER))
    working_rsp = t.offset(stack, -176)
    require(prologue.r['rsp'] == working_rsp, 'Stack frame is not 176 bytes')
    require(len(prologue.stores) == 19 and
            {(s['width'], s['address']) for s in prologue.stores} ==
            {(64, t.offset(stack, -8 * n)) for n in range(1, 20)}, 'Unexpected prologue memory write')
    require([e['assembly'] for e in prologue.trace if e['assembly'].startswith('push ')][:15] == ['push ' + r for r in SAVED], 'Saved-register order changed')
    lane_registers = INPUTS + OUTPUTS + WORDS
    for index, reg in enumerate(lane_registers + ['r14']):
        require(prologue.r[reg] == t.load(64, t.offset(q, 8 * index)), 'State load layout changed')
    for displacement, expected in ((32, t.load(64, t.offset(q, 0x70))),
                                   (40, t.load(64, t.offset(q, 0x68))), (48, q)):
        require(prologue.memory[64, t.offset(working_rsp, displacement)] == expected, 'Auxiliary frame layout changed')

    logical = {kind: [t.var(f'current.{kind}{i}') for i in range(4)] for kind in ('input', 'output', 'word')}
    table = t.var('current.table')
    current = dict(prologue.r)
    for regs, kind in ((INPUTS, 'input'), (OUTPUTS, 'output'), (WORDS, 'word')):
        current.update(zip(regs, logical[kind]))
    current['r14'] = table
    outer = Lift(t, current, prologue.memory).run(select(OUTER, SEED))
    require(len(outer.stores) == 2 and
            {(s['width'], s['address']) for s in outer.stores} ==
            {(64, t.offset(working_rsp, n)) for n in (0, 8)}, 'Unexpected outer-guard memory write')
    require(all(outer.r[r] == current[r] for r in lane_registers + ['r14', 'rsp']), 'Outer guards clobber live lane state')
    guards = [e['condition'] for e in outer.trace if 'condition' in e]
    require(len(guards) == 4 and guards[0] == dict(relation='equal', operands=[outer.r['r15'], logical['output'][3]]), 'Unexpected early exit guards')
    for i, guard in enumerate(guards[1:]):
        require(guard == dict(relation='unsigned_below', operands=[logical['input'][i + 1], logical['input'][i]]), 'Cursor-order guard changed')

    seed = Lift(t, outer.r, outer.memory).run(select(SEED, INNER))
    require(len(seed.stores) == 4 and
            {(s['width'], s['address']) for s in seed.stores} ==
            {(64, t.offset(working_rsp, n)) for n in (0, 8, 16, 24)}, 'Unexpected seed memory write')
    for i, cell in enumerate(CELLS):
        require(seed.r[cell] == t.table_cell(table, logical['word'][i]), 'Initial table-cell transfer changed')
    require(seed.memory[64, t.offset(working_rsp, 24)] == outer.r['r15'], 'Loop stop is not saved')
    loop = Lift(t, seed.r, seed.memory).run(select(INNER, TAIL))
    emitted = [s for s in loop.stores if s['width'] == 8]
    require(len(emitted) == 20, 'Inner iteration does not have twenty byte stores')
    spills = [s for s in loop.stores if s['width'] != 8]
    require(len(spills) == 3 and
            {(s['width'], s['address']) for s in spills} ==
            {(64, t.offset(working_rsp, n)) for n in (0, 8, 16)}, 'Unexpected inner-loop memory write')
    lane_reports = []
    for lane in range(4):
        word, output, inp = (logical[k][lane] for k in ('word', 'output', 'input'))
        cells, stores = [], []
        for byte in range(5):
            cell = t.table_cell(table, word)
            record = emitted[byte * 4 + lane]
            require(record['address'] == t.offset(output, byte), 'Five-byte lane footprint changed')
            require(record['value'] == t.extract(cell, 8, 8), 'Emission is not the table-word high byte')
            cells.append(cell)
            stores.append(record)
            word = t.shift('left', word, cell)
        bsf = t.op('trailing_zero_count_nonzero', word)
        retreat = t.shift('logical_right', bsf, t.const(3))
        updated_input = t.op('sub', inp, retreat)
        updated_word = t.shift('left', t.op('or', t.load(64, updated_input), t.const(1)), t.op('and', bsf, t.const(7)))
        require(loop.r[OUTPUTS[lane]] == t.offset(output, 5), 'Output cursor is not advanced by five')
        require(loop.r[WORDS[lane]] == updated_word, 'BSF/refill word transfer changed')
        actual_input = loop.r['r8'] if lane == 0 else loop.memory[64, t.offset(working_rsp, (lane - 1) * 8)]
        require(actual_input == updated_input, 'Input cursor retreat/spill changed')
        require(loop.r[CELLS[lane]] == t.table_cell(table, updated_word), 'Next-iteration cell invariant changed')
        require(loop.bsf_inputs[lane]['nonzero_term'] == word, 'BSF does not consume post-emission word')
        lane_reports.append(dict(lane=lane, input_register=INPUTS[lane], output_register=OUTPUTS[lane],
                                 word_register=WORDS[lane], cell_register=CELLS[lane],
                                 emitted_stores=stores, cell_terms=cells, post_fifth_word=word,
                                 required_nonzero_bsf_word=word, input_after=updated_input,
                                 defined_bsf_range=[0, 63], input_retreat_bytes_range=[0, 7],
                                 refill_shift_count_range=[0, 7], input_read_width_bits=64,
                                 output_after=t.offset(output, 5), word_after=updated_word))
    require(len(loop.bsf_inputs) == 4, 'Unexpected BSF domain')
    loop_condition = [e['condition'] for e in loop.trace if 'condition' in e]
    require(loop_condition == [dict(relation='unsigned_above', operands=[outer.r['r15'], t.offset(logical['output'][3], 5)])], 'Loop continuation predicate changed')
    tail = Lift(t, loop.r, loop.memory).run(select(TAIL, EXIT))
    require(not tail.stores, 'Unexpected tail-restore memory write')
    for lane in range(4):
        require(tail.r[INPUTS[lane]] == lane_reports[lane]['input_after'], 'Outer-loop input restoration changed')
        require(tail.r[OUTPUTS[lane]] == lane_reports[lane]['output_after'] and
                tail.r[WORDS[lane]] == lane_reports[lane]['word_after'], 'Outer-loop live word/output restoration changed')
    require(tail.r['r14'] == table and tail.r['rsp'] == working_rsp, 'Loop changes table base or frame')
    protected = [(64, t.offset(working_rsp, n)) for n in range(32, 176, 8)]
    for phase in (outer, seed, loop, tail):
        require(all(phase.memory[key] == prologue.memory[key] for key in protected), 'Loop changes a protected saved/configuration slot')

    # Exit may follow the first guards or any number of completed cycles.
    # Scratch +24 is initially a dummy saved R15, later the saved loop stop.
    # The first POP reads it before three overwrites of RAX; generalize all
    # mutable scratch slots instead of falsely reusing prologue values.
    exit_memory = dict(prologue.memory)
    exit_scratch = {n: t.var(f'exit.scratch{n}') for n in (0, 8, 16, 24)}
    for displacement, value in exit_scratch.items():
        exit_memory[64, t.offset(working_rsp, displacement)] = value
    epilogue = Lift(t, current, exit_memory).run(select(EXIT, END))
    require(len(epilogue.stores) == 12, 'Normal return does not have twelve state writebacks')
    writebacks = []
    for index, record in enumerate(epilogue.stores):
        reg = lane_registers[index]
        require(record == dict(va=record['va'], width=64, address=t.offset(q, index * 8), value=current[reg]), 'State writeback layout/value changed')
        writebacks.append(dict(**record, entry_rdi_offset=index * 8, register=reg))
    require(all(epilogue.r[r] == initial[r] for r in SAVED), 'Saved GPR restoration changed')
    require(epilogue.r['rsp'] == t.offset(stack, 8), 'RET stack effect changed')
    phases = dict(prologue=prologue, outer_guards=outer, seed=seed, inner_iteration=loop,
                  tail_restore=tail, normal_return=epilogue)
    require(sum(len(p.trace) for p in phases.values()) == len(rows), 'Incomplete phase lifting')
    return dict(cfg=graph, terms=t.nodes, phases={k: v.trace for k, v in phases.items()},
                state_base_term=q, entry_stack_term=stack, working_rsp_term=working_rsp,
                loop_stop_term=outer.r['r15'], early_exit_guards=guards,
                inner_continue_condition=loop_condition[0], lanes=lane_reports,
                state_layout=[dict(entry_rdi_offset=8 * i, width=64, physical_register=reg,
                                   prologue_value=prologue.r[reg]) for i, reg in enumerate(lane_registers + ['r14'])] +
                             [dict(entry_rdi_offset=n, width=64, physical_register=None,
                                   prologue_value=t.load(64, t.offset(q, n))) for n in (0x68, 0x70)],
                loop_invariant=dict(table_base_register='r14',
                                    cell_registers=CELLS,
                                    cell_relation='zero_extend_64(load16(T + 2 * logical_right_64(B, 53)))',
                                    input1_to_input3_frame_offsets=[0, 8, 16],
                                    saved_loop_stop_frame_offset=24,
                                    protected_frame_offsets=list(range(32, 176, 8)),
                                    establishment='The seed fallthrough establishes all four cells; the sole inner backedge preserves all four via refill. The tail restores the three input registers before the sole outer backedge.'),
                normal_return_writebacks=writebacks, restored_gprs=SAVED,
                normal_return_cutpoint=dict(mutable_frame_offsets=list(exit_scratch),
                                            mutable_slot_value_terms=exit_scratch,
                                            protected_frame_offsets=list(range(32, 176, 8)),
                                            join='Arbitrary current scratch values cover initial dummy and previous-loop-stop histories. Protected slots retain exact prologue values; the twelve writebacks and fifteen restored GPRs are independent of mutable exit scratch.'),
                normal_return_register_result='All fifteen saved GPRs restore their entry values; RAX does not carry a newly computed status/result on the proven normal-return paths. RFLAGS preservation is not claimed.',
                table=dict(base_term=table, index_bits=11, index_shift=53,
                           entry_bits=16, maximum_offset=4094, read_span_bytes=4096),
                phase_instruction_count={k: len(v.trace) for k, v in phases.items()})


DOMAIN = [
    'Static normal-return paths on x86-64 with the used instructions available; no target execution or concrete-state evaluation.',
    'All referenced memory is valid for its recorded width and access, without faults, concurrent modification, signal intervention or asynchronous changes.',
    'The state block at entry RDI, the 176-byte stack frame plus return-address slot, table reads, input reads and output writes do not overlap each other; output lanes are disjoint for the stream interpretation.',
    'Every one of the four BSF operands is nonzero at each executed inner iteration; zero has an architecturally undefined destination and is outside this contract.',
    'All qword arithmetic and address construction use 64-bit modular machine semantics; the contract does not prove nonwrapping ranges, allocation bounds, input validity, termination or total iteration counts.',
]


def inspect_target(binary, objdump='objdump'):
    # Admit one descriptor/mapping. Native tools receive only the copied raw
    # slice, never a second open of the original ELF pathname.
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
        report = dict(target_sha256=DIGEST, target_bytes=len(data), source_base='1f8c67c63ca4794c9689235471c60297f8a5c985',
                      coordinates='linked ELF virtual addresses; source file offset recorded separately',
                      candidate=dict(start=START, end=END, bytes=len(code), file_offset=offset, sha256=sha(code)),
                      claim='Conditional static memory contract of one boundary candidate; no original source/type/ABI/algorithm or equivalence claim.',
                      proof_domain=DOMAIN,
                      limits=['No incoming caller or runtime dispatch is recovered.',
                              'Boundary/FDE context is in PR #981; this tool independently admits/decode-checks base bytes and does not depend on that unmerged tool.',
                              'No algorithm, original type or source function is named. No Rust implementation, component gate or whole-node denominator is established.',
                              'Pre/post hashes bind the admitted mmap; they do not provide an atomic snapshot against transient in-place writes.'],
                      native=dict(version=version, argv=argv, raw_sha256=sha(raw.encode())),
                      source_tool_sha256=sha(Path(__file__).read_bytes()), **result)
    return report, rows, raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--objdump', default='objdump')
    args = parser.parse_args()
    report, rows, raw = inspect_target(args.binary, args.objdump)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    outputs = {'REPORT.json': json.dumps(report, indent=2) + '\n',
               'instructions.json': json.dumps(rows, indent=2) + '\n', 'native.objdump': raw}
    for name, content in outputs.items():
        (args.output_dir / name).write_text(content)
    manifest = {name: sha(content.encode()) for name, content in outputs.items()}
    (args.output_dir / 'OUTPUT-MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(output=str(args.output_dir), candidate_bytes=END - START,
                          instructions=len(rows), output_store_sites=20, state_writeback_sites=12)))


if __name__ == '__main__':
    main()
