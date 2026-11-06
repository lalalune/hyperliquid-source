#!/usr/bin/env python3
'''Compare the independently compiled u32 probe with static Node #115 evidence.'''
from pathlib import Path
import argparse
import hashlib
import itertools
import json
import subprocess
import tempfile

import evm_amount_scale as engine
from numeric_selector115_rust import NoExternalMemory
import u32_varint_reader_static as native
from fde_extents import eh_frame_records
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = Path(__file__).resolve().parents[1]


class ReaderMachine(engine.Machine):
    def i_jle(self, operands):
        if self.flag('zf') or self.flag('sf') != self.flag('of'):
            self.i_jmp(operands)


def own_machine(path):
    data = Path(path).read_bytes()
    if len(data) < 64:
        raise ValueError('Truncated own Rust object')
    if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[16:18], 'little') != 1 or int.from_bytes(data[18:20], 'little') != 62:
        raise ValueError('Expected our Linux x86-64 relocatable Rust object')
    image = engine.Image(data)
    if any((name.startswith(('.rela.text', '.rel.text')) for name in image.sec)):
        raise ValueError('External code relocations are not supported')
    text = [(name, section) for name, section in image.sec.items() if name == '.text.node115_u32_reader_probe' and section[2]]
    if len(text) != 1 or text[0][0] != '.text.node115_u32_reader_probe':
        raise ValueError('Exactly one known Rust scalar section required')
    _, (_, offset, size) = text[0]
    body = data[offset:offset + size]
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_IMM, CS_OP_MEM
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    instructions = list(cs.disasm(body, 1048576))
    rows = []
    if sum((i.size for i in instructions)) != len(body):
        raise ValueError('Incomplete own-object decoding')
    for ins in instructions:
        operands = []
        for op in ins.operands:
            if op.type == CS_OP_REG:
                register, width = engine.REGS[ins.reg_name(op.reg)]
                operands.append(('r', register, width))
            elif op.type == CS_OP_IMM:
                operands.append(('i', op.imm))
            elif op.type == CS_OP_MEM:
                if ins.reg_name(op.mem.base) == 'rip':
                    raise ValueError('External data reference')
                base = engine.REGS[ins.reg_name(op.mem.base)][0] if op.mem.base else None
                index = engine.REGS[ins.reg_name(op.mem.index)][0] if op.mem.index else None
                operands.append(('m', op.size, base, index, op.mem.scale, op.mem.disp))
            else:
                raise ValueError('Unsupported operand')
        if ins.mnemonic == 'call':
            raise ValueError('Opaque compiled helper call')
        rows.append((ins.address, ins.mnemonic, tuple(operands), ins.address + ins.size))
    return (ReaderMachine(rows, NoExternalMemory(), {}), body, instructions)

def evaluate(machine, data, mode, limit, count, alignment):
    machine.reset()
    machine.setreg(engine.RSP, engine.STACK_TOP)
    machine.store(engine.STACK_TOP, 8, engine.RET_MAGIC)
    input_address = engine.BUFFER + 1024 + alignment
    for index, value in enumerate(data):
        machine.store(input_address + index, 1, value)
    saved = {
        register: 0xabcddcba00000000 + register
        for register in (engine.RBX, engine.RBP, engine.R12, engine.R13, engine.R14, engine.R15)
    }
    for register, value in saved.items():
        machine.setreg(register, value)
    arguments = [engine.BUFFER, input_address, len(data), mode, limit, count]
    registers = [engine.RDI, engine.RSI, engine.RDX, engine.RCX, engine.R8, engine.R9]
    for register, value in zip(registers, arguments):
        machine.setreg(register, value)
    if machine.run(0x100000, limit=1000) != engine.RET_MAGIC:
        raise ValueError('Own probe did not return')
    for register, value in saved.items():
        if machine.regs[register] != value or machine.known[register] != engine.MASK:
            raise ValueError('Callee-saved register changed')
    return [machine.load(engine.BUFFER + 8 * index, 8) for index in range(7)]


MAX = (1 << 64) - 1
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def expected(blob, mode, limit, count, charge=4, threshold=4):
    if mode == 1:
        if count > MAX - charge:
            return [2, 0, 0, 0, 0, len(blob), count]
        count += charge
        if count > limit:
            return [2, 0, 0, 0, 0, len(blob), count]
    length = len(blob)
    marker = blob[0] if blob else 0
    projection = (native.fast_marker_outcome(marker) if length > threshold
                  else native.slow_outcome(marker, length))
    consumed = projection['consumed']
    remaining = length - consumed
    if projection['outcome'] == 'need':
        return [0, projection['additional'], 0, 0, consumed, remaining, count]
    if projection['outcome'] == 'error':
        return [3, 0, projection['field1'], projection['field2'], consumed, remaining, count]
    value = marker if marker <= 250 else int.from_bytes(blob[1:consumed], 'little')
    return [18, value, 0, 0, consumed, remaining, count]


def native_record(data):
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != TARGET:
        raise ValueError('Wrong capture')
    _, frames = eh_frame_records(data)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    owners = {}
    for role, (start, end, digest) in native.OWNERS.items():
        found = [f for f in frames if f['start'] == start]
        assert len(found) == 1 and found[0]['end'] == end
        body = native.read(data, start, end - start)[1]
        assert hashlib.sha256(body).hexdigest() == digest
        instructions = list(decoder.disasm(body, start))
        assert sum(i.size for i in instructions) == len(body)
        owners[role] = dict(start=hex(start), end=hex(end), sha256=digest,
                            capstone=[f'{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip()
                                      for i in instructions])
    relocs = native.relocations(data)
    assert relocs[native.SLOW_SLOT] == [(8, native.SLOW)]
    assert relocs[native.CTOR_SLOT] == [(8, native.CTOR)]
    assert native.read(data, native.CTOR, len(native.CTOR_BODY))[1] == native.CTOR_BODY
    copies = {
        role: native.copy_semantics(data, role, native.OWNERS[role][0], table)
        for role, table in native.COPY_TABLES.items()
    }
    return dict(owners=owners, copies=copies, slow=native.slow_semantics(data),
                selected_relocations={hex(slot): relocs[slot] for slot in (native.SLOW_SLOT, native.CTOR_SLOT)},
                constructor_boundary=native.CTOR_BODY.hex())


def cases():
    blobs = {b''}
    for marker, length in itertools.product(range(256), range(1, 10)):
        blobs.add(bytes([marker] + [(marker * 73 + i * 137) & 255 for i in range(length - 1)]))
    for marker, width in ((251, 2), (252, 4)):
        for value in (0, 1, 250, 251, (1 << (8 * width)) - 1):
            encoded = bytes([marker]) + value.to_bytes(width, 'little')
            blobs.update([encoded, encoded + b'\xff\0\x01'])
    states = [(0, 0, 19), (1, MAX, 0), (1, 4, 0), (1, 3, 0),
              (1, MAX, MAX - 4), (1, MAX, MAX - 3), (2, 0, MAX), (0xffffffff, 0, 17)]

    for blob, (mode, limit, count) in itertools.product(sorted(blobs), states):
        yield dict(input_hex=blob.hex(), mode=mode, limit=limit, count=count,
                   expected=expected(blob, mode, limit, count))


def compile_probe(rustc, source, obj):
    subprocess.run([
        str(rustc), '--edition=2024', '--crate-type=lib',
        '--target=x86_64-unknown-linux-gnu', '--emit=obj', '-O', '-C', 'panic=abort',
        '-C', 'jump-tables=no', str(source), '-o', str(obj),
    ], check=True)


def verify(capture, rustc):
    native_record(capture.read_bytes())
    source = ROOT / 'src/node115-u32-varint/src/lib.rs'
    corpus = hashlib.sha256()
    transcript = hashlib.sha256()
    evaluations = 0
    scratch = ROOT / 'work'
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as tmp:
        obj = Path(tmp) / 'probe.o'
        compile_probe(rustc, source, obj)
        machine, body, instructions = own_machine(obj)
        for index, case in enumerate(cases()):
            corpus.update((json.dumps(case, sort_keys=True) + '\n').encode())
            data = bytes.fromhex(case['input_hex'])
            for alignment in range(8):
                actual = evaluate(machine, data, case['mode'], case['limit'], case['count'], alignment)
                if actual != case['expected']:
                    raise ValueError((case, alignment, actual))
                row = dict(case=index, alignment=alignment, actual=actual)
                transcript.update((json.dumps(row, sort_keys=True) + '\n').encode())
                evaluations += 1
    if corpus.hexdigest() != 'd034505c11350651f2781d6c9218ad3a8f39b5a5aeb8c0fcc36f7f7518147805':
        raise ValueError('Corpus differs from the pre-source freeze')
    return dict(cases=evaluations // 8, evaluations=evaluations, mismatches=0,
                corpus_sha256=corpus.hexdigest(), transcript_sha256=transcript.hexdigest(),
                own_code_sha256=hashlib.sha256(body).hexdigest(),
                own_code_bytes=len(body), own_instructions=len(instructions))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', default='rustc')
    parser.add_argument('--capture', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    options = parser.parse_args()
    print(json.dumps(verify(options.capture, options.rustc), indent=2))
