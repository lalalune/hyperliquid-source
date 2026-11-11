"""Qualified packed-word preparation and CAS retry. Captured code stays inert."""
from pathlib import Path
import hashlib
import itertools
import json
import random
import subprocess
from fde_extents import eh_frame_records

import evm_amount_scale as engine
import ip_permit_state_static as native
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_IMM, CS_OP_MEM


ROOT = Path(__file__).resolve().parents[1]
BINARY = 'artifacts/node/115/hl-node'
CRATE = ROOT / 'src/node115-packed-word-step'
NATIVE_RECORD = ROOT / 'research/work-items/RE-001-node115-ip-permit-state/records.json'
PACKET = ROOT / 'research/work-items/RE-014-packed-word-step-rust-115'


class SyntheticMemory:
    def in_rodata(self, *args):
        return False


class PermitMachine(engine.Machine):
    def i_cmpxchg(self, operands):
        destination, source = operands
        if destination[0:2] != ('m', 8) or source[0] != 'r' or source[2] != 8:
            raise engine.Unmodelled('Only locked 64-bit memory CAS is supported here')
        address = self.ea(destination)
        if address != self.word_address:
            raise engine.Unmodelled('CAS outside the synthetic word')
        index = len(self.attempts)
        if index < len(self.schedule) and self.schedule[index] is not None:
            self.store(address, 8, self.schedule[index])
        accumulator = ('r', engine.RAX, 8)
        observed = self.rd(accumulator)
        current = self.rd(destination)
        desired = self.rd(source)
        self.i_cmp((accumulator, destination))
        success = self.flag('zf')
        self.wr(destination, desired if success else current)
        if not success:
            self.wr(accumulator, current)
        self.attempts.append([observed, current, desired, success])


def own_machine(path, probe):
    data = path.read_bytes()
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or data[16:20] != b'\x01\x00\x3e\x00':
        raise ValueError('Expected freshly compiled x86-64 ELF REL')
    image = engine.Image(data)
    if any(name.startswith(('.rela.text', '.rel.text')) for name in image.sec):
        raise ValueError('External text relocation')
    if probe not in ('step', 'init'):
        raise ValueError('Unknown own probe')
    _, offset, length = image.sec['.text.node115_permit_' + probe + '_probe']
    body = data[offset:offset + length]
    if not body or len(body) != length:
        raise ValueError('Missing or truncated own section')
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(body, 0x100000))
    if sum(i.size for i in instructions) != len(body):
        raise ValueError('Incomplete own decode')
    rows = []
    for instruction in instructions:
        operands = []
        for operand in instruction.operands:
            if operand.type == CS_OP_REG:
                register, width = engine.REGS[instruction.reg_name(operand.reg)]
                operands.append(('r', register, width))
            elif operand.type == CS_OP_IMM:
                operands.append(('i', operand.imm))
            elif operand.type == CS_OP_MEM:
                if instruction.reg_name(operand.mem.base) == 'rip':
                    raise ValueError('External data reference')
                base = engine.REGS[instruction.reg_name(operand.mem.base)][0] if operand.mem.base else None
                index = engine.REGS[instruction.reg_name(operand.mem.index)][0] if operand.mem.index else None
                operands.append(('m', operand.size, base, index, operand.mem.scale, operand.mem.disp))
            else:
                raise ValueError('Unsupported operand')
        mnemonic = instruction.mnemonic
        if mnemonic == 'lock cmpxchg' and instruction.bytes[0] == 0xf0:
            mnemonic = 'cmpxchg'
        elif mnemonic in ('call', 'cmpxchg'):
            raise ValueError('Unsupported call or unlocked CAS')
        rows.append((instruction.address, mnemonic, tuple(operands), instruction.address + instruction.size))
    return PermitMachine(rows, SyntheticMemory(), {}), body


def evaluate(machine, argument, schedule=None):
    machine.reset()
    machine.setreg(engine.RSP, engine.STACK_TOP)
    machine.store(engine.STACK_TOP, 8, engine.RET_MAGIC)
    machine.setreg(engine.RDI, engine.BUFFER)
    machine.word_address = engine.BUFFER + 64
    machine.attempts = []
    machine.schedule = schedule or ()
    if schedule is None:
        machine.setreg(engine.RSI, argument)
    else:
        machine.setreg(engine.RSI, machine.word_address)
        machine.store(machine.word_address, 8, argument)
    if machine.run(0x100000, limit=1000) != engine.RET_MAGIC:
        raise ValueError('Own probe did not return')
    route = machine.load(engine.BUFFER, 8)
    if schedule is None:
        return [route, machine.load(engine.BUFFER + 8, 8)] if route else [0]
    return [route, machine.load(engine.BUFFER + 8, 8), machine.attempts]


def expected_step(parameters, word, schedule):
    attempts = []
    current = word
    while True:
        route, desired = native.attempt_projection(parameters, word)
        if route != 'eligible':
            return [int(route == 'empty-gate'), current, attempts]
        index = len(attempts)
        if index < len(schedule) and schedule[index] is not None:
            current = schedule[index]
        success = current == word
        attempts.append([word, current, desired, success])
        if success:
            return [2, desired, attempts]
        word = current


def native_record(data):
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != native.SHA:
        raise ValueError('Wrong node115 capture')
    record = native.analyze(data)
    if record != json.loads(NATIVE_RECORD.read_bytes()):
        raise ValueError('Existing native certificate differs')
    _, frames = eh_frame_records(data)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    for owner in record['owners']:
        start = int(owner['start'], 16)
        end = int(owner['end'], 16)
        matches = [f for f in frames if f['start'] == start]
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('Missing or ambiguous full native extent')
        for kind, frame in owner['frames'].items():
            raw = bytes.fromhex(frame['bytes_hex'])
            address = int(frame['va'], 16)
            if matches[0][kind] != address or native.read(data, address, len(raw))[1] != raw:
                raise ValueError('Actual native frame differs')
        body = native.read(data, start, end - start)[1]
        instructions = list(decoder.disasm(body, start))
        if len(instructions) != owner['instructions'] or sum(i.size for i in instructions) != len(body):
            raise ValueError('Incomplete native partition')
        owner['capstone'] = [
            f'{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}'.rstrip()
            for i in instructions
        ]
    return record


def corpus():
    generator = random.Random(0x4770f40)
    boundaries = {
        ((1 << bit) + delta) & engine.MASK
        for bit in range(64)
        for delta in (-2, -1, 0, 1, 2)
    }
    words = sorted(set(range(256)) | boundaries | {generator.getrandbits(64) for _ in range(512)})
    schedules = [
        (), (0,), (1,), (2,), (4, 6, 8), (6, 1), (8, 0), (None, 0),
        (engine.MASK,), (engine.MASK - 1,),
    ]
    return words, schedules


def expected_init(parameters, capacity):
    return [1, capacity * 2] if native.guard_passes(parameters, capacity) else [0]


def verify(rustc, output):
    rustc = Path(rustc).resolve()
    forbidden = {
        native.SHA,
        '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
        '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31',
    }
    compiler_hash = hashlib.sha256(rustc.read_bytes()).hexdigest()
    if rustc.is_relative_to(ROOT / 'artifacts') or compiler_hash in forbidden:
        raise ValueError('Captured artifact cannot be a compiler')
    version = subprocess.run([str(rustc), '-Vv'], check=True, capture_output=True, text=True).stdout
    if not version.startswith('rustc 1.94.1 '):
        raise ValueError('Pinned Rust 1.94.1 required')
    data = (ROOT / BINARY).read_bytes()
    record = native_record(data)
    parameters = record['parameters']
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    source = (CRATE / 'src/lib.rs').read_text(encoding='utf8')
    flags = [
        '--crate-name', 'node115_packed_word_step', '--edition=2024', '--crate-type=lib',
        '--emit=obj', '--target=x86_64-unknown-linux-gnu', '-C', 'opt-level=3',
        '-C', 'panic=abort', '-C', 'codegen-units=1', '-C', 'no-vectorize-loops',
        '-C', 'no-vectorize-slp',
    ]

    def build(label, text):
        folder = output / label
        folder.mkdir()
        rust = folder / 'lib.rs'
        rust.write_text(text, encoding='utf8', newline='\n')
        obj = folder / 'own.o'
        subprocess.run([str(rustc), *flags, str(rust), '-o', str(obj)],
                       check=True, capture_output=True)
        return obj

    first = build('first', source)
    if first.read_bytes() != build('repeat', source).read_bytes():
        raise ValueError('Repeated own objects differ')
    init, init_body = own_machine(first, 'init')
    step, step_body = own_machine(first, 'step')
    words, schedules = corpus()
    failures = 0
    transcript = hashlib.sha256()
    with (output / 'comparisons.jsonl').open('wb') as raw:
        def compare(probe, word, schedule, actual, expected):
            if actual != expected:
                raise ValueError(f'Own {probe} mismatch for {word}, schedule {schedule}')
            row = dict(probe=probe, word=word, schedule=schedule, actual=actual, expected=expected)
            line = (json.dumps(row, sort_keys=True) + '\n').encode()
            transcript.update(line)
            raw.write(line)

        for word in words:
            compare('init', word, None, evaluate(init, word), expected_init(parameters, word))
        for word, schedule in itertools.product(words, schedules):
            actual = evaluate(step, word, schedule)
            compare('step', word, schedule, actual, expected_step(parameters, word, schedule))
            failures += sum(not attempt[3] for attempt in actual[2])
    mutations = [
        ('capacity_limit', 'capacity >> 61', 'capacity >> 62', 'init', 1 << 61, None),
        ('capacity_word', 'Some(capacity * 2)', 'Some(capacity * 4)', 'init', 1, None),
        ('flag_gate', 'observed & 1 != 0', 'observed & 2 != 0', 'step', 1, ()),
        ('empty_gate', 'observed < 2', 'observed < 4', 'step', 2, ()),
        ('decrement', 'observed - 2', 'observed - 1', 'step', 4, ()),
        ('retry', 'Err(actual) => observed = actual',
         'Err(_) => return WordStep::Decremented', 'step', 4, (6,)),
    ]
    compiled = []
    for label, before, after, probe, word, schedule in mutations:
        if source.count(before) != 1:
            raise ValueError('Mutation anchor changed')
        machine, _ = own_machine(build(label, source.replace(before, after)), probe)
        actual = evaluate(machine, word, schedule)
        expected = (expected_init(parameters, word) if schedule is None
                    else expected_step(parameters, word, schedule))
        if actual == expected:
            raise ValueError(f'Surviving compiled mutation {label}')
        compiled.append(dict(name=label, expected=expected, changed=actual, input=word,
                             schedule=list(schedule) if schedule is not None else None))
    controls = []
    for name, address, replacement, word in [
        ('capacity_limit', 0x4771101, 62, 1 << 61),
        ('flag_gate', 0x4770f71, 2, 1),
        ('empty_gate', 0x4770f7b, 4, 2),
        ('decrement', 0x4770f85, 255, 4),
    ]:
        changed = bytearray(data)
        offset, _ = native.read(data, address, 1)
        changed[offset] = replacement
        operands = native.parameters(changed)
        if name == 'capacity_limit':
            expected = expected_init(parameters, word)
            actual = expected_init(operands, word)
        else:
            expected = expected_step(parameters, word, ())
            actual = expected_step(operands, word, ())
        if expected == actual:
            raise ValueError(f'Inoperative native operand control {name}')
        try:
            native.analyze(changed)
        except ValueError as error:
            rejection = str(error)
        else:
            raise ValueError('Changed operand passed below whole-image identity')
        controls.append(dict(name=name, va=hex(address), expected=expected, changed=actual,
                             rejection=rejection))
    result = dict(
        native=record,
        source_sha256={n: hashlib.sha256((CRATE / n).read_bytes()).hexdigest()
                       for n in ('Cargo.toml', 'Cargo.lock', 'src/lib.rs')},
        checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        native_model_sha256=hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),
        shared_engine_sha256=hashlib.sha256(Path(engine.__file__).read_bytes()).hexdigest(),
        compiler_version=version, compiler_sha256=compiler_hash, flags=flags,
        initialization_cases=len(words), step_cases=len(words) * len(schedules),
        observed_failed_cas=failures, mismatches=0,
        init_code_sha256=hashlib.sha256(init_body).hexdigest(),
        step_code_sha256=hashlib.sha256(step_body).hexdigest(),
        raw_comparisons_sha256=transcript.hexdigest(), compiled_controls=compiled,
        native_operand_controls=controls, repeated_objects_equal=True, captured_executed=False,
        scope='Finite scheduled same-word writes before own CAS attempts. No concurrency or native provider closure.',
    )
    (output / 'rust-validation.json').write_text(
        json.dumps(result, indent=2) + '\n', encoding='utf8', newline='\n',
    )
    return result


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    result = verify(args.rustc, args.out)
    print(json.dumps({k: result[k] for k in ('initialization_cases', 'step_cases', 'observed_failed_cas', 'mismatches')}))
