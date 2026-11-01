#!/usr/bin/env python3
"""Revalidate selected native widths/branches; never evaluate captured code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FREEZE = 'adc217c39692223e24f57ea9eb63fbd9c0a833e34ec3103c40885533f9e8d49b'
BOUNDS = {
    0x4dbd490: (0x4dbdb5e, '3c4cf31225ada53f7cb30d9d2b16c805db9e47f30cc63ae8dbcb6167d901c1f3'),
    0x4497a90: (0x4498022, 'bf665db5f3a63b27ae18b6aa81c17b0ee3264ad56086e1f8a85f8b2e2d85f0a3'),
    0x4918d30: (0x49190b7, '9ae5e9107aca9a7ef4fd40d9b6dccee0cfa521a205a1422ea0a84b0ff9c05ed3'),
    0x4912a50: (0x4912d13, 'dd0aa09a10e58302a205c8e2ea0dac5c9f1428519d96b4a60c26bfb5c666f38a'),
}
LO, HI = 0x4918f00, 0x4919018
LINE = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Image:
    def __init__(self, data):
        self.data = data
        ph = struct.unpack_from('<Q', data, 32)[0]
        width, count = struct.unpack_from('<HH', data, 54)
        require(width == 56, 'program header width')
        self.loads = []
        for i in range(count):
            kind, _, off, va, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', data, ph + i * width)
            if kind == 1:
                self.loads.append((va, va + size, off))

    def offset(self, va, size):
        hits = [off + va - lo for lo, hi, off in self.loads if lo <= va and va + size <= hi]
        require(len(hits) == 1, 'unique file-backed range')
        return hits[0]

    def read(self, va, size):
        at = self.offset(va, size)
        return self.data[at:at + size]

    def record(self, va):
        return self.read(va, struct.unpack('<I', self.read(va, 4))[0] + 4).hex()


def decode(path, image, llvm):
    commands = [
        ['objdump', '-d', '-M', 'intel', '--insn-width=16', f'--start-address={LO}', f'--stop-address={HI}', str(path)],
        [llvm, '-d', '--x86-asm-syntax=intel', f'--start-address={LO}', f'--stop-address={HI}', str(path)],
    ]
    all_rows, texts = [], []
    for command in commands:
        text = subprocess.check_output(command, text=True)
        texts.append(text.replace(str(path), 'artifacts/node/94/hl-node'))
        rows = []
        for line in text.splitlines():
            match = LINE.match(line)
            if match:
                rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3]))
        cursor = LO
        for va, raw, _ in rows:
            require(va == cursor and image.read(va, len(raw)) == raw, 'complete native bytes')
            cursor += len(raw)
        require(cursor == HI, 'complete native envelope')
        all_rows.append(rows)
    require([(a, b) for a, b, _ in all_rows[0]] == [(a, b) for a, b, _ in all_rows[1]], 'native partitions disagree')
    return {a: (b, c) for a, b, c in all_rows[0]}, texts


def properties(rows):
    raw = lambda at: rows[at][0]
    asm = lambda at: re.sub(r'\s+', ' ', rows[at][1])
    require(asm(0x4918f12) == 'mov rdi,QWORD PTR [r15+rsi*8]', 'source-qword-index')
    require(asm(0x4918f16) == 'mov QWORD PTR [r14+rsi*8],rdi', 'append-qword-width')
    require(raw(0x4918f22)[0] == 0x73 and 0x4918f24 + int.from_bytes(raw(0x4918f22)[1:], 'little', signed=True) == 0x4918f06, 'unsigned-first-gate')
    require(asm(0x4918f30) == 'mov QWORD PTR [r14+r8*1],r9', 'shift-qword-width')
    require(raw(0x4918f34)[-1] == 8 and raw(0x4918f38)[0] == 0x74 and 0x4918f3a + int.from_bytes(raw(0x4918f38)[1:], 'little', signed=True) == 0x4918f00, 'front-bound-before-read')
    require(int.from_bytes(raw(0x4918f3a)[-1:], 'little', signed=True) == -16, 'preceding-word-address')
    require(int.from_bytes(raw(0x4918f3f)[-1:], 'little', signed=True) == -8, 'one-qword-progress')
    require(raw(0x4918f46)[0] == 0x72 and 0x4918f48 + int.from_bytes(raw(0x4918f46)[1:], 'little', signed=True) == 0x4918f30, 'unsigned-predecessor-gate')
    require(asm(0x4918f00) == 'mov r8,r14' and asm(0x4918f03) == 'mov QWORD PTR [r8],rdi', 'front-and-final-store')
    require(not any(a.split()[0].startswith('call') for _, a in rows.values()), 'no-calls-in-step-envelope')
    require(asm(0x4918f0d) == 'cmp rsi,r12', 'left-compares-right-length')
    require(raw(0x4918f10)[0] == 0x74 and 0x4918f12 + int.from_bytes(raw(0x4918f10)[1:], 'little', signed=True) == 0x4918f4d, 'left-exit-inverted')
    require(raw(0x4918f09)[-1] == 8 and asm(0x4918f06) == 'inc rsi', 'left-byte-offset-plus16')
    require(asm(0x4918f4d) == 'lea rax,[r14+r12*8]', 'right-scratch-base-scale4')
    require(raw(0x4918f54)[0] == 0x73 and 0x4918f56 + int.from_bytes(raw(0x4918f54)[1:], 'little', signed=True) == 0x4918fbd, 'right-count-gate-JBE')
    require(int.from_bytes(raw(0x4918fbd)[-1:], 'little', signed=True) == -1, 'merge-back-index-n')
    require(asm(0x4918fe0) == 'mov r9,QWORD PTR [rax]' and asm(0x4918fe3) == 'mov r10,QWORD PTR [rsi]', 'first-front-read-widths')
    require(asm(0x4918fec) == 'cmp r9,r10' and asm(0x4918fef) == 'setae r11b' and asm(0x4918ff3) == 'setb r13b' and asm(0x4918ff7) == 'cmovb r10,r9', 'unsigned-front-tie-left')
    require(asm(0x4919014) == 'mov QWORD PTR [r15+rdi*8],r10', 'first-front-store-width')


def verify(binary, llvm, out):
    require(not out.exists(), 'choose a fresh output directory')
    data = binary.read_bytes()
    require(sha(data) == SHA, 'target SHA mismatch')
    frozen_raw = (HERE / 'J9-TRANSITION-FREEZE.json').read_bytes()
    require(sha(frozen_raw) == FREEZE, 'frozen native states changed')
    frozen = json.loads(frozen_raw)
    image = Image(data)
    secs = sections(data)
    _, frames = eh_frame_records(data, secs)
    functions = []
    for start, (end, digest) in BOUNDS.items():
        matches = [f for f in frames if f['start'] == start]
        require(len(matches) == 1 and matches[0]['end'] == end, 'FDE boundary')
        require(sha(image.read(start, end - start)) == digest, 'complete body identity')
        f = matches[0]
        functions.append(dict(start=hex(start), end=hex(end), body_sha256=digest,
                              fde=hex(f['fde']), fde_hex=image.record(f['fde']),
                              cie=hex(f['cie']), cie_hex=image.record(f['cie']),
                              lsda=None if f['lsda'] is None else hex(f['lsda'])))
    calls = []
    for site, target in [(0x4497acd, 0x4918d30), (0x4918d71, 0x4912a50), (0x4918d86, 0x4912a50)]:
        raw = image.read(site, 5)
        require(raw[0] == 0xe8 and site + 5 + struct.unpack('<i', raw[1:])[0] == target, 'direct call binding')
        calls.append(dict(site=hex(site), target=hex(target), bytes=raw.hex()))
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    slots = [struct.unpack_from('<QQq', data, pos) for pos in range(rela['offset'], rela['offset'] + rela['size'], 24)]
    require([entry for entry in slots if entry[0] == 0x57768a0] == [(0x57768a0, 8, 0x4497a90)], 'RELATIVE adapter binding')
    dispatch = image.read(0x4dbd5d1, 6)
    require(dispatch[:2] == b'\xff\x15' and 0x4dbd5d7 + struct.unpack('<i', dispatch[2:])[0] == 0x57768a0, 'core dispatch slot')
    rows, texts = decode(binary, image, llvm)
    properties(rows)
    controls = []
    with tempfile.TemporaryDirectory(prefix='first-insertion-native-') as name:
        path = Path(name) / 'inert-mutant.elf'
        for control in frozen['proposed_static_controls']:
            va, before, after = int(control['va'], 16), bytes.fromhex(control['before']), bytes.fromhex(control['after'])
            require(image.read(va, len(before)) == before, 'native control anchor')
            changed = bytearray(data)
            at = image.offset(va, len(before))
            changed[at:at + len(after)] = after
            path.write_bytes(changed)
            path.chmod(0o600)
            altered, _ = decode(path, Image(changed), llvm)
            try:
                properties(altered)
            except ValueError as error:
                require(str(error) == control['name'], 'wrong static rejection')
                controls.append(dict(name=control['name'], rejection=str(error), va=control['va'], before=control['before'], after=control['after']))
            else:
                raise ValueError('native property mutation accepted')
            path.unlink()
    out.mkdir(parents=True)
    for decoder, text in zip(('gnu', 'llvm'), texts):
        (out / f'j9-front.{decoder}.txt').write_text(text)
    report = dict(target_sha256=SHA, frozen_states_sha256=FREEZE, functions=functions, direct_calls=calls,
                  relative_slot=dict(call='0x4dbd5d1', call_bytes=dispatch.hex(), slot='0x57768a0', type=8, symbol=0, target='0x4497a90'),
                  envelope=dict(start=hex(LO), end=hex(HI), bytes=HI - LO, instructions=len(rows), sha256=sha(image.read(LO, HI - LO))),
                  native_controls=controls, below_identity_and_frozen_window_guards=True,
                  captured_execution=False, instruction_evaluation=False,
                  limits='Finite static operand/CFG checks, not target runtime or whole-sort equivalence. J9/front domains are separate and conditional as documented.',
                  tools=dict(gnu=subprocess.check_output(['objdump', '--version'], text=True).splitlines()[0], llvm=subprocess.check_output([llvm, '--version'], text=True).splitlines()[0]))
    (out / 'native-validation.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--llvm', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.binary, args.llvm, args.out)
    print('PASS: four exact FDE/body bindings, four helper edges, 280-byte native envelope and six static controls')
