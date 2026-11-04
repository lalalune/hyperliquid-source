"""Interpret the node115 raw metadata gate; never execute a captured process."""
from pathlib import Path
import hashlib
import itertools
import json
import sys
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import decimal_scaled_u64 as cpu
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET = ROOT / 'artifacts/node/115/hl-node'
START, END = 0x57d2f80, 0x57d329b
ENTRY, OPEN, CLOSED = 0x57d3009, 0x57d303c, 0x57d3108
PACKET = Path(__file__).resolve().parent

def evaluate(image, new, cached):
    if not (len(new) == len(cached) == 3 and all(type(v) is int and 0 <= v < 2**32 for v in (*new, *cached))):
        raise ValueError('raw u32 triples required')
    m = cpu.Machine(image)
    m.set_reg(cpu.RAX, new[0])
    m.set_reg(cpu.RCX, new[2])  # established by MOV ECX,[RSP+0x14] at 0x57d2ffe
    m.set_reg(cpu.RBX, cpu.INPUT)
    m.set_reg(cpu.RSP, cpu.STACK)
    m.store(cpu.STACK, 4, new[2])
    m.store(cpu.STACK+4, 4, new[1])
    for k, word in enumerate(cached):
        m.store(cpu.INPUT+0x80+4*k, 4, word)
    m.pc = ENTRY
    for _ in range(24):
        if m.pc in (OPEN, CLOSED):
            return int(m.pc == OPEN), sorted(m.seen)
        if not ENTRY <= m.pc < OPEN:
            raise ValueError(f'gate escaped at {m.pc:#x}')
        m.step()
    raise ValueError('instruction budget exhausted')

def cases():
    triples = list(itertools.product([0, 1, 0x7fffffff, 0x80000000, 0xffffffff], repeat=3))
    for new in triples:
        for old in triples:
            yield new, old
    state = 0x115a01
    for _ in range(1024):
        values = []
        for _ in range(6):
            state = (1664525*state+1013904223) & 0xffffffff
            values.append(state)
        yield tuple(values[:3]), tuple(values[3:])

def authenticate(data):
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node115 identity mismatch')
    image = cpu.Image(data)
    if image.fde_of(START) != (START, END):
        raise ValueError('FDE changed')
    return image

def corpus(image):
    inputs, expected, visited = [], [], set()
    for new, old in cases():
        result, seen = evaluate(image, new, old)
        inputs.append('\t'.join(map(str, (*new, *old)))+'\n')
        expected.append(str(result)+'\n')
        visited.update(seen)
    return ''.join(inputs).encode(), ''.join(expected).encode(), visited

def verify():
    image = authenticate(TARGET.read_bytes())
    frozen = json.loads((PACKET/'FREEZE.json').read_text())
    inputs, expected, seen = corpus(image)
    if hashlib.sha256(inputs).hexdigest() != frozen['input_sha256'] or hashlib.sha256(expected).hexdigest() != frozen['expected_sha256']:
        raise ValueError('frozen comparison differs')
    if len(expected.splitlines()) != frozen['rows'] or sorted(seen) != frozen['visited_addresses']:
        raise ValueError('frozen denominator differs')
    return inputs, expected

if __name__ == '__main__':
    a, b = verify()
    print(json.dumps({'rows':len(b.splitlines()), 'input_sha256':hashlib.sha256(a).hexdigest(), 'expected_sha256':hashlib.sha256(b).hexdigest(), 'captured_process_executed':False}))
