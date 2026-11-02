import itertools
import random

MODEL = 'restart_setting_static'
COMPONENT = 'node94-restart-settings'
OWNERS = [0x13ca000, 0x144b900]
MUTANTS = {
    'leading_dot_extension': ('dot > 0', 'dot != usize::MAX'),
    'case_sensitive_extension': ('eq_ignore_ascii_case(b"rmp")', 'eq(b"rmp")'),
    'binary_success_low_bit': ('parse_tag as u8 == 9', 'parse_tag & 1 == 0'),
    'text_success_full_word': ('parse_tag & 1 == 0', 'parse_tag == 0'),
    'wrong_read_sentinel': ('read_word == (1 << 63)', 'read_word == u64::MAX'),
    'invert_eligibility': ('!eligible ||', 'eligible ||'),
    'wrong_zero_wrapper': ('word == 0', 'word == 1'),
}


def corpus(data, model):
    model.build(data)
    inputs, expected = [], []
    names = [b'', b'.rmp', b'rmp', b'foo.rmpx', b'foo..rmp', b'foo.json', b'..', b'a.RMP', b'\x00.rmp', b'a.r\xffp']
    names += [b'x.' + bytes(c) for c in itertools.product(*[bytes([x, x-32]) for x in b'rmp'])]
    edges = [0, 1, 2, 8, 9, 255, 256, (1 << 63), (1 << 64)-1]
    def add(name, eligible, read, tag, payload):
        codec = model.component_codec(name)
        value = model.loader_value(codec, bool(eligible), read, tag, payload)
        # Independent byte-suffix classifier and normal-return truth table.
        dot = name.rfind(b'.')
        binary = dot > 0 and name[dot+1:].lower() == b'rmp'
        assert binary == (codec == 'rmp_candidate')
        success = (tag % 256 == 9) if binary else (tag % 2 == 0)
        oracle = payload if eligible and read != 1 << 63 and success else 0
        assert oracle == value
        inputs.append(f'{name.hex() or "-"} {eligible} {read} {tag} {payload}')
        expected.append(f'{int(binary)} {value} {model.page_count(value)}')
    for args in itertools.product(names, [0, 1], edges, edges, edges):add(*args)
    for name in [b'x.rmp', b'x.json']:
        for byte in range(256):
            for high in [0, 0x1234567800000000, 0xffffffffffffff00]:add(name,1,0,high|byte,byte)
    rng=random.Random(0x144b900)
    for _ in range(1000):add(rng.choice(names),rng.randrange(2),rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(64))
    return '\n'.join(inputs)+'\n',expected
