"""Freeze the established ASCII post-replacement protocol before Rust exists."""
import itertools
import random

MODEL = 'restart_token_filter'
COMPONENT = 'node94-restart-token'
OWNERS = [0x1438e90, 0x13df3c0, 0x13df5f0, 0x14b1090]
MUTANTS = {
    'retain_backup_flag': ('token == b"--backup-logs"', 'token == b"--backup-logX"'),
    'retain_empty_tokens': ('if token.is_empty() ||', 'if'),
    'miss_vertical_tab': ("b'\\t' | b'\\n' | 0x0b | 0x0c", "b'\\t' | b'\\n' | 0x0c"),
    'wrong_join_separator': ("output.push(b' ')", "output.push(b'\\t')"),
    'accept_non_ascii': ('!input.is_ascii()', 'false'),
}


def corpus(data, model):
    image = model.Image(data)
    mask = int.from_bytes(image.read(0x13df3f1, 8), 'little')
    separators = bytes(i for i in range(128) if i <= 32 and (mask >> i) & 1)
    removed = image.read(0x219582, 13)
    joiner = image.read(0x219581, image.read(0x1438f57, 1)[0])
    assert separators == b'\t\n\x0b\x0c\r ' and removed == b'--backup-logs' and joiner == b' '
    inputs, expected = [], []

    def add(raw):
        inputs.append(raw.hex() or '-')
        if not raw.isascii():
            expected.append('R')  # New safe API refusal, not native behavior.
            return
        tokens = raw.translate(bytes.maketrans(separators, b' ' * len(separators))).split(b' ')
        value = joiner.join(t for t in tokens if t and t != removed)
        assert value == model.normalize_ascii(image, raw)
        expected.append('O ' + (value.hex() or '-'))

    for raw in [b'', b'--backup-logs', b'--backup-logs --backup-logs', b'"--backup-logs"',
                b'"a b"', b"a\x00b", b'--backup-logs=x', b'x--backup-logs', b'LoopChild']:
        add(raw)
    for a, b in itertools.product(range(128), repeat=2):
        add(b'a' + bytes([a]) + removed + bytes([b]) + b'b')
    for index, byte in itertools.product(range(13), range(256)):
        add(removed[:index] + bytes([byte]) + removed[index + 1:])
    for byte in range(256):
        add(bytes([byte])); add(b' ' + bytes([byte]) + b' ')
    rng = random.Random(0x1438E90)
    alphabet = [b'a', b'bb', removed, b'--backup-logsX', b'"', b"'", b'\x00']
    for _ in range(1000):
        raw = b''.join(rng.choice(alphabet) + bytes([rng.choice(separators)])
                       for _ in range(rng.randrange(15)))
        add(raw)
    return '\n'.join(inputs) + '\n', expected
