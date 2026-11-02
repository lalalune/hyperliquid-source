"""Independent grammar/state mathematics for the greeting pre-code contract.

No native instructions, addresses, registers, emulation or target evaluator are
used. This file is frozen before the later production parser exists. Logical
maps use a flat Python dictionary and sorted unsigned-byte keys, not the native
B-tree or a future Rust implementation. Only active values are represented.
"""
from dataclasses import dataclass, field

MAX = (1 << 64) - 1


class Stop(Exception):
    def __init__(self, value):
        self.value = value


@dataclass
class State:
    data: bytes
    cursor: int = 0
    enabled: bool = False
    limit: int = 0
    charged: int = 0
    events: list = field(default_factory=list)

    @property
    def remaining(self):
        return len(self.data) - self.cursor

    def charge(self, amount):
        if not self.enabled:
            return
        old = self.charged
        total = old + amount
        self.events.append(('charge', old, amount, total))
        if total > MAX:
            raise Stop((2,))
        self.charged = total
        if total > self.limit:
            raise Stop((2,))

    def refund(self, amount):
        if self.enabled:
            if self.charged < amount:
                raise ValueError('proved reservation invariant violated')
            self.events.append(('refund', self.charged, amount))
            self.charged -= amount

    def integer(self, kind):
        """Closed marker relation; fast/slow effects are selected by old length."""
        width = 4 if kind == 'u32' else 8
        self.charge(width)
        n = self.remaining
        if n == 0:
            raise Stop((0, 1))
        marker = self.data[self.cursor]
        fast = n > width
        widths = {251: 2, 252: 4, 253: 8}
        payload = widths.get(marker)
        supported = marker <= 250 or payload is not None and (kind != 'u32' or payload <= 4)
        if not fast:
            self.cursor += 1
        if not supported:
            expected = 2 if kind == 'u32' or kind == 'u64' and fast else (3 if kind == 'u64' else 5)
            raise Stop((3, expected, {253: 3, 254: 4, 255: 12}[marker]))
        if marker <= 250:
            if fast:
                self.cursor += 1
            return marker
        if n < 1 + payload:
            raise Stop((0, 1 + payload - n))
        begin = self.cursor + (1 if fast else 0)
        value = sum(byte * 256**i for i, byte in enumerate(self.data[begin:begin+payload]))
        self.cursor = begin + payload
        return value

    def fixed(self, n):
        self.charge(n)
        if self.remaining < n:
            raise Stop((0, n - self.remaining))
        at = self.cursor; self.cursor += n
        return self.data[at:self.cursor]

    def vector(self):
        n = self.integer('u64')
        self.charge(n)
        if self.remaining < n:
            raise Stop((1,))
        at = self.cursor; self.cursor += n
        return self.data[at:self.cursor]

    def signature(self):
        limbs = []
        for _ in range(2):
            self.charge(32)
            for _ in range(4):
                self.refund(8)
                limbs.append(self.integer('u64'))
        byte = self.fixed(1)[0]
        return tuple(limbs), byte

    def mapping(self):
        n = self.integer('u64')
        if self.enabled:
            product = 96 * n
            self.events.append(('multiply', 96, n, product))
            if product > MAX:
                raise Stop((2,))
            self.charge(product)
        flat = {}
        # The finite byte span bounds successful iterations: every row uses at
        # least 29 bytes. A huge wire count therefore reaches a first read error.
        for _ in range(n):
            self.refund(96)
            key = self.fixed(20)
            flat[key] = self.signature()
        return tuple(sorted(flat.items()))

    def record(self):
        a = self.integer('usize')
        b = self.integer('usize')
        return a, b, self.fixed(2048)

    def greeting(self):
        outer = self.integer('u32')
        if outer > 5:
            raise Stop((5, 'AbciStreamGreeting', 0, 5, outer))
        if outer >= 2:
            return outer + 2,
        if outer == 1:
            return 3, tuple(self.integer('u64') for _ in range(3))
        vector = self.vector()
        scalar = self.integer('u64')
        inner = self.integer('u32')
        if inner > 2:
            raise Stop((5, 'GreetingHash', 0, 2, inner))
        if inner == 0:
            h = self.fixed(32)
            return 0, vector, scalar, h, self.mapping()
        if inner == 1:
            h = self.fixed(32)
            first = self.mapping()
            return 1, vector, scalar, h, first, self.mapping()
        return 2, vector, scalar, tuple(self.record() for _ in range(3))


def outcome(state):
    try:
        return state.greeting()
    except Stop as error:
        return 8, error.value


def integer_bytes(value, width):
    if not 0 <= value < 256**width:
        raise ValueError('fixed transport integer range')
    return value.to_bytes(width, 'little')


def validate_case(case):
    op = case.get('op', 0)
    enabled = case.get('enabled', False)
    if type(op) is not int or op not in (0, 1):
        raise ValueError('operation must be exactly integer 0 or 1')
    if not isinstance(enabled, (int, bool)) or enabled not in (0, 1):
        raise ValueError('canonical enabled tag must be exactly 0 or 1')
    if not isinstance(case['data'], bytes):
        raise ValueError('immutable wire bytes')
    for name in ('limit', 'charged', 'cursor'):
        value = case.get(name, 0)
        if type(value) is not int or not 0 <= value <= MAX:
            raise ValueError('u64 '+name)
    if len(case['data']) > (1 << 63) - 1:
        raise ValueError('native span domain')
    if op == 0 and case.get('cursor', 0) > len(case['data']):
        raise ValueError('cursor outside supplied span')


def encode_input(case):
    validate_case(case)
    data = case['data']; op = case.get('op', 0)
    b = bytearray(b'G94R' + bytes([op]))
    if op == 0:
        b.append(int(case.get('enabled', False)))
        for name in ['limit', 'charged', 'cursor']:
            b += integer_bytes(case.get(name, 0), 8)
    elif op == 1:
        b += integer_bytes(case.get('limit', 0), 8)
    else:
        raise ValueError('operation')
    b += integer_bytes(len(data), 4) + data
    return bytes(b)


def encode_value(value):
    tag = value[0]; b = bytearray([tag])
    def word(x):
        b.extend(integer_bytes(x, 8))
    def vector(data):
        b.extend(integer_bytes(len(data), 4)); b.extend(data)
    def mapping(items):
        b.extend(integer_bytes(len(items), 4))
        for key, (limbs, byte) in items:
            b.extend(key)
            for limb in limbs:
                word(limb)
            b.append(byte)
    if tag in (0, 1, 2):
        vector(value[1]); word(value[2])
        if tag <= 1:
            b.extend(value[3]); mapping(value[4])
            if tag == 1:
                mapping(value[5])
        else:
            for a, c, raw in value[3]:
                word(a); word(c); b.extend(raw)
    elif tag == 3:
        for x in value[1]:
            word(x)
    elif tag == 8:
        error = value[1]; b.append(error[0])
        if error[0] == 0:
            word(error[1])
        elif error[0] == 3:
            b.extend(error[1:])
        elif error[0] == 5:
            name = error[1].encode('ascii'); b.append(len(name)); b.extend(name)
            for x in error[2:]:
                b.extend(integer_bytes(x, 4))
        elif error[0] not in (1, 2):
            raise ValueError('active error kind')
    elif tag not in (4, 5, 6, 7):
        raise ValueError('active value tag')
    return bytes(b)


def expected(case):
    validate_case(case)
    op = case.get('op', 0)
    state = State(case['data'], case.get('cursor', 0) if op == 0 else 0,
                  bool(case.get('enabled', False)) if op == 0 else True,
                  case.get('limit', 0), case.get('charged', 0) if op == 0 else 0)
    if not 0 <= state.cursor <= len(state.data) <= (1 << 63) - 1 or not all(0 <= v <= MAX for v in (state.limit, state.charged)):
        raise ValueError('native-correspondence input domain')
    value = outcome(state)
    if op == 0:
        frame = b''.join(integer_bytes(x, 8) for x in (state.cursor, state.remaining, state.charged)) + encode_value(value)
    else:
        frame = encode_value(value) + (b'\0' if value[0] == 8 else b'\1' + integer_bytes(state.cursor, 8))
    return frame, state, value
