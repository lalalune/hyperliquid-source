"""Complete transport comparison and source edits; no wire/native oracle.

Only the parent harness opens frozen expected frames. The separately compiled
client receives opaque identifiers and fixed input frames, never these values.
"""
import hashlib
import re
import struct


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Frame:
    def __init__(self, raw):
        self.raw, self.at = raw, 0

    def take(self, count):
        need(0 <= count <= len(self.raw) - self.at, 'short complete output')
        value = self.raw[self.at:self.at + count]
        self.at += count
        return value

    def byte(self):
        return self.take(1)[0]

    def count(self):
        return int.from_bytes(self.take(4), 'little')

    def mapping(self):
        count = self.count()
        need(count <= (len(self.raw) - self.at) // 85, 'map output span')
        previous = None
        for _ in range(count):
            key = self.take(20)
            need(previous is None or previous < key, 'map output key order/uniqueness')
            previous = key
            self.take(65)

    def value(self):
        tag = self.byte()
        need(tag <= 8, 'output tag')
        if tag in (0, 1, 2):
            self.take(self.count())
            self.take(8)
            if tag in (0, 1):
                self.take(32)
                self.mapping()
                if tag == 1:
                    self.mapping()
            else:
                self.take(3 * (16 + 2048))
        elif tag == 3:
            self.take(24)
        elif tag == 8:
            kind = self.byte()
            need(kind in (0, 1, 2, 3, 5), 'active native error kind')
            if kind == 0:
                self.take(8)
            elif kind == 3:
                self.take(2)
            elif kind == 5:
                name = self.take(self.byte())
                need(name and all(32 <= byte < 127 for byte in name), 'error name ASCII')
                self.take(12)
        return tag


def rows(raw, ids, operations):
    need(len(ids) == len(operations) and len(set(ids)) == len(ids), 'expected row metadata')
    need(raw.endswith(b'\n') and b'\r' not in raw, 'canonical output terminator')
    lines = raw[:-1].split(b'\n')
    need(len(lines) == len(ids), 'complete output row count')
    values = []
    for line, identifier, operation in zip(lines, ids, operations):
        fields = line.split(b'\t')
        need(len(fields) == 2 and fields[0] == identifier, 'exact ordered opaque identifier')
        need(re.fullmatch(rb'(?:[0-9a-f]{2})+', fields[1]) is not None, 'canonical output hex')
        frame = Frame(bytes.fromhex(fields[1].decode('ascii')))
        need(operation in (0, 1), 'input operation metadata')
        if operation == 0:
            frame.take(24)
        tag = frame.value()
        if operation == 1:
            option = frame.byte()
            need(option == (0 if tag == 8 else 1), 'caller consumed option shape')
            if option:
                frame.take(8)
        need(frame.at == len(frame.raw), 'trailing complete output')
        values.append(frame.raw)
    return values


def compare(actual, expected, ids, operations):
    left = rows(actual, ids, operations)
    right = rows(expected, ids, operations)
    different = [i for i, pair in enumerate(zip(left, right)) if pair[0] != pair[1]]
    return dict(equal=not different, rows=len(left), different_rows=len(different),
                first_different_ids=[ids[i].decode('ascii') for i in different[:12]],
                stdout_sha256=sha(actual), expected_sha256=sha(expected))


def comparator_controls(expected, ids, operations):
    lines = expected.splitlines(keepends=True)
    first_id, first_hex = lines[0][:-1].split(b'\t')
    failures = {
        'missing-row': b''.join(lines[:-1]),
        'extra-row': expected + lines[-1],
        'reordered-rows': b''.join([lines[1], lines[0], *lines[2:]]),
        'duplicate-id': lines[0] + lines[0] + b''.join(lines[2:]),
        'missing-lf': expected[:-1],
        'crlf': expected.replace(b'\n', b'\r\n'),
        'extra-column': lines[0][:-1] + b'\t0\n' + b''.join(lines[1:]),
        'odd-hex': first_id + b'\t' + first_hex[:-1] + b'\n' + b''.join(lines[1:]),
        'bad-hex': first_id + b'\tg' + first_hex[1:] + b'\n' + b''.join(lines[1:]),
        'partial-frame': first_id + b'\t00\n' + b''.join(lines[1:]),
        'trailing-frame': first_id + b'\t' + first_hex + b'00\n' + b''.join(lines[1:]),
    }
    controls = []
    for name, raw in failures.items():
        try:
            compare(raw, expected, ids, operations)
        except ValueError:
            controls.append(dict(name=name, outcome='rejected', stdout_sha256=sha(raw)))
        else:
            raise ValueError('comparator control accepted: ' + name)
    # Deliberately alter a complete active Reader state field, not its syntax.
    index = operations.index(0)
    identifier, encoded = lines[index][:-1].split(b'\t')
    changed = bytearray.fromhex(encoded.decode())
    changed[16] ^= 1
    altered = list(lines)
    altered[index] = identifier + b'\t' + changed.hex().encode() + b'\n'
    result = compare(b''.join(altered), expected, ids, operations)
    need(result['different_rows'] == 1, 'active field comparator control')
    controls.append(dict(name='complete-active-charge-difference', outcome='one-row-mismatch', **result))
    return controls


def mutate(original, definitions):
    names, results = set(), []
    for definition in definitions:
        name = definition['name']
        need(name not in names and re.fullmatch(r'[a-z0-9-]+', name), 'mutant identity')
        names.add(name)
        need(definition['original_sha256'] == sha(original.encode()), 'mutant original identity')
        changed = original
        for edit in definition['edits']:
            need(changed.count(edit['before']) == edit['count'], 'exact mutant coordinate: ' + name)
            changed = changed.replace(edit['before'], edit['after'])
        need(changed != original and sha(changed.encode()) == definition['mutated_sha256'], 'mutant changed identity')
        results.append((name, changed, definition))
    return results


def malformed_inputs():
    core = b'G94R\x00\x00' + struct.pack('<QQQI', 0, 0, 0, 1) + b'\x02'
    caller = b'G94R\x01' + struct.pack('<QI', 4, 1) + b'\x02'
    def line(frame, identifier=b'C000000'):
        return identifier + b'\t' + frame.hex().encode() + b'\n'
    short_size = bytearray(core)
    short_size[30:34] = struct.pack('<I', 2)
    cursor = bytearray(core)
    cursor[22:30] = struct.pack('<Q', 2)
    return {
        'short-magic': line(core[:3]),
        'wrong-magic': line(b'BAD!' + core[4:]),
        'operation-tag': line(core[:4] + b'\x02' + core[5:]),
        'enabled-tag': line(core[:5] + b'\x02' + core[6:]),
        'short-core-fields': line(core[:25]),
        'short-core-bytes': line(bytes(short_size)),
        'cursor-outside-input': line(bytes(cursor)),
        'trailing-core': line(core + b'\x00'),
        'short-caller-fields': line(caller[:10]),
        'short-caller-bytes': line(caller[:-1]),
        'trailing-caller': line(caller + b'\x00'),
        'odd-hex': b'C000000\t0\n',
        'uppercase-hex': b'C000000\tAB\n',
        'nonhex': b'C000000\tgg\n',
        'bad-id': line(core, b'case000'),
        'short-id': line(core, b'C00000'),
        'missing-tab': b'C000000\n',
        'extra-field': line(core)[:-1] + b'\t00\n',
        'missing-lf': line(core)[:-1],
        'crlf': line(core)[:-1] + b'\r\n',
        'invalid-utf8': b'C000000\t\xff\n',
        'duplicate-id': line(core) + line(caller),
        'malformed-after-valid': line(core) + b'C000001\tzz\n',
    }
