"""Strict complete-frame comparison and source-coordinate controls; MIT.

No target instruction evaluation. This parser validates transport shape and
canonical state ordering only; expected values come from the pre-source freeze.
"""
import hashlib
import re
import struct


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Reader:
    def __init__(self, raw):
        self.raw, self.at = raw, 0

    def take(self, count):
        end = self.at + count
        need(end <= len(self.raw), 'truncated output')
        value, self.at = self.raw[self.at:end], end
        return value

    def integer(self, width):
        return int.from_bytes(self.take(width), 'little')

    def ordered(self, count, read):
        previous = None
        for _ in range(count):
            key = read()
            need(previous is None or previous < key, 'noncanonical/duplicate output state key')
            previous = key

    def state(self):
        def user():
            key = self.take(20)
            self.take(16)
            def position():
                asset = self.integer(8)
                self.take(24)
                return asset
            self.ordered(self.integer(4), position)
            return key
        self.ordered(self.integer(4), user)
        self.ordered(self.integer(4), lambda: self.take(20))
        def auxiliary():
            asset = self.integer(8)
            self.take(8)
            return asset
        self.ordered(self.integer(4), auxiliary)
        self.ordered(self.integer(4), lambda: self.take(20))


def output_frame(raw):
    r = Reader(raw)
    need(r.integer(1) == 1, 'output version')
    kind = r.integer(1)
    if kind == 1:
        need(r.integer(1) in (0, 1), 'count result')
    else:
        need(kind == 0, 'output kind')
        status = r.integer(1)
        need(0 <= status <= 5, 'output status')
        if status == 0:
            r.take(8)
            winner = r.integer(1)
            need(winner in (0, 1), 'winner option')
            if winner:
                r.take(36)
            r.take(72 * r.integer(4))
        r.state()
    need(r.at == len(raw), 'trailing output bytes')


def compare(actual, expected, ids, domains=None):
    rows = actual.splitlines(keepends=True)
    expected_rows = expected.splitlines(keepends=True)
    need(len(rows) == len(ids) == len(expected_rows), 'full stream row count')
    for line, label in zip(rows, ids, strict=True):
        need(re.fullmatch(rb'C[0-9]{6}\t(?:[0-9a-f]{2})+\n', line) is not None, 'canonical output text')
        name, hex_value = line[:-1].split(b'\t')
        need(name == label, 'output ID/order')
        output_frame(bytes.fromhex(hex_value.decode('ascii')))
    differences = [i for i, pair in enumerate(zip(rows, expected_rows, strict=True)) if pair[0] != pair[1]]
    result = dict(equal=actual == expected, rows=len(rows), different_rows=len(differences),
                  first_different_rows=differences[:12], actual_sha256=sha(actual), expected_sha256=sha(expected))
    if domains is not None:
        need(len(domains) == len(rows) and set(domains) <= {'native_corresponding', 'safe_policy'}, 'case domains')
        result['different_rows_by_domain'] = {domain: sum(domains[i] == domain for i in differences)
                                              for domain in ['native_corresponding', 'safe_policy']}
    return result


def comparator_controls(expected, ids):
    rows = expected.splitlines(keepends=True)
    first_id, first_hex = rows[0][:-1].split(b'\t')
    frame = bytearray.fromhex(first_hex.decode())
    frame[3] ^= 1  # first empty success total; still a well-formed full frame
    changed = first_id + b'\t' + frame.hex().encode() + b'\n' + b''.join(rows[1:])
    cases = {'missing': b''.join(rows[:-1]), 'extra': expected + rows[0],
             'duplicate': rows[0] + rows[0] + b''.join(rows[2:]),
             'reorder': rows[1] + rows[0] + b''.join(rows[2:]),
             'changed-ID': b'C999999' + expected[7:], 'changed-value': changed,
             'short-frame': rows[0][:-3] + b'\n' + b''.join(rows[1:]),
             'trailing-frame-byte': rows[0][:-1] + b'00\n' + b''.join(rows[1:]),
             'missing-LF': expected[:-1], 'CRLF': expected.replace(b'\n', b'\r\n'), 'empty': b''}
    need(compare(expected, expected, ids)['equal'], 'positive comparator')
    results = {}
    for name, raw in cases.items():
        try:
            result = compare(raw, expected, ids)
        except ValueError as error:
            results[name] = dict(rejected=True, kind='protocol', message=str(error))
        else:
            need(not result['equal'], 'neutral comparator control')
            results[name] = dict(rejected=True, kind='value', different_rows=result['different_rows'])
    return results


def malformed_inputs():
    u32 = lambda x: struct.pack('<I', x)
    u64 = lambda x: struct.pack('<Q', x)
    address = bytes(19) + b'\1'
    prefix = b'\1\0' + u32(0)
    empty_state = u32(0) * 4
    valid = prefix + empty_state
    line = lambda raw: b'C000000\t' + raw.hex().encode() + b'\n'
    good = line(valid)
    user = address + bytes(16) + u32(0)
    position = u64(7) + bytes(24)
    binary = {'bad-version': b'\2' + valid[1:], 'bad-kind': b'\1\2' + valid[2:],
              'truncated-state': valid[:-1], 'trailing-byte': valid + b'\0',
              'short-counts': b'\1\1' + bytes(15),
              'selection-tag': b'\1\0' + u32(1) + address + bytes(8) + b'\2',
              'duplicate-users': prefix + u32(2) + user * 2 + u32(0) * 3,
              'duplicate-positions': prefix + u32(1) + address + bytes(16) + u32(2) + position * 2 + u32(0) * 3,
              'duplicate-aru': prefix + u32(0) + u32(2) + address * 2 + u32(0) * 2,
              'duplicate-auxiliary': prefix + u32(0) * 2 + u32(2) + (u64(7) + bytes(8)) * 2 + u32(0),
              'duplicate-membership': prefix + u32(0) * 3 + u32(2) + address * 2}
    result = {name: line(raw) for name, raw in binary.items()}
    result.update({'missing-LF': good[:-1], 'blank-line': b'\n', 'short-ID': good[1:],
                   'bad-ID': b'X' + good[1:], 'extra-ID-digit': b'C0' + good[1:],
                   'duplicate-ID': good + good, 'odd-hex': b'C000000\t0\n',
                   'uppercase-hex': b'C000000\tAF\n', 'nonhex': b'C000000\tgg\n',
                   'empty-hex': b'C000000\t\n', 'missing-tab': good.replace(b'\t', b' ', 1),
                   'extra-tab': good.replace(b'\t', b'\t\t', 1), 'CRLF': good[:-1] + b'\r\n',
                   'bad-after-valid': good + b'bad\n', 'invalid-UTF8': good + b'\xff\n'})
    return result


def mutate(original, definitions):
    result = []
    for definition in definitions:
        need(definition['expected_domain'] in ('native_corresponding', 'safe_policy_only'), 'mutation domain')
        changed = original
        for edit in definition['edits']:
            need(changed.count(edit['before']) == edit['count'], 'mutation coordinate: ' + definition['name'])
            changed = changed.replace(edit['before'], edit['after'])
        need(changed != original and sha(changed.encode()) == definition['source_sha256'], 'mutation source identity')
        result.append((definition['name'], changed, definition))
    return result
