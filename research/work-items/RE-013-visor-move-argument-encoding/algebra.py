#!/usr/bin/env python3
"""Finite value-level certificates, not a target instruction evaluator.

Checks byte-set algebra, canonical UTF-8 digit equations, a declarative chunk
grammar and integer size bounds. No machine state, target calls or shell exists
in this program. Native-to-equation reasoning is manual in PROOF.md.
"""
import hashlib
import itertools
import json
from pathlib import Path
from collect import require, pins

SAFE = b'+-./0123456789:@ABCDEFGHIJKLMNOPQRSTUVWXYZ]_abcdefghijklmnopqrstuvwxyz'
WHITE = frozenset([*range(9, 14), 32, 0x85, 0xa0, 0x1680,
                  *range(0x2000, 0x200b), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000])
ESCAPE = frozenset(b'"$\\`')

def constants(p):
    def imm(label):
        return int.from_bytes(bytes.fromhex(p['instructions'][label]['hex'])[2:], 'little')
    return (imm('quote-raw-low'), imm('quote-raw-high'),
            imm('quote-not-double'), imm('quote-not-single'),
            imm('quote-double-escape-mask'))

def sets_from_bits(c):
    lo, hi, nd, ns, escape = c
    raw = {b for b in range(128) if ((lo if b < 64 else hi) >> (b % 64)) & 1}
    not_double = {b + 33 for b in range(64) if (nd >> b) & 1}
    not_single = {b + 33 for b in range(64) if (ns >> b) & 1}
    escaped = {b + 34 for b in range(63) if (escape >> b) & 1}
    return raw, not_single | {94}, not_double | {94}, escaped

def alphabet_mask(b):
    return (int(b in SAFE) | (2 if b not in b"'\\^" else 0)
            | (4 if b not in b'!$`^' else 0))

def white_from_table(scalar, table):
    if 9 <= scalar < 14 or scalar == 32:
        return True
    if scalar < 128:
        return False
    page = scalar // 256
    if page == 0:
        return bool(table[scalar % 256] & 1)
    if page == 0x20:
        return bool(table[scalar % 256] & 2)
    return scalar in (0x1680, 0x3000)

def scalar_digits(raw):
    # Positional equations on canonical encodings, not x86 operations.
    widths = {1: 7, 2: 5, 3: 4, 4: 3}
    value = raw[0] & ((1 << widths[len(raw)]) - 1)
    for byte in raw[1:]:
        value = value * 64 + (byte & 63)
    return value

def segments(raw):
    """Longest prefixes with nonempty mask intersection; leading ^ is special.

    This is a byte-string definition of Q, not execution of recovered code.
    """
    if not raw:
        return [(2, b'')]
    require(0 not in raw, 'NUL outside grammar domain')
    answer = []
    while raw:
        special = raw[0] == 94
        mask, length = (2, 1) if special else (7, 0)
        for b in raw[length:]:
            next_mask = mask & alphabet_mask(b)
            if not next_mask:
                break
            mask, length = next_mask, length + 1
        require(length > 0 and mask != 0, 'positive grammar segment')
        choice = mask & -mask
        answer.append((choice, raw[:length]))
        raw = raw[length:]
    return answer

def render(parts):
    answer = bytearray()
    for choice, word in parts:
        if choice == 1:
            answer.extend(word)
        elif choice == 2:
            answer.extend(b"'" + word + b"'")
        else:
            require(choice == 4, 'grammar choice')
            answer.extend(b'"')
            for b in word:
                if b in ESCAPE:
                    answer.extend(b'\\')
                answer.append(b)
            answer.extend(b'"')
    return bytes(answer)

def certificate(p=None):
    p = pins() if p is None else p
    raw, ns, nd, escaped = sets_from_bits(constants(p))
    require(raw == set(SAFE), 'raw alphabet')
    require(ns == set(b"'\\^"), 'single exclusions')
    require(nd == set(b'!$`^'), 'double exclusions')
    require(escaped == ESCAPE, 'double escaping')
    transitions = 0
    for b in range(256):
        bit_mask = int(b in raw) | (0 if b in ns else 2) | (0 if b in nd else 4)
        require(bit_mask == alphabet_mask(b), 'byte mask')
        require((bit_mask == 0) == (b == 94), 'sole initial conflict')
        for m in range(1, 8):
            nxt = m & bit_mask
            require(nxt == 0 or nxt & -nxt in (1, 2, 4), 'choice partition')
            require(nxt & ~m == 0, 'intersection shrinks')
            transitions += 1
    table = bytes.fromhex(p['data']['whitespace-table']['hex'])
    scalar_count, white_count = 0, 0
    digit_hash = hashlib.sha256()
    for cp in range(0x110000):
        if 0xd800 <= cp < 0xe000:
            continue
        enc = chr(cp).encode('utf-8')
        require(scalar_digits(enc) == cp, 'canonical scalar digits')
        require(white_from_table(cp, table) == (cp in WHITE), 'whitespace classification')
        if len(enc) > 1:
            require(all(128 <= b < 192 for b in enc[1:]), 'continuation domain')
            require(enc[0] >= 192, 'backward leading-byte domain')
        digit_hash.update(cp.to_bytes(4, 'little') + enc)
        scalar_count += 1
        white_count += cp in WHITE
    # Frozen handwritten examples distinguish omission from trimming, quoting
    # priority, original byte preservation, repeated caret and segmentation.
    examples = [
        (b'', b"''"), (b'mv', b'mv'), (b'a-b./_Z9', b'a-b./_Z9'),
        (b' a ', b"' a '"), (b'a b', b"'a b'"),
        (b"'", b'"\'"'), (b'\\', b'"\\\\"'),
        (b'^', b"'^'"), (b'^^', b"'^''^'"), (b'a^b', b"a'^b'"),
        (b'!$`', b"'!$`'"), (b'a"b', b'\'a"b\''),
        (b"a'b", b'"a\'b"'), (b"$'", b'\'$\'"\'"'),
        (b"'$", b'"\'"\'$\''), ('é'.encode(), "'é'".encode()),
        (b'a\nb', b"'a\nb'"), (b'2>&1', b"'2>&1'")]
    for source, expected in examples:
        require(render(segments(source)) == expected, 'handwritten grammar example:' + source.hex())
    # Finite representative words exercise every conflict category up to length 4.
    # A structural grammar property is checked, not a shell parser/argv property.
    basis = [b'a', b' ', b"'", b'"', b'\\', b'^', b'$', b'!', b'`', b'\xc3\xa9']
    words = 0
    for length in range(1, 5):
        for pieces in itertools.product(basis, repeat=length):
            source = b''.join(pieces)
            parts = segments(source)
            require(b''.join(w for _, w in parts) == source, 'grammar partition')
            require(all(len(w) > 0 for _, w in parts), 'grammar progress')
            require(len(render(parts)) <= 4 * len(source), 'grammar size bound')
            words += 1
    # Fixed move has 1..3 records; literal mv contributes 2 and separators <=2.
    nmax = (1 << 61) - 2
    require(4 * nmax + 4 == (1 << 63) - 4, 'aggregate signed bound')
    require(4 * (nmax + 1) + 4 == (1 << 63), 'outside bound can reach sign limit')
    # This is a sufficient bound, not a claim that every longer input fails.
    return {'byte_transitions': transitions, 'canonical_scalars': scalar_count,
            'whitespace_scalars': white_count, 'scalar_equation_sha256': digit_hash.hexdigest(),
            'handwritten_examples': len(examples), 'grammar_words': words,
            'raw_alphabet_hex': SAFE.hex(), 'maximum_combined_input': nmax,
            'maximum_join_bound': 4 * nmax + 4,
            'limits': 'Value-level finite/algebraic checks only; manual native binding and storage/callee premises remain required.'}

if __name__ == '__main__':
    print(json.dumps(certificate(), sort_keys=True))
