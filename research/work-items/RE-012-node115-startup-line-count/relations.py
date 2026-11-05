"""Manual static relations for the observed normal-memory branch.

These are explanatory projections, not a target differential oracle, emulator,
source reconstruction, or tests of the captured process. No commands are run.
"""
WHITE = frozenset([*range(9, 14), 32, 0x85, 0xa0, 0x1680, *range(0x2000, 0x200b),
                   0x2028, 0x2029, 0x202f, 0x205f, 0x3000])
MAX = (1 << 64) - 1


def decimal(token):
    """Return raw numeric code1/2, before the opaque error wrapper, or value."""
    if token in (b'', b'+', b'-'):
        return {'numericError': 1}
    if token.startswith(b'+'):
        token = token[1:]
    value = 0
    for byte in token:
        product = value * 10
        # The multiply's overflow branch still classifies this byte.
        if not 48 <= byte <= 57:
            return {'numericError': 1}
        if product > MAX:
            return {'numericError': 2}
        value = product + byte - 48
        if value > MAX:
            return {'numericError': 2}
    return {'value': value}


def output_relation(status_word, stdout):
    """Synthetic process-result boundary, not a fabricated Output struct ABI."""
    if status_word != 0:
        return {'boundaryError': 'command-status'}
    try:
        text = stdout.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return {'boundaryError': 'utf8'}
    begin = 0
    while begin < len(text) and ord(text[begin]) in WHITE:
        begin += 1
    end = begin
    while end < len(text) and ord(text[end]) not in WHITE:
        end += 1
    if begin == end:
        return {'boundaryError': 'no-token'}
    return decimal(text[begin:end].encode('utf-8'))


def quote(argument, reject_nul=True):
    """Projection of 5c67050's byte flags, with ordinary allocation assumed."""
    if not argument:
        return b"''"
    if reject_nul and b'\0' in argument:
        raise ValueError('argument NUL')
    low, high = 0x7ffe80000000000, 0x7fffffea7ffffff
    out = bytearray()
    while argument:
        flags = 2 if argument[0] == 94 else 7
        end = 1 if argument[0] == 94 else 0
        while end < len(argument):
            byte = argument[end]
            allowed = (byte < 64 and low >> byte & 1) or (64 <= byte < 128 and high >> (byte - 64) & 1)
            new = flags if allowed else flags & ~1
            if byte in b'!$`':
                new &= ~4
            if byte in b"'\\":
                new &= ~2
            if byte == 94:
                new &= ~6
            if not new:
                break
            flags, end = new, end + 1
        if not end:
            raise ValueError('zero segment: model assumption failed')
        part, argument = argument[:end], argument[end:]
        if flags & 1:
            out += part
        elif flags & 2:
            out += b"'" + part + b"'"
        elif flags & 4:
            out += b'"' + b''.join((b'\\' if b in b'"$\\`' else b'') + bytes([b]) for b in part) + b'"'
        else:
            raise ValueError('no quote mode')
    return bytes(out)


def command_relation(path):
    # 1541040 tests a trimmed view for emptiness but transforms the original.
    views = [b'wc', b'-l', path]
    kept = [s for s in views if any(ord(c) not in WHITE for c in s.decode('utf-8'))]
    return b' '.join(quote(s) for s in kept)
