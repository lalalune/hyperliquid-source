"""Pure abstract branch/integer support, never captured instruction evaluation."""
from itertools import product
from survey import DATA, require
import json

TABLE = DATA['trim-table'][1]
WS = frozenset([*range(9, 14), 32, 0x85, 0xa0, 0x1680,
                *range(0x2000, 0x200b), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000])

def addressed_predicate(cp):
    if 9 <= cp < 14 or cp == 32:
        return True
    if cp < 0x80:
        return False
    page = cp >> 8
    if page == 0:
        return bool(TABLE[cp & 255] & 1)
    if page == 0x16:
        return cp == 0x1680
    if page == 0x20:
        return bool((TABLE[cp & 255] >> 1) & 1)
    if page == 0x30:
        return cp == 0x3000
    return False

def trim_offsets(text):
    # High-level code-point algorithm derived from the manual invariant.
    # It neither decodes nor evaluates captured instructions.
    first = 0
    while first < len(text) and addressed_predicate(ord(text[first])):
        first += 1
    if first == len(text):
        return 0, 0
    end = len(text)
    while end > first + 1 and addressed_predicate(ord(text[end - 1])):
        end -= 1
    start_byte = len(text[:first].encode('utf-8'))
    return start_byte, len(text[first:end].encode('utf-8'))

def declarative_offsets(text):
    retained = [i for i, c in enumerate(text) if ord(c) not in WS]
    if not retained:
        return 0, 0
    first, end = retained[0], retained[-1] + 1
    return len(text[:first].encode('utf-8')), len(text[first:end].encode('utf-8'))

def primary(marker, tag, value):
    if marker:
        return 0x21
    if tag == 0:
        return value
    return 0x21

def main():
    require(len(TABLE) == 256 and len(WS) == 25, 'Predicate inventory differs')
    scalars = 0
    for cp in range(0x110000):
        if 0xd800 <= cp <= 0xdfff:
            continue
        require(addressed_predicate(cp) == (cp in WS), 'Addressed predicate differs')
        scalars += 1
    alphabet = tuple(chr(c) for c in sorted(WS)) + ('a', '\0', '/', '\u200b', '\u001c', '\ufeff', '\U0001f642')
    words = 0
    for n in range(4):
        for letters in product(alphabet, repeat=n):
            text = ''.join(letters)
            require(trim_offsets(text) == declarative_offsets(text), 'Abstract slice offsets differ')
            words += 1
    primary_rows = 0
    for marker, tag, value in product((False, True), range(256), range(256)):
        expected = value if not marker and tag == 0 else 0x21
        require(primary(marker, tag, value) == expected, 'Primary branch table differs')
        primary_rows += 1
    default_rows = 0
    for marker, value in product((False, True), range(256)):
        actual = 'diagnostic' if marker or value == 0x4f else value
        expected = value if not marker and value != 0x4f else 'diagnostic'
        require(actual == expected, 'Default branch table differs')
        default_rows += 1
    fixtures = {'empty': ('', (0, 0)), 'all-ascii-space': (' \t\r\n', (0, 0)),
                'all-wide-space': ('\u2000\u3000', (0, 0)),
                'wide-prefix': ('\u2000a\u3000', (3, 1)),
                'embedded-space': (' a b ', (1, 3)),
                'nul-retained': (' \0 ', (1, 1)),
                'format-not-space': ('\ufeffa\u200b', (0, 7)),
                'astral-middle': ('\u3000\U0001f642\u3000', (3, 4))}
    for label, (text, expected) in fixtures.items():
        require(trim_offsets(text) == expected, 'Fixture differs: ' + label)
    # Distinguish fresh observations with synthetic byte strings, not OS paths.
    g1, g2 = b'/first', b'/second'
    require(g1 + b'/code/static_config' != g2 + b'/aws_name', 'Fresh prefix witness collapsed')
    witnesses = {
        'ascii-only-trim': trim_offsets('\u2000a') != (0, 4),
        'all-space-pointer-moves-to-end': trim_offsets(' ') != (1, 0),
        'nul-is-space': trim_offsets('\0') != (0, 0),
        'python-extra-control-whitespace': trim_offsets('\u001ca') == (0, 2),
        'low-page-uses-page20-table-bit': not addressed_predicate(0) and addressed_predicate(0x85),
        'conversion-0x21-is-error': not isinstance(0x21, str) and 0x21 != 0x4f,
        'every-primary-tag-is-success': primary(False, 1, 7) != 7,
        'primary-marker-keeps-parser-byte': primary(True, 0, 7) != 7,
        'inner-marker-returns-0x21': ('diagnostic' if True else 0x21) != 0x21,
        'fresh-prefix-equals-factory-prefix': g1 != g2,
    }
    require(all(witnesses.values()), 'False simplification witness missing')
    print(json.dumps({'scope': 'Pure abstract branch, code-point predicate and byte-offset support for the addressed manual proof; not a target comparator.',
        'unicodeScalars': scalars, 'whitespaceCodePoints': len(WS), 'finiteWords': words,
        'primaryRows': primary_rows, 'defaultRows': default_rows, 'offsetFixtures': len(fixtures),
        'falseSimplificationWitnesses': list(witnesses), 'capturedExecution': False,
        'instructionEvaluation': False}, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
