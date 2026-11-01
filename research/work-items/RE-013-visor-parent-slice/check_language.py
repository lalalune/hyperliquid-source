"""Two abstract byte-language specifications, not a captured-instruction evaluator.

Supports the addressed manual native proof in PROOF.md. Agreement alone does
not prove that native code implements either abstract specification.
No host path or filesystem operations, target execution or target networking.
"""
import itertools
import json


def require(value, message):
    if not value:
        raise ValueError(message)


def utf8(value):
    try:
        value.decode('utf-8', errors='strict')
        return True
    except UnicodeDecodeError:
        return False


def protected(value, length, rooted):
    if rooted:
        return 1
    return int(value[:length] == b'.' or value[:length].startswith(b'./'))


def suffix(value, length, rooted):
    low = protected(value, length, rooted)
    require(length > low, 'Suffix step needs a nonempty unprotected interval')
    separator = value.rfind(b'/', low, length)
    start = separator + 1 if separator >= 0 else low
    tail = value[start:length]
    remaining = separator if separator >= 0 else low
    tag = 10 if tail in (b'', b'.') else 8 if tail == b'..' else 9
    require(0 < length - remaining <= length - low, 'Invalid consumption')
    return tag, remaining


def suffix_spec(value):
    rooted = value.startswith(b'/')
    length = len(value)
    while length > protected(value, length, rooted):
        tag, length = suffix(value, length, rooted)
        if tag != 10:
            break
    else:
        if rooted:
            return {'tag': 6, 'eligible': False, 'parent': None, 'selected': value}
        if protected(value, length, False):
            return {'tag': 7, 'eligible': True, 'parent': b'', 'selected': b''}
        return {'tag': 10, 'eligible': False, 'parent': None, 'selected': value}
    while length > protected(value, length, rooted):
        inspected, shortened = suffix(value, length, rooted)
        if inspected != 10:
            break
        length = shortened
    parent = value[:length]
    return {'tag': tag, 'eligible': True, 'parent': parent,
            'selected': parent if utf8(parent) else value}


def token_spec(value):
    # Independent formulation: locate semantic tokens, then retain the raw
    # prefix ending at the penultimate token. Interior bytes are never rebuilt.
    rooted = value.startswith(b'/')
    initial_dot = not rooted and (value == b'.' or value.startswith(b'./'))
    positions = []
    start = 0
    for end in range(len(value) + 1):
        if end == len(value) or value[end] == 47:
            token = value[start:end]
            if token not in (b'', b'.'):
                positions.append((start, end, token))
            start = end + 1
    if not positions:
        if rooted:
            return {'tag': 6, 'eligible': False, 'parent': None, 'selected': value}
        if initial_dot:
            return {'tag': 7, 'eligible': True, 'parent': b'', 'selected': b''}
        return {'tag': 10, 'eligible': False, 'parent': None, 'selected': value}
    tag = 8 if positions[-1][2] == b'..' else 9
    end = positions[-2][1] if len(positions) >= 2 else int(rooted or initial_dot)
    parent = value[:end]
    return {'tag': tag, 'eligible': True, 'parent': parent,
            'selected': parent if utf8(parent) else value}


FIXTURES = [
    (b'', 10, b''), (b'.', 7, b''), (b'./', 7, b''),
    (b'.//.', 7, b''), (b'/', 6, b'/'), (b'//', 6, b'//'),
    (b'/./', 6, b'/./'), (b'/./.', 6, b'/./.'),
    (b'foo', 9, b''), (b'foo/', 9, b''), (b'foo/.', 9, b''),
    (b'./foo', 9, b'.'), (b'./foo/.', 9, b'.'),
    (b'..', 8, b''), (b'../', 8, b''), (b'a/..', 8, b'a'),
    (b'/..', 8, b'/'), (b'/a', 9, b'/'), (b'/a/./b', 9, b'/a'),
    (b'a//b/c', 9, b'a//b'), (b'a/../b', 9, b'a/..'),
    (b'./a//./b', 9, b'./a'), (b'...', 9, b''),
    (b'a\\b', 9, b''), (b'C:\\a/b', 9, b'C:\\a'),
    (b'a\x00/b', 9, b'a\x00'), (b'a/\x80', 9, b'a'),
    (b'\x80/a', 9, b'\x80/a'), (b'\xc2\x80/a', 9, b'\xc2\x80'),
    (b'a/\xc2', 9, b'a'), (b'./\x80', 9, b'.'),
]


def main():
    for value, tag, selected in FIXTURES:
        a, b = suffix_spec(value), token_spec(value)
        require(a == b, 'Fixture specifications disagree: ' + value.hex())
        require(a['tag'] == tag and a['selected'] == selected,
                'Explicit expected fixture fails: ' + value.hex())
        if utf8(value) and a['eligible']:
            require(utf8(a['parent']), 'A valid UTF8 prefix should remain valid')
    count = 0
    valid_parent_lemmas = 0
    alphabet = (0, 46, 47, 92, 97, 128, 194)
    for length in range(7):
        for letters in itertools.product(alphabet, repeat=length):
            value = bytes(letters)
            a, b = suffix_spec(value), token_spec(value)
            require(a == b, 'Finite byte-language specifications disagree: ' + value.hex())
            if utf8(value) and a['eligible']:
                require(utf8(a['parent']), 'Finite UTF8-prefix lemma fails')
                valid_parent_lemmas += 1
            count += 1
    # Concrete witnesses distinguish false simplifications of the theorem.
    witnesses = [
        ('always-original', b'a/b', b'a/b'),
        ('collapse-interior-slashes', b'a//b/c', b'a/b'),
        ('cancel-dotdot', b'a/../b', b''),
        ('normalize-root-bypass', b'/./', b'/'),
        ('reject-empty-parent', b'foo', b'foo'),
        ('skip-validator-fallback', b'\x80/a', b'\x80'),
        ('treat-nul-as-invalid-utf8', b'a\x00/b', b'a\x00/b'),
    ]
    for name, value, false_result in witnesses:
        require(suffix_spec(value)['selected'] != false_result, 'Witness is vacuous: ' + name)
    print(json.dumps({'state': 'abstract-support-only-not-native-qualification',
                      'explicitFixtures': len(FIXTURES), 'finiteByteInputs': count,
                      'alphabetHex': bytes(alphabet).hex(), 'maximumLength': 6,
                      'utf8PrefixLemmaInstances': valid_parent_lemmas,
                      'falseSimplificationWitnesses': [w[0] for w in witnesses],
                      'capturedExecution': False, 'instructionEvaluation': False}, sort_keys=True))


if __name__ == '__main__':
    main()
