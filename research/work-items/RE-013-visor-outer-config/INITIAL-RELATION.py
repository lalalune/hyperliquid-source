"""Proposed high-level grammar relation, checked against already frozen cases.

This is an abstract syntax parser. It neither loads nor evaluates captured
instructions, register states, jump tables or native branch state.
"""
from pathlib import Path
import collections, datetime, gzip, hashlib, json, re, sys
from json.decoder import scanstring

B = Path(__file__).resolve().parent
NAMES = {x['literal']: x['code'] for x in json.loads((B/'visor-config-name-map-intake.json').read_text(encoding='utf-8-sig'))['map']}
NUMBER = re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')
W = ' \t\r\n'
class Invalid(ValueError):
    pass

class Relation:
    def __init__(self, raw, default):
        self.s = raw.decode('utf-8', 'strict')
        self.i = 0
        self.default = default
        self.calls = 0

    def whitespace(self):
        while self.i < len(self.s) and self.s[self.i] in W:
            self.i += 1

    def peek(self):
        self.whitespace()
        return self.s[self.i:self.i+1]

    def take(self, token):
        self.whitespace()
        if not self.s.startswith(token, self.i):
            raise Invalid('Required syntax absent')
        self.i += len(token)

    def string(self, strict_unicode):
        self.take('"')
        try:
            value, self.i = scanstring(self.s, self.i, True)
        except ValueError as error:
            raise Invalid('Invalid quoted syntax') from error
        if strict_unicode and any(0xd800 <= ord(c) <= 0xdfff for c in value):
            raise Invalid('Unpaired surrogate in decoded string')
        return value

    def name_value(self):
        if self.peek() == '"':
            name = self.string(True)
        elif self.peek() == '{':
            self.take('{')
            name = self.string(True)
            self.take(':')
            self.take('null')
            self.take('}')
        else:
            raise Invalid('Not a name value')
        if name not in NAMES:
            raise Invalid('Unknown name')
        return NAMES[name]

    def ignored(self):
        # Work items are grammar nonterminals, with no numeric conversion or
        # Python recursion. Deep ignored syntax is bounded by ordinary memory.
        tasks = ['value']
        while tasks:
            task = tasks.pop()
            ch = self.peek()
            if task == 'value':
                if ch == '"':
                    self.string(False)
                elif ch == '[':
                    self.take('[')
                    tasks.append('array-first')
                elif ch == '{':
                    self.take('{')
                    tasks.append('object-first')
                elif ch and ch in '-0123456789':
                    match = NUMBER.match(self.s, self.i)
                    if match is None:
                        raise Invalid('Invalid number syntax')
                    self.i = match.end()
                else:
                    for literal in ['true', 'false', 'null']:
                        if self.s.startswith(literal, self.i):
                            self.i += len(literal)
                            break
                    else:
                        raise Invalid('Unknown discarded value')
            elif task == 'array-first':
                if ch == ']':
                    self.take(']')
                else:
                    tasks.extend(['array-tail', 'value'])
            elif task == 'array-tail':
                if ch == ']':
                    self.take(']')
                else:
                    self.take(',')
                    tasks.extend(['array-tail', 'value'])
            elif task in ['object-first', 'object-required']:
                if task == 'object-first' and ch == '}':
                    self.take('}')
                else:
                    self.string(False)
                    self.take(':')
                    tasks.extend(['object-tail', 'value'])
            elif task == 'object-tail':
                if ch == '}':
                    self.take('}')
                else:
                    self.take(',')
                    tasks.append('object-required')
            else:
                raise RuntimeError('Unknown abstract nonterminal')

    def default_value(self):
        self.calls += 1
        return self.default

    def outer(self):
        if self.peek() == '{':
            self.take('{')
            code = None
            if self.peek() != '}':
                while True:
                    key = self.string(True)
                    if key == 'aws_name' and code is not None:
                        raise Invalid('Duplicate recognized field')
                    self.take(':')
                    if key == 'aws_name':
                        code = self.name_value()
                    else:
                        self.ignored()
                    if self.peek() == '}':
                        break
                    self.take(',')
            if code is None:
                code = self.default_value()
            self.take('}')
        elif self.peek() == '[':
            self.take('[')
            code = self.default_value() if self.peek() == ']' else self.name_value()
            self.take(']')
        else:
            raise Invalid('Not an outer configuration')
        self.whitespace()
        if self.i != len(self.s):
            raise Invalid('Unread suffix')
        return code

def outcome(raw, default):
    parser = Relation(raw, default)
    try:
        return 0, parser.outer(), parser.calls
    except Invalid:
        return 1, None, parser.calls

def run(dest):
    meta = json.loads((B/'visor-outer-frozen-receipt-20261102T011254Z.json').read_bytes())
    corpus = B/'visor-outer-frozen-expectations-20261102T011254Z.tsv.gz'
    compressed = corpus.read_bytes()
    payload = gzip.decompress(compressed)
    if hashlib.sha256(compressed).hexdigest() != meta['compressedSha256'] or hashlib.sha256(payload).hexdigest() != meta['uncompressedSha256']:
        raise ValueError('Frozen expectation identity differs')
    count = 0
    h = hashlib.sha256()
    for line in payload.splitlines():
        raw_hex, default, tag, code, calls = line.decode('ascii').split('\t')
        expected = int(tag), None if code == '-' else int(code), int(calls)
        actual = outcome(bytes.fromhex(raw_hex), int(default))
        if actual != expected:
            raise ValueError('Proposed relation disagrees with frozen construction: '+str((bytes.fromhex(raw_hex), default, expected, actual)))
        h.update(line+b'\n')
        count += 1
    if count != meta['cases']:
        raise ValueError('Frozen count differs')
    result = {
        'state': 'abstract-outer-grammar-agreement-intake-unqualified',
        'targetSha256': meta['targetSha256'], 'frozenCases': count,
        'frozenUncompressedSha256': h.hexdigest(),
        'modelSourceSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'fullNativeBindingQualification': False,
        'capturedExecution': False, 'instructionEvaluation': False,
        'semanticQualification': False, 'newRecoveredByteCredit': 0,
        'limits': 'Agreement with independently frozen structured expectations supports this high-level relation only. Addressed native manual proof, full identity bindings and normal helper premises remain separate obligations. No runtime comparison or Rust claim.',
    }
    path = B/dest
    if path.exists():
        raise ValueError('Preserve earlier result')
    path.write_text(json.dumps(result, sort_keys=True, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    run(sys.argv[1])
