"""Deterministic supplied-value corpus authoring, not a native oracle.

Draft: do not run until parent admits execution after source/effects review and
actual reference qualification. Only stdlib plus the sibling mathematical
reference. Reads pinned manual JSON and own sources; writes a fresh directory.
No subprocess, network, native artifact, decoder or captured-code evaluator.
"""
import argparse
from collections import Counter
import hashlib
from itertools import combinations_with_replacement
import json
from pathlib import Path
import re

from reference_math import Found, Missing, Ring, Row, U64_MAX

MAX_RECORDS = 16384
MAX_INPUT_BYTES = 16777216
MAX_CAPACITY = 256
MAX_QUERIES = 32
PINS = {
    'handcases': '21b7bafc2a85c84879c32ef72dcb849f9e073dd06875cc636b0861aea8e843ad',
    'host_invalid': '5d45a4b2bc46db37c98b412f30df594c75d130d61f9564096bb8b874a95962cc',
    'manual_freeze': '8a935e4bf7f9d8e9e7d2c1415a9a61cf02b634d3bb3517c6fabd19fb001c91f7',
}
SOURCE_PINS = {
    'reference_math.py': 'ebeff5fc0d45f57547ef6b46faa463df90c3056cedeaa04802f780e1462b0a4b',
    'qualify_handcases.py': '368c757808e0438dddebf58eb4ea860451404269eaecedf0ddde72024e898cfb',
}
QUALIFICATION_SHA = 'cc4680b2c319ca6dd885de9b046271db361fd0d610375fe557fb75abf77fdb9e'
UNSET = object()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded_json(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True)+'\n').encode('ascii')


def key(number):
    return number.to_bytes(32, 'big')


def supplied_ring(capacity, head, keys, high_values=False):
    rows = [Row(bytes([255])*32, 0) for _ in range(capacity)]
    payloads = (1, U64_MAX, 1 << 63, 0x0102030405060708, 0x8000000000000001)
    for logical, value in enumerate(keys):
        physical = (head+logical) % capacity
        payload = payloads[physical % len(payloads)] if high_values else 0x1000+physical
        rows[physical] = Row(value, payload)
    return Ring(tuple(rows), head, len(keys))


def output_fields(operation, result):
    if operation == 'S':
        if isinstance(result, Found):
            return '\t'.join(['H', str(result.logical_index), str(result.physical_index), f'{result.value:016x}'])
        if isinstance(result, Missing):
            return 'N\t'+str(result.insertion_index)
        raise ValueError('invalid search result type')
    if result is None:
        return 'F'
    return 'V\t'+(','.join(f'{value:016x}' for value in result) if result else '-')


class Corpus:
    def __init__(self):
        self.input_lines = []
        self.expected_lines = []
        self.metadata = []
        self.aliases = []
        self.identifiers = set()
        self.by_input = {}
        self.requested = Counter()
        self.retained = Counter()
        self.input_bytes = 0

    def add(self, identifier, family, operation, ring, queries, literal=UNSET, origin=None):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', identifier) or identifier in self.identifiers:
            raise ValueError('invalid or repeated candidate identifier: '+identifier)
        self.identifiers.add(identifier)
        queries = tuple(queries)
        if operation not in ('S','M') or (operation == 'S' and len(queries) != 1):
            raise ValueError('operation/query arity')
        if ring.capacity > MAX_CAPACITY or len(queries) > MAX_QUERIES:
            raise ValueError('driver per-row bounds exceeded')
        physical = ','.join(row.key.hex()+f'{row.value:016x}' for row in ring.physical_rows) or '-'
        query_text = ','.join(query.hex() for query in queries) or '-'
        body = '\t'.join([operation, str(ring.capacity), str(ring.head), str(ring.live_len), physical, query_text])
        actual = ring.search(queries[0]) if operation == 'S' else ring.materialize(queries)
        result_text = output_fields(operation, actual)
        provenance = 'reference-derived'
        if literal is not UNSET:
            literal_text = output_fields(operation, literal)
            if result_text != literal_text:
                raise ValueError('manual/reference mismatch at '+identifier)
            result_text = literal_text
            provenance = 'independent-literal-manual'
        self.requested[family] += 1
        if body in self.by_input:
            canonical_id, canonical_result = self.by_input[body]
            if canonical_result != result_text:
                raise ValueError('identical input has contradictory expectations')
            self.aliases.append({'candidate_id': identifier, 'canonical_id': canonical_id,
                                 'family': family, 'expected_provenance': provenance,
                                 'origin': origin})
            return
        line = (identifier+'\t'+body+'\n').encode('ascii')
        expected = (identifier+'\t'+result_text+'\n').encode('ascii')
        if len(self.input_lines)+1 > MAX_RECORDS or self.input_bytes+len(line) > MAX_INPUT_BYTES:
            raise ValueError('whole-invocation bound exceeded; no truncation is allowed')
        self.input_lines.append(line)
        self.expected_lines.append(expected)
        self.input_bytes += len(line)
        self.by_input[body] = (identifier, result_text)
        self.retained[family] += 1
        self.metadata.append({'id': identifier, 'family': family, 'operation': operation,
                              'capacity': ring.capacity, 'head': ring.head, 'live_len': ring.live_len,
                              'query_count': len(queries), 'expected_provenance': provenance,
                              'origin': origin, 'input_line_sha256': sha(line),
                              'expected_line_sha256': sha(expected)})


def manual_cases(corpus, document):
    keys = {name: bytes.fromhex(value) for name, value in document['key_catalogue'].items()}
    if len(document['cases']) != 24:
        raise ValueError('manual case count changed')
    for case in document['cases']:
        if case['capacity'] != len(case['physical_rows']):
            raise ValueError('manual physical allocation mismatch')
        rows = tuple(Row(keys[name], int(value)) for name, value in case['physical_rows'])
        ring = Ring(rows, case['head'], case['live_len'])
        queries = tuple(keys[name] for name in case['queries'])
        if len(queries) != len(case['searches']):
            raise ValueError('manual expected search count mismatch')
        for i, (query, expectation) in enumerate(zip(queries, case['searches'])):
            if expectation['tag'] == 0:
                literal = Found(expectation['logical_index'], expectation['physical_index'], int(expectation['value_u64']))
            elif expectation['tag'] == 1:
                literal = Missing(expectation['insertion_index'])
            else:
                raise ValueError('unknown manual result tag')
            corpus.add(f'{case["id"]}_S{i:02d}', 'manual', 'S', ring, (query,), literal,
                       {'manual_id': case['id'], 'search_ordinal': i})
        expected = case['materializer']['result']
        literal = None if expected is None else tuple(int(value) for value in expected)
        corpus.add(case['id']+'_M', 'manual', 'M', ring, queries, literal,
                   {'manual_id': case['id'], 'projection': 'materializer.result only'})


def exhaustive_small(corpus):
    alphabet = tuple(key(value) for value in (0x40,0x80,0xc0))
    queries = tuple(key(value) for value in (0,0x40,0x60,0x80,0xa0,0xc0,0xff))
    states = 0
    for capacity in range(7):
        for head in range(capacity) if capacity else (0,):
            for length in range(capacity+1):
                for ordinal, live in enumerate(combinations_with_replacement(alphabet, length)):
                    ring = supplied_ring(capacity, head, live)
                    stem = f's{capacity}_{head}_{length}_{ordinal:03d}'
                    states += 1
                    for i, query in enumerate(queries):
                        corpus.add(stem+f'_S{i}', 'small-search', 'S', ring, (query,))
                    hit = (live[0],live[-1],live[0],live[-1]) if live else ()
                    first = (queries[0],live[0]) if live else (queries[0],)
                    middle = (live[0],queries[0],live[-1]) if live else (queries[0],)
                    last = (live[0],live[-1],live[0],queries[-1]) if live else (queries[-1],)
                    for suffix, batch in [('empty',()),('hit',hit),('first',first),('middle',middle),('last',last)]:
                        corpus.add(stem+'_M_'+suffix, 'small-materialize', 'M', ring, batch)
    if states != 1009:
        raise ValueError('small exhaustive enumeration count')
    return states


def depth_boundaries(corpus):
    lengths = (7,8,9,15,16,17,31,32,33,63,64,65,127,128,129,255,256)
    for length in lengths:
        geometries = ((length,0),(length,1),(min(256,length+3),min(256,length+3)-2))
        for geometry, (capacity, head) in enumerate(geometries):
            patterns = (tuple(key(2*i+2) for i in range(length)),
                        tuple(key(2*(i//3)+2) for i in range(length)),
                        (key(0x80),)*length)
            for pattern, live in enumerate(patterns):
                ring = supplied_ring(capacity, head, live)
                seam_index = capacity-head if length > capacity-head else 0
                queries = (key(0),live[0],live[seam_index],live[length//2],key(0xffff))
                stem = f'd{length}_{geometry}_{pattern}'
                for i, query in enumerate(queries):
                    corpus.add(stem+f'_S{i}', 'depth-search', 'S', ring, (query,))
                batch = (live[-1],live[0],live[length//2],live[seam_index])*8
                corpus.add(stem+'_M_hit32', 'depth-materialize', 'M', ring, batch)
                corpus.add(stem+'_M_last32', 'depth-materialize', 'M', ring, batch[:31]+(key(0),))


def byte_comparisons(corpus):
    for position in range(32):
        def at(value):
            return bytes([0x55])*position+bytes([value])+bytes([0x55])*(31-position)
        live = tuple(at(value) for value in (0,1,0x7f,0x80,0x80,0xfe,0xff))
        queries = tuple(at(value) for value in (0,1,2,0x7f,0x80,0xfe,0xff))
        for head in (0,6,8):
            ring = supplied_ring(9, head, live, high_values=True)
            stem = f'b{position}_{head}'
            for i, query in enumerate(queries):
                corpus.add(stem+f'_S{i}', 'byte-search', 'S', ring, (query,))
            corpus.add(stem+'_M_hit32', 'byte-materialize', 'M', ring, (live[-1],live[0],live[3],live[1])*8)
            corpus.add(stem+'_M_middle', 'byte-materialize', 'M', ring, (live[-1],at(2),live[0]))
    live = tuple(sorted({number.to_bytes(32, order) for number in (1,256,65536,0x01020304)
                         for order in ('big','little')}))
    if len(live) != 8:
        raise ValueError('fixed endian key-family cardinality')
    for head in (0,3,9):
        ring = supplied_ring(10, head, live, high_values=True)
        stem = f'e{head}'
        for i, query in enumerate((key(0),)+live+(bytes([255])*32,)):
            corpus.add(stem+f'_S{i}', 'endian-search', 'S', ring, (query,))
        corpus.add(stem+'_M_hit32', 'endian-materialize', 'M', ring, (live[-1],live[0],live[4],live[1])*8)
        corpus.add(stem+'_M_middle', 'endian-materialize', 'M', ring, (live[-1],key(0),live[0]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in PINS:
        parser.add_argument('--'+name.replace('_','-'), type=Path, required=True)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output must be fresh')
    for name, expected in SOURCE_PINS.items():
        if sha((Path(__file__).parent/name).read_bytes()) != expected:
            parser.error('frozen source identity mismatch: '+name)
    qualification_bytes = args.qualification.read_bytes()
    if sha(qualification_bytes) != QUALIFICATION_SHA:
        parser.error('reference qualification identity mismatch')
    qualification = json.loads(qualification_bytes)
    if (qualification['result'] != 'PASS' or qualification['mismatches'] or
            qualification['source_sha256'] != SOURCE_PINS or
            qualification['cases'] != 24 or qualification['standalone_searches'] != 64 or
            qualification['materializer_values'] != 24 or qualification['host_refusal_examples'] != 7):
        parser.error('reference qualification result mismatch')
    inputs = {}
    for name, expected in PINS.items():
        content = getattr(args, name).read_bytes()
        if sha(content) != expected:
            parser.error(name+' identity mismatch')
        inputs[name] = content
    corpus = Corpus()
    manual_cases(corpus, json.loads(inputs['handcases']))
    states = exhaustive_small(corpus)
    depth_boundaries(corpus)
    byte_comparisons(corpus)
    if sum(corpus.requested.values()) != 14167:
        raise ValueError('specified requested-row count changed')
    files = {'inputs.tsv': b''.join(corpus.input_lines), 'expected.tsv': b''.join(corpus.expected_lines),
             'case-metadata.jsonl': b''.join((json.dumps(row,sort_keys=True)+'\n').encode('ascii') for row in corpus.metadata),
             'aliases.jsonl': b''.join((json.dumps(row,sort_keys=True)+'\n').encode('ascii') for row in corpus.aliases),
             'manual-handcases.json': inputs['handcases'],
             'manual-host-invalid.json': inputs['host_invalid'],
             'manual-freeze.json': inputs['manual_freeze'],
             'reference-qualification.json': qualification_bytes}
    coverage = {'schema':1, 'requested':sum(corpus.requested.values()), 'retained':len(corpus.input_lines),
                'dedup_aliases':len(corpus.aliases), 'requested_by_family':dict(corpus.requested),
                'retained_by_family':dict(corpus.retained), 'input_bytes':len(files['inputs.tsv']),
                'small_geometry_key_states':states, 'small_search_queries_per_state':7,
                'driver_limits':{'max_records':MAX_RECORDS,'max_bytes':MAX_INPUT_BYTES,
                                 'max_capacity':MAX_CAPACITY,'max_queries':MAX_QUERIES},
                'seed':'none: fixed enumeration, no PRNG',
                'limits':['Generated expectations are mathematical reference projections, not native observations.',
                          'Manual literal expectations retain independent provenance and exact original bytes.',
                          'Dedup aliases retain all requested-case provenance; no input is dropped for resource limits.',
                          'No native lifetime, allocator-failure, callback-count or whole-RPC equivalence claim.']}
    files['coverage.json'] = encoded_json(coverage)
    sources = {name:sha((Path(__file__).parent/name).read_bytes()) for name in
               ['reference_math.py','qualify_handcases.py','generate_corpus.py','GENERATOR-SPEC.md']}
    manifest = {'schema':1, 'source_sha256':sources, 'manual_input_sha256':PINS,
                'reference_qualification_sha256':QUALIFICATION_SHA,
                'outputs':{name:{'bytes':len(content),'sha256':sha(content)} for name,content in files.items()},
                'contract_sha256':'2919fdb8323d4826063e8ffc70c89286f6e11566c6b8f0f1f9cff4d9a9bc325d',
                'transport_sha256':'2838931cd554744a81bb88d58beefb7646db829b1a5d633007132c6816098e52'}
    files['manifest.json'] = encoded_json(manifest)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        with (args.output/name).open('xb') as handle:
            handle.write(content)
    print(json.dumps({'requested':coverage['requested'],'retained':coverage['retained'],
                      'input_bytes':coverage['input_bytes'],'aliases':coverage['dedup_aliases'],
                      'manifest_sha256':sha(files['manifest.json'])},sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
