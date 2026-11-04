"""Unexecuted independent RPC host-transport fixture draft.

Constructs fixed input bytes and manually specified status/stdout expectations.
No native/reference/Rust imports, child runner, network or executable decoder.
Run only after parent source/effects review; output directory must be fresh.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

TRANSPORT_SHA = '2838931cd554744a81bb88d58beefb7646db829b1a5d633007132c6816098e52'
K0 = '00'*32
K1 = '00'*31+'01'
K2 = '00'*31+'02'
KAB = '00'*31+'ab'
KFF = 'ff'*32
ZERO_ROW = K0+'0000000000000000'
AB_ROW = KAB+'00000000000000ab'
AB_VALUE = '00000000000000ab'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def line(identifier, operation, capacity, head, length, rows, queries):
    """Serialize literal supplied fields only; does not parse or calculate a lookup."""
    return ('\t'.join([identifier, operation, str(capacity), str(head), str(length), rows, queries])+'\n').encode('ascii')


def field(frame, index, replacement):
    fields = frame[:-1].split(b'\t')
    fields[index] = replacement.encode('ascii')
    return b'\t'.join(fields)+b'\n'


class Cases:
    def __init__(self):
        self.rows = []
        self.ids = set()

    def add(self, name, family, data, status, expected=b'', args=(), reason=''):
        need(re.fullmatch(r'[a-z0-9_-]+', name) is not None and name not in self.ids, 'control name')
        need(type(data) is bytes and type(expected) is bytes and status in (0,2), 'literal fixture types')
        need(status == 0 or expected == b'', 'refusal must have empty stdout')
        self.ids.add(name)
        self.rows.append({'id': name, 'family': family, 'input': data, 'expected': expected,
                          'expected_exit': status, 'arguments': list(args), 'reason': reason})

    def refuse(self, name, family, data, reason, args=()):
        self.add(name, family, data, 2, args=args, reason=reason)


def construct():
    cases = Cases()
    empty = line('p', 'M', 0, 0, 0, '-', '-')
    one = line('one', 'S', 1, 0, 1, AB_ROW, KAB)
    unused_one = line('unused1', 'M', 1, 0, 0, ZERO_ROW, '-')
    two_live = line('two', 'S', 2, 0, 2, K1+'0000000000000001,'+K2+'0000000000000002', K1)

    # Positive expectations are fixed by empty sequences or direct literal rows.
    cases.add('empty-materialization', 'positive', empty, 0, b'p\tV\t-\n', reason='Some(empty), one valid record')
    cases.add('empty-search', 'positive', line('es','S',0,0,0,'-',K0), 0, b'es\tN\t0\n', reason='Empty ring insertion0')
    cases.add('one-hit', 'positive', one, 0, b'one\tH\t0\t0\t00000000000000ab\n', reason='Literal singleton hit')
    id64 = 'A'*62+'_-'
    cases.add('id-64-boundary', 'positive', field(one,0,id64), 0,
              (id64+'\tH\t0\t0\t00000000000000ab\n').encode('ascii'), reason='64 allowed ID characters')
    cases.add('query-32-boundary', 'positive', line('q32','M',1,0,1,AB_ROW,','.join([KAB]*32)), 0,
              ('q32\tV\t'+','.join([AB_VALUE]*32)+'\n').encode('ascii'), reason='Exactly32 repeated supplied-key hits')
    ignored = KFF+'0000000000000000,'+AB_ROW+','+ZERO_ROW
    cases.add('unused-zero-and-order-allowed', 'positive', line('unused','S',3,1,1,ignored,KAB), 0,
              b'unused\tH\t0\t1\t00000000000000ab\n', reason='Inactive zero values and physical key disorder do not affect admission')
    wrapped = K2+'0000000000000002,'+K1+'0000000000000001'
    cases.add('logical-order-wrapped-allowed', 'positive', line('wrap','S',2,1,2,wrapped,K1), 0,
              b'wrap\tH\t0\t1\t0000000000000001\n', reason='Physical descending order has sorted live logical order')
    cases.add('capacity-256-boundary', 'positive', line('c256','M',256,255,0,','.join([ZERO_ROW]*256),'-'), 0,
              b'c256\tV\t-\n', reason='Exactly256 physical slots, valid final head, no live values')
    multi = (line('a','S',1,0,1,AB_ROW,KAB)+line('b','S',1,0,1,AB_ROW,K0)+
             line('c','M',1,0,1,AB_ROW,KAB+','+KAB)+line('d','M',1,0,1,AB_ROW,K0))
    cases.add('ordered-mixed-positive', 'positive', multi, 0,
              b'a\tH\t0\t0\t00000000000000ab\nb\tN\t0\nc\tV\t00000000000000ab,00000000000000ab\nd\tF\n',
              reason='Four literal results retain input order; missing lookup is a valid F value, not exit2')

    cases.refuse('empty-stream','framing',b'','At least one input record')
    cases.refuse('missing-final-lf','framing',empty[:-1],'Mandatory final LF')
    cases.refuse('crlf','framing',empty.replace(b'\n',b'\r\n'),'LF-only; CRLF explicitly rejected')
    cases.refuse('bare-cr','framing',empty[:-1]+b'\r','CR is not a line ending')
    cases.refuse('blank-first-row','framing',b'\n'+empty,'Empty rows forbidden')
    cases.refuse('blank-final-row','framing',empty+b'\n','Extra empty trailing row forbidden')
    cases.refuse('non-ascii-byte','framing',b'\xff'+empty,'Non-ASCII byte rejected, regardless of UTF-8 decoding')
    cases.refuse('utf8-non-ascii-id','framing',b'\xc3\xa9'+empty[1:],'Valid UTF-8 is still outside the ASCII protocol')
    cases.refuse('nul-in-id','framing',b'\x00'+empty,'ASCII NUL is not an allowed ID character')
    second = line('second','M',0,0,0,'-','-')
    for name, separator in [('vt',b'\x0b'),('ff',b'\x0c'),('fs',b'\x1c'),('gs',b'\x1d'),('rs',b'\x1e')]:
        cases.refuse('non-lf-'+name,'framing',empty[:-1]+separator+second,
                     'This ASCII control must not be promoted into a row separator')
    cases.refuse('six-fields','arity',b'\t'.join(empty[:-1].split(b'\t')[:-1])+b'\n','Exactly seven fields')
    cases.refuse('eight-fields','arity',empty[:-1]+b'\textra\n','Extra field forbidden')
    cases.refuse('empty-id','id',field(empty,0,''),'Nonempty ID required')
    cases.refuse('id-65','id',field(empty,0,'a'*65),'ID limit64')
    cases.refuse('id-dot','id',field(empty,0,'has.dot'),'Dot is outside alphanumeric/underscore/hyphen')
    cases.refuse('duplicate-id','id',empty+empty,'Duplicate IDs rejected before any output')

    # Each noncanonical numeric replacement has otherwise compatible fields.
    cases.refuse('capacity-leading-zero','canonical-number',field(unused_one,2,'01'),'Leading zero on nonzero decimal')
    cases.refuse('capacity-double-zero','canonical-number',field(empty,2,'00'),'Zero must be literal0')
    cases.refuse('head-leading-zero','canonical-number',field(unused_one,3,'00'),'Header head uses canonical decimal')
    cases.refuse('length-leading-zero','canonical-number',field(empty,4,'00'),'Live length uses canonical decimal')
    cases.refuse('number-leading-plus','canonical-number',field(empty,2,'+0'),'Leading plus forbidden even for zero')
    cases.refuse('number-leading-minus','canonical-number',field(empty,2,'-0'),'Signed zero forbidden')
    cases.refuse('number-leading-space','canonical-number',field(empty,3,' 0'),'No surrounding numeric whitespace')
    cases.refuse('number-trailing-space','canonical-number',field(empty,4,'0 '),'No surrounding numeric whitespace')
    cases.refuse('number-fraction','canonical-number',field(empty,4,'0.0'),'Decimal integers only')
    cases.refuse('number-exponent','canonical-number',field(empty,4,'0e0'),'Exponent syntax forbidden')
    cases.refuse('number-empty','canonical-number',field(empty,3,''),'Numeric field nonempty')
    cases.refuse('number-u64-plus-one','numeric-bound',field(empty,2,'18446744073709551616'),
                 'Large canonical number refused safely, not native overflow behavior')

    for name, index, value, reason in [
        ('row-upper-key',5,KAB.upper()+'00000000000000ab','Row key must use lowercase hex'),
        ('row-upper-value',5,KAB+'00000000000000AB','Value must use lowercase hex'),
        ('row-nonhex-key',5,'g'+AB_ROW[1:],'Row key hex alphabet'),
        ('row-nonhex-value',5,AB_ROW[:-1]+'g','Row value hex alphabet'),
        ('row-short',5,AB_ROW[:-1],'Row exactly80 characters'),
        ('row-long',5,AB_ROW+'0','Row exactly80 characters'),
        ('query-upper',6,KAB.upper(),'Query must use lowercase hex'),
        ('query-nonhex',6,KAB[:-1]+'g','Query hex alphabet'),
        ('query-short',6,KAB[:-1],'Query exactly64 characters'),
        ('query-long',6,KAB+'0','Query exactly64 characters'),
        ('query-empty-element',6,KAB+',','No empty query after comma'),
        ('row-empty-element',5,AB_ROW+',','No empty row after comma'),
    ]:
        cases.refuse(name,'hex-and-list',field(one,index,value),reason)
    cases.refuse('capacity-zero-with-row','row-count',field(empty,5,AB_ROW),'Capacity0 uses dash, not an allocated row')
    cases.refuse('capacity-one-with-dash','row-count',field(one,5,'-'),'Positive capacity requires physical rows')
    cases.refuse('missing-physical-slot','row-count',field(two_live,5,K1+'0000000000000001'),
                 'Record-loader capacity/row-count mismatch; not representable RingView state')
    cases.refuse('extra-physical-slot','row-count',field(one,5,AB_ROW+','+AB_ROW),'Exactly capacity records')
    cases.refuse('unknown-operation','operation',field(empty,1,'X'),'Only uppercase S/M admitted')
    cases.refuse('lowercase-operation','operation',field(empty,1,'m'),'Operation spelling is case-sensitive')
    cases.refuse('search-zero-query','operation',field(empty,1,'S'),'S requires exactly one query')
    cases.refuse('search-two-query','operation',field(one,6,KAB+','+KAB),'S does not accept two queries')
    cases.refuse('query-33','resource-query',line('q33','M',1,0,1,AB_ROW,','.join([KAB]*33)),'M query limit32')
    cases.refuse('capacity-257','resource-capacity',line('c257','M',257,0,0,','.join([ZERO_ROW]*257),'-'),
                 'Driver capacity limit256; logical empty view itself need not be natively invalid')
    cases.refuse('zero-capacity-head-one','ring-domain',field(empty,3,'1'),'Capacity0 requires head0')
    cases.refuse('zero-capacity-live-one','ring-domain',field(empty,4,'1'),'Live length cannot exceed capacity')
    cases.refuse('head-equals-capacity','ring-domain',field(one,3,'1'),'Positive capacity requires head strictly below capacity')
    cases.refuse('live-length-over-capacity','ring-domain',field(one,4,'2'),'Live length bound')
    cases.refuse('unsorted-live-contiguous','ring-domain',line('unsorted','S',2,0,2,wrapped,K1),
                 'Nondecreasing logical live keys required')
    cases.refuse('unsorted-live-wrapped','ring-domain',field(two_live,3,'1'),
                 'Logical wrap order, not physical storage order, governs admissibility')
    cases.refuse('zero-live-value','ring-domain',field(one,5,KAB+'0000000000000000'),
                 'A live opaque value cannot be zero; this is not a referenced count')

    cases.refuse('late-malformed-row-no-output','whole-input-validation',empty+field(second,0,''),
                 'A valid first row must not be printed before all later syntax is validated')
    cases.refuse('late-domain-error-no-output','whole-input-validation',empty+second+field(one,4,'2'),
                 'All host-domain checks must precede first output, not only syntax checks')
    cases.refuse('late-missing-lf-no-output','whole-input-validation',empty+second[:-1],
                 'Final-LF failure after a valid row still requires empty stdout')
    for name, arguments in [('unexpected-argument',('extra',)),('help-argument',('--help',)),('version-argument',('--version',))]:
        cases.refuse(name,'argv',empty,'The stdin-only client accepts no arguments',args=arguments)

    # Separate exact record-count boundary invocations, far below byte limit.
    records = [line(f'r{i:05d}','M',0,0,0,'-','-') for i in range(16385)]
    output = b''.join((f'r{i:05d}\tV\t-\n').encode('ascii') for i in range(16384))
    cases.add('records-16384-positive','resource-record-count',b''.join(records[:16384]),0,output,
              reason='Exactly16384 unique valid empty-materialization rows')
    cases.refuse('records-16385-refusal','resource-record-count',b''.join(records),
                 'Exactly16385 otherwise valid rows, well below raw-byte limit')

    # Exact byte boundary using valid zero-live rings, never padding garbage.
    full_rows = ','.join([ZERO_ROW]*256)
    prefix = b''.join(line(f'b{i:04d}','M',256,0,0,full_rows,'-') for i in range(808))
    tail_id = 'tail_'+'x'*29  # length34; final frame is7,984 bytes.
    tail_rows = ','.join([ZERO_ROW]*98)
    exact = prefix+line(tail_id,'M',98,0,0,tail_rows,'-')
    over = prefix+line(tail_id+'x','M',98,0,0,tail_rows,'-')
    need(len(exact)==16777216 and len(over)==16777217, 'exact raw-byte boundary construction')
    expected = b''.join((f'b{i:04d}\tV\t-\n').encode('ascii') for i in range(808))
    expected += (tail_id+'\tV\t-\n').encode('ascii')
    cases.add('bytes-16777216-positive','resource-byte-count',exact,0,expected,
              reason='Exactly16MiB,809 valid unique zero-live M rows; no garbage padding')
    cases.refuse('bytes-16777217-refusal','resource-byte-count',over,
                 'Exactly16MiB+1; only one extra valid ID character,809 otherwise valid rows')
    need(sum(len(c['input'])+len(c['expected']) for c in cases.rows)<40*1024*1024,'bounded fixture output volume')
    return cases.rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    need(not args.output.exists(),'output directory must be fresh')
    controls = construct()
    args.output.mkdir(parents=True,exist_ok=False)
    records = []
    for case in controls:
        input_name = case['id']+'.stdin'
        expected_name = case['id']+'.expected-stdout'
        for name, content in [(input_name,case['input']),(expected_name,case['expected'])]:
            with (args.output/name).open('xb') as handle:
                handle.write(content)
        records.append({k:v for k,v in case.items() if k not in ('input','expected')} |
                       {'stdin':{'path':input_name,'bytes':len(case['input']),'sha256':sha(case['input'])},
                        'expected_stdout':{'path':expected_name,'bytes':len(case['expected']),'sha256':sha(case['expected'])},
                        'stderr_policy':'record raw stderr, no content constraint',
                        'expectation_origin':'independently specified host transport policy and literal supplied values'})
    manifest = {'schema':1,'status':'INPUT_AND_EXPECTATION_DATA_ONLY_NOT_CLIENT_EXECUTION',
                'transport_sha256':TRANSPORT_SHA,
                'source_sha256':{name:sha((Path(__file__).parent/name).read_bytes()) for name in
                                 ['generate_controls.py','PLAN.md']},
                'cases':records,
                'limits':['No child process, source-built client, native target or reference is run.',
                          'Exit2/empty stdout applies to malformed input/arguments, not post-write I/O failure.',
                          'Resource-limit invocations are separate from smaller malformed cases.',
                          'No OOM, allocator failure, lifetime, Linux execution or native-error equivalence claim.']}
    encoded=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode('ascii')
    with (args.output/'cases.json').open('xb') as handle:
        handle.write(encoded)
    print(json.dumps({'fixture_cases':len(records),'fixture_input_bytes':sum(len(c['input']) for c in controls),
                      'cases_manifest_sha256':sha(encoded)},sort_keys=True))


if __name__ == '__main__':
    main()
