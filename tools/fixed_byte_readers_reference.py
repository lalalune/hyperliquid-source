"""Authenticate unchanged pre-Rust wire expectations; do not restamp their origin."""
from pathlib import Path
from collections import Counter
import gzip, hashlib, json, re
import fixed_byte_readers_contract as native

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/'research/work-items/RE-005-fixed-byte-readers-94'
PREP = PACKET/'preparation'
FREEZE_SHA = 'e67df596434c9fcc71516be10d67542b5d21375e1051aa5a252742ca1a2df72d'
UNIT_SHA = 'ad011079b9d3f77412b5eb2b5eec415a240bdde10323932c8b8876e8a0a400ee'
UNIT_RECEIPT_SHA = '5ca04d4836949c2ae7c8c1d0542f8b71de3d9a56908cf916028a4935732986dd'
KEYS = ['additional','call','charged','consumed','cursor','id','kind','limit','mode','output','remaining','tail']

def need(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def exact(name, wanted):
    raw = (PREP/('independent-'+name)).read_bytes()
    need(sha(raw) == wanted, 'Independent sealed file differs: '+name)
    return raw

def inflated(name, wanted):
    with gzip.open(PREP/('independent-'+name+'.gz'), 'rb') as stream:
        raw = stream.read(wanted['bytes']+1)
    need(len(raw) == wanted['bytes'] and sha(raw) == wanted['sha256'],
         'Original decompressed authority bytes differ: '+name)
    return raw

def raw_stimuli(raw):
    need(raw.endswith(b'\n') and b'\r' not in raw, 'Raw input framing differs')
    parsed, seen, identifiers = [], set(), set()
    for line in raw.decode('ascii').splitlines():
        parts = line.split('|')
        need(len(parts) == 8, 'Eight raw input fields required')
        ident, width, mode, limit, charged, wire, output, calls = parts
        need(re.fullmatch(r'[A-Za-z0-9_-]+', ident) and ident not in identifiers,
             'Raw identifier differs/duplicates')
        need(width in ('20','32') and re.fullmatch(r'0|[1-9][0-9]*', mode), 'Raw width/mode differs')
        need(re.fullmatch(r'[0-9a-f]{16}', limit) and re.fullmatch(r'[0-9a-f]{16}', charged),
             'Full u64 hexadecimal inputs required')
        need(re.fullmatch(r'(?:[0-9a-f]{2})*', wire) and len(wire) <= 8192, 'Raw wire transport differs')
        n, m, b, c = int(width), int(mode), int(limit,16), int(charged,16)
        need(0 <= m < 2**32 and len(output) == 2*(n+1) and re.fullmatch(r'[0-9a-f]+', output),
             'Raw u32 mode/initialized result differs')
        need(calls in ('1','2','3','4'), 'Bounded raw call count differs')
        key = tuple(parts[1:])
        need(key not in seen, 'Complete raw stimulus duplicate')
        seen.add(key);identifiers.add(ident)
        parsed.append({'id':ident,'width':n,'mode':m,'limit':b,'charged':c,
                       'wire':bytes.fromhex(wire),'initial_output':bytes.fromhex(output),
                       'calls':int(calls),'line':line})
    need(len(parsed) == 50391, 'Frozen stimulus denominator differs')
    return parsed

def fresh(binary):
    freeze = json.loads(exact('FREEZE.json', FREEZE_SHA))
    need(freeze['author_clean'] and freeze['new_source_path_absent'] and
         freeze['author_head'] == '56c0ec672bd8fdcfaa80f2db700a61e6240b3663',
         'Historical pre-Rust origin differs')
    for name in ['generate.py','PROOF.md','NATIVE-REVIEW.json']:
        exact(name, freeze['files'][name]['sha256'])
    authority_raw = inflated('authority.json', freeze['files']['authority.json'])
    inputs = inflated('inputs.txt', freeze['files']['inputs.txt'])
    expected = inflated('expected.jsonl', freeze['files']['expected.jsonl'])
    authority = json.loads(authority_raw)
    need(authority['schema'] == 'fixed217-pre-rust-authority-v1' and
         authority['domain_proof_sha256'] == freeze['files']['PROOF.md']['sha256'] and
         authority['native_review_sha256'] == freeze['files']['NATIVE-REVIEW.json']['sha256'],
         'Independent authority/proof binding differs')
    stimuli = raw_stimuli(inputs)
    need(len(authority['cases']) == len(stimuli), 'Authority input denominator differs')
    for case, stimulus in zip(authority['cases'], stimuli):
        need(all(case[k] == stimulus[k] for k in ['id','width','mode','limit','charged','calls']) and
             bytes(case['wire']) == stimulus['wire'] and
             bytes(case['initial_output']) == stimulus['initial_output'],
             'Raw input is not the unchanged independent authority')
    rows = expected.splitlines()
    need(len(rows) == 122634 and expected.endswith(b'\n') and b'\r' not in expected,
         'Frozen observation framing/denominator differs')
    index, counts, per_id = 0, Counter(), {}
    for stimulus in stimuli:
        previous = 0; trace = []
        for call in range(1, stimulus['calls']+1):
            raw = rows[index]; row = json.loads(raw); index += 1
            need(list(row) == KEYS and raw == json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode(),
                 'Frozen observation is not canonical JSON')
            need(row['id'] == stimulus['id'] and row['call'] == call and
                 row['mode'] == stimulus['mode'] and row['limit'] == stimulus['limit'],
                 'Frozen observation identity/input differs')
            need(row['kind'] in ('value','end','charge') and type(row['charged']) is int and
                 0 <= row['charged'] < 2**64, 'Frozen logical result differs')
            need(type(row['consumed']) is int and row['consumed'] in (0,stimulus['width']) and
                 row['cursor'] == previous+row['consumed'] and
                 0 <= row['cursor'] <= len(stimulus['wire']), 'Frozen cursor relation differs')
            need(row['remaining'] == len(stimulus['wire'])-row['cursor'] and
                 row['tail'] == stimulus['wire'][row['cursor']:].hex(), 'Frozen full tail differs')
            need(type(row['output']) is str and len(row['output']) == 2*(stimulus['width']+1) and
                 re.fullmatch('[0-9a-f]+',row['output']), 'Frozen full initialized result differs')
            need((type(row['additional']) is int and 1 <= row['additional'] <= stimulus['width'])
                 if row['kind'] == 'end' else row['additional'] is None, 'Frozen active additional differs')
            trace.append(row);counts[row['kind']] += 1;previous = row['cursor']
        per_id[stimulus['id']] = trace
    need(dict(counts) == freeze['outcome_observations'] and index == len(rows), 'Frozen route counts differ')
    receipt_raw = (PREP/'UNIT-FIXTURE-RECEIPT.json').read_bytes()
    need(sha(receipt_raw) == UNIT_RECEIPT_SHA, 'Pre-source unit subset receipt differs')
    receipt = json.loads(receipt_raw)
    need(receipt['source_path_absent'] and not receipt['new_Rust_authored'], 'Unit subset chronology differs')
    unit = (ROOT/'src/node94-fixed-byte-readers/unit-vectors.tsv').read_bytes()
    need(sha(unit) == UNIT_SHA == receipt['fixture_sha256'], 'Pre-source unit cases differ')
    source_by_id = {s['id']:s for s in stimuli};selected = []
    for ident in receipt['selected_ids']:
        trace = per_id[ident]
        encoded = ';'.join(','.join([r['kind'],'-' if r['additional'] is None else str(r['additional']),
                                    str(r['charged']),str(r['consumed']),str(r['cursor']),str(r['remaining']),
                                    r['output'],r['tail']]) for r in trace)
        selected.append(source_by_id[ident]['line']+'|'+encoded)
    need(unit == ('\n'.join(selected)+'\n').encode() and len(selected) == 20 and
         sum(len(per_id[i]) for i in receipt['selected_ids']) == 50, 'Unit rows are not unchanged frozen expectations')
    native_record = native.analyze(Path(binary).read_bytes())
    return {'inputs':inputs,'expected':expected,'stimuli':stimuli,'native_record':native_record,
            'metadata':{'pre_rust_freeze_sha256':FREEZE_SHA,'stimuli':50391,'observations':122634,
                        'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),
                        'outcome_observations':dict(counts),'unit_stimuli':20,'unit_observations':50,
                        'original_origin_generator_executed':False,
                        'scope':'Unchanged pre-Rust expectations authenticated, not a newly invented post-source oracle.'}}
