"""Audit every retained command stream, frozen fixture, native result and control."""
import base64
import gzip
import hashlib
import json
import re

import oracle


def check():
    packet = oracle.PACKET
    observed = packet/'observed'
    load = lambda path: json.loads(path.read_text())
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    frozen = load(packet/'frozen/ORACLE-FREEZE.json')
    result = load(observed/'results.json')
    commands = load(observed/'commands.json')
    require = oracle.require
    require(oracle.digest(packet/'oracle.py') == frozen['oracle_source_sha256'], 'Frozen oracle changed')
    for field, name in [('validator_sha256','validate.py'),
                        ('static_verifier_sha256','verify_static.py'),
                        ('oracle_freeze_sha256','frozen/ORACLE-FREEZE.json')]:
        require(oracle.digest(packet/name) == result[field], 'Changed '+name)
    source = oracle.ROOT/'src/node94-six-word-subtract-family'
    for name, value in result['source_sha256'].items():
        require(oracle.digest(source/name) == value, 'Changed source '+name)
    streams = {}
    archive = json.loads(gzip.decompress((observed/'raw-streams.json.gz').read_bytes()))
    for item in archive['streams']:
        key = item['label'], item['stream']
        if 'xor_base64' in item:
            delta = base64.b64decode(item['xor_base64'], validate=True)
            basis = streams[item['basis_label'],'stdout']
            require(len(delta) == len(basis), 'XOR width')
            raw = bytes(a^b for a,b in zip(delta,basis))
        else:
            raw = base64.b64decode(item['base64'], validate=True)
        require(key not in streams and len(raw) == item['bytes'] and sha(raw) == item['sha256'], 'Raw stream drift')
        streams[key] = raw
    wanted = set()
    for command in commands:
        require(command['returncode'] == command.get('expected_returncode',0), 'Command failed')
        if command['label'] == 'target-frames':
            continue
        for channel in ['stdout','stderr']:
            key = command['label'],channel
            wanted.add(key)
            require(sha(streams[key]) == command[channel+'_sha256'], 'Command binding')
    require(wanted == set(streams), 'Stream census')
    for i, body in enumerate(frozen['static_facts']['bodies']):
        label = f'body-{i}-disassembly'
        text = streams[label,'stdout'].decode()
        readable = '\n'.join(line.rstrip() for line in text.splitlines()).rstrip('\n')+'\n'
        require((packet/(label+'.gnu.txt')).read_text() == readable, 'Readable GNU export')
        # GNU can wrap one long instruction across physical lines. Concatenate
        # the complete displayed byte stream and compare its frozen body hash.
        raw = bytearray()
        cursor = body['start']
        for line in text.splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
            if match:
                address = int(match[1],16)
                fragment = bytes.fromhex(match[2])
                require(address == cursor, 'GNU byte coverage')
                raw.extend(fragment)
                cursor += len(fragment)
        require(cursor == body['end'] and sha(raw) == body['body_sha256'], 'Complete GNU bytes')
    truth = gzip.decompress((packet/'frozen/expected.bin.gz').read_bytes())
    inputs = gzip.decompress((packet/'frozen/inputs.bin.gz').read_bytes())
    require(sha(truth) == frozen['expected_sha256'] and sha(inputs) == frozen['inputs_sha256'], 'Frozen raw hashes')
    rows = [truth[i:i+oracle.OUTPUT_SIZE] for i in range(0,len(truth),oracle.OUTPUT_SIZE)]
    controls = {}
    for label, record in list(result['builds'].items()) + [('mutant-'+k,v) for k,v in result['compiled_controls'].items()]:
        actual = streams[label+'-run','stdout']
        require(len(actual) == len(truth) and sha(actual) == record['output_sha256'], 'Native width/hash')
        require(record['cases'] == len(rows) == result['coverage']['cases'], 'Case count')
        actual_rows = [actual[i:i+oracle.OUTPUT_SIZE] for i in range(0,len(actual),oracle.OUTPUT_SIZE)]
        changed = [i for i,(a,b) in enumerate(zip(actual_rows,rows)) if a != b]
        admitted = [i for i in changed if rows[i][:8] == (1).to_bytes(8,'little')]
        successful = [i for i in admitted if actual_rows[i][:8] == (1).to_bytes(8,'little')]
        require(len(changed) == record['mismatches'] and len(admitted) == record['admitted_mismatches'], 'Actual mismatch counts')
        for witness in record['first_mismatches']:
            i = witness['row_zero_based']
            require(i in changed and witness['input_hex'] == inputs[i*oracle.INPUT_SIZE:(i+1)*oracle.INPUT_SIZE].hex()
                    and witness['actual_hex'] == actual_rows[i].hex() and witness['expected_hex'] == rows[i].hex(), 'Native witness')
        if label.startswith('mutant-'):
            changed_source = (source/'lib.rs').read_text()
            for patch in record['source_change']:
                require(changed_source.count(patch['before']) == 1, 'Mutant patch uniqueness')
                changed_source = changed_source.replace(patch['before'],patch['after'])
            require(sha(changed_source.encode()) == record['source_sha256'], 'Actual mutant source binding')
            require(changed, 'Ineffective control')
            controls[label] = {'changed':len(changed),'admitted_changed':len(admitted),'successful_value_changes':len(successful),
                               'classification':'admitted value changes' if successful else ('rejects admitted domain' if admitted else 'new API refusal only')}
        else:
            require(not changed, 'Correct build mismatch')
    altered = bytearray(truth)
    altered[0] ^= 1
    actual = streams['opt3-build1-run','stdout']
    count = sum(actual[i:i+oracle.OUTPUT_SIZE] != altered[i:i+oracle.OUTPUT_SIZE] for i in range(0,len(truth),oracle.OUTPUT_SIZE))
    require(count == result['corrupted_expectation_mismatches'] == 1, 'Comparator control')
    require(not streams['driver-malformed','stdout'] and b'expected complete 536-byte input records' in streams['driver-malformed','stderr'], 'Malformed driver control')
    for level in [0,3]:
        a,b = (result['builds'][f'opt{level}-build{i}'] for i in [1,2])
        require(all(a[k] == b[k] for k in ['library_sha256','client_sha256','output_sha256']), 'Repeat build identity')
    return {'verified_streams':len(streams),'cases_per_run':len(rows),'native_runs':len(result['builds'])+len(controls),'controls':controls}


if __name__ == '__main__':
    print(json.dumps(check(),indent=2))
