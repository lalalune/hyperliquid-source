#!/usr/bin/env python3
"""Real-byte structural negative controls only.

This is not a machine, numerical model, oracle, or execution of a captured
program. A control changes static encoding/data fields and tests rejection.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import types


def require(ok, label):
    if not ok:
        raise ValueError(label)


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'regular input')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'stable input')
        return raw
    finally:
        os.close(fd)


def rejected(call, fragment):
    try:
        call()
    except ValueError as error:
        require(fragment in str(error), 'unexpected refusal: ' + str(error))
        return str(error)
    raise ValueError('negative control accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'root', 'evidence', 'scope', 'scope-sha', 'collector-sha',
                 'controls-sha', 'out'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    code = read_regular(here / 'collect.py')
    require(hashlib.sha256(code).hexdigest() == args.collector_sha, 'collector identity')
    module = types.ModuleType('reviewed_fee_static_collector')
    module.__file__ = str(here / 'collect.py')
    # Authenticated authored Python only; __name__ is not __main__.
    exec(compile(code, module.__file__, 'exec'), module.__dict__)
    scope = module.read_scope(args.scope, args.scope_sha)
    raw_controls = read_regular(here / 'controls.json')
    require(module.digest(raw_controls) == args.controls_sha, 'control definitions identity')
    controls = json.loads(raw_controls, object_pairs_hook=module.unique_object)
    data = read_regular(args.binary)
    module.authenticate(data, scope['target'], 'whole node115 identity')
    helpers = module.load_helpers(args.root, scope)
    baseline = module.inspect(data, scope, args.root, args.evidence, helpers)
    original_image = module.Image(data)
    before = module.facts(original_image, scope)
    results = []
    for label, wrong in [('front-door-truncated', data[:-1]),
                         ('front-door-wrong-magic', bytes([data[0] ^ 1]) + data[1:])]:
        message = rejected(lambda: module.authenticate(wrong, scope['target'], 'whole node115 identity'),
                           'whole node115 identity')
        results.append({'name': label, 'refusal': message, 'stage': 'public-input-identity'})
    for control in controls:
        offset = control['file_offset']
        old, new = bytes.fromhex(control['before']), bytes.fromhex(control['after'])
        require(len(old) == len(new) and old != new and data[offset:offset + len(old)] == old,
                'control edit does not match actual authenticated input')
        changed = data[:offset] + new + data[offset + len(old):]
        image = module.Image(changed)
        kind = control['kind']
        observation = None
        if kind == 'anchor':
            observed = module.facts(image, scope)
            name = control['anchor']
            require(observed[name] != before[name], 'control did not change extracted fact')
            require(observed[name] == control['changed_fact'], 'unexpected changed encoding fact')
            observation = {'before': before[name], 'after': observed[name]}
            message = rejected(lambda: module.check_facts(observed, scope), 'semantic pin: ')
        elif kind == 'data':
            pin = next(p for p in scope['data'] if p['name'] == control['data'])
            actual = image.raw(pin['va'], pin['bytes']).hex()
            require(actual != pin['hex'], 'data control had no effect')
            observation = {'before': pin['hex'], 'after': actual}
            message = rejected(lambda: require(actual == pin['hex'], 'selected data'), 'selected data')
        elif kind == 'relocation':
            observed = module.relocation_facts(image, scope)
            require(observed != scope['relocations'], 'RELA control had no effect')
            observation = [r for r in observed if r['offset'] == offset]
            message = rejected(lambda: module.check_relocations(observed, scope), 'selected relocation')
        elif kind == 'frame':
            # No full-input or complete-body hash is checked in this inner test.
            _, fdes = helpers['fde_extents'].eh_frame_records(changed)
            found = [f for f in fdes if f['start'] == control['start']]
            original = next(b['fde'] for b in baseline['bodies'] if b['start'] == control['start'])
            require(len(found) == 1 and found[0]['end'] != original['end'], 'FDE control did not change range')
            observation = {'before': original['end'], 'after': found[0]['end']}
            message = rejected(lambda: require(found[0]['end'] == original['end'], 'FDE extent'), 'FDE extent')
        elif kind == 'cie':
            message = rejected(lambda: helpers['fde_extents'].eh_frame_records(changed), 'augmentation')
            observation = {'before': old.hex(), 'after': new.hex()}
        else:
            raise ValueError('unknown control kind')
        results.append({'name': control['name'], 'stage': 'below-full-hash-gate',
                        'file_offset': offset, 'before': old.hex(), 'after': new.hex(),
                        'changed_observation': observation, 'refusal': message})
    # A retained GNU row is altered independently of target data and export SHA.
    pin = next(b for b in scope['bodies'] if b['start'] == 0x3876290)
    export = read_regular(Path(args.evidence) / pin['export']).decode('utf-8')
    code_bytes = original_image.raw(pin['start'], pin['end'] - pin['start'])
    original_line = next(line for line in export.splitlines() if line.lstrip().startswith('3876290:'))
    wrong_line = original_line.replace('55 ', '54 ', 1)
    require(wrong_line != original_line, 'GNU byte control target')
    wrong_export = export.replace(original_line, wrong_line, 1)
    message = rejected(lambda: helpers['foundation_millis'].decode_export(
        wrong_export, pin['start'], pin['end'], code_bytes), 'Disassembly bytes/extent changed')
    results.append({'name': 'retained-GNU-first-byte', 'stage': 'below-export-hash-gate', 'refusal': message})
    require(module.digest(read_regular(args.binary)) == scope['target']['sha256'], 'original target changed')
    result = {'stage': 'actual-static-controls-only', 'target': scope['target'],
              'scope_sha256': args.scope_sha, 'controls_sha256': args.controls_sha,
              'collector_sha256': args.collector_sha, 'controls': results,
              'control_count': len(results), 'body_count': len(scope['bodies']),
              'new_body_bytes': sum(b['end'] - b['start'] for b in scope['bodies'] if b['credit'] == 'new-v3'),
              'captured_execution': False, 'numerical_oracle_imported': False,
              'limits': scope['limits']}
    out = module.fresh_dir(args.out)
    (out / 'validation.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
