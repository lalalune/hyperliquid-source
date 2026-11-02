"""Replay scoped static, complete-symbol and retained-artifact qualification.

No compiler, captured instruction, socket or network service is executed here.
The separate build_sources.py recipe performs the licensed source rebuild.
"""
import argparse
import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import keepalive_source94 as static
spec = importlib.util.spec_from_file_location('keepalive_compare', PACKET / 'compare_sources.py')
comparison = importlib.util.module_from_spec(spec); spec.loader.exec_module(comparison)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def object_controls(raw):
    obj = comparison.Object(raw); tab = obj.sh[obj.names.index('.symtab')]
    symbols = obj.symbols(obj.names.index('.symtab'))
    index = next(i for i, s in enumerate(symbols) if s['name'].startswith('_ZN7socket23sys17set_tcp_keepalive17h'))
    symbol = symbols[index]
    tests = {}
    for label, at, replacement in [
        ('short_symbol', tab[4] + 24 * index + 16, struct.pack('<Q', symbol['size'] - 1)),
        ('not_function', tab[4] + 24 * index + 4, bytes([symbol['info'] & 0xf0])),
        ('wrong_machine', 18, b'\xb7\x00'),
    ]:
        changed = bytearray(raw); changed[at:at + len(replacement)] = replacement
        try:
            comparison.source_body(bytes(changed))
        except ValueError:
            tests[label] = True
        else:
            tests[label] = False
    need(all(tests.values()), 'actual ELF corruption control')
    return tests


def registry_checks(registry, expected, authority):
    rows = [r for r in registry['windows'] if r['id'].startswith('node94-socket2-keepalive-')]
    need(len(rows) == 2, 'two unique keepalive registry entries')
    need({r['start'] for r in rows} == set(static.CALLERS), 'registry target starts')
    for row in rows:
        start = row['start']
        body = next(b for b in authority['bodies'] if int(b['start'], 16) == start)
        need(row['id'] == f'node94-socket2-keepalive-{start:x}' and
             row['end'] == int(body['end'], 16) and
             row['target_body_sha256'] == body['sha256'], 'registry target bounds/hash')
        need(row['comparison_mode'] == 'extent-mismatch' and row['dependency'] == 'socket2'
             and row['component'] == 'transport' and row['target'] == 'node94'
             and row['version_assignment_proved'] is False, 'registry attribution/domain')
        alternatives = row['alternative_candidates']
        need(len(alternatives) == 2 and [a['source_version_candidate'] for a in alternatives]
             == ['0.4.10', '0.5.7'], 'both version alternatives retained')
        for alternate in alternatives:
            version = alternate['source_version_candidate']
            source = next(s for s in expected['sources'] if s['version_candidate'] == version)
            index = next(i for i, c in enumerate(expected['comparisons'])
                         if c['target_start'] == hex(start) and c['source_version_candidate'] == version)
            name = f'research/work-items/RE-012-keepalive-source-94/comparison/socket2-{version}-internal.bin'
            source_spec = {'path': name, 'encoding': 'binary', 'offset': 0,
                           'length': source['symbol']['size'], 'body_sha256': source['sha256']}
            need(alternate == {'source_version_candidate': version, 'canonical': version == '0.4.10',
                               'source': source_spec, 'object_sha256': source['object_sha256'],
                               'comparison_pointer': ['comparisons', index]}, 'registry alternative binding')
            need(sha((ROOT / name).read_bytes()) == source['sha256']
                 == registry['evidence_sha256'][name], 'registry source evidence hash')
        need(row['source'] == alternatives[0]['source'], 'one canonical source per target')
        evidence = 'research/work-items/RE-012-keepalive-source-94/comparison/comparison.json'
        need(row['evidence'] == evidence and sha((ROOT / evidence).read_bytes())
             == registry['evidence_sha256'][evidence], 'registry comparison evidence')
    return {'target_intervals': 2, 'alternative_comparisons': 4,
            'canonical_version_candidate': '0.4.10', 'version_assignment_proved': False,
            'comparison_mode': 'extent-mismatch', 'aligned_byte_credit': 0}


def main(args):
    manifest = json.loads((PACKET / 'manifest.json').read_text())
    for name, expected in manifest.items():
        need(sha((ROOT / name).read_bytes()) == expected, 'manifest: ' + name)
    raw = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    authority = json.loads((PACKET / 'static/records.json').read_text())
    need(static.inspect(raw) == authority, 'static record regeneration')
    im = static.Image(raw)
    decoder_checks = []
    for body in authority['bodies']:
        start, end = int(body['start'], 16), int(body['end'], 16)
        for decoder in ['gnu', 'llvm']:
            path = PACKET / 'static' / (f'{start:x}.{decoder}.stdout')
            rows = []
            for line in path.read_text().splitlines():
                m = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}(?:\s+|$))+)', line)
                if m:
                    rows.append((int(m[1], 16), bytes.fromhex(m[2])))
            pos = start; collected = bytearray()
            for va, data in rows:
                need(va == pos and va + len(data) <= end, 'raw decoder byte partition')
                collected += data; pos += len(data)
            need(pos == end and bytes(collected) == im.read(start, end - start), 'full decoder bytes')
            decoder_checks.append({'body': hex(start), 'decoder': decoder, 'bytes': len(collected)})
    audit = json.loads((PACKET / 'archive-audit.json').read_text())
    compressed = (PACKET / audit['archive']).read_bytes()
    need(sha(compressed) == audit['sha256'], 'archive hash')
    entries = json.loads(gzip.decompress(compressed))['entries']
    decoded = {}
    for name, entry in entries.items():
        data = base64.b64decode(entry['base64'], validate=True)
        need(len(data) == entry['bytes'] and sha(data) == entry['sha256'], 'archive entry: ' + name)
        decoded[name] = data
    expected = json.loads((PACKET / 'comparison/comparison.json').read_text())
    source_controls = {}; actual_comparisons = []
    for source in expected['sources']:
        version = source['version_candidate']
        object_raw = decoded[f'qualified/socket2-{version}/opt0/socket2.o']
        need(sha(object_raw) == source['object_sha256'], 'whole source object')
        body, result = comparison.source_body(object_raw)
        result.update({'version_candidate': version, 'object_sha256': sha(object_raw), 'optimization': 0})
        need(result == source, 'source symbol/FDE/relocation regeneration')
        source_controls[version] = object_controls(object_raw)
        for va in static.CALLERS:
            actual_comparisons.append({'target_start': hex(va), 'source_version_candidate': version,
                                       **comparison.compare(im.read(va, static.BODIES[va][0] - va), body)})
    need(actual_comparisons == expected['comparisons'], 'whole body comparisons')
    registration = registry_checks(json.loads((ROOT / 'research/byte-windows.json').read_text()), expected, authority)
    result = {'manifest_files': len(manifest), 'static_bodies': 4, 'static_bytes': 7516,
              'static_instructions': 1616, 'raw_decoder_byte_checks': decoder_checks,
              'archive_entries_verified': len(entries), 'source_elf_controls': source_controls,
              'unique_target_windows': 2, 'alternative_candidate_comparisons': 4,
              'raw_equal': 0, 'normalized_only': 0, 'unmatched': 4,
              'global_byte_registry_registration': registration,
              'captured_execution': False, 'instruction_emulation': False,
              'new_native_source_rebuild_in_this_replay': False}
    if args.out:
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    main(parser.parse_args())
