#!/usr/bin/env python3
"""Static replay and operative binding/algebra controls; no captured execution."""
import argparse
import copy
import gzip
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

import collect
import arithmetic


def controls(image, pins, frames, observed):
    results = []
    def reject(name, function, expected, **coordinates):
        try:
            function()
        except ValueError as error:
            collect.require(expected in str(error), name+': wrong rejection '+str(error))
            results.append(dict(name=name, outcome='REJECTED', reason=str(error), **coordinates))
        else:
            raise ValueError(name+': incorrectly accepted')
    changed = bytearray(image.data)
    off = image.offset(0x44464f, 1)
    changed[off] ^= 1
    reject('full-identity-change', lambda: collect.admit_image(bytes(changed), pins), 'target identity',
           va='0x44464f', file_offset=off, scope='identity only')
    reject('truncated-identity', lambda: collect.admit_image(image.data[:-1], pins), 'target identity',
           scope='identity only')
    # These enter BELOW full-image and whole-body admission. Each actual anchor
    # independently rejects its changed byte; this is operand binding, not a
    # claim about the runtime behavior of a changed captured instruction.
    for va in (0x444649, 0x44464f, 0x443ed2, 0x443f00, 0x443f34, 0x443f6d,
               0x443f84, 0x44407c, 0x4458a2, 0x5b447b, 0x5b44c6):
        anchor = next(a for a in pins['anchors'] if int(a['va'], 16) == va)
        modified = bytearray(image.data)
        offset = image.offset(va, 1)
        modified[offset] ^= 1
        altered = collect.Image(bytes(modified))
        reject('operand-'+hex(va), lambda a=altered: collect.derive(a, pins, frames, False),
               'native operand anchor', va=hex(va), file_offset=offset,
               original=anchor['hex'], scope='below identity; anchor binding only')
    for va, name in ((0x7d692, 'prefix'), (0x7d823, 'flags'), (0x6e748, 'duration'), (0x7c7e4, 'maximum')):
        modified = bytearray(image.data)
        offset = image.offset(va, 1)
        modified[offset] ^= 1
        altered = collect.Image(bytes(modified))
        reject('literal-'+name, lambda a=altered: collect.derive(a, pins, frames, False),
               'literal binding', va=hex(va), file_offset=offset, scope='below identity; literal binding')
    for byte_offset, expected in ((4, 'FDE CIE pointer'), (8, 'FDE start'), (12, 'FDE extent')):
        p = copy.deepcopy(pins)
        body = p['bodies'][0]
        va = int(body['fde_va'], 16)
        modified = bytearray(image.data)
        offset = image.offset(va+byte_offset, 1)
        modified[offset] ^= 1
        altered = collect.Image(bytes(modified))
        body['fde_raw'] = altered.record(va).hex()
        reject('repinned-frame-'+str(byte_offset), lambda a=altered, q=p: collect.derive(a, q, frames, False),
               expected, va=hex(va+byte_offset), file_offset=offset,
               scope='raw FDE repinned; structural relation must reject')
    # Repin instruction bytes/anchors while leaving the claimed target fixed.
    p = copy.deepcopy(pins)
    modified = bytearray(image.data)
    site = 0x44460f
    offset = image.offset(site+1, 1)
    modified[offset] ^= 1
    altered = collect.Image(bytes(modified))
    for anchor in p['anchors']:
        anchor['hex'] = altered.at(int(anchor['va'], 16), len(bytes.fromhex(anchor['hex']))).hex()
    next(c for c in p['calls'] if int(c['site'], 16) == site)['raw'] = altered.at(site, 5).hex()
    reject('repinned-direct-call', lambda: collect.derive(altered, p, frames, False), 'actual direct-call target',
           va=hex(site+1), file_offset=offset, scope='raw instruction repinned; target relation')
    slot = 0x7e50c8
    rela = next(r for r in collect.relas(image) if r['destination'] == slot)
    modified = bytearray(image.data)
    struct.pack_into('<q', modified, rela['file_offset']+16, rela['addend']+1)
    reject('constructor-relocation', lambda: collect.derive(collect.Image(bytes(modified)), pins, frames, False),
           'call relocation binding', file_offset=rela['file_offset']+16, slot=hex(slot),
           scope='below identity; relocated helper binding')
    modified = bytearray(image.data)
    struct.pack_into('<Q', modified, rela['file_offset'], 0x444600)
    reject('relocation-overlaps-code', lambda: collect.derive(collect.Image(bytes(modified)), pins, frames, False),
           'relocation writer overlaps', file_offset=rela['file_offset'], scope='all-RELA protected-range check')
    # Import name comes from actual dynsym->dynstr, independent of a guessed ABI.
    dynsym, dynstr = image.sections['.dynsym'], image.sections['.dynstr']
    name_offset = struct.unpack('<I', image.file(dynsym[4]+135*24, 4))[0]
    modified = bytearray(image.data)
    modified[dynstr[4]+name_offset] ^= 1
    reject('actual-import-name', lambda: collect.derive(collect.Image(bytes(modified)), pins, frames, False),
           'actual undefined import symbol', file_offset=dynstr[4]+name_offset,
           scope='below identity; actual dynamic symbol binding')
    body = pins['bodies'][0]
    text = gzip.decompress((observed/(body['name']+'.gnu.txt.gz')).read_bytes()).decode()
    first = next(line for line in text.splitlines() if re.match(r'\s*66eb20:', line))
    reject('missing-native-row', lambda: collect.qualify_export(text.replace(first+'\n', '', 1), image, body, pins),
           'native row identity/tiling', scope='native partition control')
    p = copy.deepcopy(pins)
    p['calls'] = [c for c in p['calls'] if c['site'] != '0x66eb2d']
    reject('missing-import-call-inventory', lambda: collect.qualify_export(text, image, body, p),
           'complete retained call inventory', scope='native full-call inventory')
    # Execute only edited copies of our own mathematical certificate, never
    # native bytes or instructions. Exactly one formula site must change.
    source = (collect.HERE/'arithmetic.py').read_text()
    for name, old, new, reason in [
            ('seconds-reciprocal', '(86400, 0x1845c8a0ce512957, 77,', '(86400, 0x1845c8a0ce512956, 77,', 'whole-interval reciprocal'),
            ('cycle-reciprocal', '(146097, 0x396b06bd, 47,', '(146097, 0x396b06bd, 46,', 'whole-interval reciprocal'),
            ('365-estimate', '(c*0x6719f361)', '(c*0x6619f361)', '365 reciprocal finite domain'),
            ('borrow-correction', 'ordinal = t-prefix[estimate-1]+366', 'ordinal = t-prefix[estimate-1]+365', 'exact ordinal'),
            ('signed-year-correction', '+ int(y < 0)', '- int(y < 0)', 'signed 400 quotient'),
            ('fixed-duration', 't = second+60', 't = second+59', 'fixed60 carry')]:
        collect.require(source.count(old) == 1, 'exact algebra mutation coordinate')
        changed_source = source.replace(old, new, 1)
        namespace = {'__name__': 'algebra_mutant'}
        exec(compile(changed_source, '<algebra-mutant-'+name+'>', 'exec'), namespace)
        reject('algebra-'+name, lambda ns=namespace: ns['certificate'](image), reason,
               source_sha256=collect.sha(changed_source.encode()),
               scope='operative mathematical expression mutant; not a target evaluator')
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=collect.REPO)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--require-source-absent', action='store_true')
    args = parser.parse_args()
    collect.require(not args.scratch.exists() and not args.receipt.exists(), 'fresh output paths required')
    if args.require_source_absent:
        collect.require(not (args.repo/'src/visor-readiness-value').exists(), 'production source must be absent at pre-code gate')
    manifest = json.loads((collect.HERE/'MANIFEST.json').read_text())
    for entry in manifest['files']:
        raw = (collect.HERE/entry['path']).read_bytes()
        collect.require(len(raw) == entry['bytes'] and collect.sha(raw) == entry['sha256'], 'manifest entry differs: '+entry['path'])
    pins = json.loads((collect.HERE/'BASIS-PINS.json').read_text())
    image = collect.authenticate(args.repo, pins)
    args.scratch.mkdir(parents=True)
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    commands = []
    def run(argv):
        completed = subprocess.run(argv, cwd=args.repo, env=environment, capture_output=True, check=False, timeout=180)
        logical = [str(x).replace(str(args.repo), '<repo>').replace(str(args.scratch), '<scratch>') for x in argv]
        commands.append(dict(argv=logical, returncode=completed.returncode,
                             stdout=completed.stdout.decode(), stderr=completed.stderr.decode()))
        collect.require(completed.returncode == 0 and not completed.stderr, 'reproduction subprocess failed')
        return completed.stdout
    compared = []
    for tree in ('one', 'two'):
        run([sys.executable, '-B', str(collect.HERE/'collect.py'), '--repo', str(args.repo),
             '--out', str(args.scratch/('native-'+tree))])
        run([sys.executable, '-B', str(collect.HERE/'arithmetic.py'), '--repo', str(args.repo),
             '--out', str(args.scratch/('arithmetic-'+tree+'.json'))])
        run([sys.executable, '-B', str(collect.HERE/'corpus.py'), '--out', str(args.scratch/('corpus-'+tree))])
        pairs = [(collect.HERE/'observed', args.scratch/('native-'+tree)),
                 (collect.HERE/'corpus', args.scratch/('corpus-'+tree))]
        for baseline, fresh in pairs:
            expected = sorted(x.name for x in baseline.iterdir())
            collect.require(expected == sorted(x.name for x in fresh.iterdir()), 'exact regenerated output set')
            for name in expected:
                raw = (baseline/name).read_bytes()
                collect.require(raw == (fresh/name).read_bytes(), 'regenerated bytes differ: '+name)
                compared.append(dict(tree=tree, path=str((baseline/name).relative_to(collect.HERE)), sha256=collect.sha(raw)))
        raw = (collect.HERE/'arithmetic.json').read_bytes()
        collect.require(raw == (args.scratch/('arithmetic-'+tree+'.json')).read_bytes(), 'mathematical certificate differs')
        compared.append(dict(tree=tree, path='arithmetic.json', sha256=collect.sha(raw)))
    frames = run(['/opt/homebrew/opt/binutils/bin/readelf', '--debug-dump=frames', pins['target']['path']]).decode()
    # Full readelf stdout is large and already projected into all raw FDE/CIE
    # records. Keep its exact hash/length, not another duplicate full text dump.
    commands[-1]['stdout_sha256'] = collect.sha(frames.encode())
    commands[-1]['stdout_bytes'] = len(frames.encode())
    del commands[-1]['stdout']
    rejected = controls(image, pins, frames, collect.HERE/'observed')
    receipt = dict(status='PASS: pre-code static bindings, algebra and finite expected corpus only',
                   source_absence_required=args.require_source_absent,
                   production_source_exists=(args.repo/'src/visor-readiness-value').exists(),
                   manifest_sha256=collect.sha((collect.HERE/'MANIFEST.json').read_bytes()),
                   python=dict(version=sys.version, executable_sha256=collect.sha(Path(sys.executable).resolve().read_bytes())),
                   path_mapping='Commands replace actual checkout by <repo> and requested fresh scratch directory by <scratch>; no path normalization of evidence contents.',
                   commands=commands, regenerated=compared, controls=rejected,
                   limits='No captured execution, instruction evaluation, production Rust, native equivalence or whole-readiness claim.')
    collect.write_json(args.receipt, receipt)
    print(json.dumps(dict(status=receipt['status'], controls=len(rejected), regenerated=len(compared))))


if __name__ == '__main__':
    main()
