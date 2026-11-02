#!/usr/bin/env python3
"""Static replay and evidence/math controls; no captured execution or evaluator.

Replay mechanics adapt independently authored MIT readiness-value verify.py;
SHA256 25c87b9359c12b711ede9ce057032a982091b84f5f31a880c41e385947e64f8a.
New controls and semantic domain are specific to this complete duration pair.
"""
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
    def reject(name, function, reason, **details):
        try:
            function()
        except ValueError as error:
            collect.require(reason in str(error), name+': wrong rejection '+str(error))
            results.append(dict(name=name, outcome='REJECTED', reason=str(error), **details))
        else:
            raise ValueError(name+': falsely accepted')
    changed = bytearray(image.data)
    changed[image.offset(0x33044f, 1)] ^= 1
    reject('changed-capture-identity', lambda: collect.admit_image(bytes(changed), pins), 'target identity', scope='identity only')
    reject('truncated-capture-identity', lambda: collect.admit_image(image.data[:-1], pins), 'target identity', scope='identity only')
    for fact in pins['facts']:
        va = int(fact['va'], 16)
        offset = image.offset(va, fact['bytes'])
        changed = bytearray(image.data)
        changed[offset] ^= 1
        altered = collect.Image(bytes(changed))
        measured = collect.facts(altered, pins)[fact['name']]
        collect.require(measured != fact['value'], 'actual fact mutation was not observed')
        reject('actual-field-'+fact['name'], lambda a=altered: collect.derive(a, pins, frames, False),
               'actual operand/data facts differ', va=hex(va), file_offset=offset,
               original_value=fact['value'], observed_changed_value=measured,
               scope='below image/body identity; actual field extraction and binding, not altered-native behavior')
    for va in (0x3303a5, 0x3304b5, 0x33052e, 0x330574, 0x7a6564, 0x330580):
        changed = bytearray(image.data); offset = image.offset(va, 1); changed[offset] ^= 1
        reject('branch-return-anchor-'+hex(va), lambda a=collect.Image(bytes(changed)): collect.derive(a, pins, frames, False),
               'native instruction anchor', va=hex(va), file_offset=offset, scope='below identity; raw instruction binding')
    for va in (0x6dd28, 0x6cf48):
        changed = bytearray(image.data); offset = image.offset(va, 1); changed[offset] ^= 1
        reject('full-vector-literal-'+hex(va), lambda a=collect.Image(bytes(changed)): collect.derive(a, pins, frames, False),
               'literal identity', va=hex(va), file_offset=offset, scope='below identity; complete16-byte read binding')
    for body_index in (0, 1):
        for relative, reason in [(4, 'FDE CIE pointer'), (8, 'FDE start'), (12, 'FDE extent'), (16, 'FDE augmentation')]:
            p = copy.deepcopy(pins); body = p['bodies'][body_index]; va = int(body['fde_va'], 16)
            changed = bytearray(image.data); offset = image.offset(va+relative, 1); changed[offset] ^= 1
            altered = collect.Image(bytes(changed)); body['fde_raw'] = altered.record(va).hex()
            reject('repinned-fde-'+str(body_index)+'-'+str(relative), lambda a=altered, q=p: collect.derive(a, q, frames, False),
                   reason, va=hex(va+relative), file_offset=offset, scope='repinned raw metadata; actual structural relation')
    p = copy.deepcopy(pins); va = int(p['bodies'][0]['cie_va'], 16)
    changed = bytearray(image.data); offset = image.offset(va+16, 1); changed[offset] ^= 1
    altered = collect.Image(bytes(changed))
    for b in p['bodies']:
        if int(b['cie_va'], 16) == va:
            b['cie_raw'] = altered.record(va).hex()
    reject('repinned-cie-encoding', lambda: collect.derive(altered, p, frames, False),
           'CIE signed-PC-relative encoding', va=hex(va+16), file_offset=offset, scope='CIE pointer encoding relation')
    baseline = collect.derive(image, pins, frames)
    entry = baseline['unwind_index']['selected'][0]
    va = int(entry['va'], 16)+4
    changed = bytearray(image.data); offset = image.offset(va, 1); changed[offset] ^= 1
    reject('unwind-index-fde-pointer', lambda a=collect.Image(bytes(changed)): collect.derive(a, pins, frames, False),
           'unwind index body/FDE binding', va=hex(va), file_offset=offset)
    for relative, reason in [(4, 'unwind index frame base'), (8, 'unwind index extent')]:
        va = image.sections['.eh_frame_hdr'][3]+relative
        changed = bytearray(image.data); offset = image.offset(va, 1); changed[offset] ^= 1
        reject('unwind-header-'+str(relative), lambda a=collect.Image(bytes(changed)): collect.derive(a, pins, frames, False),
               reason, va=hex(va), file_offset=offset)
    p = copy.deepcopy(pins); site = 0x330377
    changed = bytearray(image.data); offset = image.offset(site+2, 1); changed[offset] ^= 1
    altered = collect.Image(bytes(changed))
    next(a for a in p['anchors'] if int(a['va'], 16) == site)['raw'] = altered.at(site, 6).hex()
    next(c for c in p['calls'] if int(c['site'], 16) == site)['raw'] = altered.at(site, 6).hex()
    reject('repinned-helper-call-displacement', lambda: collect.derive(altered, p, frames, False),
           'RIP call displacement', va=hex(site+2), file_offset=offset, scope='repinned call bytes; decoded actual target relation')
    rela = next(r for r in collect.relas(image) if r['destination'] == 0x7e5450)
    changed = bytearray(image.data); struct.pack_into('<q', changed, rela['file_offset']+16, rela['addend']+1)
    reject('actual-helper-relocation', lambda a=collect.Image(bytes(changed)): collect.derive(a, pins, frames, False),
           'call target relocation', file_offset=rela['file_offset']+16, slot='0x7e5450')
    for name, destination in [('code', 0x330360), ('literal', 0x6cf40-7), ('unwind', int(pins['bodies'][0]['fde_va'], 16)-7)]:
        changed = bytearray(image.data); struct.pack_into('<Q', changed, rela['file_offset'], destination)
        reject('relocation-overlap-'+name, lambda a=collect.Image(bytes(changed)): collect.derive(a, pins, frames, False),
               'RELA writer overlaps protected range', file_offset=rela['file_offset'], destination=hex(destination),
               scope='all-RELA full8-byte write overlap, including left-edge overlap')
    changed = bytearray(image.data)
    shoff = struct.unpack_from('<Q', changed, 40)[0]
    shsize, shnum = struct.unpack_from('<HH', changed, 58)
    for index in range(shnum):
        if struct.unpack_from('<IIQQQQIIQQ', changed, shoff+index*shsize) == image.sections['.text']:
            offset = shoff+index*shsize+8
            struct.pack_into('<Q', changed, offset, image.sections['.text'][2] & ~4)
            break
    else:
        raise ValueError('actual text section header absent')
    reject('nonexecutable-code-section', lambda a=collect.Image(bytes(changed)): collect.derive(a, pins, frames, False),
           'executable PROGBITS section', file_offset=offset)
    body = pins['bodies'][0]
    text = gzip.decompress((observed/(body['name']+'.gnu.txt.gz')).read_bytes()).decode()
    first = next(line for line in text.splitlines() if re.match(r'\s*330360:', line))
    reject('missing-native-row', lambda: collect.qualify_export(text.replace(first+'\n', '', 1), image, body, pins),
           'native row identity/tiling')
    p = copy.deepcopy(pins); p['calls'] = [c for c in p['calls'] if c['site'] != '0x330377']
    reject('missing-helper-call-inventory', lambda: collect.qualify_export(text, image, body, p), 'complete selected call inventory')
    decoded = collect.qualify_export(text, image, body, pins)
    reject('vacuous-all-ret-cfg', lambda: collect.cfg([(a, raw, 'ret') for a, raw, asm in decoded]), 'unreachable decoded row')
    changed_rows = list(decoded); a, raw, asm = changed_rows[-1]; changed_rows[-1] = (a, raw, 'nop')
    reject('missing-terminal-ret-cfg', lambda: collect.cfg(changed_rows), 'CFG leaves admitted body')
    # Execute only changed versions of our own closed-form mathematics. This
    # never executes native instructions, registers, a PC or an emulator.
    source = (collect.HERE/'arithmetic.py').read_text()
    mutants = [
        ('tie-parity', 'quotient % 2 == 1', 'quotient % 2 == 0', 'split equations'),
        ('tiny-cutoff', 'or e < 992:', 'or e < 993:', 'split equations'),
        ('fraction-scale', '(m << (e-979))*1_000_000_000', '(m << (e-979))*999_999_999', 'split equations'),
        ('fraction-carry', 'return seconds+carry, nano', 'return seconds, nano', 'split equations'),
        ('integral-scale', 'return m << (e-1075), 0', 'return m << (e-1074), 0', 'split equations'),
        ('fallback-units', 'return seconds, microseconds*1000', 'return seconds, microseconds*999', 'split equations'),
        ('overflow-cut', 'if bits >= boundary:', 'if bits > boundary:', 'split equations'),
        ('reciprocal-shift', "64+f['microsecond-shift']", "65+f['microsecond-shift']", 'reachable reciprocal/remainder')]
    for name, old, new, reason in mutants:
        collect.require(source.count(old) == 1, 'unique mathematical mutation coordinate')
        changed = source.replace(old, new, 1); namespace = {'__name__': 'mathematical_mutant'}
        exec(compile(changed, '<mathematical-mutant-'+name+'>', 'exec'), namespace)
        reject('mathematical-'+name, lambda ns=namespace: ns['certificate'](image, pins), reason,
               changed_source_sha256=collect.sha(changed.encode()), scope='operative closed-form math mutant; no captured evaluation')
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
        collect.require(not (args.repo/'src/visor-duration-value').exists(), 'production source must be absent at pre-code gate')
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
                   production_source_exists=(args.repo/'src/visor-duration-value').exists(),
                   manifest_sha256=collect.sha((collect.HERE/'MANIFEST.json').read_bytes()),
                   python=dict(version=sys.version, executable_sha256=collect.sha(Path(sys.executable).resolve().read_bytes())),
                   path_mapping='Commands replace actual checkout by <repo> and requested fresh scratch directory by <scratch>; no path normalization of evidence contents.',
                   commands=commands, regenerated=compared, controls=rejected,
                   limits='No captured execution, instruction evaluation, production Rust, native equivalence or whole-Visor claim.')
    collect.write_json(args.receipt, receipt)
    print(json.dumps(dict(status=receipt['status'], controls=len(rejected), regenerated=len(compared))))


if __name__ == '__main__':
    main()
