"""Offline retained-evidence replay. No compiler, target, emulator or socket runs."""
import argparse
import base64
import gzip
import importlib.util
import io
import json
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile

sys.dont_write_bytecode = True
PACKET = Path(__file__).absolute().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import accept4_source115 as static
spec = importlib.util.spec_from_file_location('accept4_compare', PACKET / 'compare_source.py')
comparison = importlib.util.module_from_spec(spec); spec.loader.exec_module(comparison)
need, sha = static.need, static.sha


def regular_path(root, path, directory=False):
    """Reject symlinks in the named entry and every parent inside the root."""
    relative = path.relative_to(root)
    current = root
    need(stat.S_ISDIR(current.lstat().st_mode), 'root must be a real directory')
    for index, part in enumerate(relative.parts):
        current = current / part
        mode = current.lstat().st_mode
        expected_directory = index + 1 < len(relative.parts) or directory
        need(stat.S_ISDIR(mode) if expected_directory else stat.S_ISREG(mode),
             'nonregular or symlink path: ' + str(current))


def check_inventory(root, packet, manifest):
    regular_path(root, packet, directory=True)
    prefix = packet.relative_to(root).as_posix() + '/'
    external = {'tools/accept4_source115.py', 'tests/test_accept4_source115.py'}
    need({name for name in manifest if not name.startswith(prefix)} == external,
         'only the two selected external analysis files')
    expected_files = {name[len(prefix):] for name in manifest if name.startswith(prefix)}
    expected_files.add('MANIFEST.sha256')
    files, directories = set(), set()
    for path in packet.rglob('*'):
        mode = path.lstat().st_mode
        relative = path.relative_to(packet).as_posix()
        if stat.S_ISDIR(mode):
            directories.add(relative)
        else:
            need(stat.S_ISREG(mode), 'unknown nonregular or symlink packet entry: ' + relative)
            files.add(relative)
    need(directories == {'comparison', 'overlap', 'static'}, 'closed packet directory inventory')
    need(files == expected_files, 'closed packet file inventory')
    for name in manifest:
        relative = Path(name)
        need(not relative.is_absolute() and '..' not in relative.parts and
             relative.as_posix() == name, 'canonical root-relative manifest path')
        regular_path(root, root / relative)


def object_controls(raw):
    obj = comparison.Object(raw)
    symbol_table = obj.sh[obj.names.index('.symtab')]
    symbols = obj.symbols(obj.names.index('.symtab'))
    index = next(i for i, s in enumerate(symbols) if s['name'].startswith('_ZN3mio3net3tcp8listener11TcpListener6accept17h'))
    symbol = symbols[index]; eh = obj.sh[obj.names.index('.eh_frame')]
    result = {}
    for name, at, replacement in [
        ('short_FUNC', symbol_table[4] + 24 * index + 16, struct.pack('<Q', symbol['size'] - 1)),
        ('not_FUNC', symbol_table[4] + 24 * index + 4, bytes([symbol['info'] & 0xf0])),
        ('wrong_ELF_machine', 18, b'\xb7\x00'),
        ('changed_CIE_encoding', eh[4] + 15, b'\x03'),
    ]:
        changed = bytearray(raw); changed[at:at + len(replacement)] = replacement
        try:
            comparison.source_body(bytes(changed))
        except ValueError:
            result[name] = True
        else:
            result[name] = False
    need(all(result.values()), 'actual source ELF corruption controls')
    return result


def registry_checks(expected):
    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    rows = [r for r in registry['windows'] if r['id'] == 'node115-mio-accept4']
    need(len(rows) == 1, 'one selected accept interval')
    row = rows[0]
    need(row['target'] == 'node115' and row['component'] == 'transport' and row['dependency'] == 'mio',
         'dependency-owned transport allocation')
    need((row['start'], row['end']) == (0x475b050, 0x475b154) and
         row['target_body_sha256'] == expected['target_body_sha256'], 'registry full target')
    prefix = 'research/work-items/RE-012-accept4-source-115/comparison/'
    need(row['comparison_mode'] == 'extent-mismatch' and row['source'] == {
        'path': prefix + 'candidate-body.bin', 'encoding': 'binary', 'offset': 0,
        'length': expected['source']['bytes'], 'body_sha256': expected['source']['sha256']}, 'registry full source')
    need(row['evidence'] == prefix + 'comparison.json', 'registry comparison evidence')
    for path in [row['source']['path'], row['evidence']]:
        need(sha((ROOT / path).read_bytes()) == registry['evidence_sha256'][path], 'registry evidence hash')
    return {'target_intervals': 1, 'source_candidates': 1, 'mode': 'extent-mismatch', 'aligned_byte_credit': 0}


def licensed_build_inputs(provenance, packet=PACKET):
    meta = provenance['licensed_inputs_archive']
    need(meta['path'] == 'licensed-build-inputs.json.gz', 'owned licensed input archive')
    raw = (packet / meta['path']).read_bytes()
    need(len(raw) == meta['bytes'] and sha(raw) == meta['sha256'], 'licensed archive identity')
    entries = json.loads(gzip.decompress(raw))['entries']; decoded = {}
    need(len(entries) == meta['entries'], 'licensed archive entry count')
    for name, entry in entries.items():
        data = base64.b64decode(entry['base64'], validate=True)
        need(len(data) == entry['bytes'] and sha(data) == entry['sha256'], 'licensed archive member')
        decoded[name] = data
    # Historical path strings identify archive records, never filesystem reads.
    for record in provenance['reused_file_bindings']:
        need(record['path'] in decoded and sha(decoded[record['path']]) == record['sha256'],
             'retained licensed source/build record')
    manifests = [data for name, data in decoded.items() if name.endswith('/source-manifest.json')]
    need(len(manifests) == 1, 'one original source file manifest')
    expected = json.loads(manifests[0]); actual = {}
    for name in ['mio-1.0.2.crate', 'libc-0.2.149.crate']:
        with tarfile.open(fileobj=io.BytesIO(decoded['downloads/' + name]), mode='r:gz') as archive:
            for member in archive.getmembers():
                need(member.isfile() or member.isdir(), 'no source archive link/special member')
                if member.isfile():
                    key = 'vendor/' + member.name
                    need(key not in actual, 'duplicate source archive member')
                    actual[key] = sha(archive.extractfile(member).read())
    need(actual == expected and len(actual) == meta['complete_official_crate_files_verified'],
         'complete official source archives reproduce original file manifest')
    return {'archive_entries': len(entries), 'complete_crate_files': len(actual),
            'retired_tree_files_read': 0}


def main(args):
    regular_path(ROOT, PACKET / 'MANIFEST.sha256')
    entries = [line.split('  ', 1) for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines()]
    need(all(len(row) == 2 and re.fullmatch('[0-9a-f]{64}', row[0]) for row in entries),
         'manifest entry format')
    manifest = {name: digest for digest, name in entries}
    need(len(manifest) == len(entries), 'manifest has no duplicate path')
    check_inventory(ROOT, PACKET, manifest)
    for name, digest in manifest.items():
        need(sha((ROOT / name).read_bytes()) == digest, 'manifest: ' + name)
    target = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    authority = json.loads((PACKET / 'static/records.json').read_text())
    need(static.inspect(target) == authority, 'fresh static regeneration')
    image = static.Image(target); decoder_checks = []
    for b in authority['bodies']:
        start, end = int(b['start'], 16), int(b['end'], 16)
        for decoder in ['gnu', 'llvm']:
            rows = []
            for line in (PACKET / 'static' / f'{start:x}.{decoder}.stdout').read_text().splitlines():
                m = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}(?:\s+|$))+)', line)
                if m:
                    rows.append((int(m[1], 16), bytes.fromhex(m[2])))
            at = start; data = bytearray()
            for va, raw in rows:
                need(va == at and va + len(raw) <= end, 'full decoder byte partition')
                data.extend(raw); at += len(raw)
            need(at == end and bytes(data) == image.read(start, end - start), 'all decoder bytes retained')
            decoder_checks.append({'start': hex(start), 'decoder': decoder, 'bytes': len(data)})
    audit = json.loads((PACKET / 'archive-audit.json').read_text())
    archive = (PACKET / audit['archive']).read_bytes()
    need(len(archive) == audit['bytes'] and sha(archive) == audit['sha256'], 'archive identity')
    entries = json.loads(gzip.decompress(archive))['entries']; decoded = {}
    for name, entry in entries.items():
        raw = base64.b64decode(entry['base64'], validate=True)
        need(len(raw) == entry['bytes'] and sha(raw) == entry['sha256'], 'archive member')
        decoded[name] = raw
    provenance = json.loads((PACKET / 'source-provenance.json').read_text())
    licensed = licensed_build_inputs(provenance)
    obj = decoded['source/initial-mio.o']
    need(obj == decoded['source/repeat-mio.o'] and sha(obj) == provenance['object_sha256'],
         'actual retained source object pair')
    body, observed = comparison.record(target, obj)
    expected = json.loads((PACKET / 'comparison/comparison.json').read_text())
    need(observed == expected and body == (PACKET / 'comparison/candidate-body.bin').read_bytes(),
         'whole source FUNC/FDE/relocation comparison')
    result = {'manifest_files': len(manifest), 'bodies': len(authority['bodies']),
              'static_bytes': sum(b['bytes'] for b in authority['bodies']),
              'primary_bytes': 260, 'context_bytes': 18170, 'decoder_checks': decoder_checks,
              'archive_entries': len(entries), 'source_elf_controls': object_controls(obj),
              'comparison': expected['comparison'], 'registration': registry_checks(expected),
              'new_native_build': False, 'reused_object_pair_identical': True,
              'licensed_build_inputs': licensed,
              'captured_execution': False, 'instruction_emulation': False}
    if args.out:
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    main(parser.parse_args())
