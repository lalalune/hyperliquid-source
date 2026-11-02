#!/usr/bin/env python3
"""Digest-bound static wrapper evidence; never evaluate captured instructions."""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
GNU = '/opt/homebrew/opt/binutils/bin/objdump'
LLVM = '/Library/Developer/CommandLineTools/usr/bin/llvm-objdump'
READELF = '/opt/homebrew/opt/binutils/bin/readelf'
DEPENDENCIES = {
    'tools/elf_index.py': 'd77a002e9b2d3dce86822f6c67169298ad0ea54f5f4cb5c0d244328cbed1774f',
    'tools/fde_extents.py': '9ce52ed319743ecfbaaafec799f6cef20148e0d46f161091f89b7c58ffdd2345',
}
RANGES = {
    'u32-wrapper': (0x466bc10, 0x466bd03, '9e1325517b785daba397193914a99a3c119b1b7dc9603cda4df553c46f0485a8'),
    'u64-wrapper': (0x466bd10, 0x466bdf5, 'fca33a99b93d22ee7cde15b995c1faf05b6fc7f4967c1489ecaf77030d0f6f5e'),
    'u32-reader': (0x466d850, 0x466d975, '2f4fb65647ac687706f7f902dd72913232d1fb05aef63a21597a4b4e907d006c'),
    'u64-reader': (0x466d980, 0x466dabc, '1f88da45c1b59f158544acc1df436cf698e6e4dcc10e960db50b102f8ae42f5b'),
    'error-builder': (0x466dac0, 0x466dace, 'e9c285d5d073c7afed38f1407c356d1bbd68f7d91948f2527ca58b5c55e64841'),
    'request-context': (0x438b5c0, 0x438b6d7, '7a48fd979909abac3a2a0afaf73f2b63ee8ee30111626fb3e0d859171661feeb'),
}
TABLES = {
    0x6f6e98: (0x466bc79, 0x466bc85, 0x466bcd3, 0x466bcbb),
    0x6f6ea8: (0x466bd76, 0x466bd8e, 0x466bd82, 0x466bdc5),
    0x6f6ec8: (0x466d8b7, 0x466d8c4, 0x466d945, 0x466d92d),
    0x6f6ed8: (0x466d9e7, 0x466da01, 0x466d9f4, 0x466da8c),
}
SLOTS = {0x5775138: 0x466d850, 0x57745e0: 0x466d980, 0x57745e8: 0x466dac0}
CALLS = {
    0x466bcb0: ('slot', 0x5775138), 0x466bcc8: ('slot', 0x57745e8),
    0x466bce0: ('slot', 0x57745e8), 0x466bcf8: ('slot', 0x57745e8),
    0x466bdba: ('slot', 0x57745e0), 0x466bdd2: ('slot', 0x57745e8),
    0x466bdea: ('slot', 0x57745e8), 0x466d93a: ('slot', 0x57745e8),
    0x466d952: ('slot', 0x57745e8), 0x466d96a: ('slot', 0x57745e8),
    0x466da99: ('slot', 0x57745e8), 0x466dab1: ('slot', 0x57745e8),
    0x438b5d2: ('direct', 0x466bc10), 0x438b646: ('direct', 0x466bd10),
    0x438b65e: ('direct', 0x466bd10),
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


for dependency, digest in DEPENDENCIES.items():
    need(sha((ROOT / dependency).read_bytes()) == digest, 'static parser dependency changed')
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        phoff = struct.unpack_from('<Q', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 54)
        need(size == 56 and phoff + size * count <= len(data), 'program header bounds')
        self.loads = []
        for i in range(count):
            typ, _, off, va, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', data, phoff + i * size)
            if typ == 1:
                self.loads.append((va, va + filesz, off))

    def offset(self, va, count):
        matches = [off + va - first for first, end, off in self.loads if first <= va and va + count <= end]
        need(count >= 0 and len(matches) == 1, 'unique file-backed PT_LOAD required')
        off = matches[0]
        need(0 <= off <= off + count <= len(self.data), 'file range bounds')
        return off

    def at(self, va, count):
        off = self.offset(va, count)
        return self.data[off:off + count]


def admit(data):
    need(len(data) == SIZE and sha(data) == DIGEST, 'wrong complete node94 identity')
    return Image(data)


def parameters(image):
    """Read immediates, not a CPU interpreter; full sequence binding is separate."""
    p = {}
    for width, start in ((32, 0x466bc10), (64, 0x466bd10)):
        p[width] = {'mode': image.at(start + 3, 1)[0],
                    'charge': image.at(start + 0x17, 1)[0],
                    'threshold': image.at(start + 0x30, 1)[0],
                    'overflow_max': struct.unpack('<b', image.at(start + 0xd, 1))[0] % (1 << 64)}
    p[32]['fast_expected'] = image.at(0x466bcbf, 1)[0]
    p[64]['fast_expected'] = image.at(0x466bdc9, 1)[0]
    p[32]['reader_expected'] = image.at(0x466d931, 1)[0]
    p[64]['reader_expected'] = image.at(0x466da90, 1)[0]
    return p


def validate(image):
    """Below-identity binding checks; no public admission bypass."""
    cies, fdes = eh_frame_records(image.data, image.secs)
    bodies = {}
    for label, (start, end, digest) in RANGES.items():
        found = [f for f in fdes if f['start'] == start]
        need(len(found) == 1 and found[0]['end'] == end, 'FDE extent changed')
        f = found[0]
        raw = image.at(start, end - start)
        need(sha(raw) == digest, 'complete body changed: ' + label)
        records = {}
        for key, va in (('fde', f['fde']), ('cie', f['cie'])):
            count = 4 + struct.unpack('<I', image.at(va, 4))[0]
            records[key] = {'va': hex(va), 'hex': image.at(va, count).hex()}
        bodies[label] = {'start': hex(start), 'end': hex(end), 'bytes': len(raw),
                         'sha256': sha(raw), 'lsda': f['lsda'], **records}
    tables = []
    for table, targets in TABLES.items():
        raw = image.at(table, 16)
        actual = tuple(table + x for x in struct.unpack('<4i', raw))
        need(actual == targets, 'dispatch table changed')
        tables.append({'va': hex(table), 'hex': raw.hex(), 'targets': list(map(hex, actual))})
    relas = [s for s in image.secs if s['name'] == '.rela.dyn']
    need(len(relas) == 1 and relas[0]['size'] % 24 == 0, 'RELA scope changed')
    sec = relas[0]; bindings = {}
    for i, (slot, info, addend) in enumerate(struct.iter_unpack('<QQq', image.at(sec['address'], sec['size']))):
        if slot in SLOTS:
            need(slot not in bindings and info == 8 and addend == SLOTS[slot], 'RELATIVE binding changed')
            bindings[slot] = {'slot': hex(slot), 'type': 8, 'symbolIndex': 0, 'addend': hex(addend),
                              'fileOffset': sec['offset'] + i * 24}
    need(set(bindings) == set(SLOTS), 'selected relocation missing')
    # These two data references are used only for the caller's active invalid-tag metadata.
    need(image.at(0x204640, 16) == b'GossipRpcRequest', 'request type literal changed')
    need(image.at(0x209410, 16).hex() == '00000000000000000000000002000000', 'request range record changed')
    return {'targetSha256': DIGEST, 'targetBytes': SIZE, 'dependencies': DEPENDENCIES,
            'ranges': bodies, 'tables': tables, 'relocations': [bindings[x] for x in sorted(bindings)],
            'parameters': parameters(image), 'capturedExecution': False, 'instructionEvaluation': False}


def rows(text, image, start, end):
    result = []; cursor = start
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$', line)
        if not match:
            continue
        va, raw, asm = int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()
        need(va == cursor and va + len(raw) <= end, 'native tiling differs')
        need(raw == image.at(va, len(raw)), 'native bytes differ')
        need('(bad)' not in asm and '.byte' not in asm, 'incomplete native decoding')
        result.append((va, raw, asm)); cursor += len(raw)
    need(cursor == end and result, 'native range incomplete')
    return result


def native(argv, cwd):
    process = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=60)
    need(process.returncode == 0, 'native parser failed: ' + argv[0])
    return process.stdout.decode()


def collect(binary=TARGET):
    image = admit(Path(binary).read_bytes()); record = validate(image); files = {}; calls = {}
    with tempfile.TemporaryDirectory(prefix='bincode-wrapper-static-') as temp:
        temp = Path(temp); snapshot = temp / 'node94.elf'
        snapshot.write_bytes(image.data); snapshot.chmod(0o400)
        record['providers'] = {name: native([tool, '--version'], temp).splitlines()[0]
                               for name, tool in [('gnu', GNU), ('llvm', LLVM), ('readelf', READELF)]}
        frames = native([READELF, '-W', '--debug-dump=frames', snapshot.name], temp)
        blocks = re.split(r'\n\s*\n', frames); selected_frames = []
        for label, (start, end, _) in RANGES.items():
            exports = {}
            for provider, tool, flags in [('gnu', GNU, ['-d', '-M', 'intel', '--insn-width=16']),
                                          ('llvm', LLVM, ['-d', '--x86-asm-syntax=intel'])]:
                text = native([tool, *flags, '--start-address=' + hex(start), '--stop-address=' + hex(end), snapshot.name], temp)
                files[label + '.' + provider + '.txt'] = text.encode()
                exports[provider] = rows(text, image, start, end)
            need([(va, b) for va, b, _ in exports['gnu']] == [(va, b) for va, b, _ in exports['llvm']], 'native partitions differ')
            record['ranges'][label]['instructions'] = len(exports['gnu'])
            for va, raw, asm in exports['gnu']:
                if asm.split()[0] != 'call':
                    continue
                if len(raw) == 5 and raw[0] == 0xe8:
                    calls[va] = ('direct', va + 5 + struct.unpack('<i', raw[1:])[0])
                elif len(raw) == 6 and raw[:2] == b'\xff\x15':
                    calls[va] = ('slot', va + 6 + struct.unpack('<i', raw[2:])[0])
                else:
                    raise ValueError('unreviewed call form')
            matches = [b for b in blocks if re.search(r'FDE cie=[0-9a-f]+ pc=0*' + f'{start:x}' + r'\.\.0*' + f'{end:x}' + r'\b', b)]
            need(len(matches) == 1, 'native FDE extent differs')
            selected_frames.append(matches[0])
        need(snapshot.read_bytes() == image.data, 'private snapshot changed')
    need(calls == CALLS, 'complete native call census differs')
    record['calls'] = [{'site': hex(va), kind: hex(target)} for va, (kind, target) in sorted(calls.items())]
    record['nativeComparison'] = {'bytes': 1374, 'instructionRows': 406, 'normalizationMasks': [],
                                  'scope': 'Complete byte partitions, not compiled Rust or semantic equivalence.'}
    files['selected.frames.txt'] = ('\n\n'.join(selected_frames) + '\n').encode()
    files['records.json'] = encoded(record)
    return files


def write_new(destination, files):
    destination = Path(destination)
    need(not destination.exists(), 'preserve existing output')
    destination.mkdir(parents=True)
    for name, data in files.items():
        (destination / name).write_bytes(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        need(not args.output.exists(), 'preserve existing output')
        write_new(args.output, collect())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')
