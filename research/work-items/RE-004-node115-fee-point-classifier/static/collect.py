#!/usr/bin/env python3
"""Static file/ELF checks; never a target evaluator.

Only the explicitly pinned Python parser source is imported. Binary bytes are
data. No numeric oracle is imported and no instruction is evaluated.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import types


def require(ok, label):
    if not ok:
        raise ValueError(label)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'nonregular input')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read()
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                'input changed during read')
        return data
    finally:
        os.close(fd)


def authenticate(data, pin, label):
    require(len(data) == pin['bytes'] and digest(data) == pin['sha256'], label)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def read_scope(path, wanted):
    raw = regular_bytes(path)
    require(digest(raw) == wanted, 'scope identity')
    return json.loads(raw, object_pairs_hook=unique_object)


def load_helpers(root, scope):
    """Called only after whole-target authentication; executes parser PYTHON."""
    loaded = {}
    for name in ('elf_index', 'fde_extents', 'foundation_millis'):
        require(name not in sys.modules, 'unexpected existing parser module')
        pin = scope['helpers'][name]
        path = Path(root) / pin['path']
        source = regular_bytes(path)
        authenticate(source, pin, 'parser identity: ' + name)
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        # This is pinned reviewed Python source, never captured ELF data.
        exec(compile(source, str(path), 'exec'), module.__dict__)
        loaded[name] = module
    return loaded


class Image:
    def __init__(self, data):
        require(data[:6] == b'\x7fELF\x02\x01' and len(data) >= 64, 'ELF64 LE')
        self.data = data
        start = struct.unpack_from('<Q', data, 32)[0]
        width, count = struct.unpack_from('<HH', data, 54)
        require(width >= 56 and count and start + width * count <= len(data), 'PHDR bounds')
        self.loads = []
        for index in range(count):
            typ, flags, off, va, _, size, mem, _ = struct.unpack_from('<IIQQQQQQ', data, start + index * width)
            if typ == 1:
                require(size <= mem and off + size <= len(data), 'PT_LOAD bounds')
                self.loads.append((va, off, size, flags))

    def offset(self, va, size):
        require(size > 0, 'empty span')
        matches = [(off + va - base, flags) for base, off, length, flags in self.loads
                   if base <= va and va + size <= base + length]
        require(len(matches) == 1, 'ambiguous/non-file-backed span')
        return matches[0][0]

    def raw(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def relas(self):
        data = self.data
        start = struct.unpack_from('<Q', data, 40)[0]
        width, count = struct.unpack_from('<HH', data, 58)
        require(width >= 64 and count and start + width * count <= len(data), 'SHDR bounds')
        out = []
        for index in range(count):
            row = struct.unpack_from('<IIQQQQIIQQ', data, start + index * width)
            if row[1] == 4:
                off, size, entry = row[4], row[5], row[9]
                require(entry == 24 and size % 24 == 0 and off + size <= len(data), 'RELA table')
                for pos in range(off, off + size, 24):
                    target, info, addend = struct.unpack_from('<QQq', data, pos)
                    out.append({'offset': pos, 'target': target, 'type': info & 0xffffffff,
                                'symbol': info >> 32, 'addend': addend,
                                'hex': data[pos:pos + 24].hex()})
        return out


def encoding_fact(raw, va, kind):
    """Finite encoding fields only: no flags, register state or instruction loop."""
    if kind == 'branch':
        if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
            return {'condition': raw[0] & 15, 'target': va + 2 + int.from_bytes(raw[1:], 'little', signed=True)}
        if len(raw) == 6 and raw[0] == 15 and 0x80 <= raw[1] <= 0x8f:
            return {'condition': raw[1] & 15, 'target': va + 6 + int.from_bytes(raw[2:], 'little', signed=True)}
        raise ValueError('unsupported selected branch encoding')
    if kind == 'cmov':
        require(len(raw) == 4 and 0x40 <= raw[0] <= 0x4f and raw[1] == 15
                and 0x40 <= raw[2] <= 0x4f, 'selected CMOV encoding')
        return {'rex': raw[0], 'condition': raw[2] & 15, 'modrm': raw[3]}
    if kind == 'call':
        if len(raw) == 5 and raw[0] == 0xe8:
            return {'direct': va + 5 + int.from_bytes(raw[1:], 'little', signed=True)}
        require(len(raw) == 6 and raw[:2] == b'\xff\x15', 'selected CALL encoding')
        return {'slot': va + 6 + int.from_bytes(raw[2:], 'little', signed=True)}
    require(kind == 'bytes', 'unknown fact kind')
    return {'hex': raw.hex()}


def facts(image, scope):
    return {p['name']: encoding_fact(image.raw(p['va'], p['bytes']), p['va'], p['kind'])
            for p in scope['anchors']}


def check_facts(observed, scope):
    for pin in scope['anchors']:
        require(observed[pin['name']] == pin['fact'], 'semantic pin: ' + pin['name'])


def relocation_facts(image, scope):
    spans = [(p['va'], p['bytes']) for p in scope['data']]
    spans += [(p['start'], p['end'] - p['start']) for p in scope['bodies']]
    return [r for r in image.relas()
            if any(r['target'] < va + size and va < r['target'] + 8 for va, size in spans)]


def check_relocations(observed, scope):
    require(observed == scope['relocations'], 'selected relocation set/fields')
    for row in observed:
        require(row['type'] == 8 and row['symbol'] == 0, 'RELATIVE requires symbol zero')


def portable_export(raw):
    lines = raw.splitlines(keepends=True)
    header = [i for i, line in enumerate(lines) if line.endswith(b':     file format elf64-x86-64\n')]
    require(len(header) == 1, 'one GNU file header')
    lines[header[0]] = b'authenticated-node115:     file format elf64-x86-64\n'
    return b''.join(lines)


def inspect(data, scope, root, evidence, helpers):
    image = Image(data)
    secs, indexed = helpers['elf_index'].unwind_index(data)
    cies, fdes = helpers['fde_extents'].eh_frame_records(data, secs)
    observed = facts(image, scope)
    check_facts(observed, scope)
    relocations = relocation_facts(image, scope)
    check_relocations(relocations, scope)
    bodies = []
    for pin in scope['bodies']:
        start, end = pin['start'], pin['end']
        code = image.raw(start, end - start)
        require(digest(code) == pin['body_sha256'], 'complete body identity')
        export = regular_bytes(Path(evidence) / pin['export'])
        authenticate(export, pin['export_identity'], 'retained GNU export')
        rows = helpers['foundation_millis'].decode_export(export.decode('utf-8'), start, end, code)
        require(len(rows) == pin['rows'], 'full instruction partition')
        fs = [f for f in fdes if f['start'] == start]
        ix = [f for f in indexed if f['start'] == start]
        require(len(fs) == len(ix) == 1 and fs[0]['end'] == end
                and fs[0]['fde'] == ix[0]['fde'], 'exact indexed FDE')
        frame = fs[0]
        require(frame['cie'] in cies, 'selected CIE')
        for key in ('cie', 'fde'):
            record = pin['frames'][key]
            require(frame[key] == record['va'], 'frame address')
            raw = image.raw(record['va'], record['bytes'])
            require(raw.hex() == record['hex'] and digest(raw) == record['sha256'], 'frame bytes')
        # Complete structural census is syntax, not a path/normal-return proof.
        structural = []
        for line in export.decode('utf-8').splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.+)$', line)
            if match and re.match(r'(?:j\w+|call|ret|ud2)\b', match[3].strip()):
                structural.append({'va': int(match[1], 16), 'hex': bytes.fromhex(match[2]).hex(),
                                   'gnu': match[3].strip()})
        bodies.append({'start': start, 'end': end, 'credit': pin['credit'], 'rows': len(rows),
                       'body_sha256': digest(code), 'fde': frame, 'structural': structural})
    for pin in scope['data']:
        require(image.raw(pin['va'], pin['bytes']).hex() == pin['hex'], 'selected data: ' + pin['name'])
    return {'target': scope['target'], 'bodies': bodies, 'anchors': observed,
            'relocations': relocations, 'data': scope['data'],
            'limits': scope['limits'], 'captured_execution': False}


def fresh_dir(path):
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), 'fresh output required')
    path.mkdir(mode=0o700)
    return path


def regenerate(data, scope, out, executable):
    # Snapshot and executable pins precede EVERY native-tool invocation.
    tool = Path(executable).resolve(strict=True)
    tool_data = regular_bytes(tool)
    authenticate(tool_data, scope['objdump'], 'GNU decoder identity')
    snapshot = out / 'authenticated-node115'
    snapshot.write_bytes(data)
    snapshot.chmod(0o400)
    receipts = []
    jobs = [('version', ['--version'])]
    jobs += [(hex(p['start'])[2:], ['-d', '-M', 'intel', '--insn-width=16',
              '--start-address=' + hex(p['start']), '--stop-address=' + hex(p['end']), snapshot.name])
             for p in scope['bodies'] if p['credit'] == 'new-v3']
    try:
        for label, arguments in jobs:
            authenticate(regular_bytes(snapshot), scope['target'], 'snapshot before decoder')
            authenticate(regular_bytes(tool), scope['objdump'], 'decoder before invocation')
            env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
            stdout, stderr, code, failure, diagnostic = b'', b'', None, None, b''
            try:
                process = subprocess.run([str(tool), *arguments], cwd=out, env=env,
                                         stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
                stdout, stderr, code = process.stdout, process.stderr, process.returncode
            except subprocess.TimeoutExpired as error:
                stdout, stderr, failure = error.stdout or b'', error.stderr or b'', 'timeout'
            except OSError as error:
                failure = type(error).__name__  # not fabricated child stderr
                diagnostic = str(error).encode('utf-8')
            (out / (label + '.stdout')).write_bytes(stdout)
            (out / (label + '.stderr')).write_bytes(stderr)
            if diagnostic:
                (out / (label + '.launch-error.txt')).write_bytes(diagnostic)
            receipts.append({'label': label, 'argv': ['<pinned-objdump>', *arguments], 'env': env,
                             'exit_code': code, 'failure': failure,
                             'stdout': {'bytes': len(stdout), 'sha256': digest(stdout)},
                             'stderr': {'bytes': len(stderr), 'sha256': digest(stderr)},
                             'launch_error_diagnostic': {'bytes': len(diagnostic), 'sha256': digest(diagnostic)}})
            (out / 'commands.json').write_text(json.dumps(receipts, indent=2, sort_keys=True) + '\n')
            require(failure is None and code == 0 and not stderr, 'decoder command failed')
            if label == 'version':
                require(digest(stdout) == scope['objdump']['version_sha256'], 'GNU version output')
            else:
                pin = next(p for p in scope['bodies'] if p['start'] == int(label, 16))
                require(digest(portable_export(stdout)) == pin['export_identity']['sha256'],
                        'fresh GNU output differs from retained portable export')
        authenticate(regular_bytes(snapshot), scope['target'], 'snapshot after all commands')
        authenticate(regular_bytes(tool), scope['objdump'], 'decoder after all commands')
    finally:
        snapshot.unlink()  # input copy only; raw command streams are retained
    return receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'root', 'evidence', 'scope', 'scope-sha', 'out'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--objdump', help='Optional, separately admitted regeneration of three bodies')
    args = parser.parse_args()
    scope = read_scope(args.scope, args.scope_sha)
    data = regular_bytes(args.binary)
    authenticate(data, scope['target'], 'whole node115 identity')
    helpers = load_helpers(args.root, scope)
    result = inspect(data, scope, args.root, args.evidence, helpers)
    out = fresh_dir(args.out)  # no output exists before complete static admission
    (out / 'records.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    if args.objdump:
        regenerate(data, scope, out, args.objdump)


if __name__ == '__main__':
    main()
