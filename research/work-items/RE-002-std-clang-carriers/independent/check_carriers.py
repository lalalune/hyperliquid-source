#!/usr/bin/env python3
"""Independent Python ar-format/pyelftools check of four rlibs; offline and static."""
import argparse
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
MAX_RLIB = 128 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_TAR_BYTES = 768 * 1024 * 1024
STAMPS = {'1.94.1': 'clang version 21.1.0-rc2', '1.95.0': 'clang version 22.1.0-rc2'}
CODE_SHA256 = '09027f7508488f9fabf097f96e8db1d2e2740cf931ae88d008e04df4a8ab2916'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    result = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def ar_members(data):
    require(data.startswith(b'!<arch>\n'), 'ordinary ar required; thin archives excluded')
    cursor, index, strings = 8, 0, b''
    while cursor < len(data):
        require(index < 100000 and cursor + 60 <= len(data), 'ar table truncated/oversized')
        header = data[cursor:cursor + 60]
        require(header[58:60] == b'`\n' and header[48:58].strip().isdigit(), 'malformed ar header')
        size = int(header[48:58])
        start, end = cursor + 60, cursor + 60 + size
        require(size <= MAX_MEMBER and end <= len(data), 'ar payload outside bounds')
        field, payload = header[:16].rstrip(b' '), data[start:end]
        if field == b'//':
            require(not strings, 'duplicate GNU name table')
            strings, name = payload, '//'
        elif field.startswith(b'#1/'):
            width = int(field[3:])
            require(0 <= width <= len(payload), 'BSD name outside payload')
            name, payload = payload[:width].rstrip(b'\0').decode('utf-8'), payload[width:]
            start += width
        elif field.startswith(b'/') and field[1:].isdigit():
            offset = int(field[1:])
            require(offset < len(strings), 'GNU name offset outside table')
            end_name = strings.find(b'/\n', offset)
            require(end_name >= offset, 'unterminated GNU name')
            name = strings[offset:end_name].decode('utf-8')
        else:
            name = field.decode('utf-8').rstrip('/') or '/'
        yield dict(index=index, name=name, offset=start, size=len(payload), sha256=sha(payload)), payload
        cursor = end + size % 2
        require(cursor <= len(data), 'ar alignment byte missing')
        index += 1


def decode_listing(text):
    rows = []
    for line in text.splitlines():
        match = re.fullmatch(r'\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)(.*?)\s*', line)
        if match:
            assembly = match.group(3)
            rows.append(dict(offset=int(match.group(1), 16), bytes=bytes.fromhex(match.group(2)).hex(),
                             assembly=assembly, mnemonic=assembly.split(None, 1)[0]))
    return rows


def check_listing(text, body):
    rows, cursor = decode_listing(text), 0
    require(rows and '<__popcountdi2>:' in text, 'named symbol listing missing')
    for row in rows:
        require(row['offset'] == cursor, 'disassembly not contiguous')
        cursor += len(bytes.fromhex(row['bytes']))
    require(cursor == 98 and b''.join(bytes.fromhex(r['bytes']) for r in rows) == body, 'listing bytes differ')
    calls = [r for r in rows if r['mnemonic'].startswith('call')]
    jumps = [r for r in rows if r['mnemonic'].startswith('j')]
    memory = [r for r in rows if '(' in r['assembly'] or '[' in r['assembly']]
    rip = [r for r in rows if re.search(r'%rip|\brip\b', r['assembly'])]
    returns = [r for r in rows if r['mnemonic'].startswith('ret')]
    require(len(rows) == 27 and not (calls or jumps or memory or rip), 'unexpected instruction dependencies')
    require(len(returns) == 1 and returns[0] == rows[-1], 'unexpected return structure')
    return dict(instruction_count=len(rows), decoded_bytes=cursor, code_sha256=sha(body),
                calls=calls, jumps=jumps, explicit_memory_operands=memory, rip_relative_references=rip,
                return_offset=returns[0]['offset'])


def compare_carriers(records, inventory, stamp):
    primary = []
    with inventory.open() as stream:
        for line in stream:
            row = json.loads(line)
            basename = PurePosixPath(row['tar_name']).name
            if not basename.startswith(('libcompiler_builtins-', 'libprofiler_builtins-')):
                continue
            if not any(c['text'] == stamp for c in row.get('comments', [])):
                continue
            member = row['ar_member']
            require(member is not None, 'primary carrier lacks ar identity')
            primary.append(dict(tar_name=row['tar_name'], index=member['index'], name=member['name'],
                                offset=member['offset'], size=member['size'], sha256=row['sha256']))
    key = lambda row: (row['tar_name'], row['index'], row['name'])
    require(len({key(r) for r in primary}) == len(primary), 'duplicate primary identity')
    require(sorted(records, key=key) == sorted(primary, key=key), 'independent/primary carrier disagreement')
    return dict(exact_carriers=len(records), all_member_name_index_offset_size_sha256_equal=True,
                canonical_carrier_identity_sha256=sha(json.dumps(sorted(records, key=key),
                    sort_keys=True, separators=(',', ':')).encode()),
                primary_inventory_sha256=file_sha(inventory))


def scan_selected(archive, row, native, out):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
    require(archive.stat().st_size == row['bytes'] and file_sha(archive) == row['sha256'], 'archive identity differs')
    stamp, libraries, carriers, objects = STAMPS[row['version']], [], [], []
    seen, logical_bytes = set(), 0
    with tarfile.open(archive, 'r|xz') as package:
        for number, entry in enumerate(package):
            path = PurePosixPath(entry.name)
            require(number < 100000 and entry.name not in seen, 'tar table oversized/duplicate')
            require(not path.is_absolute() and '..' not in path.parts, 'unsafe tar name')
            seen.add(entry.name)
            if entry.isfile():
                require(0 <= entry.size <= 256 * 1024 * 1024, 'tar file size limit')
                logical_bytes += entry.size
                require(logical_bytes <= MAX_TAR_BYTES, 'tar logical byte limit')
            family = next((f for f in ('compiler_builtins', 'profiler_builtins')
                           if path.name.startswith('lib' + f + '-') and path.name.endswith('.rlib')), None)
            if family is None:
                continue
            require(entry.isfile() and entry.size <= MAX_RLIB, 'unexpected selected tar member')
            handle = package.extractfile(entry)
            require(handle is not None, 'missing selected payload')
            data = handle.read(MAX_RLIB + 1)
            require(len(data) == entry.size, 'rlib size differs')
            counts = dict(ar_members=0, elf_members=0, exact_stamp_members=0)
            for identity, payload in ar_members(data):
                counts['ar_members'] += 1
                if not payload.startswith(b'\x7fELF'):
                    continue
                elf = ELFFile(io.BytesIO(payload))
                counts['elf_members'] += 1
                sections = list(elf.iter_sections())
                stamped = any(s.name == '.comment' and stamp.encode() in s.data().split(b'\0') for s in sections)
                if not stamped:
                    continue
                require(elf.elfclass == 64 and elf.little_endian and elf['e_type'] == 'ET_REL'
                        and elf['e_machine'] == 'EM_X86_64', 'unexpected stamped ELF type')
                counts['exact_stamp_members'] += 1
                carriers.append(dict(tar_name=entry.name, **identity))
                if family != 'compiler_builtins' or not identity['name'].endswith('-popcountdi2.o'):
                    continue
                symbols = [symbol for table in sections if isinstance(table, SymbolTableSection)
                           for symbol in table.iter_symbols() if symbol.name == '__popcountdi2']
                require(len(symbols) == 1, 'popcount symbol count differs')
                symbol = symbols[0]
                index = symbol['st_shndx']
                require(symbol['st_info']['type'] == 'STT_FUNC' and isinstance(index, int)
                        and 0 < index < len(sections), 'popcount symbol definition differs')
                section = sections[index]
                body = section.data()
                require(section['sh_type'] == 'SHT_PROGBITS' and section['sh_flags'] & 4
                        and symbol['st_value'] == 0 and symbol['st_size'] == len(body) == 98, 'popcount extent differs')
                relocations = sum(s.num_relocations() for s in sections
                                  if isinstance(s, RelocationSection) and s['sh_info'] == index)
                require(relocations == 0 and sha(body) == CODE_SHA256, 'popcount code/relocations differ')
                result = dict(member=identity, library_sha256=sha(data), code_sha256=sha(body), code_bytes=98,
                              code_section_relocations=0, native_listing=None)
                if native:
                    options = ['--disassemble', '--disassemble-symbols=__popcountdi2', '--print-imm-hex', '-']
                    env = {k: os.environ[k] for k in ('HOME', 'USER', 'LOGNAME', 'SystemRoot') if k in os.environ}
                    env.update(PATH=os.defpath, LANG='C', LC_ALL='C')
                    run = subprocess.run([str(native), *options], input=payload, capture_output=True, env=env, timeout=30)
                    require(run.returncode == 0, 'explicit native reader failed')
                    name = 'popcount-' + row['version'] + '.asm'
                    (out / name).write_bytes(run.stdout)
                    (out / (name + '.stderr')).write_bytes(run.stderr)
                    result['native_listing'] = dict(file=name, sha256=sha(run.stdout), options=options,
                                                   **check_listing(run.stdout.decode(), body))
                objects.append(result)
            libraries.append(dict(family=family, tar_name=entry.name, bytes=len(data), sha256=sha(data), **counts))
    require(len(libraries) == 2 and {r['family'] for r in libraries} == {'compiler_builtins', 'profiler_builtins'}, 'expected library pair absent')
    require(len(objects) == 1, 'expected single popcount member absent')
    return dict(version=row['version'], archive_sha256=row['sha256'], libraries=libraries,
                carriers=carriers, popcount=objects[0])


def parser_controls():
    def member(name, payload):
        return name.encode().ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) + b'0'.ljust(6) + b'0'.ljust(8) + str(len(payload)).encode().ljust(10) + b'`\n' + payload + (b'\n' if len(payload) % 2 else b'')
    good = b'!<arch>\n' + member('//', b'long-object-name.o/\n') + member('/0', b'abcd')
    decoded = list(ar_members(good))
    require(decoded[-1][0]['name'] == 'long-object-name.o' and decoded[-1][1] == b'abcd', 'GNU-name control failed')
    rejected = []
    for name, bad in [('thin', b'!<thin>\n'), ('truncated_header', good[:20]),
                      ('truncated_payload', good[:-1]), ('bad_long_name', b'!<arch>\n' + member('/400', b'abcd'))]:
        try:
            list(ar_members(bad))
        except (ValueError, UnicodeError):
            rejected.append(name)
        else:
            raise ValueError('accepted malformed control: ' + name)
    return dict(gnu_long_name='pass', rejected=rejected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=HERE.parents[3])
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--primary', type=Path, required=True, help='canonical probe output with members-<version>.jsonl')
    parser.add_argument('--out', type=Path, required=True, help='fresh repository work/ subdirectory')
    parser.add_argument('--native-objdump', type=Path, help='optional existing LLVM reader with stdin support')
    args = parser.parse_args()
    require(importlib.metadata.version('pyelftools') == '0.32', 'pyelftools 0.32 is required; nothing is installed automatically')
    repo, out = args.repo.resolve(), args.out.resolve()
    require(not (repo / 'work').is_symlink(), 'work/ is a symlink')
    require(out.is_relative_to((repo / 'work').resolve()) and out != (repo / 'work').resolve(), 'output outside work/')
    require(not out.exists(), 'output already exists')
    config = json.loads((HERE.parent / 'inputs.json').read_text())
    require(len(config['archives']) == 2 and {r['version'] for r in config['archives']} == set(STAMPS), 'archive set differs')
    for row in config['archives']:
        require(PurePosixPath(row['filename']).name == row['filename'] and not any(c in row['filename'] for c in '/\\:'), 'unsafe archive basename')
    native = args.native_objdump.resolve() if args.native_objdump else None
    require(native is None or native.is_file(), 'explicit native reader missing')
    out.mkdir(parents=True, exist_ok=False)
    tool = None
    if native:
        version = subprocess.run([str(native), '--version'], capture_output=True, text=True, timeout=30)
        require(version.returncode == 0, 'native reader version failed')
        (out / 'objdump-version.txt').write_text(version.stdout)
        tool = dict(binary_basename=native.name, binary_sha256=file_sha(native), version_stdout=version.stdout)
    versions = []
    for row in config['archives']:
        result = scan_selected(args.inputs / row['filename'], row, native, out)
        result['agreement'] = compare_carriers(result['carriers'], args.primary / ('members-' + row['version'] + '.jsonl'), STAMPS[row['version']])
        versions.append(result)
    output = dict(method='independent Python GNU/BSD ar-format parser plus pyelftools 0.32',
                  script_sha256=file_sha(Path(__file__)), parser_controls=parser_controls(), versions=versions,
                  native_reader=tool, extracted_files=0, executed_archive_members=0,
                  signatures_verified=False, target_binding_performed=False)
    (out / 'agreement.json').write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
    print(json.dumps(dict(carriers=sum(len(r['carriers']) for r in versions), libraries=4,
                         native_reader_used=bool(native), agreement=True)))


if __name__ == '__main__':
    main()
