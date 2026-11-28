#!/usr/bin/env python3
"""Link Noble's startup and real libc with an inert fixture main; inspect both non-executed PIEs."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from verify import HERE, abi_tag, compare, section_bytes, sections, startup_object
from packages import require, sha, ubuntu


def run(args, *, cwd=None):
    env = {k: os.environ[k] for k in ('PATH', 'TMPDIR') if k in os.environ}
    return subprocess.check_output(args, cwd=cwd, env=dict(env, LC_ALL='C'), text=True).strip()


def resolved_fixture(path, readelf, raw, obj, relax):
    data = path.read_bytes()
    rows = sections(data)
    require(struct.unpack_from('<HH', data, 16) == (3, 62), 'Expected x86-64 PIE')
    entry = struct.unpack_from('<Q', data, 24)[0]
    symtab = run([readelf, '-Ws', str(path)]).splitlines()
    def symbol(name):
        row, = (line.split() for line in symtab if line.split() and line.split()[-1] == name
                and len(line.split()) == 8 and line.split()[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT'])
        return int(row[1], 16), int(row[2])
    start, extent = symbol('_start')
    main, _ = symbol('main')
    require(start == entry and extent == len(raw), 'PIE entry symbol extent mismatch')
    text, = (s for s in rows if s['flags'] & 4 and s['type'] == 1 and
             s['address'] <= entry and entry+extent <= s['address']+s['size'])
    offset = entry - text['address']
    body = section_bytes(data, text)[offset:offset+extent]
    reloc = [line.split() for line in run([readelf, '-Wr', str(path)]).splitlines()]
    call, = (r for r in reloc if len(r) == 7 and r[2] == 'R_X86_64_GLOB_DAT' and
             r[4:] == ['__libc_start_main@GLIBC_2.34', '+', '0'])
    got = int(call[0], 16)
    record = dict(elf_sha256=sha(data), extent_sha256=sha(body), entry_va=entry, main_va=main,
                  libc_start_main_got=got, abi=abi_tag(data, rows))
    if relax:
        record['comparison'] = compare(obj, raw, record, body)
    else:
        slot, = (r for r in reloc if len(r) == 4 and r[2] == 'R_X86_64_RELATIVE' and int(r[3], 16) == main)
        main_slot = int(slot[0], 16)
        wanted = bytearray(raw)
        for r in obj['relocations']:
            if r['section'] == '.text':
                at = r['offset'] - obj['start_section_offset']
                where = main_slot if r['symbol'] == 'main' else got
                struct.pack_into('<i', wanted, at, where + r['addend'] - (entry + at))
        require(bytes(wanted) == body, 'Unrelaxed startup differs outside verified GOT displacements')
        record['main_got_slot_with_relative_relocation'] = main_slot
    return record


def experiment(cache, keyring, fetch, assembler, readelf):
    dev, objects = ubuntu(cache, 'noble', keyring, fetch)
    libc_package, libraries = ubuntu(cache, 'noble', keyring, fetch, 'libc6')
    require(dev['version'] == libc_package['version'], 'Mismatched development and runtime packages')
    driver = ['rustup', 'run', '1.95.0', 'rustc']
    rust = dict(line.split(': ', 1) for line in subprocess.check_output(driver + ['-vV'], text=True).splitlines()
                if ': ' in line)
    require(rust['commit-hash'] == '59807616e1fa2540724bfbac14d7976d7e4a3860', 'Unexpected compiler release')
    sysroot = Path(subprocess.check_output(driver + ['--print', 'sysroot'], text=True).strip())
    linker = sysroot / 'lib/rustlib' / rust['host'] / 'bin/rust-lld'
    banner = run([linker, '-flavor', 'gnu', '--version'])
    require('1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e' in banner, 'Unexpected bundled linker revision')
    obj, raw = startup_object(objects['Scrt1.o'])
    with tempfile.TemporaryDirectory(prefix='re002-crt-') as tmp:
        directory = Path(tmp)
        (directory / 'Scrt1.o').write_bytes(objects['Scrt1.o'])
        (directory / 'libc.so.6').write_bytes(libraries['libc.so.6'])
        (directory / 'main.s').write_bytes((HERE / 'main.s').read_bytes())
        run([assembler, '--target=x86_64-unknown-linux-gnu', '-c', 'main.s', '-o', 'main.o'], cwd=directory)
        result = dict(host=rust['host'], assembler=run([assembler, '--version']).splitlines()[0],
                      linker=banner, linker_sha256=sha(linker.read_bytes()), dev_package_sha256=dev['package_sha256'],
                      libc_package=libc_package, libc_sha256=sha(libraries['libc.so.6']),
                      main_source_sha256=sha((HERE / 'main.s').read_bytes()),
                      main_object_sha256=sha((directory / 'main.o').read_bytes()), links={})
        for label, flags in [('default', []), ('no_relax', ['--no-relax'])]:
            run([linker, '-flavor', 'gnu', '-pie', *flags, '--build-id=sha1', '--dynamic-linker',
                 '/lib64/ld-linux-x86-64.so.2', '-o', 'fixture', 'Scrt1.o', 'main.o', 'libc.so.6'], cwd=directory)
            result['links'][label] = resolved_fixture(directory / 'fixture', readelf, raw, obj, not flags)
        require(result['links']['default']['extent_sha256'] != result['links']['no_relax']['extent_sha256'],
                'Missing independent relaxation control')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cache', type=Path)
    parser.add_argument('--keyring', type=Path, required=True)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--readelf', default='readelf', help='GNU readelf')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        output = json.dumps(experiment(args.cache, args.keyring, args.fetch, args.clang, args.readelf), indent=2)+'\n'
        if args.output:
            args.output.write_text(output)
        else:
            print(output, end='')
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
