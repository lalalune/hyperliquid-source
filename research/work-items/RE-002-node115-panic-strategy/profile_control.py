"""Link the same unwind-enabled Rust rlib into separately compiled abort and unwind roots."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = 'x86_64-unknown-linux-gnu'
INPUTS = ('Scrt1.o', 'libc.so.6', 'libm.so.6', 'libgcc_s.so.1', 'libpthread.a', 'libdl.a', 'librt.a', 'libutil.a')


def require(ok, msg):
    if not ok:
        raise ValueError(msg)


def run(args, work=None):
    return subprocess.check_output(args, cwd=work, text=True, env=dict(os.environ, LC_ALL='C')).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect(exe, readelf):
    data = exe.read_bytes()
    rows = sections(data)
    require(struct.unpack_from('<HH', data, 16) == (3, 62), 'Expected x86-64 Linux PIE')
    ex, = (r for r in rows if r['name'] == '.gcc_except_table')
    _, fdes = eh_frame_records(data, rows)
    symbols = [line.split() for line in run([readelf, '-Ws', str(exe)]).splitlines()]
    operations = {}
    for name in ('root_operation', 'dependency_operation'):
        sym, = (s for s in symbols if len(s) == 8 and s[-1] == name and s[3] == 'FUNC' and s[6] != 'UND')
        va, size = int(sym[1], 16), int(sym[2])
        f, = (f for f in fdes if f['start'] == va and f['end']-va == size)
        operations[name] = dict(va=va, size=size, lsda=f['lsda'])
    selected = set(re.findall(r'libpanic_(abort|unwind)-[0-9a-f]+\.rlib\(', exe.with_suffix('.map').read_text()))
    require(len(selected) == 1, 'Linker map did not select one Rust panic runtime')
    raises = any(len(s) >= 8 and s[6] == 'UND' and s[7].split('@')[0] == '_Unwind_RaiseException' for s in symbols)
    return dict(elf_sha256=sha(exe), linked_panic_runtime='panic_'+selected.pop(), imports_raise_exception=raises,
                gcc_except_table_bytes=ex['size'], fdes=len(fdes), fdes_with_lsda=sum(f['lsda'] is not None for f in fdes),
                functions=operations)


def experiment(libdir, readelf, ar):
    rustc = ['rustup', 'run', '1.95.0', 'rustc']
    info = dict(s.split(': ', 1) for s in run(rustc+['-vV']).splitlines() if ': ' in s)
    require(info['commit-hash'] == '59807616e1fa2540724bfbac14d7976d7e4a3860', 'Wrong Rust release')
    sysroot = Path(run(rustc+['--print', 'sysroot']))
    lld = sysroot/'lib/rustlib'/info['host']/'bin/rust-lld'
    result = dict(rustc_commit=info['commit-hash'], host=info['host'], target=TARGET,
                  linker=run([lld, '-flavor', 'gnu', '--version']), linker_sha256=sha(lld),
                  native_inputs_sha256={name: sha(libdir/name) for name in INPUTS},
                  source_sha256={name: sha(HERE/name) for name in ('component.rs', 'root.rs')}, roots={})
    with tempfile.TemporaryDirectory(prefix='re002-profile-') as tmp:
        work = Path(tmp)
        # Use pinned shared-object names directly. No sysroot installation or system symlink changes.
        native = work/'native'
        native.mkdir()
        for name in INPUTS:
            (native/name).symlink_to((libdir/name).resolve())
        for name, source in [('libc.so', 'libc.so.6'), ('libm.so', 'libm.so.6'), ('libgcc_s.so', 'libgcc_s.so.1')]:
            (native/name).symlink_to(source)
        common = rustc + ['--edition=2021', '--target', TARGET, '-Copt-level=2', '-Ccodegen-units=1',
                          '--remap-path-prefix', str(HERE)+'=/src', '--remap-path-prefix', str(work)+'=/build']
        lib = work/'libcomponent.rlib'
        run(common+[HERE/'component.rs', '--crate-name=component', '--crate-type=rlib', '-Cpanic=unwind',
                    '-o', lib], work)
        shared_archive_sha = sha(lib)
        member, = (name for name in run([ar, 't', str(lib)]).splitlines() if name.endswith('.rcgu.o'))
        result['dependency_object_sha256'] = hashlib.sha256(subprocess.check_output([ar, 'p', str(lib), member])).hexdigest()
        for strategy in ('abort', 'unwind'):
            exe = work/strategy
            run(common+[HERE/'root.rs', '--extern', 'component='+str(lib), '-Cpanic='+strategy,
                        '-Clinker='+str(lld), '-Clinker-flavor=ld.lld', '-Lnative='+str(native),
                        '-Clink-arg='+str(native/'Scrt1.o'), '-Clink-arg=--dynamic-linker=/lib64/ld-linux-x86-64.so.2',
                        '-Clink-arg=-Map='+str(exe.with_suffix('.map')), '-o', exe], work)
            require(sha(lib) == shared_archive_sha, 'The precompiled dependency changed between links')
            row = inspect(exe, readelf)
            require(row['linked_panic_runtime'] == 'panic_'+strategy, 'Wrong panic runtime in the link map')
            require(row['functions']['dependency_operation']['lsda'] is not None, 'Lost the dependency cleanup')
            require((row['functions']['root_operation']['lsda'] is not None) == (strategy == 'unwind'),
                    'Root-owned cleanup did not track the selected strategy')
            require(row['imports_raise_exception'] == (strategy == 'unwind'), 'Raise import did not distinguish fixtures')
            result['roots'][strategy] = row
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lib-dir', type=Path, default=Path('/usr/lib/x86_64-linux-gnu'))
    parser.add_argument('--ar', default='ar', help='GNU or LLVM ar with GNU long member names')
    parser.add_argument('--readelf', default='readelf', help='GNU readelf')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = json.dumps(experiment(args.lib_dir, args.readelf, args.ar), indent=2)+'\n'
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end='')
