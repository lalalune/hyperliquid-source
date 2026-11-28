"""Qualify the engine given to the registered base64 encoder by one static caller."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections

NODE = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CRATES = {'0.20.0': '0ea22880d78093b0cbe17c89f64a7d457941e65759157ec6cb31a31d652b05e5',
          '0.21.7': '9d297deb1925b89f2ccc13d7635fa0714f12c87adce1c75356b39ca9b7178567',
          '0.22.1': '72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6'}
SOURCE = 'src/engine/fast_portable/mod.rs'
ROOT_VA = 0x1607710
READS = HERE.parent / 'RE-002-node115-rust-base64-encode-bindings' / 'references.tsv'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def build_controls(crates, temp):
    files = {}
    for path in crates:
        digest = sha(path.read_bytes())
        version, = [v for v, h in CRATES.items() if h == digest]
        with tarfile.open(path) as archive:
            member = f'base64-{version}/{SOURCE}'
            files[version] = archive.extractfile(member).read() if member in archive.getnames() else b''
            if version == '0.20.0':
                archive.extractall(temp, filter='data')
    require(files.keys() == CRATES.keys(), 'Supply the three different previously registered releases')
    compiler = ['rustup', 'run', '1.95.0', 'rustc']
    identity = subprocess.check_output([*compiler, '-V'], text=True).strip()
    require(identity.startswith('rustc 1.95.0 (59807616e '), 'Wrong compiler build')
    flags = [*compiler, '--edition=2021', '--target=x86_64-unknown-linux-gnu']
    subprocess.run([*flags, '--cap-lints=allow', '--crate-type=rlib', '--crate-name=base64',
                    'base64-0.20.0/src/lib.rs', '-o', 'libbase64.rlib'], cwd=temp, check=True)
    subprocess.run([*flags, '--crate-type=lib', '--emit=obj', '--extern=base64=libbase64.rlib',
                    HERE / 'control.rs', '-o', 'control.o'], cwd=temp, check=True)
    obj = (temp / 'control.o').read_bytes()
    controls = {s['name'].removeprefix('.check.'): obj[s['offset']:s['offset'] + s['size']]
                for s in sections(obj) if s['name'].startswith('.check.')}
    require(set(controls) == {'standard', 'url', 'unpadded'}, 'Missing ELF controls')
    return controls, files, identity


def observe(controls, sources):
    image = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    require(sha(image) == NODE, 'Wrong capture')
    mapped = [s for s in sections(image) if s['flags'] & 2 and s['type'] != 8]

    def read(va, size):
        sec, = [s for s in mapped if s['address'] <= va and va + size <= s['address'] + s['size']]
        off = sec['offset'] + va - sec['address']
        return image[off:off+size]

    def dest(va, prefix):
        code = read(va, len(prefix) + 4)
        require(code.startswith(prefix), 'Unexpected addressing instruction')
        return va + len(code) + struct.unpack_from('<i', code, len(prefix))[0]

    rel, = [s for s in mapped if s['name'] == '.rela.dyn']
    relative = {a: v for a, kind, v in struct.iter_unpack('<QQq', read(rel['address'], rel['size'])) if kind == 8}
    locations = []
    with READS.open() as stream:
        for r in csv.DictReader(stream, delimiter='\t'):
            if not r['instruction'].startswith('lea'):
                continue
            va = int(r['instruction_va'], 16)
            ins = bytes.fromhex(r['instruction_hex'])
            require(read(va, len(ins)) == ins, 'Earlier reference bytes disagree')
            addr = dest(va, ins[:-4])
            _, length, line, col = struct.unpack('<QQII', read(addr, 24))
            source_path = read(relative[addr], length).decode()
            require(source_path.endswith('/z_vendor/base64-0.20.0/' + SOURCE), 'Unexpected location path')
            source_line = sources['0.20.0'].splitlines()[line-1]
            require(0 < col <= len(source_line), 'Column outside the published source')
            locations.append({'instruction': hex(va), 'location': hex(addr), 'line': line, 'column': col,
                              'source_line_sha256': sha(source_line)})
    require(len(locations) == 9 and len({r['location'] for r in locations}) == 9, 'Location census differs')
    calls = [0x26e2b19, 0x43035e4]
    slots = [dest(call, bytes.fromhex('ff15')) for call in calls]
    require(len(set(slots)) == 1 and relative[slots[0]] == ROOT_VA, 'Call slot does not reach the encoder')
    # No intervening write to the first argument between the LEA and the first call.
    require(read(0x26e2b10, 9) == bytes.fromhex('4c89e24c89f14989d8'), 'Argument sequence differs')
    engine = dest(0x26e2b09, bytes.fromhex('488d3d'))
    require(read(0x1607768, 6) == bytes.fromhex('420fb66c3703'), 'Wrong table index/offset in encoder')
    require(read(0x26e2b4a, 5) == bytes.fromhex('c64410ff3d'), 'Expected caller padding write')
    require(read(0x43035d8, 3) == bytes.fromhex('4889cf'), 'Expected second caller to forward its argument')
    size = len(controls['standard'])
    require(all(len(v) == size for v in controls.values()), 'Control sizes differ')
    actual = read(engine, size)
    diffs = {k: sum(a != b for a, b in zip(actual, v)) for k, v in controls.items()}
    require(diffs['standard'] == 0 and min(diffs['url'], diffs['unpadded']) > 0, 'Control discrimination failed')
    ro, = [s for s in mapped if s['name'] == '.rodata']
    contents = read(ro['address'], ro['size'])
    copies = []
    off = contents.find(actual)
    while off >= 0:
        copies.append(hex(ro['address'] + off))
        off = contents.find(actual, off + 1)
    return {'source_locations': locations, 'encoder': hex(ROOT_VA), 'caller_sites': [hex(c) for c in calls],
            'call_slot': hex(slots[0]), 'constant_caller_engine': hex(engine), 'engine_bytes': size,
            'engine_sha256': sha(actual), 'control_different_bytes': diffs, 'rodata_copies': copies,
            'source_path_present': {v: bool(src) for v, src in sources.items()}}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('crates', type=Path, nargs=3)
    p.add_argument('--print', action='store_true', dest='show')
    args = p.parse_args()
    with tempfile.TemporaryDirectory() as td:
        controls, files, rust = build_controls(args.crates, Path(td))
        result = {'rust': rust, 'target_sha256': NODE, 'archive_sha256': CRATES,
                  'observations': observe(controls, files)}
    if args.show:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        require(result == json.loads((HERE / 'result.json').read_bytes()), 'Result drift')
        print('9 source locations, 2 call sites, 3 independently compiled engine controls agree')
