"""Match rustc 1.95.0 ThinLTO + tikv-jemallocator stdlib & vendor crate CGUs against node115 FDEs.

Node #115 was compiled with rustc 1.95.0 (59807616e 2026-04-14),
-C opt-level=3 -C overflow-checks=yes -C lto=thin, and tikv-jemallocator as
#[global_allocator]. Without ThinLTO + jemalloc, pre-LTO .rlib functions emit
__rust_dealloc / out-of-line allocator calls and miss cross-crate ThinLTO
inlining of _rjem_je_sdallocx, leaving large fractions of rust-std, rust-core,
rust-alloc, and allocating third-party crates unmatched.

This census compiles pinned crates.io harnesses with the exact node #115
ThinLTO + tikv-jemallocator + overflow-checks profile and -C save-temps, then
scans ONLY post-ThinLTO codegen units originating directly from rustc 1.95.0
sysroot rlibs or locked crates.io rlibs (*.<crate>-<hash>.<crate>.*.rcgu.o.rcgu.o;
harness CGUs are excluded), enforcing all adversarial admission gates:
  - length >= 32 bytes, unmasked bytes >= 16, masked bytes * 2 <= length;
  - relocation-masked bytes (plus exact psABI GOTPCRELX relaxations shared with
    tools/byte_progress.py) match exactly one complete node115 .text FDE;
  - no multi-copy credit;
  - zero overlap with any non-node115-thinlto-* window in research/byte-windows.json;
  - strict own-crate mangled symbol filter (length-prefixed crate ident or
    legacy $LT$<ident>.., matching both legacy and v0 Rust mangling);
  - zero cross-crate ambiguity across all input builds.

Usage (repository root):
  Build/generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-std-vendor-census/census.py \
      <sysroot-lib-dir> <bin-name> <deps-dir> <Cargo.lock> [<bin-name> <deps-dir> <Cargo.lock> ...]
  Verify committed packet against artifacts/node/115/hl-node:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-std-vendor-census/census.py --verify
"""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
WINDOW_PREFIX = 'node115-thinlto-'
MIN_BYTES = 32
MIN_UNMASKED = 16

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from byte_progress import RELAXATIONS, compare, relaxation_bytes  # noqa: E402


def _load_std_census_helpers():
    spec = importlib.util.spec_from_file_location(
        'node115_std_census_helpers',
        ROOT / 'research/work-items/RE-002-node115-std-census/census.py',
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.object_functions


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relaxed_match(src: bytes, tgt: bytes, rel, mask: set):
    """Return {offset: relaxation} if src equals tgt outside masks up to exact relaxations, else None."""
    allowed, applied = set(mask), {}
    for o, kind, _ in rel:
        for name in RELAXATIONS:
            rewritten = relaxation_bytes(src, tgt, o, kind, name)
            if rewritten is not None:
                if rewritten & allowed:
                    return None
                applied[o] = name
                allowed |= rewritten
                break
    if not applied or any(src[i] != tgt[i] for i in range(len(src)) if i not in allowed):
        return None
    return applied


def own_crate_symbol(crate: str, symbol: str) -> bool:
    """True iff mangled Rust symbol (legacy or v0) names the producing crate."""
    ident = crate.replace('-', '_')
    return f'{len(ident)}{ident}' in symbol or f'$LT${ident}..' in symbol


def sysroot_dependency_bucket(crate_ident: str) -> str:
    if crate_ident == 'core':
        return 'rust-core'
    if crate_ident == 'alloc':
        return 'rust-alloc'
    if crate_ident == 'compiler_builtins':
        return 'compiler-builtins'
    return 'rust-std'


def lock_versions(lock: Path):
    text = Path(lock).read_text()
    out = {}
    for block in text.split('[[package]]')[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M).group(1)
        version = re.search(r'^version = "([^"]+)"', block, re.M).group(1)
        source = re.search(r'^source = "([^"]+)"', block, re.M)
        checksum = re.search(r'^checksum = "([^"]+)"', block, re.M)
        out.setdefault(name.replace('-', '_'), []).append({
            'crate': name,
            'version': version,
            'source': source and source.group(1),
            'checksum': checksum and checksum.group(1),
        })
    return out


def generate(sysroot: Path, builds):
    object_functions = _load_std_census_helpers()
    sysroot_crates = {}
    sysroot_inputs = []
    for rlib in sorted(sysroot.glob('lib*.rlib')):
        stem = rlib.name[3:-5]  # <crate_ident>-<hash>
        crate_ident = stem.rsplit('-', 1)[0]
        sysroot_crates[stem] = crate_ident
        raw = rlib.read_bytes()
        sysroot_inputs.append({'file': rlib.name, 'bytes': len(raw), 'sha256': sha(raw)})

    data = (ROOT / TARGET).read_bytes()
    text = next(s for s in sections(data) if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    starts = {}
    for f in fdes:
        starts[f['start']] = starts.get(f['start'], 0) + 1
    by_len = {}
    for f in fdes:
        if f['section'] == '.text' and starts[f['start']] == 1:
            n = f['end'] - f['start']
            off = text['offset'] + f['start'] - text['address']
            by_len.setdefault(n, []).append((f['start'], data[off:off + n]))

    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    taken = [
        (w['start'], w['end'])
        for w in registry['windows']
        if w['target'] == 'node115' and not w['id'].startswith(WINDOW_PREFIX)
    ]

    claimed, records, locks = {}, [], []
    scanned_cgus = 0
    for build_idx, (bin_name, deps, lock) in enumerate(builds):
        versions = lock_versions(lock)
        locks.append({
            'build': build_idx,
            'bin_name': bin_name,
            'lockfile': str(lock),
            'sha256': sha(Path(lock).read_bytes()),
        })
        pattern = f'{bin_name}-*.rcgu.o.rcgu.o'
        for obj_path in sorted(deps.glob(pattern)):
            parts = obj_path.name.split('.')
            if len(parts) < 5:
                continue
            crate_hash = parts[1]
            if '-' not in crate_hash:
                continue
            crate_ident = crate_hash.rsplit('-', 1)[0]
            if crate_hash in sysroot_crates:
                is_sysroot = True
                dep_bucket = sysroot_dependency_bucket(sysroot_crates[crate_hash])
                crate_name = sysroot_crates[crate_hash]
                candidates = [{
                    'crate': crate_name,
                    'version': 'rustc-1.95.0-sysroot',
                    'source': None,
                    'checksum': None,
                }]
            else:
                is_sysroot = False
                candidates = [c for c in versions.get(crate_ident, []) if c['source']]
                if not candidates:
                    continue
                dep_bucket = 'vendored-crates'
                crate_name = candidates[0]['crate']

            obj = obj_path.read_bytes()
            if obj[:4] != b'\x7fELF':
                continue
            scanned_cgus += 1
            for symbols, body, rel in object_functions(obj):
                n = len(body)
                if n < MIN_BYTES or n not in by_len:
                    continue
                if any(bin_name in s for s in symbols):
                    continue
                mask = set()
                for o, _, _ in rel:
                    mask.update(range(o, o + 4))
                if len(mask) * 2 > n or n - len(mask) < MIN_UNMASKED:
                    continue
                keep = [i for i in range(n) if i not in mask]
                probe = bytes(body[i] for i in keep)
                hits = [(va, t) for va, t in by_len[n] if bytes(t[i] for i in keep) == probe]
                relaxed = {}
                if not hits and any(k in (41, 42) for _, k, _ in rel):
                    candidates_relaxed = [
                        (va, t, r)
                        for va, t in by_len[n]
                        for r in [relaxed_match(body, t, rel, mask)]
                        if r
                    ]
                    if len(candidates_relaxed) == 1:
                        va, t, relaxed = candidates_relaxed[0]
                        hits = [(va, t)]
                if len(hits) != 1:
                    continue
                va, target = hits[0]
                if any(not (va + n <= a or va >= b) for a, b in taken):
                    continue
                body_sha = sha(body)
                if va in claimed:
                    prior = claimed[va]
                    if prior['crate'] != crate_name or prior['dependency'] != dep_bucket:
                        prior['ambiguous_sources'] = True
                    elif prior['cgu'] != obj_path.name or prior['symbol'] != symbols[0]:
                        prior.setdefault('identical_sources', []).append({
                            'symbol': symbols[0],
                            'cgu': obj_path.name,
                            'crate': crate_name,
                            'dependency': dep_bucket,
                            'versions': [c['version'] for c in candidates],
                        })
                    continue
                record = {
                    'symbol': symbols[0],
                    'cgu': obj_path.name,
                    'bin_name': bin_name,
                    'sysroot': is_sysroot,
                    'native': False,
                    'dependency': dep_bucket,
                    'crate': crate_name,
                    'versions': candidates,
                    'start': va,
                    'end': va + n,
                    'target_body_sha256': sha(target),
                    'source_body': body,
                    'source_body_sha256': body_sha,
                    'raw_equal': target == body,
                    'relocations': [
                        {
                            'offset': o,
                            'kind': t,
                            'width': 4,
                            'addend': a,
                            **({'relaxation': relaxed[o]} if o in relaxed else {}),
                        }
                        for o, t, a in rel
                    ],
                }
                claimed[va] = record
                records.append(record)

    # Filter ambiguous, cross-crate identical, and non-own-crate symbols.
    records = [
        r for r in records
        if not r.pop('ambiguous_sources', False)
        and all(
            s['crate'] == r['crate'] and s['dependency'] == r['dependency']
            for s in r.get('identical_sources', [])
        )
        and own_crate_symbol(r['crate'], r['symbol'])
    ]
    records.sort(key=lambda r: (r['start'], r['end'], r['dependency'], r['crate'], r['symbol']))

    lock_packages = {}
    for r in records:
        versions = {v['version'] for v in r['versions']}
        for other in r.get('identical_sources', []):
            versions.update(other['versions'])
        r['candidate_versions'] = sorted(versions)
        r['candidate_symbols'] = sorted({r['symbol'], *(o['symbol'] for o in r.get('identical_sources', []))})
        for v in r.pop('versions'):
            if v['source']:
                lock_packages[f"{v['crate']} {v['version']}"] = {
                    'source': v['source'],
                    'checksum': v['checksum'],
                }
        r['identical_source_count'] = len(r.pop('identical_sources', []))

    blob = bytearray()
    for r in records:
        body = r.pop('source_body')
        r['source_offset'] = len(blob)
        blob += body

    (HERE / 'bodies.bin').write_bytes(blob)

    by_dep = {}
    by_crate = {}
    for r in records:
        sz = r['end'] - r['start']
        d = by_dep.setdefault(r['dependency'], {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
        d['windows'] += 1
        d['bytes'] += sz
        d['raw_equal_windows'] += int(r['raw_equal'])
        ck = f"{r['dependency']}:{r['crate']}"
        c = by_crate.setdefault(ck, {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
        c['windows'] += 1
        c['bytes'] += sz
        c['raw_equal_windows'] += int(r['raw_equal'])

    out = {
        'schema_version': 1,
        'task': 'RE-002',
        'target': {'path': TARGET, 'sha256': sha(data)},
        'toolchain': {
            'rustc': '1.95.0 (59807616e 2026-04-14)',
            'target_triple': 'x86_64-unknown-linux-gnu',
            'profile': 'opt-level=3 overflow-checks=true lto=thin global_allocator=tikv-jemallocator',
            'basis': 'node115 .comment rustc 1.95.0 + overflow panic calls + _rjem_je_sdallocx ThinLTO inlining',
        },
        'locks': locks,
        'sysroot_rlibs': len(sysroot_inputs),
        'scanned_cgus': scanned_cgus,
        'lock_packages': dict(sorted(lock_packages.items())),
        'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
        'minimum_bytes': MIN_BYTES,
        'minimum_unmasked_bytes': MIN_UNMASKED,
        'summary': {
            'total_windows': len(records),
            'total_bytes': sum(r['end'] - r['start'] for r in records),
            'raw_equal_windows': sum(int(r['raw_equal']) for r in records),
            'relaxed_windows': sum(
                1 for r in records if any('relaxation' in x for x in r['relocations'])
            ),
            'by_dependency': dict(sorted(by_dep.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
            'crates_matched': len(by_crate),
            'by_crate': dict(sorted(by_crate.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
        },
        'records': records,
        'limits': [
            'Post-ThinLTO sysroot and locked crates.io Rust CGUs (*.<crate>-<hash>.*.rcgu.o.rcgu.o) only; harness CGUs and native C/C++ objects are excluded.',
            'Every record passes own-crate symbol attribution (legacy or v0 mangling), minimum 32 B length, minimum 16 B unmasked, unique complete .text FDE hit, and zero overlap with existing byte-windows.json windows.',
            'No first-party component credit, gate, or behavior claim; all windows are strictly dependency buckets (rust-std, rust-core, rust-alloc, compiler-builtins, vendored-crates).',
        ],
    }
    (HERE / 'census.json').write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps(out['summary']['by_dependency'], indent=1))
    print(f"TOTAL: {out['summary']['total_windows']} windows, {out['summary']['total_bytes']:,} B, {out['summary']['crates_matched']} crates")


def verify():
    census = json.loads((HERE / 'census.json').read_text())
    bodies = (HERE / 'bodies.bin').read_bytes()
    data = (ROOT / TARGET).read_bytes()
    if sha(data) != census['target']['sha256']:
        raise AssertionError('target node115 SHA-256 mismatch')
    if sha(bodies) != census['bodies']['sha256'] or len(bodies) != census['bodies']['bytes']:
        raise AssertionError('bodies.bin digest/size mismatch')

    text = next(s for s in sections(data) if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    fde_map = {(f['start'], f['end']) for f in fdes if f['section'] == '.text'}

    licenses = json.loads((HERE / 'licenses.json').read_text())
    missing_lic = set(census['lock_packages']) - set(licenses)
    if missing_lic:
        raise AssertionError(f'missing license entries: {sorted(missing_lic)}')

    seen = []
    total_bytes = 0
    for rec in census['records']:
        start, end = rec['start'], rec['end']
        n = end - start
        if n < MIN_BYTES:
            raise AssertionError(f'window too short at {hex(start)}: {n}')
        if (start, end) not in fde_map:
            raise AssertionError(f'window {hex(start)}..{hex(end)} is not a complete .text FDE')
        if not own_crate_symbol(rec['crate'], rec['symbol']):
            raise AssertionError(f"non-own-crate symbol {rec['symbol']} for {rec['crate']}")
        if rec['dependency'] not in {'rust-std', 'rust-core', 'rust-alloc', 'compiler-builtins', 'vendored-crates'}:
            raise AssertionError(f"invalid dependency bucket {rec['dependency']}")
        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        if sha(src) != rec['source_body_sha256']:
            raise AssertionError(f'source body digest mismatch at {hex(start)}')
        off = text['offset'] + start - text['address']
        tgt = data[off:off + n]
        if sha(tgt) != rec['target_body_sha256']:
            raise AssertionError(f'target body digest mismatch at {hex(start)}')
        cmp = compare(src, tgt, rec['relocations'])
        if not cmp['relocation_qualified']:
            raise AssertionError(f'not relocation-qualified at {hex(start)}')
        if cmp['raw_equal'] != rec['raw_equal']:
            raise AssertionError(f'raw_equal mismatch at {hex(start)}')
        if n - cmp['relocation_bytes'] < MIN_UNMASKED:
            raise AssertionError(f'too few unmasked bytes at {hex(start)}')
        seen.append((start, end))
        total_bytes += n

    seen.sort()
    for (_, e1), (s2, _) in zip(seen, seen[1:]):
        if s2 < e1:
            raise AssertionError(f'internal overlap at {hex(s2)} < {hex(e1)}')

    if total_bytes != census['summary']['total_bytes'] or len(seen) != census['summary']['total_windows']:
        raise AssertionError('summary mismatch')

    print(
        f"VERIFIED RE-002-node115-thinlto-std-vendor-census: "
        f"{len(seen)} windows, {total_bytes:,} bytes, "
        f"{census['summary']['raw_equal_windows']} raw-equal, "
        f"{census['summary']['relaxed_windows']} relaxed, "
        f"{census['summary']['crates_matched']} crates"
    )


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--verify':
        verify()
        return
    if len(sys.argv) < 5 or (len(sys.argv) - 2) % 3 != 0:
        raise SystemExit(
            'usage: census.py --verify | census.py <sysroot-lib-dir> <bin-name> <deps-dir> <Cargo.lock> [...]'
        )
    sysroot = Path(sys.argv[1])
    builds = [
        (sys.argv[i], Path(sys.argv[i + 1]), Path(sys.argv[i + 2]))
        for i in range(2, len(sys.argv), 3)
    ]
    generate(sysroot, builds)


if __name__ == '__main__':
    main()
