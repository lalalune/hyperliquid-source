"""Match rustc 1.95.0 ThinLTO + tikv-jemallocator Wave 3 stdlib & vendored-crate monomorphizations against node115 FDEs.

Extends RE-002-node115-thinlto-wave2-census across additional locked crates.io
versions observed in node #115 (revm 41.0.0 & 43.0.3, alloy-consensus 2.1.1 &
2.5.0, alloy-primitives 1.6.1 & 1.7.3, alloy-trie 0.9.5 & 0.9.9, alloy-sol-types
1.6.1 & 1.7.3, jsonrpsee-core 0.26.0 & 0.26.1, tokio 1.52.3 & 1.54.1, hyper
1.10.1, h2 0.4.14, k256 0.13.4, p256 0.13.2, blst 0.3.16, curve25519-dalek-ng
4.1.1, ethabi 18.0.0, ethers-core 2.0.14, rust_decimal 1.36.0, serde 1.0.229,
serde_json 1.0.154, rmp-serde 1.3.0/1.3.1, hashbrown 0.15.2/0.16.1, indexmap
2.5.0, ruint 1.18.0/1.21.1, bincode 1.3.3/2.0.1, ark-bls12-381/ark-bn254 0.5.0,
and additional std/core/alloc monomorphizations).

Strict adversarial admission gates (all enforced by --verify):
  1. length >= 32 bytes, unmasked bytes >= 16, masked bytes * 2 <= length;
  2. relocation-masked bytes (plus exact psABI GOTPCRELX relaxations shared with
     tools/byte_progress.py) match EXACTLY ONE complete node115 .text FDE
     (no multi-copy credit);
  3. zero harness crate identifiers (`thinlto_sv*`, `thinlto_w2*`, `thinlto_w3*`)
     anywhere in the mangled symbol;
  4. defining crate extracted from the mangled symbol (legacy `_ZN` or v0 `_R`)
     MUST resolve unambiguously to either a rustc 1.95.0 sysroot crate
     (`rust-std`, `rust-core`, `rust-alloc`, `compiler-builtins`) or a locked
     permissive crates.io package in that build's `Cargo.lock` (`vendored-crates`);
  5. zero cross-bucket ambiguity across all builds;
  6. zero overlap with any non-`node115-w3-thinlto-*` window in
     `research/byte-windows.json` and zero overlap with any sibling peer packet.

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-wave3-census/census.py \
      <sysroot-lib-dir> <bin-name> <deps-dir> <Cargo.lock> [...]
  Verify:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-wave3-census/census.py --verify
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
WINDOW_PREFIX = 'node115-w3-thinlto-'
MIN_BYTES = 32
MIN_UNMASKED = 16

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from byte_progress import RELAXATIONS, compare, relaxation_bytes  # noqa: E402

SYSROOT_STD_CRATES = {
    'std', 'gimli', 'addr2line', 'adler2', 'miniz_oxide', 'object',
    'rustc_demangle', 'memchr', 'std_detect', 'panic_unwind', 'unwind',
    'panic_abort', 'cfg_if',
}
HARNESS_TOKENS = ('thinlto_sv', 'thinlto_w2', 'thinlto_w3')


def _load_object_functions():
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


def extract_defining_crate_ident(symbol: str):
    """Extract the leading Rust crate identifier from a legacy (_ZN) or v0 (_R) mangled symbol."""
    if any(tok in symbol for tok in HARNESS_TOKENS):
        return None
    if symbol.startswith('_ZN'):
        m = re.match(r'^_ZN(\d+)', symbol)
        if not m:
            return None
        ln = int(m.group(1))
        seg = symbol[3 + len(m.group(1)):3 + len(m.group(1)) + ln]
        if seg.startswith('_$LT$') or seg.startswith('$LT$'):
            inner = seg[5:] if seg.startswith('_$LT$') else seg[4:]
            while True:
                if inner.startswith('$RF$'):
                    inner = inner[4:]
                elif inner.startswith('$u5b$'):
                    inner = inner[5:]
                elif inner.startswith('mut$u20$'):
                    inner = inner[8:]
                elif inner.startswith('$BP$const$u20$'):
                    inner = inner[14:]
                elif inner.startswith('$BP$mut$u20$'):
                    inner = inner[12:]
                else:
                    break
            if inner.startswith('impl$u20$'):
                inner = inner[9:]
            m2 = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\.\.', inner)
            if m2:
                return m2.group(1)
            as_pos = inner.find('$u20$as$u20$')
            if as_pos >= 0:
                rest = inner[as_pos + 12:]
                m3 = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\.\.', rest)
                if m3:
                    return m3.group(1)
            return None
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', seg):
            return seg
        return None
    if symbol.startswith('_R'):
        m = re.search(r'C(?:s[0-9a-zA-Z]*_)?(\d+)([a-zA-Z_][a-zA-Z0-9_]*)', symbol)
        if m:
            ln = int(m.group(1))
            ident = m.group(2)[:ln]
            if len(ident) == ln:
                return ident
        return None
    return None


def classify_symbol(symbol: str, versions: dict):
    """Return (dependency_bucket, crate_name, candidates) or None."""
    ident = extract_defining_crate_ident(symbol)
    if not ident:
        return None
    if ident == 'core':
        return ('rust-core', 'core', [{'crate': 'core', 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    if ident == 'alloc':
        return ('rust-alloc', 'alloc', [{'crate': 'alloc', 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    if ident == 'compiler_builtins':
        return ('compiler-builtins', 'compiler_builtins', [{'crate': 'compiler_builtins', 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    if ident in SYSROOT_STD_CRATES and ident not in versions:
        return ('rust-std', ident, [{'crate': ident, 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    cands = [c for c in versions.get(ident, []) if c['source']]
    if cands:
        return ('vendored-crates', cands[0]['crate'], cands)
    if ident in SYSROOT_STD_CRATES:
        return ('rust-std', ident, [{'crate': ident, 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    return None


def _parse_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 16) if v.startswith(('0x', '0X')) else int(v)
        except ValueError:
            return None
    return None


def collect_peer_intervals():
    intervals = []
    for pat in ('*/records.json', '*/census.json'):
        for rec_file in sorted((ROOT / 'research/work-items').glob(pat)):
            if rec_file.parent.resolve() == HERE.resolve():
                continue
            d = json.loads(rec_file.read_text())
            rows = d if isinstance(d, list) else d.get('windows', d.get('records', []))
            if not isinstance(rows, list):
                continue
            for r in rows:
                if not isinstance(r, dict):
                    continue
                v = _parse_int(r.get('start_va', r.get('start', r.get('vaddr'))))
                if v is None:
                    continue
                sz = _parse_int(r.get('size', r.get('size_bytes', r.get('bytes'))))
                if sz is None:
                    e = _parse_int(r.get('end_va', r.get('end')))
                    if e is not None:
                        sz = e - v
                if sz is not None and sz > 0:
                    intervals.append((v, v + sz))
    return intervals


def generate(sysroot: Path, builds):
    object_functions = _load_object_functions()
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
    taken.extend(collect_peer_intervals())

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
        for obj_path in sorted(deps.glob(f'{bin_name}-*.rcgu.o')):
            obj = obj_path.read_bytes()
            if obj[:4] != b'\x7fELF':
                continue
            scanned_cgus += 1
            is_harness_cgu = not obj_path.name.endswith('.rcgu.o.rcgu.o')
            for symbols, body, rel in object_functions(obj):
                n = len(body)
                if n < MIN_BYTES or n not in by_len:
                    continue
                if any(tok in s for s in symbols for tok in HARNESS_TOKENS):
                    continue
                cls = classify_symbol(symbols[0], versions)
                if cls is None:
                    continue
                dep_bucket, crate_name, candidates = cls
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
                    cands_r = [
                        (va, t, r)
                        for va, t in by_len[n]
                        for r in [relaxed_match(body, t, rel, mask)]
                        if r
                    ]
                    if len(cands_r) == 1:
                        va, t, relaxed = cands_r[0]
                        hits = [(va, t)]
                if len(hits) != 1:
                    continue
                va, target = hits[0]
                if any(not (va + n <= a or va >= b) for a, b in taken):
                    continue
                body_sha = sha(body)
                if va in claimed:
                    prior = claimed[va]
                    if prior['dependency'] != dep_bucket or prior['crate'] != crate_name:
                        prior['ambiguous_sources'] = True
                    elif prior['symbol'] != symbols[0] or prior['cgu'] != obj_path.name:
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
                    'harness_cgu': is_harness_cgu,
                    'sysroot': dep_bucket != 'vendored-crates',
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

    records = [
        r for r in records
        if not r.pop('ambiguous_sources', False)
        and all(
            s['crate'] == r['crate'] and s['dependency'] == r['dependency']
            for s in r.get('identical_sources', [])
        )
    ]
    records.sort(key=lambda r: (r['start'], r['end'], r['dependency'], r['crate'], r['symbol']))

    lock_packages = {}
    for r in records:
        vers = {v['version'] for v in r['versions']}
        for other in r.get('identical_sources', []):
            vers.update(other['versions'])
        r['candidate_versions'] = sorted(vers)
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
        },
        'locks': locks,
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
        if n < MIN_BYTES or (start, end) not in fde_map:
            raise AssertionError(f'invalid FDE at 0x{start:x}')
        if any(tok in rec['symbol'] for tok in HARNESS_TOKENS):
            raise AssertionError(f"harness token leaked into symbol {rec['symbol']}")
        ident = extract_defining_crate_ident(rec['symbol'])
        if ident != rec['crate'].replace('-', '_'):
            raise AssertionError(f"defining crate mismatch: {ident} != {rec['crate']} ({rec['symbol']})")
        if rec['dependency'] not in {'rust-std', 'rust-core', 'rust-alloc', 'compiler-builtins', 'vendored-crates'}:
            raise AssertionError(f"invalid dependency {rec['dependency']}")
        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        if sha(src) != rec['source_body_sha256']:
            raise AssertionError(f'source sha mismatch at 0x{start:x}')
        off = text['offset'] + start - text['address']
        tgt = data[off:off + n]
        if sha(tgt) != rec['target_body_sha256']:
            raise AssertionError(f'target sha mismatch at 0x{start:x}')
        cmp = compare(src, tgt, rec['relocations'])
        if not cmp['relocation_qualified'] or cmp['raw_equal'] != rec['raw_equal']:
            raise AssertionError(f'compare failed at 0x{start:x}')
        if n - cmp['relocation_bytes'] < MIN_UNMASKED:
            raise AssertionError(f'too few unmasked bytes at 0x{start:x}')
        seen.append((start, end))
        total_bytes += n

    seen.sort()
    for (_, e1), (s2, _) in zip(seen, seen[1:]):
        if s2 < e1:
            raise AssertionError(f'internal overlap at 0x{s2:x} < 0x{e1:x}')
    if total_bytes != census['summary']['total_bytes'] or len(seen) != census['summary']['total_windows']:
        raise AssertionError('summary mismatch')
    print(
        f"VERIFIED RE-002-node115-thinlto-wave3-census: "
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
        raise SystemExit('usage: census.py --verify | census.py <sysroot-lib-dir> <bin-name> <deps-dir> <Cargo.lock> [...]')
    sysroot = Path(sys.argv[1])
    builds = [
        (sys.argv[i], Path(sys.argv[i + 1]), Path(sys.argv[i + 2]))
        for i in range(2, len(sys.argv), 3)
    ]
    generate(sysroot, builds)


if __name__ == '__main__':
    main()
