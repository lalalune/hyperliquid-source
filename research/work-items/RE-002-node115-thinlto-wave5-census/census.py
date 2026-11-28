"""Match rustc 1.95.0 ThinLTO + tikv-jemallocator Wave 5 nested-collection & serde/HTTP FDEs against node115.

Adds two new locked ThinLTO + tikv-jemallocator builds (`w5_serde_http` and
`w5_btree`) targeting deep `serde_json`/`rmp-serde`/`rmp`/`bincode`/`axum`/
`serde_path_to_error`/`rust_decimal`/`alloy-primitives`/`hashbrown` paths and
nested `BTreeMap`/`HashMap`/`IndexMap` + extended value-size monomorphizations.

Admits complete `.text` FDE matches under two strict, zero-relaxation tiers:
  1. `unique_fde`: length >= 32 B, unmasked >= 16 B, masked * 2 <= length,
     exactly 1 matching `.text` FDE in node #115.
  2. `high_entropy_multi_copy`: length >= 128 B, unmasked >= 96 B,
     masked * 2 <= length, 2 <= node115_hits <= 4, zero `drop_in_place` glue.

All safeguards enforced on both tiers:
  - zero GOTPCRELX or TLS relaxations (`tools/byte_progress.py::compare`);
  - zero harness crate identifiers (`thinlto_sv*`, `thinlto_w2*`, `thinlto_w3*`,
    `thinlto_w5*`) anywhere in symbols;
  - zero `drop_in_place` glue;
  - strictly disjoint from the Rust TLS/runtime/CLI/crypto lane (`#499`/`#542`);
  - defining crate extracted strictly from `_ZN`/`_R` symbol -> `rust-alloc`,
    `rust-core`, or a locked permissive crates.io package (`licenses.json`);
  - zero cross-crate/cross-bucket ambiguity;
  - zero overlap with `research/byte-windows.json` or any sibling peer packet.

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-wave5-census/census.py
  Verify:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-thinlto-wave5-census/census.py --verify
"""
import bisect
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
WINDOW_PREFIX = 'node115-w5-thinlto-'
MIN_BYTES_UNIQUE = 32
MIN_UNMASKED_UNIQUE = 16
MIN_BYTES_MULTI = 128
MIN_UNMASKED_MULTI = 96
MAX_MULTI_HITS = 4

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from byte_progress import compare  # noqa: E402

HARNESS_TOKENS = ('thinlto_sv', 'thinlto_w2', 'thinlto_w3', 'thinlto_w5')

# Strictly exclude crates owned by the parallel Rust TLS/runtime/CLI/crypto stream (#499/#542)
EXCLUDED_CRATE_PREFIXES = (
    'std', 'tokio', 'tracing', 'rayon', 'rand', 'parking_lot', 'crossbeam',
    'regex', 'clap', 'chrono', 'url', 'idna', 'icu_', 'flate2', 'openssl',
    'native_tls', 'native-tls', 'reqwest', 'rustls', 'tungstenite', 'log4rs',
    'sysinfo', 'mio', 'socket2', 'signal_hook', 'signal-hook', 'gimli',
    'addr2line', 'object', 'miniz_oxide', 'adler', 'rustc_demangle',
    'panic_unwind', 'unwind', 'std_detect',
)

DEFAULT_BUILDS = [
    ('thinlto_w5_serde_http', 'work/target/thinlto-surge/x86_64-unknown-linux-gnu/release/deps', 'research/work-items/RE-002-node115-thinlto-wave5-census/w5_serde_http/Cargo.lock'),
    ('thinlto_w5_btree', 'work/target/thinlto-surge/x86_64-unknown-linux-gnu/release/deps', 'research/work-items/RE-002-node115-thinlto-wave5-census/w5_btree/Cargo.lock'),
]


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
    if 'drop_in_place' in symbol:
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


def is_excluded_crate(crate_name: str) -> bool:
    norm = crate_name.replace('-', '_')
    return any(
        norm == p.replace('-', '_')
        or norm.startswith(p.replace('-', '_') + '_')
        or crate_name.startswith(p)
        for p in EXCLUDED_CRATE_PREFIXES
    )


def classify_symbol(symbol: str, versions: dict):
    ident = extract_defining_crate_ident(symbol)
    if not ident or is_excluded_crate(ident):
        return None
    if ident == 'core':
        return ('rust-core', 'core', [{'crate': 'core', 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    if ident == 'alloc':
        return ('rust-alloc', 'alloc', [{'crate': 'alloc', 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    cands = [c for c in versions.get(ident, []) if c['source']]
    if cands and not is_excluded_crate(cands[0]['crate']):
        return ('vendored-crates', cands[0]['crate'], cands)
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
            try:
                d = json.loads(rec_file.read_text())
            except Exception:
                continue
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


def _build_merged(intervals):
    intervals = sorted(intervals)
    merged = []
    for a, b in intervals:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged, [a for a, _ in merged]


def _overlaps(merged, starts, s, e):
    i = bisect.bisect_right(starts, s)
    if i > 0 and merged[i - 1][1] > s:
        return True
    if i < len(merged) and merged[i][0] < e:
        return True
    return False


def generate(builds=None):
    builds = builds or [(b, ROOT / d, ROOT / l) for b, d, l in DEFAULT_BUILDS]
    object_functions = _load_object_functions()
    data = (ROOT / TARGET).read_bytes()
    text = next(s for s in sections(data) if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    starts_cnt = {}
    for f in fdes:
        starts_cnt[f['start']] = starts_cnt.get(f['start'], 0) + 1
    by_len = {}
    for f in fdes:
        if f['section'] == '.text' and starts_cnt[f['start']] == 1:
            n = f['end'] - f['start']
            if n < MIN_BYTES_UNIQUE:
                continue
            off = text['offset'] + f['start'] - text['address']
            by_len.setdefault(n, []).append((f['start'], data[off:off + n]))

    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    taken = [
        (w['start'], w['end'])
        for w in registry['windows']
        if w['target'] == 'node115' and not w['id'].startswith(WINDOW_PREFIX)
    ]
    taken.extend(collect_peer_intervals())
    merged, m_starts = _build_merged(taken)

    claimed, records, locks = {}, [], []
    scanned_cgus = 0
    for build_idx, (bin_name, deps, lock) in enumerate(builds):
        versions = lock_versions(lock)
        locks.append({
            'build': build_idx,
            'bin_name': bin_name,
            'lockfile': str(Path(lock).relative_to(ROOT)),
            'sha256': sha(Path(lock).read_bytes()),
        })
        for obj_path in sorted(Path(deps).glob(f'{bin_name}-*.rcgu.o')):
            obj = obj_path.read_bytes()
            if obj[:4] != b'\x7fELF':
                continue
            scanned_cgus += 1
            is_harness_cgu = not obj_path.name.endswith('.rcgu.o.rcgu.o')
            for symbols, body, rel in object_functions(obj):
                n = len(body)
                if n < MIN_BYTES_UNIQUE or n not in by_len:
                    continue
                if any(tok in s for s in symbols for tok in HARNESS_TOKENS):
                    continue
                if 'drop_in_place' in symbols[0]:
                    continue
                cls = classify_symbol(symbols[0], versions)
                if cls is None:
                    continue
                dep_bucket, crate_name, candidates = cls
                mask = set()
                for o, _, _ in rel:
                    mask.update(range(o, o + 4))
                unmasked = n - len(mask)
                if len(mask) * 2 > n or unmasked < MIN_UNMASKED_UNIQUE:
                    continue
                keep = [i for i in range(n) if i not in mask]
                probe = bytes(body[i] for i in keep)
                hits = [(va, t) for va, t in by_len[n] if bytes(t[i] for i in keep) == probe]
                if not hits:
                    continue
                if len(hits) == 1:
                    tier = 'unique_fde'
                elif 2 <= len(hits) <= MAX_MULTI_HITS and n >= MIN_BYTES_MULTI and unmasked >= MIN_UNMASKED_MULTI:
                    tier = 'high_entropy_multi_copy'
                else:
                    continue
                body_sha = sha(body)
                rel_rows = [{'offset': o, 'kind': t, 'width': 4, 'addend': a} for o, t, a in rel]
                for va, target in hits:
                    if _overlaps(merged, m_starts, va, va + n):
                        continue
                    cmp = compare(body, target, rel_rows)
                    if not cmp['relocation_qualified'] or cmp.get('relaxations'):
                        continue
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
                        'match_tier': tier,
                        'node115_hit_count': len(hits),
                        'versions': candidates,
                        'start': va,
                        'end': va + n,
                        'target_body_sha256': sha(target),
                        'source_body': body,
                        'source_body_sha256': body_sha,
                        'raw_equal': target == body,
                        'relocations': rel_rows,
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

    # Ensure zero internal overlap
    for a, b in zip(records, records[1:]):
        if b['start'] < a['end']:
            raise AssertionError(f"internal overlap at 0x{b['start']:x} < 0x{a['end']:x}")

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

    by_dep, by_crate, by_tier = {}, {}, {}
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
        t = by_tier.setdefault(r['match_tier'], {'windows': 0, 'bytes': 0})
        t['windows'] += 1
        t['bytes'] += sz

    out = {
        'schema_version': 1,
        'task': 'RE-002',
        'window_prefix': WINDOW_PREFIX,
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
        'thresholds': {
            'unique_fde': {'min_bytes': MIN_BYTES_UNIQUE, 'min_unmasked': MIN_UNMASKED_UNIQUE, 'hits': 1},
            'high_entropy_multi_copy': {'min_bytes': MIN_BYTES_MULTI, 'min_unmasked': MIN_UNMASKED_MULTI, 'min_hits': 2, 'max_hits': MAX_MULTI_HITS},
        },
        'summary': {
            'total_windows': len(records),
            'total_bytes': sum(r['end'] - r['start'] for r in records),
            'raw_equal_windows': sum(int(r['raw_equal']) for r in records),
            'relaxed_windows': 0,
            'by_tier': by_tier,
            'by_dependency': dict(sorted(by_dep.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
            'crates_matched': len(by_crate),
            'by_crate': dict(sorted(by_crate.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
        },
        'records': records,
    }
    (HERE / 'census.json').write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps(out['summary'], indent=1))


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
        if (start, end) not in fde_map:
            raise AssertionError(f'invalid FDE at 0x{start:x}')
        tier = rec['match_tier']
        if tier == 'unique_fde':
            if n < MIN_BYTES_UNIQUE or rec['node115_hit_count'] != 1:
                raise AssertionError(f'invalid unique_fde gate at 0x{start:x}')
        elif tier == 'high_entropy_multi_copy':
            if n < MIN_BYTES_MULTI or not (2 <= rec['node115_hit_count'] <= MAX_MULTI_HITS):
                raise AssertionError(f'invalid multi_copy gate at 0x{start:x}')
        else:
            raise AssertionError(f'unknown tier {tier} at 0x{start:x}')
        if any(tok in rec['symbol'] for tok in HARNESS_TOKENS) or 'drop_in_place' in rec['symbol']:
            raise AssertionError(f"forbidden token in symbol {rec['symbol']}")
        ident = extract_defining_crate_ident(rec['symbol'])
        if ident != rec['crate'].replace('-', '_') or is_excluded_crate(rec['crate']):
            raise AssertionError(f"defining crate mismatch/excluded: {ident} vs {rec['crate']} ({rec['symbol']})")
        if rec['dependency'] not in {'rust-core', 'rust-alloc', 'vendored-crates'}:
            raise AssertionError(f"invalid dependency {rec['dependency']}")
        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        if sha(src) != rec['source_body_sha256']:
            raise AssertionError(f'source sha mismatch at 0x{start:x}')
        off = text['offset'] + start - text['address']
        tgt = data[off:off + n]
        if sha(tgt) != rec['target_body_sha256']:
            raise AssertionError(f'target sha mismatch at 0x{start:x}')
        cmp = compare(src, tgt, rec['relocations'])
        if not cmp['relocation_qualified'] or cmp['raw_equal'] != rec['raw_equal'] or cmp.get('relaxations'):
            raise AssertionError(f'compare failed at 0x{start:x}')
        seen.append((start, end))
        total_bytes += n

    seen.sort()
    for a, b in zip(seen, seen[1:]):
        if b[0] < a[1]:
            raise AssertionError(f'internal overlap at 0x{b[0]:x} < 0x{a[1]:x}')
    if total_bytes != census['summary']['total_bytes'] or len(seen) != census['summary']['total_windows']:
        raise AssertionError('summary totals mismatch')
    print(f"VERIFIED RE-002-node115-thinlto-wave5-census: {len(seen)} windows, {total_bytes:,} bytes, {census['summary']['raw_equal_windows']} raw-equal, 0 relaxed, {census['summary']['crates_matched']} crates")


def main():
    if '--verify' in sys.argv[1:]:
        verify()
    else:
        generate()


if __name__ == '__main__':
    main()
