"""Match third-party Rust crate rlibs built with rustc 1.95.0 -C overflow-checks=yes against node115 FDEs.

Node #115 was compiled globally with Rust integer overflow checks enabled
(-C opt-level=3 -C overflow-checks=yes). RE-002-node115-vendor-census compiled
its Rust crates with cargo release defaults (-C overflow-checks=no), leaving
overflow-checked third-party Rust functions unmatched.

This census applies the exact adversarial-reviewed admission rules of
RE-002-node115-vendor-census/vendor_census.py, restricted strictly to Rust
codegen unit objects (*.rcgu.o; native C/C++ objects are excluded):
  - length >= 32 bytes, unmasked bytes >= 16, masked bytes * 2 <= length;
  - body SHA-256 not in rustc 1.95.0 sysroot rlibs;
  - relocation-masked bytes (plus exact psABI GOTPCRELX relaxations shared with
    tools/byte_progress.py) match exactly one complete node115 .text FDE;
  - no multi-copy credit for Rust bodies;
  - zero overlap with any non-node115-ovf-vendor-* window in research/byte-windows.json;
  - strict own-crate mangled symbol filter (length-prefixed crate ident or
    legacy $LT$<ident>..);
  - zero cross-crate ambiguity across all input builds.

Usage (repository root):
  Build/generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-vendor-overflow-census/census.py \
      <sysroot-lib-dir> <deps-dir> <Cargo.lock> [<deps-dir> <Cargo.lock> ...]
  Verify committed packet against artifacts/node/115/hl-node:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-vendor-overflow-census/census.py --verify
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
WINDOW_PREFIX = 'node115-ovf-vendor-'
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
    return mod.ar_members, mod.object_functions


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
    """True iff mangled Rust symbol names the producing crate."""
    ident = crate.replace('-', '_')
    return f'{len(ident)}{ident}' in symbol or f'$LT${ident}..' in symbol


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
    ar_members, object_functions = _load_std_census_helpers()
    sysroot_bodies = set()
    for rlib in sorted(sysroot.glob('*.rlib')):
        for member, obj in ar_members(rlib.read_bytes()):
            if member.endswith('.o') and obj[:4] == b'\x7fELF':
                sysroot_bodies.update(sha(body) for _, body, _ in object_functions(obj))

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

    std = json.loads((ROOT / 'research/work-items/RE-002-node115-std-census/census.json').read_text())
    std_vas = {r['start'] for r in std['records']}
    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    taken = [
        (w['start'], w['end'])
        for w in registry['windows']
        if w['target'] == 'node115' and not w['id'].startswith(WINDOW_PREFIX)
    ]

    claimed, records, inputs, locks = {}, [], [], []
    archives = []
    for build_idx, (deps, lock) in enumerate(builds):
        versions = lock_versions(lock)
        locks.append({'build': build_idx, 'lockfile': str(lock), 'sha256': sha(Path(lock).read_bytes())})
        for rlib in sorted(deps.glob('lib*.rlib')):
            stem = rlib.name[3:rlib.name.rindex('-')]
            candidates = [c for c in versions.get(stem, []) if c['source']]
            if candidates:
                archives.append((rlib, rlib.name, candidates, build_idx))

    for path, name, candidates, build_idx in archives:
        raw = path.read_bytes()
        inputs.append({'build': build_idx, 'file': name, 'bytes': len(raw), 'sha256': sha(raw)})
        for member, obj in ar_members(raw):
            # Rust codegen units only: exclude any bundled native C/C++ objects.
            if not member.endswith('.rcgu.o') or obj[:4] != b'\x7fELF':
                continue
            for symbols, body, rel in object_functions(obj):
                n = len(body)
                if n < MIN_BYTES or n not in by_len:
                    continue
                mask = set()
                for o, _, _ in rel:
                    mask.update(range(o, o + 4))
                if len(mask) * 2 > n or n - len(mask) < MIN_UNMASKED:
                    continue
                body_sha = sha(body)
                if body_sha in sysroot_bodies:
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
                if va in std_vas or any(not (va + n <= a or va >= b) for a, b in taken):
                    continue
                if va in claimed:
                    prior = claimed[va]
                    if prior['crate'] != candidates[0]['crate']:
                        prior['ambiguous_sources'] = True
                    elif prior['rlib'] != name or prior['symbol'] != symbols[0]:
                        prior.setdefault('identical_sources', []).append({
                            'symbol': symbols[0],
                            'rlib': name,
                            'crate': candidates[0]['crate'],
                            'versions': [c['version'] for c in candidates],
                        })
                    continue
                record = {
                    'symbol': symbols[0],
                    'member': member,
                    'rlib': name,
                    'native': False,
                    'crate': candidates[0]['crate'],
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
        and all(s['crate'] == r['crate'] for s in r.get('identical_sources', []))
        and own_crate_symbol(r['crate'], r['symbol'])
    ]
    # Deterministic order by target virtual address.
    records.sort(key=lambda r: (r['start'], r['end'], r['crate'], r['symbol']))

    lock_packages = {}
    for r in records:
        versions = {v['version'] for v in r['versions']}
        for other in r.get('identical_sources', []):
            versions.update(other['versions'])
        r['candidate_versions'] = sorted(versions)
        r['candidate_symbols'] = sorted({r['symbol'], *(o['symbol'] for o in r.get('identical_sources', []))})
        for v in r.pop('versions'):
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

    summary = {}
    for r in records:
        s = summary.setdefault(r['crate'], {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
        s['windows'] += 1
        s['bytes'] += r['end'] - r['start']
        s['raw_equal_windows'] += int(r['raw_equal'])

    out = {
        'schema_version': 1,
        'task': 'RE-002',
        'target': {'path': TARGET, 'sha256': sha(data)},
        'toolchain': {
            'rustc': '1.95.0 (59807616e 2026-04-14)',
            'target_triple': 'x86_64-unknown-linux-gnu',
            'profile': 'cargo release + -C overflow-checks=yes (opt-level 3, overflow-checks=yes, 16 codegen units, no LTO, unwind)',
        },
        'lockfile_sha256': [entry['sha256'] for entry in locks],
        'lock_packages': dict(sorted(lock_packages.items())),
        'inputs': inputs,
        'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
        'minimum_bytes': MIN_BYTES,
        'minimum_unmasked_bytes': MIN_UNMASKED,
        'summary': dict(sorted(summary.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
        'records': records,
        'limits': [
            'Rust codegen unit objects (*.rcgu.o) only; native C/C++ objects are excluded.',
            'Rust symbols are kept only when their mangled path names the producing crate '
            '(this includes core/alloc generics instantiated over that crate\'s own types).',
            'Each body matches exactly one complete node115 .text FDE under relocation masking '
            'and exact psABI GOTPCRELX relaxations; no multi-copy credit is taken.',
            'A match confirms that rustc 1.95.0 -C opt-level=3 -C overflow-checks=yes reproduces '
            'that body; it does not pin the whole crate version or feature set.',
            'Relocation fields are masked, not resolved. No first-party component credit.',
        ],
    }
    (HERE / 'census.json').write_text(json.dumps(out, separators=(',', ':')) + '\n')
    total = sum(s['bytes'] for s in summary.values())
    raw_eq = sum(s['raw_equal_windows'] for s in summary.values())
    print(f'{len(records)} windows, {total} bytes, {raw_eq} raw-equal across {len(summary)} crates')
    for crate, st in list(out['summary'].items())[:25]:
        print(f"  {crate:30s} {st['windows']:4d}w  {st['bytes']:8d} B  (raw={st['raw_equal_windows']})")
    return out


def verify():
    census = json.loads((HERE / 'census.json').read_text())
    bodies = (HERE / 'bodies.bin').read_bytes()
    if len(bodies) != census['bodies']['bytes'] or sha(bodies) != census['bodies']['sha256']:
        raise ValueError('bodies.bin size or sha256 mismatch')

    data = (ROOT / TARGET).read_bytes()
    if sha(data) != census['target']['sha256']:
        raise ValueError('target binary sha256 mismatch')
    text = next(s for s in sections(data) if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    fde_map = {(f['start'], f['end']) for f in fdes if f['section'] == '.text'}

    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    taken = [
        (w['start'], w['end'])
        for w in registry['windows']
        if w['target'] == 'node115' and not w['id'].startswith(WINDOW_PREFIX)
    ]

    seen_spans = []
    total_bytes = 0
    raw_equal = 0
    for idx, rec in enumerate(census['records']):
        if rec['native']:
            raise ValueError(f'record {idx} is native')
        if not own_crate_symbol(rec['crate'], rec['symbol']):
            raise ValueError(f'record {idx} fails own-crate filter: {rec["crate"]} vs {rec["symbol"]}')
        start, end = rec['start'], rec['end']
        n = end - start
        if n < MIN_BYTES:
            raise ValueError(f'record {idx} below MIN_BYTES: {n}')
        if (start, end) not in fde_map:
            raise ValueError(f'record {idx} ({hex(start)}..{hex(end)}) is not a complete .text FDE')
        if any(not (end <= a or start >= b) for a, b in taken):
            raise ValueError(f'record {idx} ({hex(start)}..{hex(end)}) overlaps existing byte-windows.json entry')
        if any(not (end <= a or start >= b) for a, b in seen_spans):
            raise ValueError(f'record {idx} ({hex(start)}..{hex(end)}) overlaps earlier record')
        seen_spans.append((start, end))

        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        if sha(src) != rec['source_body_sha256']:
            raise ValueError(f'record {idx} source_body_sha256 mismatch')
        off = text['offset'] + start - text['address']
        tgt = data[off:off + n]
        if sha(tgt) != rec['target_body_sha256']:
            raise ValueError(f'record {idx} target_body_sha256 mismatch')

        cmp_res = compare(src, tgt, rec['relocations'])
        if not cmp_res['relocation_qualified']:
            raise ValueError(f'record {idx} failed relocation-qualified comparison')
        if cmp_res['raw_equal'] != rec['raw_equal']:
            raise ValueError(f'record {idx} raw_equal mismatch')
        if n - cmp_res['relocation_bytes'] < MIN_UNMASKED:
            raise ValueError(f'record {idx} below MIN_UNMASKED after relaxations')
        total_bytes += n
        raw_equal += int(rec['raw_equal'])

    print(
        f'OK: {len(census["records"])} windows, {total_bytes} bytes, '
        f'{raw_equal} raw-equal across {len(census["summary"])} crates'
    )


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--verify':
        verify()
        return
    if len(sys.argv) < 4 or (len(sys.argv) - 2) % 2 != 0:
        raise SystemExit(
            'Usage: census.py --verify  OR  census.py <sysroot-lib-dir> <deps-dir> <Cargo.lock> ...'
        )
    sysroot = Path(sys.argv[1])
    builds = [(Path(a), Path(b)) for a, b in zip(sys.argv[2::2], sys.argv[3::2])]
    generate(sysroot, builds)


if __name__ == '__main__':
    main()
