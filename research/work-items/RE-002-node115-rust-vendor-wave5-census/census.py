"""Match rustc 1.95.0 Wave 5 high-yield vendored crate & nested-collection FDEs against node #115.

Targets the top uncovered vendored crates revealed by node #115 `.rela.dyn` ->
`.data.rel.ro` `core::panic::Location` X-ray census across 6 locked harnesses:
  1. `w5_alloc_collections`: ThinLTO + jemalloc `BTreeMap`/`BTreeSet`/`HashMap`/
     `hashbrown 0.15.2 & 0.16.1`/`indexmap 2.7.1`/`foldhash`/`ahash`/`rustc-hash`/
     `SmallVec`/`Vec::sort`/`VecDeque`/`BinaryHeap`/`itoa` matrix;
  2. `w5_http_h2_tokio_rpc`: ThinLTO + jemalloc `tokio 1.54.1` + `h2 0.3.26` +
     `hyper 0.14.29` + `http 0.2.12` + `axum 0.6.20` + `jsonrpsee-core/types 0.26.1`
     over real `TcpStream`/`TlsStream`/`AddrStream`/`MaybeHttpsStream`;
  3. `w5_cli_chrono_rayon_rdb`: ThinLTO + jemalloc `clap 2.34.0 (default-features=false)` +
     `chrono 0.4.38` + `rayon 1.10.0` + `rayon-core 1.12.1` + `rocksdb 0.21.0` +
     `log4rs 1.3.0` + `sysinfo 0.29.11` + `tokio 1.52.3`;
  4. `w5_evm_alloy_revm41`: ThinLTO + jemalloc `revm 41.0.0` + `alloy-trie 0.9.5` +
     `alloy-consensus 2.1.1` + `alloy-sol-types 1.7.3` + `ruint 1.21.1` + `keccak-asm 0.1.9`;
  5. `w5_nested_collections_2`: ThinLTO + jemalloc nested `BTreeMap`/`HashMap`/
     `IndexMap`/`hashbrown 0.15.2`/`Vec` + multi-threaded `rocksdb 0.21.0`;
  6. `w5_rlib_exact`: non-LTO `overflow-checks=true` `.rlib`s for all exact-version
     Wave 5 crates (`clap 2.34.0 [default-features=false]`, `rocksdb 0.21.0`,
     `jsonrpsee 0.26.1`, `hyper 0.14.29`, `h2 0.3.26`, `tokio 1.54.1`, `chrono 0.4.38`,
     `rayon 1.10.0`, `rayon-core 1.12.1`, `indexmap 2.7.1`, `hashbrown 0.15.2/0.16.1`).

Strict admission gates (identical to RE-002-node115-rust-tls-runtime-census `20da9b449`):
  1. Complete `.text` FDE in authenticated node #115 (`a6e2897c...`).
  2. Exact `tools/byte_progress.py::compare` qualification (incl. exact psABI
     TLS relaxations `gottpoff-ie-le`/`tlsgd-gd-le`/`tlsgd-gd-ie` and GOTPCRELX).
  3. Strict tiers against ALL node #115 `.text` FDEs of equal length:
     - `unique_fde`: length >= 32 B, unmasked >= 16 B, rel_bytes * 2 <= length, hits == 1.
     - `high_entropy_multi_copy`: length >= 128 B, unmasked >= 96 B,
       rel_bytes * 2 <= length, 2 <= hits <= 4.
  4. ZERO `drop_in_place` glue, ZERO harness tokens, ZERO leading-`_` internal glue,
     ZERO sysroot-internal misattribution (`rustc_demangle`/`gimli`/etc.).
  5. Defining crate maps strictly to `rust-std`, `rust-alloc`, `rust-core`,
     `compiler-builtins`, or a locked permissive crates.io package (`vendored-crates`,
     100% verified in `licenses.json`); zero first-party credit (`component: "foundation"`).
  6. Zero cross-crate / cross-bucket ambiguity; zero overlap against any
     non-`node115-rust-vendor-w5-` window in `research/byte-windows.json` and
     zero overlap against any sibling peer packet.

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-rust-vendor-wave5-census/census.py
  Verify:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-rust-vendor-wave5-census/census.py --verify
"""
import bisect
import hashlib
import json
import os
import re
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
WINDOW_PREFIX = 'node115-rust-vendor-w5-'

UNIQUE_MIN_BYTES = 32
UNIQUE_MIN_UNMASKED = 16
MULTI_MIN_BYTES = 128
MULTI_MIN_UNMASKED = 96
MULTI_MIN_HITS = 2
MULTI_MAX_HITS = 4

ALLOWED_RELOCS = {2, 4, 9, 19, 22, 41, 42}
ALLOWED_DEPS = {'rust-core', 'rust-alloc', 'rust-std', 'compiler-builtins', 'vendored-crates'}
SYSROOT_INTERNAL_CRATES = {
    'rustc_demangle', 'gimli', 'addr2line', 'object', 'panic_unwind',
    'panic_abort', 'std_detect', 'unwind', 'profiler_builtins',
}

HARNESS_TOKENS = (
    'w5_alloc_collections',
    'w5_http_h2_tokio_rpc',
    'w5_cli_chrono_rayon_rdb',
    'w5_evm_alloy_revm41',
    'w5_nested_collections_2',
    'w5_rlib_exact',
)

DEFAULT_BUILDS = [
    ('w5_cli_chrono_rayon_rdb', 'obj', 'work/target/pr-merger-1-w5c/release/deps',
     'research/work-items/RE-002-node115-rust-vendor-wave5-census/w5_cli_chrono_rayon_rdb/Cargo.lock'),
    ('w5_alloc_collections', 'obj', 'work/target/pr-merger-1-w5a/release/deps',
     'research/work-items/RE-002-node115-rust-vendor-wave5-census/w5_alloc_collections/Cargo.lock'),
    ('w5_nested_collections_2', 'obj', 'work/target/pr-merger-1-w5e/release/deps',
     'research/work-items/RE-002-node115-rust-vendor-wave5-census/w5_nested_collections_2/Cargo.lock'),
    ('w5_http_h2_tokio_rpc', 'obj', 'work/target/pr-merger-1-w5b/release/deps',
     'research/work-items/RE-002-node115-rust-vendor-wave5-census/w5_http_h2_tokio_rpc/Cargo.lock'),
    ('w5_evm_alloy_revm41', 'obj', 'work/target/pr-merger-1-w5d/release/deps',
     'research/work-items/RE-002-node115-rust-vendor-wave5-census/w5_evm_alloy_revm41/Cargo.lock'),
    ('w5_rlib_exact', 'rlib', 'work/target/pr-merger-1-w5rlib/release/deps',
     'research/work-items/RE-002-node115-rust-vendor-wave5-census/w5_rlib_exact/Cargo.lock'),
]

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
import byte_progress as bp  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ar_members(data: bytes):
    if data[:8] != b'!<arch>\n':
        return
    pos, longnames = 8, b''
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        name = header[:16].decode(errors='replace').strip()
        size = int(header[48:58])
        body = data[pos + 60:pos + 60 + size]
        if name == '//':
            longnames = body
        elif name.startswith('/') and name[1:].isdigit():
            off = int(name[1:])
            yield longnames[off:longnames.index(b'/\n', off)].decode(errors='replace'), body
        elif name not in ('/', '/SYM64/'):
            yield name.rstrip('/'), body
        pos += 60 + size + (size & 1)


def object_functions_tls(obj: bytes):
    if obj[:4] != b'\x7fELF':
        return
    shoff = struct.unpack_from('<Q', obj, 40)[0]
    entsize, count, shstrndx = struct.unpack_from('<HHH', obj, 58)
    sh = [struct.unpack_from('<IIQQQQIIQQ', obj, shoff + i * entsize) for i in range(count)]
    names = obj[sh[shstrndx][4]:sh[shstrndx][4] + sh[shstrndx][5]]

    def secname(i):
        n = sh[i][0]
        return names[n:names.index(b'\0', n)].decode(errors='replace')

    symtab = next((i for i, s in enumerate(sh) if s[1] == 2), None)
    if symtab is None:
        return
    strtab = sh[sh[symtab][6]]
    strs = obj[strtab[4]:strtab[4] + strtab[5]]
    syms = []
    for pos in range(sh[symtab][4], sh[symtab][4] + sh[symtab][5], 24):
        name, info, _other, shndx, value, size = struct.unpack_from('<IBBHQQ', obj, pos)
        syms.append((strs[name:strs.index(b'\0', name)].decode(errors='replace'), info, shndx, value, size))

    relocs = {}
    for s in sh:
        if s[1] == 4:
            rows = relocs.setdefault(s[7], [])
            for pos in range(s[4], s[4] + s[5], 24):
                off, info, addend = struct.unpack_from('<QQq', obj, pos)
                rows.append((off, info & 0xffffffff, addend))

    covered = {}
    for name, info, shndx, value, size in syms:
        if info & 0xf != 2 or not 0 < shndx < count or value != 0:
            continue
        s = sh[shndx]
        if s[1] != 1 or not (s[2] & 4) or s[5] != size or not secname(shndx).startswith('.text'):
            continue
        covered.setdefault(shndx, []).append(name)

    for shndx, names_ in covered.items():
        s = sh[shndx]
        rows = relocs.get(shndx, [])
        if any(t not in ALLOWED_RELOCS for _, t, _ in rows):
            continue
        names_.sort(key=lambda n: (n.startswith('_R') or n.startswith('_Z'), n))
        yield names_, obj[s[4]:s[4] + s[5]], sorted(rows)


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
                for pfx in ('$RF$', '$u5b$', 'mut$u20$', '$BP$const$u20$', '$BP$mut$u20$'):
                    if inner.startswith(pfx):
                        inner = inner[len(pfx):]
                        break
                else:
                    break
            if inner.startswith('impl$u20$'):
                inner = inner[9:]
            m2 = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\.\.', inner)
            if m2:
                ident = m2.group(1)
                return None if ident.startswith('_') else ident
            as_pos = inner.find('$u20$as$u20$')
            if as_pos >= 0:
                rest = inner[as_pos + 12:]
                m3 = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\.\.', rest)
                if m3:
                    ident = m3.group(1)
                    return None if ident.startswith('_') else ident
            return None
        if re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', seg):
            return seg
        return None
    if symbol.startswith('_R'):
        m = re.search(r'C(?:s[0-9a-zA-Z]*_)?(\d+)([a-zA-Z_][a-zA-Z0-9_]*)', symbol)
        if m:
            ln = int(m.group(1))
            ident = m.group(2)[:ln]
            if len(ident) == ln and not ident.startswith('_'):
                return ident
        return None
    return None


def classify_symbol(symbol: str, versions: dict):
    ident = extract_defining_crate_ident(symbol)
    if not ident:
        return None
    if ident == 'core':
        return ('rust-core', 'core', [{'crate': 'core', 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    if ident == 'alloc':
        return ('rust-alloc', 'alloc', [{'crate': 'alloc', 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    if ident == 'std':
        return ('rust-std', 'std', [{'crate': 'std', 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    if ident == 'compiler_builtins':
        return ('compiler-builtins', 'compiler_builtins', [{'crate': 'compiler_builtins', 'version': 'rustc-1.95.0-sysroot', 'source': None, 'checksum': None}])
    if ident in SYSROOT_INTERNAL_CRATES:
        return None
    cands = [c for c in versions.get(ident, []) if c['source']]
    if cands:
        return ('vendored-crates', cands[0]['crate'], cands)
    return None


def is_permissive_license(expr: str) -> bool:
    if not expr or not isinstance(expr, str):
        return False
    allowed_tokens = {
        'MIT', 'Apache-2.0', 'Apache-2.0 WITH LLVM-exception', 'BSD-2-Clause',
        'BSD-3-Clause', 'ISC', 'Zlib', 'Unicode-3.0', 'Unicode-DFS-2016',
        'CC0-1.0', 'Unlicense', 'BSL-1.0', '0BSD', 'OpenSSL',
    }
    branches = re.split(r'\s+OR\s+|\s*/\s*', expr.strip())
    for branch in branches:
        parts = [p.strip(' ()') for p in re.split(r'\s+AND\s+', branch.strip())]
        if parts and all(p in allowed_tokens for p in parts):
            return True
    return False


def lookup_crate_license(crate: str, version: str) -> str:
    cargo_home = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo'))
    src_root = cargo_home / 'registry' / 'src'
    if src_root.is_dir():
        for reg_dir in sorted(src_root.iterdir()):
            toml_path = reg_dir / f'{crate}-{version}' / 'Cargo.toml'
            if toml_path.is_file():
                text = toml_path.read_text(errors='replace')
                m = re.search(r'^license\s*=\s*"([^"]+)"', text, re.M)
                if m:
                    return m.group(1)
    for lp in sorted((ROOT / 'research/work-items').glob('*/licenses.json')):
        if lp.parent.resolve() == HERE.resolve():
            continue
        try:
            d = json.loads(lp.read_text())
        except Exception:
            continue
        if isinstance(d, dict):
            val = d.get(f'{crate} {version}')
            if isinstance(val, str):
                return val
            if isinstance(val, dict) and isinstance(val.get('license'), str):
                return val['license']
    raise RuntimeError(f'Could not determine SPDX license for {crate} {version}')


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
            rows = d if isinstance(d, list) else d.get('windows', d.get('records', d.get('matches', [])))
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


def _build_runs(n: int, mask_sorted):
    runs, cur = [], 0
    for m in mask_sorted:
        if m > cur:
            runs.append((cur, m))
        cur = m + 1
    if cur < n:
        runs.append((cur, n))
    return runs


def match_function_against_fdes(body: bytes, rel, all_by_len: dict, uncov_lens: set):
    n = len(body)
    if n < UNIQUE_MIN_BYTES or n not in uncov_lens:
        return None
    plt32 = {o for o, t, _ in rel if t == 4}
    mask = set()
    for o, t, _a in rel:
        if o < 0 or o + 4 > n:
            return None
        mask.update(range(o, o + 4))
        if t == 19:
            if o < 4 or o + 12 > n or (o + 8) not in plt32:
                return None
            if body[o - 4:o] != bp._TLSGD_SRC_PREFIX or body[o + 4:o + 8] != bp._TLSGD_SRC_CALL:
                return None
            mask.update(range(o - 4, o))
            mask.update(range(o + 4, o + 8))
        elif t == 22:
            if (o < 3 or body[o - 3] not in (0x48, 0x4c)
                    or (body[o - 1] & 0xc7) != 0x05 or body[o - 2] not in (0x8b, 0x03)):
                return None
            mask.update(range(o - 3, o))
        elif t in (41, 42):
            if o >= 2:
                mask.update(range(o - 2, o))
    if len(mask) * 2 > n or (n - len(mask)) < UNIQUE_MIN_UNMASKED:
        return None
    runs = _build_runs(n, sorted(mask))
    runs.sort(key=lambda ab: -(ab[1] - ab[0]))
    probes = [(a, b, body[a:b]) for a, b in runs]
    a0, b0, p0 = probes[0]
    rest = probes[1:]

    hits = []
    for va, tgt in all_by_len[n]:
        if tgt[a0:b0] != p0:
            continue
        ok = True
        for a, b, p in rest:
            if tgt[a:b] != p:
                ok = False
                break
        if not ok:
            continue
        rel_rows = []
        tls_sites = 0
        gotx_sites = 0
        valid = True
        for o, t, a in rel:
            row = {'offset': o, 'kind': t, 'width': 4, 'addend': a}
            if t == 19:
                for rn in ('tlsgd-gd-le', 'tlsgd-gd-ie'):
                    if bp.relaxation_bytes(body, tgt, o, t, rn) is not None:
                        row['relaxation'] = rn
                        tls_sites += 1
                        break
                else:
                    valid = False
                    break
            elif t == 22:
                if bp.relaxation_bytes(body, tgt, o, t, 'gottpoff-ie-le') is not None:
                    row['relaxation'] = 'gottpoff-ie-le'
                    tls_sites += 1
                else:
                    valid = False
                    break
            elif t in (41, 42):
                if body[o - 2:o] != tgt[o - 2:o]:
                    for rn in ('gotpcrelx-mov-lea', 'gotpcrelx-call'):
                        if bp.relaxation_bytes(body, tgt, o, t, rn) is not None:
                            row['relaxation'] = rn
                            gotx_sites += 1
                            break
                    else:
                        valid = False
                        break
            rel_rows.append(row)
        if not valid:
            continue
        try:
            cmp = bp.compare(body, tgt, rel_rows)
        except ValueError:
            continue
        if not cmp['relocation_qualified'] or cmp['relocation_bytes'] * 2 > n or cmp['non_relocation_bytes'] < UNIQUE_MIN_UNMASKED:
            continue
        hits.append((va, tgt, rel_rows, cmp, tls_sites, gotx_sites))
        if len(hits) > MULTI_MAX_HITS:
            return None
    return hits if hits else None


def generate(builds=None):
    builds = builds or [(b, k, ROOT / d, ROOT / l) for b, k, d, l in DEFAULT_BUILDS]
    data = (ROOT / TARGET).read_bytes()
    text = next(s for s in sections(data) if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    starts_cnt = Counter(f['start'] for f in fdes)

    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    taken = [
        (w['start'], w['end'])
        for w in registry['windows']
        if w['target'] == 'node115' and not w['id'].startswith(WINDOW_PREFIX)
    ]
    taken.extend(collect_peer_intervals())
    merged, m_starts = _build_merged(taken)

    all_by_len = {}
    uncov_lens = set()
    for f in fdes:
        if f['section'] == '.text' and starts_cnt[f['start']] == 1:
            n = f['end'] - f['start']
            if n < UNIQUE_MIN_BYTES:
                continue
            off = text['offset'] + f['start'] - text['address']
            all_by_len.setdefault(n, []).append((f['start'], data[off:off + n]))
            if not _overlaps(merged, m_starts, f['start'], f['end']):
                uncov_lens.add(n)

    claimed, records, locks = {}, [], []
    scanned_objects = 0

    def process_object(build_name, obj_label, is_harness_cgu, obj_bytes, versions):
        nonlocal scanned_objects
        if obj_bytes[:4] != b'\x7fELF':
            return
        scanned_objects += 1
        for symbols, body, rel in object_functions_tls(obj_bytes):
            n = len(body)
            if n < UNIQUE_MIN_BYTES or n not in uncov_lens:
                continue
            if any(tok in s for s in symbols for tok in HARNESS_TOKENS):
                continue
            if 'drop_in_place' in symbols[0]:
                continue
            cls = classify_symbol(symbols[0], versions)
            if cls is None:
                continue
            dep_bucket, crate_name, candidates = cls
            hits = match_function_against_fdes(body, rel, all_by_len, uncov_lens)
            if not hits:
                continue
            hit_count = len(hits)
            tier = 'unique_fde' if hit_count == 1 else 'high_entropy_multi_copy'
            if tier == 'high_entropy_multi_copy':
                if n < MULTI_MIN_BYTES:
                    continue
                if any(h[3]['non_relocation_bytes'] < MULTI_MIN_UNMASKED for h in hits):
                    continue
            body_sha = sha(body)
            for va, target, rel_rows, cmp, tls_sites, gotx_sites in hits:
                if _overlaps(merged, m_starts, va, va + n):
                    continue
                if va in claimed:
                    prior = claimed[va]
                    if prior['dependency'] != dep_bucket or prior['crate'] != crate_name:
                        prior['ambiguous_sources'] = True
                    elif prior['symbol'] != symbols[0] or prior['cgu'] != obj_label:
                        prior.setdefault('identical_sources', []).append({
                            'symbol': symbols[0],
                            'cgu': obj_label,
                            'build': build_name,
                            'crate': crate_name,
                            'dependency': dep_bucket,
                            'versions': [c['version'] for c in candidates],
                        })
                    continue
                record = {
                    'symbol': symbols[0],
                    'cgu': obj_label,
                    'build': build_name,
                    'harness_cgu': is_harness_cgu,
                    'sysroot': dep_bucket != 'vendored-crates',
                    'native': False,
                    'dependency': dep_bucket,
                    'crate': crate_name,
                    'match_tier': tier,
                    'node115_hit_count': hit_count,
                    'tls_relaxed': tls_sites > 0,
                    'tls_relaxation_sites': tls_sites,
                    'gotpcrelx_relaxed': gotx_sites > 0,
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

    for build_idx, (bin_name, kind, deps, lock) in enumerate(builds):
        versions = lock_versions(lock)
        locks.append({
            'build': build_idx,
            'name': bin_name,
            'kind': kind,
            'lockfile': str(Path(lock).relative_to(ROOT)),
            'sha256': sha(Path(lock).read_bytes()),
        })
        if kind == 'obj':
            for obj_path in sorted(Path(deps).glob(f'{bin_name}-*.rcgu.o')):
                is_harness = not obj_path.name.endswith('.rcgu.o.rcgu.o')
                process_object(bin_name, obj_path.name, is_harness, obj_path.read_bytes(), versions)
        elif kind == 'rlib':
            for rlib_path in sorted(Path(deps).glob('lib*.rlib')):
                raw = rlib_path.read_bytes()
                for member, member_bytes in ar_members(raw):
                    if member.endswith('.o'):
                        process_object(bin_name, f'{rlib_path.name}:{member}', False, member_bytes, versions)

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

    licenses = {}
    for pkg_key in sorted(lock_packages):
        crate, version = pkg_key.rsplit(' ', 1)
        lic = lookup_crate_license(crate, version)
        if not is_permissive_license(lic):
            raise RuntimeError(f'Non-permissive license for {pkg_key}: {lic}')
        licenses[pkg_key] = lic
    (HERE / 'licenses.json').write_text(json.dumps(licenses, indent=2) + '\n')

    blob = bytearray()
    for r in records:
        body = r.pop('source_body')
        r['source_offset'] = len(blob)
        blob += body
    (HERE / 'bodies.bin').write_bytes(blob)

    by_dep, by_crate, by_tier, by_build = {}, {}, {}, {}
    for r in records:
        sz = r['end'] - r['start']
        for bucket_map, key in (
            (by_dep, r['dependency']),
            (by_crate, f"{r['dependency']}:{r['crate']}"),
            (by_tier, r['match_tier']),
            (by_build, r['build']),
        ):
            d = bucket_map.setdefault(key, {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0, 'tls_relaxed_windows': 0})
            d['windows'] += 1
            d['bytes'] += sz
            d['raw_equal_windows'] += int(r['raw_equal'])
            d['tls_relaxed_windows'] += int(r['tls_relaxed'])

    out = {
        'schema_version': 1,
        'task': 'RE-002',
        'window_prefix': WINDOW_PREFIX,
        'target': {'path': TARGET, 'sha256': sha(data)},
        'toolchain': {
            'rustc': '1.95.0 (59807616e 2026-04-14)',
            'target_triple': 'x86_64-unknown-linux-gnu',
            'profile': 'opt-level=3 overflow-checks=true lto=thin (global_allocator=tikv-jemallocator) + lto=false rlibs',
        },
        'locks': locks,
        'scanned_objects': scanned_objects,
        'lock_packages': dict(sorted(lock_packages.items())),
        'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
        'thresholds': {
            'unique_fde': {'min_bytes': UNIQUE_MIN_BYTES, 'min_unmasked': UNIQUE_MIN_UNMASKED, 'hits': 1},
            'high_entropy_multi_copy': {
                'min_bytes': MULTI_MIN_BYTES,
                'min_unmasked': MULTI_MIN_UNMASKED,
                'min_hits': MULTI_MIN_HITS,
                'max_hits': MULTI_MAX_HITS,
            },
        },
        'summary': {
            'total_windows': len(records),
            'total_bytes': sum(r['end'] - r['start'] for r in records),
            'raw_equal_windows': sum(int(r['raw_equal']) for r in records),
            'tls_relaxed_windows': sum(int(r['tls_relaxed']) for r in records),
            'tls_relaxed_bytes': sum((r['end'] - r['start']) for r in records if r['tls_relaxed']),
            'tls_relaxation_sites': sum(r['tls_relaxation_sites'] for r in records),
            'gotpcrelx_relaxed_windows': sum(int(r['gotpcrelx_relaxed']) for r in records),
            'by_tier': dict(sorted(by_tier.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
            'by_dependency': dict(sorted(by_dep.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
            'by_build': dict(sorted(by_build.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
            'crates_matched': len(by_crate),
            'by_crate': dict(sorted(by_crate.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
        },
        'records': records,
    }
    (HERE / 'census.json').write_text(json.dumps(out, indent=1) + '\n')
    print('BY DEPENDENCY:', json.dumps(out['summary']['by_dependency'], indent=1))
    print('BY TIER:', json.dumps(out['summary']['by_tier'], indent=1))
    print('BY BUILD:', json.dumps(out['summary']['by_build'], indent=1))
    print('BY CRATE (top 30):')
    for ck, cv in list(out['summary']['by_crate'].items())[:30]:
        print(f"  {ck:40s}: {cv['windows']:3d}w = {cv['bytes']:8,d} B (tls={cv['tls_relaxed_windows']:2d}, raw={cv['raw_equal_windows']})")
    print(
        f"TOTAL: {out['summary']['total_windows']} windows, {out['summary']['total_bytes']:,} B, "
        f"{out['summary']['tls_relaxed_windows']} TLS-relaxed ({out['summary']['tls_relaxed_bytes']:,} B, "
        f"{out['summary']['tls_relaxation_sites']} psABI sites), "
        f"{out['summary']['raw_equal_windows']} raw-equal, {out['summary']['crates_matched']} crates"
    )


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
    for pkg_key, lic in licenses.items():
        if not is_permissive_license(lic):
            raise AssertionError(f'non-permissive license {pkg_key}: {lic}')

    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    other_reg = [
        (w['start'], w['end'])
        for w in registry['windows']
        if w['target'] == 'node115' and not w['id'].startswith(WINDOW_PREFIX)
    ]
    reg_merged, reg_starts = _build_merged(other_reg)

    seen = []
    total_bytes = 0
    tls_win = tls_bytes = tls_sites_total = gotx_win = raw_win = 0
    crates_seen = set()

    for rec in census['records']:
        start, end = rec['start'], rec['end']
        n = end - start
        tier = rec['match_tier']
        if (start, end) not in fde_map:
            raise AssertionError(f'not a complete .text FDE at 0x{start:x}..0x{end:x}')
        if _overlaps(reg_merged, reg_starts, start, end):
            raise AssertionError(f'overlap with research/byte-windows.json at 0x{start:x}')
        if tier == 'unique_fde':
            if n < UNIQUE_MIN_BYTES or rec['node115_hit_count'] != 1:
                raise AssertionError(f'invalid unique_fde bounds/hits at 0x{start:x}')
            min_unmasked = UNIQUE_MIN_UNMASKED
        elif tier == 'high_entropy_multi_copy':
            if n < MULTI_MIN_BYTES or not (MULTI_MIN_HITS <= rec['node115_hit_count'] <= MULTI_MAX_HITS):
                raise AssertionError(f'invalid high_entropy_multi_copy bounds/hits at 0x{start:x}')
            min_unmasked = MULTI_MIN_UNMASKED
        else:
            raise AssertionError(f'unknown match_tier {tier} at 0x{start:x}')
        if any(tok in rec['symbol'] for tok in HARNESS_TOKENS) or 'drop_in_place' in rec['symbol']:
            raise AssertionError(f"forbidden token in symbol {rec['symbol']}")
        ident = extract_defining_crate_ident(rec['symbol'])
        if ident != rec['crate'].replace('-', '_'):
            raise AssertionError(f"defining crate mismatch: {ident} vs {rec['crate']} ({rec['symbol']})")
        if rec['dependency'] not in ALLOWED_DEPS:
            raise AssertionError(f"invalid dependency {rec['dependency']}")
        if rec['native'] is not False:
            raise AssertionError(f"expected native=False at 0x{start:x}")
        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        if sha(src) != rec['source_body_sha256']:
            raise AssertionError(f'source sha mismatch at 0x{start:x}')
        off = text['offset'] + start - text['address']
        tgt = data[off:off + n]
        if sha(tgt) != rec['target_body_sha256']:
            raise AssertionError(f'target sha mismatch at 0x{start:x}')
        cmp = bp.compare(src, tgt, rec['relocations'])
        if not cmp['relocation_qualified'] or cmp['raw_equal'] != rec['raw_equal']:
            raise AssertionError(f'compare failed at 0x{start:x}')
        if cmp['relocation_bytes'] * 2 > n or cmp['non_relocation_bytes'] < min_unmasked:
            raise AssertionError(f'mask/entropy gate failed at 0x{start:x}')
        rec_tls = sum(1 for r in rec['relocations'] if r.get('relaxation') in bp.TLS_RELAXATIONS)
        rec_gotx = sum(1 for r in rec['relocations'] if r.get('relaxation') in bp.RELAXATIONS)
        if rec_tls != rec['tls_relaxation_sites'] or (rec_tls > 0) != rec['tls_relaxed']:
            raise AssertionError(f'TLS relaxation metadata mismatch at 0x{start:x}')
        if (rec_gotx > 0) != rec['gotpcrelx_relaxed']:
            raise AssertionError(f'GOTPCRELX relaxation metadata mismatch at 0x{start:x}')
        tls_sites_total += rec_tls
        if rec_tls > 0:
            tls_win += 1
            tls_bytes += n
        if rec_gotx > 0:
            gotx_win += 1
        if rec['raw_equal']:
            raw_win += 1
        crates_seen.add(f"{rec['dependency']}:{rec['crate']}")
        seen.append((start, end))
        total_bytes += n

    seen.sort()
    for (_, e1), (s2, _) in zip(seen, seen[1:]):
        if s2 < e1:
            raise AssertionError(f'internal overlap at 0x{s2:x} < 0x{e1:x}')
    sm = census['summary']
    if (
        len(seen) != sm['total_windows']
        or total_bytes != sm['total_bytes']
        or raw_win != sm['raw_equal_windows']
        or tls_win != sm['tls_relaxed_windows']
        or tls_bytes != sm['tls_relaxed_bytes']
        or tls_sites_total != sm['tls_relaxation_sites']
        or gotx_win != sm['gotpcrelx_relaxed_windows']
        or len(crates_seen) != sm['crates_matched']
    ):
        raise AssertionError('summary mismatch')
    print(
        f"VERIFIED RE-002-node115-rust-vendor-wave5-census: "
        f"{len(seen)} windows, {total_bytes:,} bytes, "
        f"{tls_win} TLS-relaxed ({tls_bytes:,} B, {tls_sites_total} psABI sites), "
        f"{raw_win} raw-equal, {gotx_win} GOTPCRELX-relaxed, {len(crates_seen)} crates"
    )


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--verify':
        verify()
        return
    generate()


if __name__ == '__main__':
    main()
