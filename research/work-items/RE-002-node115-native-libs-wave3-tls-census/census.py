"""Match TLS-relaxed Ubuntu 24.04 GCC 13.3.0 native C/C++ library FDEs against node #115 .text.

Node #115 (`artifacts/node/115/hl-node`) statically links `librocksdb-sys 0.11.0+8.1.1`
and `tikv-jemalloc-sys 0.6.1+5.3.0-1-ge13ca993e8ccb9ba9847cc330696e02839f328f7`
(`features = ["stats", "profiling"]`) built under Ubuntu 24.04
`GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` and linked with LLD 22.1.2.

Wave 2 (`RE-002-node115-native-libs-wave2-census`) exhausted >99% of all non-TLS
statically linked native code in node #115, leaving ~735 KB of exact-length
`librocksdb-sys` and `tikv-jemalloc-sys` functions whose only differences from
the compiled `.o` files are deterministic x86-64 ELF psABI TLS linker relaxations
(Ulrich Drepper §4.2.4-4.2.5):
  - `tlsgd-gd-le` (kind 19 `R_X86_64_TLSGD` + paired kind 4 `PLT32` at +8):
    `66 48 8d 3d [disp32] 66 66 48 e8 [plt32]` ->
    `64 48 8b 04 25 00 00 00 00 48 8d 80 [tpoff32]` (`rocksdb::perf_context`, etc.)
  - `tlsgd-gd-ie` (kind 19 `R_X86_64_TLSGD` + paired kind 4 `PLT32` at +8):
    `66 48 8d 3d [disp32] 66 66 48 e8 [plt32]` ->
    `64 48 8b 04 25 00 00 00 00 48 03 05 [gottpoff32]` (`std::__once_callable`, etc.)
  - `gottpoff-ie-le` (kind 22 `R_X86_64_GOTTPOFF`):
    exact register-preserving `mov reg,[rip+disp32] -> mov reg,imm32` and
    `add reg,[rip+disp32] -> lea reg,[reg+disp32] / add reg,imm32` (`jemalloc` TLS)

This census strictly enforces:
  - Native C/C++ archives (`*.a`) only; every admitted record carries at least
    one verified psABI TLS relaxation site (`kind in (19, 22)`), is a complete
    `.text` `.eh_frame` FDE, and is tagged `dependency: "native-libraries"`,
    `component: "foundation"` (zero first-party credit).
  - All relocation/relaxation validation runs directly through `tools/byte_progress.compare`
    and `tools/byte_progress.relaxation_bytes` with zero wildcarding.
  - length >= 32 B (single-copy) or >= 64 B (multi-copy), unmasked bytes >= 16,
    relocation-masked bytes * 2 <= length (after relaxations).
  - Zero collision with `rustc 1.95.0` sysroot `*.rlib` functions, zero cross-crate
    ambiguity, and strict link-level `distinct_source_functions >= copy_count`.
  - Zero overlap against `research/byte-windows.json` (excluding this packet's
    own `node115-native-w3-tls-*` IDs once consolidated) and all sibling packets
    (including `RE-002-node115-native-libs-wave2-census`).

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-native-libs-wave3-tls-census/census.py \
      --generate <sysroot-lib-dir> <crate::version::lock_rel::archive_path> [...]
  Verify committed packet against artifacts/node/115/hl-node:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-native-libs-wave3-tls-census/census.py --verify
"""
import bisect
import hashlib
import json
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
WINDOW_PREFIX = 'node115-native-w3-tls-'
MIN_BYTES = 32
MULTI_MIN_BYTES = 64
MIN_UNMASKED = 16
ALLOWED_RELA_KINDS = {2, 4, 9, 19, 22, 41, 42}
FORBIDDEN_LICENSE_TOKENS = ('GPL-2.0-only', 'GPL-3.0-only', 'AGPL-', 'LGPL-')

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from byte_progress import RELAXATIONS, TLS_RELAXATIONS, compare, relaxation_bytes  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_ar(data: bytes):
    """Yield (member_name, elf_bytes) for ELF64 relocatable members in an ar archive."""
    if data[:8] != b'!<arch>\n':
        return
    pos = 8
    longnames = b''
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        raw_name = hdr[:16].decode('ascii', 'replace')
        size = int(hdr[48:58].strip())
        pos += 60
        body = data[pos:pos + size]
        pos += size + (size & 1)
        if raw_name.startswith('//'):
            longnames = body
            continue
        if raw_name.startswith('/ '):
            continue
        if raw_name.startswith('#1/'):
            nlen = int(raw_name[3:].strip())
            mname = body[:nlen].rstrip(b'\x00').decode('ascii', 'replace')
            body = body[nlen:]
        elif raw_name.startswith('/') and raw_name[1:].strip().isdigit():
            off = int(raw_name[1:].strip())
            end = longnames.find(b'/\n', off)
            if end < 0:
                end = longnames.find(b'\n', off)
            if end < 0:
                end = len(longnames)
            mname = longnames[off:end].decode('ascii', 'replace')
        else:
            mname = raw_name.rstrip(' /')
        if body[:4] == b'\x7fELF':
            yield mname, body


def _parse_elf_sections(ob: bytes):
    e_shoff = struct.unpack_from('<Q', ob, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', ob, 58)
    shs = [
        struct.unpack_from('<IIQQQQIIQQ', ob, e_shoff + i * e_shentsize)
        for i in range(e_shnum)
    ]
    shstr_off = shs[e_shstrndx][4]
    names = []
    for s in shs:
        end = ob.index(b'\x00', shstr_off + s[0])
        names.append(ob[shstr_off + s[0]:end].decode('ascii', 'replace'))
    return shs, names


def extract_elf_functions(ob: bytes, require_tls: bool = True):
    """Extract STT_FUNC spans >= MIN_BYTES from executable sections of an ELF64 .o."""
    shs, names = _parse_elf_sections(ob)
    shnum = len(shs)
    relas_by_sec = {}
    sym_sh = str_sh = None
    for s in shs:
        if s[1] == 4:
            relas_by_sec[s[7]] = [
                struct.unpack_from('<QQq', ob, s[4] + j * 24)
                for j in range(s[5] // 24)
            ]
        elif s[1] == 2:
            sym_sh = s
            str_sh = shs[s[6]]
    if sym_sh is None:
        return []
    out = []
    seen_spans = set()
    for j in range(sym_sh[5] // 24):
        st_name, st_info, _st_other, st_shndx, st_val, st_size = struct.unpack_from(
            '<IBBHQQ', ob, sym_sh[4] + j * 24
        )
        if (st_info & 0xf) != 2 or st_size < MIN_BYTES or st_shndx == 0 or st_shndx >= shnum:
            continue
        sec = shs[st_shndx]
        if not (sec[2] & 0x4) or st_val + st_size > sec[5]:
            continue
        span_key = (st_shndx, st_val, st_size)
        if span_key in seen_spans:
            continue
        seen_spans.add(span_key)
        end = ob.index(b'\x00', str_sh[4] + st_name)
        snm = ob[str_sh[4] + st_name:end].decode('ascii', 'replace')
        bind = st_info >> 4
        body = ob[sec[4] + st_val:sec[4] + st_val + st_size]
        srelas = []
        bad = False
        has_tls = False
        for roff, rinfo, radd in relas_by_sec.get(st_shndx, ()):
            rtype = rinfo & 0xffffffff
            if st_val <= roff < st_val + st_size:
                if rtype not in ALLOWED_RELA_KINDS or roff - st_val + 4 > st_size:
                    bad = True
                    break
                if rtype in (19, 22):
                    has_tls = True
                srelas.append((roff - st_val, rtype, radd))
        if not bad and (not require_tls or has_tls):
            out.append((snm, bind, names[st_shndx], body, tuple(sorted(srelas))))
    return out


def masked_signature(body: bytes, srelas):
    """Canonical signature masking relocation fields and relaxable GOTPCRELX/TLS instruction bytes."""
    buf = bytearray(body)
    for off, kind, _ in srelas:
        for d in range(4):
            buf[off + d] = 0
        if kind in (41, 42) and off >= 2:
            if buf[off - 2] == 0x8b:
                buf[off - 2] = 0
            elif buf[off - 2:off] == b'\xff\x15':
                buf[off - 2] = 0
                buf[off - 1] = 0
        elif kind == 19 and off >= 4 and off + 12 <= len(buf):
            for idx in range(off - 4, off + 8):
                buf[idx] = 0
        elif kind == 22 and off >= 3:
            for idx in range(off - 3, off):
                buf[idx] = 0
    return (len(body), sha(bytes(buf)), tuple((off, kind) for off, kind, _ in srelas))


def strict_tls_match(src: bytes, tgt: bytes, srelas):
    """Return byte_progress-compatible relocation list if src matches tgt with exact psABI TLS rewrites."""
    if len(src) != len(tgt):
        return None
    rel_rows = []
    mask = set()
    plt32_offs = {off for off, kind, _ in srelas if kind == 4}
    tls_count = 0
    for off, kind, add in srelas:
        row = {'offset': off, 'kind': kind, 'width': 4, 'addend': add}
        field = set(range(off, off + 4))
        if kind == 19:
            if (off + 8) not in plt32_offs:
                return None
            matched_name = None
            for rname in ('tlsgd-gd-le', 'tlsgd-gd-ie'):
                rb = relaxation_bytes(src, tgt, off, kind, rname)
                if rb is not None:
                    matched_name = rname
                    field |= rb
                    break
            if matched_name is None:
                return None
            row['relaxation'] = matched_name
            tls_count += 1
        elif kind == 22:
            rb = relaxation_bytes(src, tgt, off, kind, 'gottpoff-ie-le')
            if rb is None:
                return None
            row['relaxation'] = 'gottpoff-ie-le'
            field |= rb
            tls_count += 1
        elif kind in (41, 42):
            for rname in RELAXATIONS:
                rb = relaxation_bytes(src, tgt, off, kind, rname)
                if rb is not None:
                    row['relaxation'] = rname
                    field |= rb
                    break
        if mask & field:
            return None
        mask |= field
        rel_rows.append(row)
    if tls_count == 0:
        return None
    if len(src) - len(mask) < MIN_UNMASKED or len(mask) * 2 > len(src):
        return None
    for i in range(len(src)):
        if i not in mask and src[i] != tgt[i]:
            return None
    res = compare(src, tgt, rel_rows)
    if not res['relocation_qualified']:
        return None
    return rel_rows


def load_lock_package(lock_path: Path, crate_name: str, expected_version: str):
    text = lock_path.read_text()
    for block in text.split('[[package]]')[1:]:
        m_name = re.search(r'^name = "([^"]+)"', block, re.M)
        m_ver = re.search(r'^version = "([^"]+)"', block, re.M)
        if not m_name or not m_ver:
            continue
        if m_name.group(1) == crate_name and m_ver.group(1) == expected_version:
            m_src = re.search(r'^source = "([^"]+)"', block, re.M)
            m_chk = re.search(r'^checksum = "([^"]+)"', block, re.M)
            return {
                'source': m_src.group(1) if m_src else None,
                'checksum': m_chk.group(1) if m_chk else None,
            }
    raise ValueError(f'Package {crate_name} {expected_version} not found in {lock_path}')


def load_covered_intervals(include_siblings: bool = True):
    """Return sorted merged covered VA intervals from byte-windows.json (+ sibling packets)."""
    intervals = []
    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    for w in registry['windows']:
        if w['target'] == 'node115' and not w['id'].startswith(WINDOW_PREFIX):
            intervals.append((w['start'], w['end']))
    if include_siblings:
        wi_root = ROOT / 'research/work-items'
        for pattern in ('*/records.json', '*/census.json'):
            for path in sorted(wi_root.glob(pattern)):
                if path.parent.resolve() == HERE.resolve():
                    continue
                try:
                    doc = json.loads(path.read_text())
                except Exception:
                    continue
                recs = doc.get('records') if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
                if not isinstance(recs, list):
                    continue
                for r in recs:
                    if not isinstance(r, dict):
                        continue
                    s = r.get('start', r.get('start_va'))
                    e = r.get('end', r.get('end_va'))
                    if isinstance(s, str):
                        s = int(s, 0)
                    if isinstance(e, str):
                        e = int(e, 0)
                    if isinstance(s, int) and isinstance(e, int) and s < e:
                        intervals.append((s, e))
    intervals.sort()
    merged = []
    for s, e in intervals:
        if merged and s <= merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))
    return merged


def overlaps_any(merged, starts, s: int, e: int) -> bool:
    idx = bisect.bisect_right(starts, s) - 1
    if idx >= 0 and merged[idx][1] > s:
        return True
    if idx + 1 < len(merged) and merged[idx + 1][0] < e:
        return True
    return False


def generate(sysroot: Path, specs):
    """Generate census.json and bodies.bin for TLS-relaxed native C/C++ FDEs."""
    std_sigs = set()
    for rlib in sorted(sysroot.glob('*.rlib')):
        for _member, obj in parse_ar(rlib.read_bytes()):
            for _snm, _bind, _sec, body, srelas in extract_elf_functions(obj, require_tls=False):
                std_sigs.add(masked_signature(body, srelas))

    data = (ROOT / TARGET).read_bytes()
    text_sec = next(s for s in sections(data) if s['name'] == '.text')
    text_va = text_sec['address']
    text_off = text_sec['offset']
    text_data = data[text_off:text_off + text_sec['size']]

    _, fdes, _ = fde_extents(data)
    fde_starts = defaultdict(int)
    for f in fdes:
        if f['section'] == '.text':
            fde_starts[f['start']] += 1

    merged_cov = load_covered_intervals(include_siblings=True)
    cov_starts = [a for a, _ in merged_cov]

    fdes_by_len = defaultdict(list)
    for f in fdes:
        if f['section'] == '.text' and fde_starts[f['start']] == 1:
            s, e = f['start'], f['end']
            if not overlaps_any(merged_cov, cov_starts, s, e):
                fdes_by_len[e - s].append((s, e))

    lock_packages = {}
    lock_files = []
    seen_locks = set()
    inputs = []
    sig_entries = defaultdict(list)

    for crate, version, lock_rel, ar_path_str in specs:
        lock_path = ROOT / lock_rel
        ar_path = Path(ar_path_str)
        if not ar_path.is_absolute():
            ar_path = ROOT / ar_path
        if lock_rel not in seen_locks:
            seen_locks.add(lock_rel)
            lock_files.append({'lockfile': lock_rel, 'sha256': sha(lock_path.read_bytes())})
        lock_packages[f'{crate} {version}'] = load_lock_package(lock_path, crate, version)
        raw_ar = ar_path.read_bytes()
        inputs.append({
            'crate': crate,
            'version': version,
            'archive': ar_path.name,
            'bytes': len(raw_ar),
            'sha256': sha(raw_ar),
        })
        for member, obj in parse_ar(raw_ar):
            for snm, bind, secnm, body, srelas in extract_elf_functions(obj, require_tls=True):
                sig = masked_signature(body, srelas)
                sig_entries[sig].append((crate, version, ar_path.name, member, snm, bind, secnm, body, srelas))

    admitted_records = []
    claimed_vas = set()
    rejected_counts = {
        'sysroot_std_collision': 0,
        'cross_crate_ambiguity': 0,
        'multi_copy_below_64b': 0,
        'multi_copy_unexplained': 0,
    }
    tls_site_totals = defaultdict(int)

    for sig, entries in sig_entries.items():
        length = sig[0]
        cands = fdes_by_len.get(length)
        if not cands:
            continue
        if sig in std_sigs:
            rejected_counts['sysroot_std_collision'] += 1
            continue
        crates = sorted({e[0] for e in entries})
        if len(crates) > 1:
            rejected_counts['cross_crate_ambiguity'] += 1
            continue
        crate = crates[0]
        distinct_keys = set()
        for _c, _v, _ar, mname, snm, bind, _sec, _b, _r in entries:
            if bind == 0:
                distinct_keys.add(('L', mname, snm))
            else:
                distinct_keys.add(('G', snm))
        rep = entries[0]
        hits = []
        for s, e in cands:
            if s in claimed_vas:
                continue
            tgt = text_data[s - text_va:e - text_va]
            rel_rows = strict_tls_match(rep[7], tgt, rep[8])
            if rel_rows is not None:
                hits.append((s, e, tgt, rel_rows))
        if not hits:
            continue
        if len(hits) > 1:
            if length < MULTI_MIN_BYTES:
                rejected_counts['multi_copy_below_64b'] += len(hits)
                continue
            if len(distinct_keys) < len(hits):
                rejected_counts['multi_copy_unexplained'] += len(hits)
                continue
        versions = sorted({e[1] for e in entries})
        cand_syms = sorted({e[4] for e in entries})
        for s, e, tgt, rel_rows in hits:
            claimed_vas.add(s)
            for row in rel_rows:
                if row.get('relaxation') in TLS_RELAXATIONS:
                    tls_site_totals[row['relaxation']] += 1
            admitted_records.append({
                'symbol': rep[4],
                'member': rep[3],
                'archive': rep[2],
                'section': rep[6],
                'native': True,
                'fde_backed': True,
                'assembly_object': False,
                'crate': crate,
                'dependency': 'native-libraries',
                'component': 'foundation',
                'start': s,
                'end': e,
                'target_body_sha256': sha(tgt),
                'source_body': rep[7],
                'source_body_sha256': sha(rep[7]),
                'raw_equal': tgt == rep[7],
                'relocations': rel_rows,
                'candidate_versions': versions,
                'candidate_symbols': cand_syms[:32],
                'copy_count': len(hits),
                'distinct_source_functions': len(distinct_keys),
                'boundary_basis': 'Complete .text .eh_frame FDE extent',
            })

    admitted_records.sort(key=lambda r: (r['start'], r['end'], r['crate'], r['symbol']))
    prev_end = 0
    blob = bytearray()
    summary = {}
    for idx, rec in enumerate(admitted_records, start=1):
        if rec['start'] < prev_end:
            raise ValueError(f'Internal overlap at {hex(rec["start"])} < {hex(prev_end)}')
        prev_end = rec['end']
        rec['id'] = f'{WINDOW_PREFIX}{idx:04d}'
        body = rec.pop('source_body')
        rec['source_offset'] = len(blob)
        blob += body
        st = summary.setdefault(
            rec['crate'],
            {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0, 'single_copy_windows': 0, 'multi_copy_windows': 0},
        )
        st['windows'] += 1
        st['bytes'] += rec['end'] - rec['start']
        st['raw_equal_windows'] += int(rec['raw_equal'])
        if rec['copy_count'] == 1:
            st['single_copy_windows'] += 1
        else:
            st['multi_copy_windows'] += 1

    (HERE / 'bodies.bin').write_bytes(blob)
    out = {
        'schema_version': 1,
        'task': 'RE-002',
        'window_prefix': WINDOW_PREFIX,
        'target': {'path': TARGET, 'sha256': sha(data)},
        'toolchain': {
            'gcc': 'GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0',
            'binutils': 'GNU binutils 2.42-4ubuntu2.11 (Ubuntu 24.04 noble-updates)',
            'rustc': '1.95.0 (59807616e 2026-04-14)',
            'target_triple': 'x86_64-unknown-linux-gnu',
            'profile': 'cargo release native C/C++ builds under exact Ubuntu 24.04 GCC 13.3.0',
        },
        'lockfiles': lock_files,
        'lock_packages': dict(sorted(lock_packages.items())),
        'inputs': inputs,
        'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
        'minimum_bytes': MIN_BYTES,
        'multi_copy_minimum_bytes': MULTI_MIN_BYTES,
        'minimum_unmasked_bytes': MIN_UNMASKED,
        'tls_relaxation_sites': dict(sorted(tls_site_totals.items())),
        'multi_copy_rule': (
            'native C/C++ objects only; length >= 64 B; single crate; zero sysroot std collision; '
            'link-level distinct_source_functions >= copy_count (STB_LOCAL keyed by (member, symbol), '
            'STB_GLOBAL/STB_WEAK keyed by symbol); each copy passes exact byte_progress.compare'
        ),
        'rejected_counts': rejected_counts,
        'summary': dict(sorted(summary.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
        'records': admitted_records,
        'limits': [
            'Native C/C++ library objects (*.a) carrying verified x86-64 ELF psABI TLS relaxations '
            '(tlsgd-gd-le, tlsgd-gd-ie, gottpoff-ie-le) only; all windows are dependency-tagged '
            '("native-libraries", component "foundation") and award zero first-party credit.',
            'Every TLS relaxation site is validated byte-for-byte with register preservation via '
            'tools/byte_progress.py; unrelaxed kind-19/kind-22 sites remain rejected.',
            'Relocation fields are masked, not resolved; a match confirms exact Ubuntu GCC 13.3.0 '
            'reproduction of that function body from the candidate crate version.',
        ],
    }
    (HERE / 'census.json').write_text(json.dumps(out, separators=(',', ':')) + '\n')
    tot_b = sum(s['bytes'] for s in summary.values())
    print(f'GENERATED: {len(admitted_records)} TLS-relaxed FDEs, {tot_b:,} B across {len(summary)} crates')
    print('  TLS sites:', dict(sorted(tls_site_totals.items())))
    for crate, st in out['summary'].items():
        print(
            f"  {crate:22s} {st['windows']:4d}w  {st['bytes']:8,} B  "
            f"(single={st['single_copy_windows']}, multi={st['multi_copy_windows']})"
        )
    return out


def verify():
    """Independently verify committed census.json, bodies.bin, and licenses.json against node #115."""
    census = json.loads((HERE / 'census.json').read_text())
    bodies = (HERE / 'bodies.bin').read_bytes()
    if len(bodies) != census['bodies']['bytes'] or sha(bodies) != census['bodies']['sha256']:
        raise ValueError('bodies.bin size or sha256 mismatch')

    licenses = json.loads((HERE / 'licenses.json').read_text())
    if set(licenses.keys()) != set(census['lock_packages'].keys()):
        raise ValueError('licenses.json keys do not match census lock_packages')
    for pkg, lic in licenses.items():
        if not isinstance(lic, str) or not lic.strip():
            raise ValueError(f'Empty license for {pkg}')
        for bad in FORBIDDEN_LICENSE_TOKENS:
            if bad in lic:
                raise ValueError(f'Non-permissive license token {bad} for {pkg}: {lic}')

    for lf in census['lockfiles']:
        p = ROOT / lf['lockfile']
        if not p.is_file() or sha(p.read_bytes()) != lf['sha256']:
            raise ValueError(f'Lockfile missing or sha256 mismatch: {lf["lockfile"]}')

    data = (ROOT / TARGET).read_bytes()
    if sha(data) != census['target']['sha256']:
        raise ValueError('target binary sha256 mismatch')
    text_sec = next(s for s in sections(data) if s['name'] == '.text')
    text_va = text_sec['address']
    text_off = text_sec['offset']
    text_end = text_va + text_sec['size']

    _, fdes, _ = fde_extents(data)
    fde_map = {(f['start'], f['end']) for f in fdes if f['section'] == '.text'}

    merged_cov = load_covered_intervals(include_siblings=True)
    cov_starts = [a for a, _ in merged_cov]

    prev_end = 0
    seen_ids = set()
    summary_check = defaultdict(lambda: {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
    tls_site_check = defaultdict(int)
    total_bytes = 0

    for idx, rec in enumerate(census['records']):
        rid = rec['id']
        if not rid.startswith(WINDOW_PREFIX) or rid in seen_ids:
            raise ValueError(f'record {idx} invalid/duplicate id: {rid}')
        seen_ids.add(rid)
        if not rec['native'] or not rec['fde_backed'] or rec['assembly_object']:
            raise ValueError(f'record {idx} must be native FDE-backed C/C++ record')
        if rec['dependency'] != 'native-libraries' or rec['component'] != 'foundation':
            raise ValueError(f'record {idx} invalid attribution: {rec.get("dependency")}/{rec.get("component")}')
        start, end = rec['start'], rec['end']
        n = end - start
        if not (text_va <= start < end <= text_end):
            raise ValueError(f'record {idx} outside .text')
        if start < prev_end:
            raise ValueError(f'record {idx} overlaps earlier record ({hex(start)} < {hex(prev_end)})')
        prev_end = end
        if (start, end) not in fde_map:
            raise ValueError(f'record {idx} ({hex(start)}..{hex(end)}) not in .text FDE map')
        if overlaps_any(merged_cov, cov_starts, start, end):
            raise ValueError(f'record {idx} ({hex(start)}..{hex(end)}) overlaps existing/sibling window')
        if rec['copy_count'] == 1:
            if n < MIN_BYTES:
                raise ValueError(f'record {idx} below MIN_BYTES: {n}')
        else:
            if n < MULTI_MIN_BYTES:
                raise ValueError(f'record {idx} multi-copy below {MULTI_MIN_BYTES} B: {n}')
            if rec['distinct_source_functions'] < rec['copy_count']:
                raise ValueError(f'record {idx} unexplained multi-copy')

        tls_rows = [r for r in rec['relocations'] if r.get('relaxation') in TLS_RELAXATIONS]
        if not tls_rows:
            raise ValueError(f'record {idx} has no psABI TLS relaxation site')
        for r in tls_rows:
            tls_site_check[r['relaxation']] += 1

        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        if sha(src) != rec['source_body_sha256']:
            raise ValueError(f'record {idx} source_body_sha256 mismatch')
        off = text_off + start - text_va
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
        if cmp_res['relocation_bytes'] * 2 > n:
            raise ValueError(f'record {idx} exceeds 50% relocation-mask cap')

        total_bytes += n
        sc = summary_check[rec['crate']]
        sc['windows'] += 1
        sc['bytes'] += n
        sc['raw_equal_windows'] += int(rec['raw_equal'])

    for crate, st in census['summary'].items():
        sc = summary_check[crate]
        if (sc['windows'], sc['bytes'], sc['raw_equal_windows']) != (
            st['windows'], st['bytes'], st['raw_equal_windows']
        ):
            raise ValueError(f'summary mismatch for {crate}')
    if set(summary_check.keys()) != set(census['summary'].keys()):
        raise ValueError('summary crate keys mismatch')
    if dict(sorted(tls_site_check.items())) != census['tls_relaxation_sites']:
        raise ValueError('tls_relaxation_sites summary mismatch')

    print(
        f'OK: {len(census["records"])} TLS-relaxed FDEs, {total_bytes:,} bytes '
        f'across {len(census["summary"])} native crates ({dict(sorted(tls_site_check.items()))})'
    )


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--verify':
        verify()
        return
    if len(sys.argv) >= 4 and sys.argv[1] == '--generate':
        sysroot = Path(sys.argv[2])
        specs = []
        for raw in sys.argv[3:]:
            parts = raw.split('::')
            if len(parts) != 4:
                raise SystemExit(f'Expected crate::version::lock_rel::archive_path, got: {raw}')
            specs.append(tuple(parts))
        generate(sysroot, specs)
        return
    raise SystemExit(
        'Usage: census.py --verify  OR  census.py --generate <sysroot-lib-dir> '
        '<crate::version::lock_rel::archive_path> [...]'
    )


if __name__ == '__main__':
    main()
