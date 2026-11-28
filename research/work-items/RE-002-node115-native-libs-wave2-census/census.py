"""Match Ubuntu 24.04 GCC 13.3.0 native C/C++/asm library archives against node #115 .text.

Node #115 (`artifacts/node/115/hl-node`) was built on Ubuntu 24.04 with
`GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0` and linked with LLD 22.1.2.
RE-002-node115-vendor-census previously matched 5.06 MB of native-libraries code
but missed ~1.26 MB of strict byte-comparable non-TLS native code for four
concrete reasons:
  1. `tikv-jemalloc-sys 0.6.1` was built without `stats` + `profiling`, and
     multi-function `.pic.o` sections were dropped by `value == 0 && s[5] == size`.
  2. `zstd-sys` and `lz4-sys` resolved newer upstream C releases (`zstd 1.5.7`,
     `lz4 1.10.0`) instead of node #115's exact `zstd-sys 2.0.13+zstd.1.5.6` and
     `lz4-sys 1.9.4`.
  3. `blst 0.3.17` lacked `portable`, `secp256k1-sys 0.10.0/0.11.0` lacked
     `recovery`, and `sha3-asm 0.1.9` (`keccak-asm`) / `blake3 1.8.5` SIMD `.S`
     assembly objects (`STT_NOTYPE` labels) were omitted.
  4. `vendor_census.py` rejected multi-copy native functions with psABI
     GOTPCRELX relaxations (dropping COMDAT C++ templates in `librocksdb-sys`
     and `ctl.pic.o` / legacy `HUF_decompress4X4` copies).

This census strictly enforces:
  - Native C/C++/asm archives (`*.a`) only; all records carry
    `dependency: "native-libraries"` and `component: "foundation"` (zero
    first-party credit).
  - Exact relocation masking limited to four-byte PC32/PLT32/GOTPCREL/GOTPCRELX/
    REX_GOTPCRELX (kinds 2, 4, 9, 41, 42) and exact psABI `gotpcrelx-mov-lea` /
    `gotpcrelx-call` relaxations checked via `tools/byte_progress.py`.
  - length >= 32 B (single-copy) or >= 64 B (multi-copy), unmasked bytes >= 16,
    relocation-masked bytes * 2 <= length (after relaxations).
  - Zero collision against `rustc 1.95.0` sysroot `*.rlib` masked signatures and
    zero cross-crate ambiguity.
  - Strict link-level distinct-function proof for multi-copy (`k > 1`):
    `STB_LOCAL` functions are keyed by `(member, symbol)` and `STB_GLOBAL`/
    `STB_WEAK` symbols are keyed by `symbol` (respecting LLD COMDAT merging),
    requiring `distinct_source_functions >= copy_count`.
  - Complete `.text` FDE membership for all compiler-emitted C/C++ records, and
    explicit `.S` entry-label boundaries inside node #115's non-FDE gap
    `0x633a4d2..0x6349360` for `blake3` SIMD assembly (all `R_X86_64_PC32`,
    0 non-relocation diffs).
  - Zero overlap against `research/byte-windows.json` (excluding this packet's
    own `node115-native-w2-*` IDs once consolidated) and all sibling
    `research/work-items/*/{records.json,census.json}` packets.

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-native-libs-wave2-census/census.py \
      --generate <sysroot-lib-dir> <crate:version:lockfile:archive> [...]
  Verify committed packet against artifacts/node/115/hl-node:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-002-node115-native-libs-wave2-census/census.py --verify
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
WINDOW_PREFIX = 'node115-native-w2-'
MIN_BYTES = 32
MULTI_MIN_BYTES = 64
MIN_UNMASKED = 16
ALLOWED_RELA_KINDS = {2, 4, 9, 41, 42}
BLAKE3_ASM_GAP = (0x633a4d2, 0x6349360)
BLAKE3_ASM_MEMBERS = {
    'blake3_sse2_x86-64_unix.o',
    'blake3_sse41_x86-64_unix.o',
    'blake3_avx2_x86-64_unix.o',
    'blake3_avx512_x86-64_unix.o',
}
FORBIDDEN_LICENSE_TOKENS = ('GPL-2.0-only', 'GPL-3.0-only', 'AGPL-', 'LGPL-')

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from byte_progress import RELAXATIONS, compare, relaxation_bytes  # noqa: E402


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


def extract_elf_functions(ob: bytes):
    """Extract all STT_FUNC spans >= MIN_BYTES from executable sections of an ELF64 .o."""
    shs, names = _parse_elf_sections(ob)
    shnum = len(shs)
    relas_by_sec = {}
    sym_sh = str_sh = None
    for s in shs:
        if s[1] == 4:  # SHT_RELA
            relas_by_sec[s[7]] = [
                struct.unpack_from('<QQq', ob, s[4] + j * 24)
                for j in range(s[5] // 24)
            ]
        elif s[1] == 2:  # SHT_SYMTAB
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
        if not (sec[2] & 0x4) or st_val + st_size > sec[5]:  # SHF_EXECINSTR
            continue
        span_key = (st_shndx, st_val, st_size)
        if span_key in seen_spans:
            continue
        seen_spans.add(span_key)
        end = ob.index(b'\x00', str_sh[4] + st_name)
        snm = ob[str_sh[4] + st_name:end].decode('ascii', 'replace')
        bind = st_info >> 4  # 0=STB_LOCAL, 1=STB_GLOBAL, 2=STB_WEAK
        body = ob[sec[4] + st_val:sec[4] + st_val + st_size]
        srelas = []
        bad = False
        for roff, rinfo, radd in relas_by_sec.get(st_shndx, ()):
            rtype = rinfo & 0xffffffff
            if st_val <= roff < st_val + st_size:
                if rtype not in ALLOWED_RELA_KINDS or roff - st_val + 4 > st_size:
                    bad = True
                    break
                srelas.append((roff - st_val, rtype, radd))
        if not bad:
            out.append((snm, bind, names[st_shndx], body, tuple(sorted(srelas))))
    return out


def extract_blake3_asm_functions(ob: bytes):
    """Extract contiguous entry-label spans from blake3 handwritten x86-64 .S objects."""
    shs, names = _parse_elf_sections(ob)
    text_idx = None
    relas = []
    sym_sh = str_sh = None
    for idx, s in enumerate(shs):
        if names[idx] == '.text':
            text_idx = idx
        elif s[1] == 2:
            sym_sh = s
            str_sh = shs[s[6]]
    if text_idx is None or sym_sh is None:
        return []
    for s in shs:
        if s[1] == 4 and s[7] == text_idx:
            relas = [
                struct.unpack_from('<QQq', ob, s[4] + j * 24)
                for j in range(s[5] // 24)
            ]
    t_sh = shs[text_idx]
    t_data = ob[t_sh[4]:t_sh[4] + t_sh[5]]
    syms = []
    for j in range(sym_sh[5] // 24):
        st_name, st_info, _st_other, st_shndx, st_val, _st_size = struct.unpack_from(
            '<IBBHQQ', ob, sym_sh[4] + j * 24
        )
        if st_shndx != text_idx or not st_name:
            continue
        end = ob.index(b'\x00', str_sh[4] + st_name)
        snm = ob[str_sh[4] + st_name:end].decode('ascii', 'replace')
        if snm.startswith('blake3_'):
            syms.append((st_val, snm))
    syms.sort()
    out = []
    for k, (sv, snm) in enumerate(syms):
        nxt = syms[k + 1][0] if k + 1 < len(syms) else len(t_data)
        if nxt - sv < MIN_BYTES:
            continue
        body = t_data[sv:nxt]
        srelas = []
        for roff, rinfo, radd in relas:
            rtype = rinfo & 0xffffffff
            if sv <= roff < nxt:
                if rtype not in ALLOWED_RELA_KINDS or roff - sv + 4 > len(body):
                    raise ValueError(f'unexpected blake3 relocation kind {rtype} in {snm}')
                srelas.append((roff - sv, rtype, radd))
        out.append((snm, 1, '.text', body, tuple(sorted(srelas))))
    return out


def masked_signature(body: bytes, srelas):
    """Canonical signature masking 4-byte relocation fields and relaxable GOTPCRELX opcodes."""
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
    return (len(body), sha(bytes(buf)), tuple((off, kind) for off, kind, _ in srelas))


def strict_match(src: bytes, tgt: bytes, srelas):
    """Return byte_progress-compatible relocation list if src matches tgt, else None."""
    if len(src) != len(tgt):
        return None
    rel_rows = []
    mask = set()
    for off, kind, add in srelas:
        row = {'offset': off, 'kind': kind, 'width': 4, 'addend': add}
        field = set(range(off, off + 4))
        if kind in (41, 42):
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
    """Generate census.json and bodies.bin from built native .a archives."""
    std_sigs = set()
    for rlib in sorted(sysroot.glob('*.rlib')):
        for _member, obj in parse_ar(rlib.read_bytes()):
            for _snm, _bind, _sec, body, srelas in extract_elf_functions(obj):
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
    blake3_asm_items = []

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
            if crate == 'blake3' and any(member.endswith(m) for m in BLAKE3_ASM_MEMBERS):
                for snm, bind, secnm, body, srelas in extract_blake3_asm_functions(obj):
                    blake3_asm_items.append((crate, version, ar_path.name, member, snm, secnm, body, srelas))
                continue
            for snm, bind, secnm, body, srelas in extract_elf_functions(obj):
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
        # Strict link-level distinct function count (LLD merges STB_GLOBAL/STB_WEAK COMDATs).
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
            rel_rows = strict_match(rep[7], tgt, rep[8])
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

    # Match handwritten blake3 SIMD .S functions strictly inside non-FDE gap BLAKE3_ASM_GAP.
    gap_s, gap_e = BLAKE3_ASM_GAP
    gap_bytes = text_data[gap_s - text_va:gap_e - text_va]
    for crate, version, ar_name, member, snm, secnm, body, srelas in blake3_asm_items:
        rmask = set()
        for off, _, _ in srelas:
            rmask.update(range(off, off + 4))
        anchor_off = next(
            a for a in range(len(body) - 16)
            if all((a + d) not in rmask for d in range(16))
        )
        anchor = body[anchor_off:anchor_off + 16]
        hits = []
        pos = 0
        while True:
            p = gap_bytes.find(anchor, pos)
            if p < 0:
                break
            sp = p - anchor_off
            if 0 <= sp and sp + len(body) <= len(gap_bytes):
                s = gap_s + sp
                e = s + len(body)
                tgt = gap_bytes[sp:sp + len(body)]
                rel_rows = strict_match(body, tgt, srelas)
                if rel_rows is not None and not overlaps_any(merged_cov, cov_starts, s, e):
                    hits.append((s, e, tgt, rel_rows))
            pos = p + 1
        if len(hits) != 1:
            raise ValueError(f'blake3 asm symbol {snm} expected 1 unique match in gap, got {len(hits)}')
        s, e, tgt, rel_rows = hits[0]
        admitted_records.append({
            'symbol': snm,
            'member': member,
            'archive': ar_name,
            'section': secnm,
            'native': True,
            'fde_backed': False,
            'assembly_object': True,
            'crate': crate,
            'dependency': 'native-libraries',
            'component': 'foundation',
            'start': s,
            'end': e,
            'target_body_sha256': sha(tgt),
            'source_body': body,
            'source_body_sha256': sha(body),
            'raw_equal': tgt == body,
            'relocations': rel_rows,
            'candidate_versions': [version],
            'candidate_symbols': [snm],
            'copy_count': 1,
            'distinct_source_functions': 1,
            'boundary_basis': (
                f'Source .S entry labels and .text endpoint inside non-FDE '
                f'assembly gap {hex(gap_s)}..{hex(gap_e)}'
            ),
        })

    # Sort deterministically by virtual address and check strict internal disjointness.
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
            'profile': 'cargo release native C/C++/asm builds under exact Ubuntu 24.04 GCC 13.3.0',
        },
        'lockfiles': lock_files,
        'lock_packages': dict(sorted(lock_packages.items())),
        'inputs': inputs,
        'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
        'minimum_bytes': MIN_BYTES,
        'multi_copy_minimum_bytes': MULTI_MIN_BYTES,
        'minimum_unmasked_bytes': MIN_UNMASKED,
        'multi_copy_rule': (
            'native C/C++ objects only; length >= 64 B; single crate; zero sysroot std collision; '
            'link-level distinct_source_functions >= copy_count (STB_LOCAL keyed by (member, symbol), '
            'STB_GLOBAL/STB_WEAK keyed by symbol); each copy passes exact byte_progress.compare'
        ),
        'rejected_counts': rejected_counts,
        'summary': dict(sorted(summary.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
        'records': admitted_records,
        'limits': [
            'Native C/C++/asm library objects (*.a) only; all windows are dependency-tagged '
            '("native-libraries", component "foundation") and award zero first-party credit.',
            'Relocations are limited strictly to four-byte PC32/PLT32/GOTPCREL/GOTPCRELX/'
            'REX_GOTPCRELX and exact psABI gotpcrelx-mov-lea / gotpcrelx-call relaxations.',
            'Native functions using x86-64 TLS GD->LE (R_X86_64_TLSGD, kind 19, ~600 KB in '
            'librocksdb-sys) or IE->LE (R_X86_64_GOTTPOFF, kind 22, ~136 KB in tikv-jemalloc-sys) '
            'linker relaxations are excluded under current unmodified tools/byte_progress.py rules.',
            'Relocation fields are masked, not resolved; a match confirms exact Ubuntu GCC 13.3.0 '
            'reproduction of that function body from the candidate crate version(s).',
        ],
    }
    (HERE / 'census.json').write_text(json.dumps(out, separators=(',', ':')) + '\n')
    tot_b = sum(s['bytes'] for s in summary.values())
    tot_raw = sum(s['raw_equal_windows'] for s in summary.values())
    print(f'GENERATED: {len(admitted_records)} windows, {tot_b:,} B, {tot_raw} raw-equal across {len(summary)} crates')
    for crate, st in out['summary'].items():
        print(
            f"  {crate:22s} {st['windows']:4d}w  {st['bytes']:8,} B  "
            f"(single={st['single_copy_windows']}, multi={st['multi_copy_windows']}, raw={st['raw_equal_windows']})"
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
    total_bytes = 0
    raw_equal = 0
    fde_count = 0
    asm_count = 0

    for idx, rec in enumerate(census['records']):
        rid = rec['id']
        if not rid.startswith(WINDOW_PREFIX) or rid in seen_ids:
            raise ValueError(f'record {idx} invalid/duplicate id: {rid}')
        seen_ids.add(rid)
        if not rec['native'] or rec['dependency'] != 'native-libraries' or rec['component'] != 'foundation':
            raise ValueError(f'record {idx} invalid attribution: {rec.get("dependency")}/{rec.get("component")}')
        start, end = rec['start'], rec['end']
        n = end - start
        if not (text_va <= start < end <= text_end):
            raise ValueError(f'record {idx} outside .text')
        if start < prev_end:
            raise ValueError(f'record {idx} overlaps earlier record ({hex(start)} < {hex(prev_end)})')
        prev_end = end
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
        if rec['fde_backed']:
            if (start, end) not in fde_map:
                raise ValueError(f'record {idx} ({hex(start)}..{hex(end)}) not in .text FDE map')
            fde_count += 1
        else:
            if not rec['assembly_object'] or rec['crate'] != 'blake3':
                raise ValueError(f'record {idx} non-FDE record only allowed for blake3 assembly')
            if not (BLAKE3_ASM_GAP[0] <= start < end <= BLAKE3_ASM_GAP[1]):
                raise ValueError(f'record {idx} outside blake3 non-FDE gap')
            asm_count += 1

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
        raw_equal += int(rec['raw_equal'])
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

    print(
        f'OK: {len(census["records"])} windows ({fde_count} FDEs + {asm_count} blake3 .S asm), '
        f'{total_bytes:,} bytes, {raw_equal} raw-equal across {len(census["summary"])} native crates'
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
