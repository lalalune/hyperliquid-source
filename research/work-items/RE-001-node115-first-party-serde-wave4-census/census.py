"""Match rustc 1.95.0 ThinLTO + tikv-jemallocator first-party serde::Deserialize Wave 4 FDEs against node115.

Extends RE-001-node115-first-party-serde-wave3-census with 33 newly mined pure
Hyperliquid compact-wire enum & struct families (all verified inside l1/src/*
CGUs with exact .rela.dyn -> .data.rel.ro -> .rodata &[&str] slice-table proof,
including the 112-variant compact action wire enum, 18-variant risk/margin wire
enum, Side ('B'/'Bid', 'A'/'Ask'), TrailingStopKind ('Pct'/'Px', 'pct'/'px'),
and compact l1/src/action & l1/src/clearinghouse wire types), compiled under
serde_json = "=1.0.140", rmp-serde = "=1.3.0", serde = "=1.0.229", and
tikv-jemallocator = "=0.6.0".

Every admitted window satisfies ALL adversarial gates:
  1. Compiled from `#![forbid(unsafe_code)]` Rust source (`harness/src/main.rs`)
     under pinned Cargo.lock; harness CGUs only (`hl_node115_serde_w4_census-*`,
     excluding `.rcgu.o.rcgu.o` vendor CGUs) and first-party defining symbols only
     (`__FieldVisitor::visit_bytes` and `__FieldVisitor::visit_str`).
  2. Complete `.eh_frame` `.text` FDE extent in `artifacts/node/115/hl-node`,
     length >= 16 bytes, relocation-masked bytes <= length / 2, and 100%
     relocation-qualified via `tools/byte_progress.compare` (zero relaxations).
  3. Exact `.rela.dyn` -> `.data.rel.ro` -> `.rodata` `&[&str]` slice-table
     proof matching the complete ordered variant/field string list in node #115.
  4. Zero overlap internally, with `research/byte-windows.json`, and across all
     sibling peer packets.
  5. Valid Hyperliquid component IDs in `research/components.json`.

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serde-wave4-census/census.py
  Verify committed packet against artifacts/node/115/hl-node:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serde-wave4-census/census.py --verify
"""
import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
WINDOW_PREFIX = 'node115-fp-serde4-'
BIN_NAME = 'hl_node115_serde_w4_census'
MIN_BYTES = 16

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from byte_progress import compare  # noqa: E402

DEFAULT_DEPS = ROOT / 'work/target/thinlto-surge/x86_64-unknown-linux-gnu/release/deps'


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_functions_xindex(obj: bytes):
    """ELF64 .o parser supporting >65280 sections (SHN_XINDEX / SHT_SYMTAB_SHNDX)."""
    e_shoff = struct.unpack_from('<Q', obj, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', obj, 58)
    sh0 = struct.unpack_from('<IIQQQQIIQQ', obj, e_shoff)
    if e_shnum == 0:
        e_shnum = sh0[5]
    if e_shstrndx == 0xffff:
        e_shstrndx = sh0[6]
    shs = [struct.unpack_from('<IIQQQQIIQQ', obj, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    symtab_idx = next(i for i, s in enumerate(shs) if s[1] == 2)
    sym_sh = shs[symtab_idx]
    str_sh = shs[sym_sh[6]]
    shndx_arr = None
    for s in shs:
        if s[1] == 18:
            cnt = s[5] // 4
            shndx_arr = struct.unpack_from(f'<{cnt}I', obj, s[4])
            break
    rela_by_sec = {}
    for s in shs:
        if s[1] == 4:
            rela_by_sec[s[7]] = s
    sec_syms = {}
    nsyms = sym_sh[5] // 24
    for idx in range(nsyms):
        st_name, st_info, _, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', obj, sym_sh[4] + idx * 24)
        if st_size == 0 or (st_info & 0xf) != 2:
            continue
        sec_i = shndx_arr[idx] if st_shndx == 0xffff and shndx_arr is not None else st_shndx
        if sec_i == 0 or sec_i >= e_shnum:
            continue
        if st_value != 0 or st_size != shs[sec_i][5]:
            continue
        off = str_sh[4] + st_name
        name = obj[off:obj.index(b'\x00', off)].decode('utf-8', 'replace')
        sec_syms.setdefault(sec_i, []).append(name)
    for sec_i, names in sec_syms.items():
        sh = shs[sec_i]
        if (sh[2] & 0x4) == 0:
            continue
        body = obj[sh[4]:sh[4] + sh[5]]
        rels = []
        rsh = rela_by_sec.get(sec_i)
        if rsh is not None:
            for pos in range(rsh[4], rsh[4] + rsh[5], 24):
                r_off, r_info, r_add = struct.unpack_from('<QQq', obj, pos)
                rels.append((r_off, r_info & 0xffffffff, r_add))
        yield names, body, rels


def load_node115_sections_and_rela(data: bytes):
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    rodata = next(s for s in secs if s['name'] == '.rodata')
    datarelro = next(s for s in secs if s['name'] == '.data.rel.ro')
    reladyn = next(s for s in secs if s['name'] == '.rela.dyn')
    rel_map = {}
    for pos in range(reladyn['offset'], reladyn['offset'] + reladyn['size'], 24):
        r_off, r_info, r_add = struct.unpack_from('<QQq', data, pos)
        if (r_info & 0xffffffff) == 8:
            rel_map[r_off] = r_add
    return text, rodata, datarelro, rel_map


def verify_slice_table_at(data: bytes, rodata: dict, datarelro: dict, rel_map: dict, tva: int, strs: list) -> bool:
    if not strs:
        return False
    dr_va, dr_off, dr_sz = datarelro['address'], datarelro['offset'], datarelro['size']
    ro_va, ro_off, ro_end = rodata['address'], rodata['offset'], rodata['address'] + rodata['size']
    if not (dr_va <= tva <= dr_va + dr_sz - 16 * len(strs)):
        return False
    doff = dr_off + tva - dr_va
    for i, s in enumerate(strs):
        sb = s.encode('utf-8')
        sp = rel_map.get(tva + 16 * i, 0)
        sl = struct.unpack_from('<Q', data, doff + 16 * i + 8)[0]
        if sl != len(sb) or not (ro_va <= sp <= ro_end - sl):
            return False
        roff = ro_off + sp - ro_va
        if data[roff:roff + sl] != sb:
            return False
    return True


def find_exact_slice_table(data: bytes, rodata: dict, datarelro: dict, rel_map: dict, va: int, tgt: bytes, rel, strs: list):
    n = len(tgt)
    for item in rel:
        if isinstance(item, dict):
            o, rt, add = item['offset'], item['kind'], item['addend']
        else:
            o, rt, add = item
        if rt != 2 or o + 4 > n:
            continue
        disp = struct.unpack_from('<i', tgt, o)[0]
        tva = va + o - add + disp
        if verify_slice_table_at(data, rodata, datarelro, rel_map, tva, strs):
            return tva
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


def generate(deps: Path = DEFAULT_DEPS):
    valid_components = {c['id'] for c in json.loads((ROOT / 'research/components.json').read_text())['components']}
    data = (ROOT / TARGET).read_bytes()
    text, rodata, datarelro, rel_map = load_node115_sections_and_rela(data)
    _, fdes, _ = fde_extents(data)
    starts_cnt = {}
    for f in fdes:
        starts_cnt[f['start']] = starts_cnt.get(f['start'], 0) + 1
    by_len = {}
    for f in fdes:
        if f['section'] == '.text' and starts_cnt[f['start']] == 1:
            n = f['end'] - f['start']
            if n < MIN_BYTES:
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

    meta = json.loads((HERE / 'family_meta.json').read_text())
    comp_meta = {r['idx']: r for r in meta['compact']}
    w3e_meta = {r['idx']: r for r in meta['w3_enums']}
    w3a_meta = {r['idx']: r for r in meta['w3_alias_enums']}
    sym_re = re.compile(r'(TagCompactEnum|UntagCompactEnum|CompactEnum|TagCompactStruct|CompactStruct|TagW3Enum|UntagW3Enum|W3Enum|TagW3AliasEnum|UntagW3AliasEnum|W3AliasEnum)(\d+)')

    claimed = {}
    records = []
    cgus = [p for p in sorted(deps.glob(f'{BIN_NAME}-*.rcgu.o')) if not p.name.endswith('.rcgu.o.rcgu.o')]
    for obj_path in cgus:
        obj = obj_path.read_bytes()
        if obj[:4] != b'\x7fELF':
            continue
        for symbols, body, rel in object_functions_xindex(obj):
            sym = symbols[0]
            if BIN_NAME not in sym:
                continue
            method = 'visit_bytes' if 'visit_bytes' in sym else ('visit_str' if 'visit_str' in sym else 'other')
            if method == 'other':
                continue
            m = sym_re.search(sym)
            if not m:
                continue
            kind, idx = m.group(1), int(m.group(2))
            if 'Compact' in kind:
                row = comp_meta.get(idx)
            elif 'W3Alias' in kind:
                row = w3a_meta.get(idx)
            else:
                row = w3e_meta.get(idx)
            if not row:
                continue
            strs = row['strings']
            fam_kind = 'struct' if 'Struct' in kind else 'enum'
            comp = row['component']
            if comp not in valid_components:
                raise AssertionError(f'invalid component {comp}')
            n = len(body)
            if n < MIN_BYTES or n not in by_len:
                continue
            mask = set()
            for o, _, _ in rel:
                mask.update(range(o, o + 4))
            if len(mask) * 2 > n:
                continue
            keep = [i for i in range(n) if i not in mask]
            probe = bytes(body[i] for i in keep)
            hits = [(va, t) for va, t in by_len[n] if bytes(t[i] for i in keep) == probe]
            if not hits:
                continue
            body_sha = sha(body)
            rel_rows = [{'offset': o, 'kind': t, 'width': 4, 'addend': a} for o, t, a in rel]
            for va, target in hits:
                if _overlaps(merged, m_starts, va, va + n) or va in claimed:
                    continue
                tva = find_exact_slice_table(data, rodata, datarelro, rel_map, va, target, rel, strs)
                if tva is None:
                    continue
                cmp = compare(body, target, rel_rows)
                if not cmp['relocation_qualified'] or cmp.get('relaxations'):
                    continue
                preview = ', '.join(strs[:4]) + (f', ... ({len(strs)} total)' if len(strs) > 4 else '')
                rec = {
                    'component': comp,
                    'family': f'{kind}{idx}',
                    'family_kind': fam_kind,
                    'method': method,
                    'label': f'{comp} {fam_kind} {method} [{preview}] (0x{va:x})',
                    'symbol': sym,
                    'cgu': obj_path.name,
                    'start': va,
                    'end': va + n,
                    'bytes': n,
                    'table_va': tva,
                    'strings': strs,
                    'target_body_sha256': sha(target),
                    'source_body': body,
                    'source_body_sha256': body_sha,
                    'raw_equal': target == body,
                    'relocations': rel_rows,
                }
                claimed[va] = rec
                records.append(rec)

    records.sort(key=lambda r: (r['start'], r['end']))
    for a, b in zip(records, records[1:]):
        if b['start'] < a['end']:
            raise AssertionError(f"internal overlap at 0x{b['start']:x} < 0x{a['end']:x}")

    blob = bytearray()
    for r in records:
        body = r.pop('source_body')
        r['source_offset'] = len(blob)
        blob += body
    (HERE / 'bodies.bin').write_bytes(blob)

    by_comp, by_method = {}, {}
    for r in records:
        c = by_comp.setdefault(r['component'], {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
        c['windows'] += 1
        c['bytes'] += r['bytes']
        c['raw_equal_windows'] += int(r['raw_equal'])
        m = by_method.setdefault(r['method'], {'windows': 0, 'bytes': 0})
        m['windows'] += 1
        m['bytes'] += r['bytes']

    lock_path = HERE / 'harness/Cargo.lock'
    out = {
        'schema_version': 1,
        'task': 'RE-001',
        'window_prefix': WINDOW_PREFIX,
        'target': {'path': TARGET, 'sha256': sha(data)},
        'toolchain': {
            'rustc': '1.95.0 (59807616e 2026-04-14)',
            'target_triple': 'x86_64-unknown-linux-gnu',
            'profile': 'opt-level=3 overflow-checks=true lto=thin global_allocator=tikv-jemallocator',
        },
        'lockfile': {'path': str(lock_path.relative_to(ROOT)), 'sha256': sha(lock_path.read_bytes())},
        'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
        'summary': {
            'total_windows': len(records),
            'total_bytes': sum(r['bytes'] for r in records),
            'raw_equal_windows': sum(int(r['raw_equal']) for r in records),
            'relaxed_windows': 0,
            'components': len(by_comp),
            'unique_families': len({tuple(r['strings']) for r in records}),
            'by_method': by_method,
            'by_component': dict(sorted(by_comp.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
        },
        'records': records,
    }
    (HERE / 'census.json').write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps(out['summary'], indent=1))


def verify():
    valid_components = {c['id'] for c in json.loads((ROOT / 'research/components.json').read_text())['components']}
    census = json.loads((HERE / 'census.json').read_text())
    bodies = (HERE / 'bodies.bin').read_bytes()
    data = (ROOT / TARGET).read_bytes()
    if sha(data) != census['target']['sha256']:
        raise AssertionError('target node115 SHA-256 mismatch')
    if sha(bodies) != census['bodies']['sha256'] or len(bodies) != census['bodies']['bytes']:
        raise AssertionError('bodies.bin digest/size mismatch')

    text, rodata, datarelro, rel_map = load_node115_sections_and_rela(data)
    _, fdes, _ = fde_extents(data)
    fde_map = {(f['start'], f['end']) for f in fdes if f['section'] == '.text'}

    seen = []
    total_bytes = 0
    for rec in census['records']:
        start, end = rec['start'], rec['end']
        n = end - start
        if n < MIN_BYTES or n != rec['bytes'] or (start, end) not in fde_map:
            raise AssertionError(f'invalid FDE at 0x{start:x}')
        if rec['component'] not in valid_components:
            raise AssertionError(f"invalid component {rec['component']}")
        if rec['method'] not in {'visit_bytes', 'visit_str'} or BIN_NAME not in rec['symbol']:
            raise AssertionError(f"invalid symbol/method {rec['symbol']}")
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
        tva = find_exact_slice_table(data, rodata, datarelro, rel_map, start, tgt, rec['relocations'], rec['strings'])
        if tva != rec['table_va']:
            raise AssertionError(f'slice table proof failed at 0x{start:x}')
        seen.append((start, end))
        total_bytes += n

    seen.sort()
    for a, b in zip(seen, seen[1:]):
        if b[0] < a[1]:
            raise AssertionError(f'internal overlap at 0x{b[0]:x} < 0x{a[1]:x}')
    if total_bytes != census['summary']['total_bytes'] or len(seen) != census['summary']['total_windows']:
        raise AssertionError('summary totals mismatch')
    print(
        f"VERIFIED RE-001-node115-first-party-serde-wave4-census: {len(seen)} windows, "
        f"{total_bytes:,} bytes across {census['summary']['components']} components "
        f"({census['summary']['unique_families']} families, 0 relaxed)"
    )


def main():
    if '--verify' in sys.argv[1:]:
        verify()
    else:
        generate()


if __name__ == '__main__':
    main()
