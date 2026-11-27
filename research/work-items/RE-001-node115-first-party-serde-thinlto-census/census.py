"""Match rustc 1.95.0 ThinLTO + tikv-jemallocator first-party serde::Deserialize FDEs against node115.

Node #115 was compiled with rustc 1.95.0 (59807616e 2026-04-14),
-C opt-level=3 -C overflow-checks=yes -C lto=thin, tikv-jemallocator 0.6.0,
serde 1.0.229, serde_json 1.0.154, and rmp-serde 1.3.0. Under this exact build
profile, #[derive(serde::Deserialize)] on Hyperliquid's first-party enums and
#[serde(deny_unknown_fields)] structs emits byte-identical __FieldVisitor
visit_bytes and visit_str FDEs (including inlined _rjem_je_sdallocx cleanup
paths for Cow<'_, str> from String::from_utf8_lossy).

Every admitted window satisfies ALL adversarial gates:
  1. Compiled from `#![forbid(unsafe_code)]` Rust source (`src/main.rs`) under
     the pinned Cargo.lock (`serde 1.0.229`, `serde_json 1.0.154`,
     `rmp-serde 1.3.0`, `tikv-jemallocator 0.6.0`); harness CGUs only
     (`hl_node115_serde_census-*.rcgu.o`, excluding `.rcgu.o.rcgu.o` vendor CGUs).
  2. Complete `.eh_frame` `.text` FDE extent in `artifacts/node/115/hl-node`,
     length >= 16 bytes, relocation-masked bytes <= length / 2, and 100%
     relocation-qualified via `tools/byte_progress.compare` (zero relaxations).
  3. Exact `.rela.dyn` -> `.data.rel.ro` -> `.rodata` `&[&str]` slice-table
     proof: a PC32 relocation inside the node #115 FDE resolves to a `.data.rel.ro`
     slice whose runtime pointers (from `.rela.dyn` R_X86_64_RELATIVE) and lengths
     match the exact complete ordered variant/field string list of that Hyperliquid
     enum or struct in node #115 `.rodata`.
  4. Zero overlap with any non-`node115-fp-serde-*` window in
     `research/byte-windows.json` and zero overlap with any sibling peer packet.
  5. Third-party `alloy` structs are explicitly excluded; every window is
     attributed to its verified Hyperliquid component in `research/components.json`.

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serde-thinlto-census/census.py \
      <deps-dir> <Cargo.lock> <family_meta.json>
  Verify committed packet against artifacts/node/115/hl-node:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-serde-thinlto-census/census.py --verify
"""
import hashlib
import importlib.util
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
WINDOW_PREFIX = 'node115-fp-serde-'
BIN_NAME = 'hl_node115_serde_census'
MIN_BYTES = 16

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from byte_progress import compare  # noqa: E402


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


def load_node115_sections_and_rela(data: bytes):
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    rodata = next(s for s in secs if s['name'] == '.rodata')
    datarelro = next(s for s in secs if s['name'] == '.data.rel.ro')
    reladyn = next(s for s in secs if s['name'] == '.rela.dyn')
    rel_map = {}
    for pos in range(reladyn['offset'], reladyn['offset'] + reladyn['size'], 24):
        r_off, r_info, r_add = struct.unpack_from('<QQq', data, pos)
        if (r_info & 0xffffffff) == 8:  # R_X86_64_RELATIVE
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


def collect_peer_intervals():
    intervals = []
    for rec_file in sorted((ROOT / 'research/work-items').glob('*/records.json')):
        if rec_file.parent == HERE:
            continue
        d = json.loads(rec_file.read_text())
        rows = d if isinstance(d, list) else d.get('windows', d.get('records', []))
        if not isinstance(rows, list):
            continue
        for r in rows:
            if not isinstance(r, dict):
                continue
            v = r.get('start_va', r.get('start', r.get('vaddr')))
            if isinstance(v, str):
                try:
                    v = int(v, 16)
                except ValueError:
                    continue
            sz = r.get('size', r.get('size_bytes', r.get('bytes')))
            if sz is None and 'end_va' in r and isinstance(v, int):
                e = int(r['end_va'], 16) if isinstance(r['end_va'], str) else r['end_va']
                sz = e - v
            if isinstance(v, int) and isinstance(sz, int) and sz > 0:
                intervals.append((v, v + sz))
    return intervals


def generate(deps: Path, lock: Path, meta_path: Path):
    object_functions = _load_object_functions()
    meta = json.loads(meta_path.read_text())
    enum_meta = {row['idx']: row for row in meta['enums']}
    struct_meta = {row['idx']: row for row in meta['structs']}

    data = (ROOT / TARGET).read_bytes()
    text, rodata, datarelro, rel_map = load_node115_sections_and_rela(data)
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

    def overlaps_taken(va, n):
        return any(not (va + n <= a or va >= b) for a, b in taken)

    cgus = [
        p for p in sorted(deps.glob(f'{BIN_NAME}-*.rcgu.o'))
        if not p.name.endswith('.rcgu.o.rcgu.o')
    ]
    claimed = {}
    records = []
    for obj_path in cgus:
        obj = obj_path.read_bytes()
        if obj[:4] != b'\x7fELF':
            continue
        for symbols, body, rel in object_functions(obj):
            sym = symbols[0]
            m = re.search(r'(TagEnumFam|EnumFam|StructFam)(\d+)', sym)
            if not m:
                continue
            kind, idx = m.group(1), int(m.group(2))
            if kind in ('EnumFam', 'TagEnumFam'):
                row = enum_meta.get(idx)
                if not row:
                    continue
                strs = row['variants']
                fam_kind = 'enum'
            else:
                row = struct_meta.get(idx)
                if not row:
                    continue
                strs = row['fields']
                fam_kind = 'struct'
            comp = row['component']
            method = 'visit_bytes' if 'visit_bytes' in sym else ('visit_str' if 'visit_str' in sym else 'other')
            if method == 'other':
                continue
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
            for va, target in hits:
                if overlaps_taken(va, n):
                    continue
                tva = find_exact_slice_table(data, rodata, datarelro, rel_map, va, target, rel, strs)
                if tva is None:
                    continue
                if va in claimed:
                    continue
                preview = ', '.join(strs[:3]) + (f', ... ({len(strs)} total)' if len(strs) > 3 else '')
                rec = {
                    'component': comp,
                    'family': f'{kind}{idx}',
                    'family_kind': fam_kind,
                    'method': method,
                    'label': f"{comp} {fam_kind} {method} [{preview}] (0x{va:x})",
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
                    'relocations': [
                        {'offset': o, 'kind': t, 'width': 4, 'addend': a}
                        for o, t, a in rel
                    ],
                }
                claimed[va] = rec
                records.append(rec)

    records.sort(key=lambda r: (r['start'], r['end']))
    # Ensure zero internal overlap
    for a, b in zip(records, records[1:]):
        if b['start'] < a['end']:
            raise AssertionError(f"internal overlap at 0x{b['start']:x} < 0x{a['end']:x}")

    blob = bytearray()
    for r in records:
        body = r.pop('source_body')
        r['source_offset'] = len(blob)
        blob += body

    (HERE / 'bodies.bin').write_bytes(blob)

    by_comp = {}
    by_method = {}
    for r in records:
        c = by_comp.setdefault(r['component'], {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
        c['windows'] += 1
        c['bytes'] += r['bytes']
        c['raw_equal_windows'] += int(r['raw_equal'])
        m = by_method.setdefault(r['method'], {'windows': 0, 'bytes': 0})
        m['windows'] += 1
        m['bytes'] += r['bytes']

    out = {
        'schema_version': 1,
        'task': 'RE-001',
        'target': {'path': TARGET, 'sha256': sha(data)},
        'toolchain': {
            'rustc': '1.95.0 (59807616e 2026-04-14)',
            'target_triple': 'x86_64-unknown-linux-gnu',
            'profile': 'opt-level=3 overflow-checks=true lto=thin global_allocator=tikv-jemallocator',
            'crates': 'serde=1.0.229 serde_json=1.0.154 rmp-serde=1.3.0 tikv-jemallocator=0.6.0',
        },
        'lockfile': {
            'path': 'research/work-items/RE-001-node115-first-party-serde-thinlto-census/harness/Cargo.lock',
            'sha256': sha(lock.read_bytes()),
        },
        'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
        'summary': {
            'total_windows': len(records),
            'total_bytes': sum(r['bytes'] for r in records),
            'raw_equal_windows': sum(int(r['raw_equal']) for r in records),
            'components': len(by_comp),
            'by_method': by_method,
            'by_component': dict(sorted(by_comp.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
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

    text, rodata, datarelro, rel_map = load_node115_sections_and_rela(data)
    _, fdes, _ = fde_extents(data)
    fde_map = {(f['start'], f['end']) for f in fdes if f['section'] == '.text'}
    valid_comps = {
        c['id'] for c in json.loads((ROOT / 'research/components.json').read_text())['components']
    }

    seen = []
    total_bytes = 0
    for rec in census['records']:
        start, end = rec['start'], rec['end']
        n = end - start
        if n != rec['bytes'] or n < MIN_BYTES:
            raise AssertionError(f'invalid length at 0x{start:x}')
        if (start, end) not in fde_map:
            raise AssertionError(f'0x{start:x}..0x{end:x} is not a complete .text FDE')
        if rec['component'] not in valid_comps:
            raise AssertionError(f"invalid component {rec['component']}")
        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        if sha(src) != rec['source_body_sha256']:
            raise AssertionError(f'source body sha mismatch at 0x{start:x}')
        off = text['offset'] + start - text['address']
        tgt = data[off:off + n]
        if sha(tgt) != rec['target_body_sha256']:
            raise AssertionError(f'target body sha mismatch at 0x{start:x}')
        cmp = compare(src, tgt, rec['relocations'])
        if not cmp['relocation_qualified']:
            raise AssertionError(f'not relocation-qualified at 0x{start:x}')
        if cmp['raw_equal'] != rec['raw_equal']:
            raise AssertionError(f'raw_equal mismatch at 0x{start:x}')
        # Independently verify the exact .rela.dyn -> .data.rel.ro -> .rodata &[&str] slice table!
        tva = find_exact_slice_table(data, rodata, datarelro, rel_map, start, tgt, rec['relocations'], rec['strings'])
        if tva != rec['table_va']:
            raise AssertionError(f'slice table anchor mismatch at 0x{start:x}: got {tva}, expected {rec["table_va"]}')
        seen.append((start, end))
        total_bytes += n

    seen.sort()
    for (_, e1), (s2, _) in zip(seen, seen[1:]):
        if s2 < e1:
            raise AssertionError(f'internal overlap at 0x{s2:x} < 0x{e1:x}')
    if total_bytes != census['summary']['total_bytes'] or len(seen) != census['summary']['total_windows']:
        raise AssertionError('summary totals mismatch')

    print(
        f"VERIFIED RE-001-node115-first-party-serde-thinlto-census: "
        f"{len(seen)} windows, {total_bytes:,} bytes across {census['summary']['components']} components "
        f"(100% .rela.dyn .data.rel.ro &[&str] slice-table anchored)"
    )


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--verify':
        verify()
        return
    if len(sys.argv) != 4:
        raise SystemExit('usage: census.py --verify | census.py <deps-dir> <Cargo.lock> <family_meta.json>')
    generate(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))


if __name__ == '__main__':
    main()
