"""Consolidate verified Phase 8 peer first-party logic packets into Wave 8 census.

Authenticates every non-overlapping first-party FDE from 5 newly landed peer
business-logic packets:
  - RE-015-node115-stream-f-logic-wave2-byte-matches (70 FDEs, 29,815 B)
  - RE-008-node115-consensus-bincode-encode-byte-matches (23 FDEs, 6,916 B)
  - RE-010-node115-action-logic-byte-matches (17 FDEs, 3,426 B)
  - RE-005-node115-transport-runtime-logic-wave2-byte-matches (9 FDEs, 3,222 B)
  - RE-004-node115-stream-e1-fees-book-logic-wave2-byte-matches (9 FDEs, 2,483 B)

against artifacts/node/115/hl-node via tools/byte_progress.compare (reading
committed verified bodies.bin / compiled_bytes_hex or live-compiling source-only
packets via their own verified compile helpers under rustc 1.95.0), and emits a
single deterministic bodies.bin and census.json for registration in
research/byte-windows.json as node115-fp-w8-*.

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave8-consolidation/consolidate.py
  Verify committed packet against artifacts/node/115/hl-node:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave8-consolidation/consolidate.py --verify
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
WINDOW_PREFIX = 'node115-fp-w8-'

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from byte_progress import compare  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parse_int(v):
    return int(v, 16) if isinstance(v, str) else int(v)


def _normalize_relocs(rel_list: list, body: bytes):
    out = []
    for x in rel_list:
        if isinstance(x, dict):
            out.append({
                'offset': int(x['offset']),
                'kind': int(x.get('kind', x.get('type', 2))),
                'width': int(x.get('width', 4)),
                'addend': int(x.get('addend', -4)),
            })
        else:
            o = int(x)
            kind = 4 if (o > 0 and body[o - 1] in (0xe8, 0xe9)) else 2
            out.append({'offset': o, 'kind': kind, 'width': 4, 'addend': -4})
    return out


def _extract_bodies_packet(pkt_dir: Path, data: bytes, text: dict):
    rec_doc = json.loads((pkt_dir / 'records.json').read_text())
    bodies = (pkt_dir / 'bodies.bin').read_bytes()
    rows = rec_doc.get('windows', rec_doc.get('records', []))
    out = []
    for r in rows:
        start = _parse_int(r.get('start', r.get('start_va')))
        end = _parse_int(r.get('end', r.get('end_va')))
        n = end - start
        tgt = data[text['offset'] + start - text['address']:text['offset'] + end - text['address']]
        off = int(r['body_offset'])
        body = bodies[off:off + n]
        rel_rows = _normalize_relocs(r.get('relocations', []), body)
        cmp = compare(body, tgt, rel_rows)
        if not cmp['relocation_qualified'] or cmp.get('relaxations'):
            raise AssertionError(f'{pkt_dir.name}: compare failed at 0x{start:x}')
        label = r.get('label') or r.get('description') or r.get('symbol') or r.get('id')
        out.append({
            'source_packet': pkt_dir.name,
            'component': r['component'],
            'label': label,
            'symbol': r.get('symbol', r.get('id', label)),
            'start': start,
            'end': end,
            'bytes': n,
            'target_body_sha256': sha(tgt),
            'source_body': body,
            'source_body_sha256': sha(body),
            'raw_equal': cmp['raw_equal'],
            'relocations': rel_rows,
        })
    return out


def _extract_re008_hex(pkt_dir: Path, data: bytes, text: dict):
    rec_doc = json.loads((pkt_dir / 'records.json').read_text())
    rows = rec_doc.get('windows', rec_doc.get('records', []))
    out = []
    for r in rows:
        start = _parse_int(r.get('start_va', r.get('start')))
        end = _parse_int(r.get('end_va', r.get('end')))
        n = end - start
        tgt = data[text['offset'] + start - text['address']:text['offset'] + end - text['address']]
        body = bytes.fromhex(r['compiled_bytes_hex'])
        if len(body) != n:
            raise AssertionError(f'{pkt_dir.name}: len mismatch at 0x{start:x}')
        rel_rows = _normalize_relocs(r.get('relocations', []), body)
        cmp = compare(body, tgt, rel_rows)
        if not cmp['relocation_qualified'] or cmp.get('relaxations'):
            raise AssertionError(f'{pkt_dir.name}: compare failed at 0x{start:x}')
        label = r.get('label') or r.get('wrapper_symbol')
        out.append({
            'source_packet': pkt_dir.name,
            'component': r['component'],
            'label': label,
            'symbol': r.get('wrapper_symbol', label),
            'start': start,
            'end': end,
            'bytes': n,
            'target_body_sha256': sha(tgt),
            'source_body': body,
            'source_body_sha256': sha(body),
            'raw_equal': cmp['raw_equal'],
            'relocations': rel_rows,
        })
    return out


def _extract_re004_w2(pkt_dir: Path, data: bytes, text: dict):
    mod = _load_mod('re004_e1_fees_book_w2_v', pkt_dir / 'verify.py')
    pools, _ = mod.compile_sources()
    rec_doc = json.loads((pkt_dir / 'records.json').read_text())
    rows = rec_doc.get('windows', rec_doc.get('records', []))
    out = []
    for r in rows:
        start = _parse_int(r['start'])
        end = _parse_int(r['end'])
        n = end - start
        tgt = data[text['offset'] + start - text['address']:text['offset'] + end - text['address']]
        pool_name = r.get('pool', 'pie')
        matched = None
        for sym, body, raw_rels in pools[pool_name]:
            if len(body) != n:
                continue
            rel_rows = _normalize_relocs(raw_rels, body)
            cmp = compare(body, tgt, rel_rows)
            if cmp['relocation_qualified'] and not cmp.get('relaxations'):
                matched = (sym, body, rel_rows, cmp['raw_equal'])
                break
        if matched is None:
            raise AssertionError(f'{pkt_dir.name}: failed to match compiled body for 0x{start:x}')
        sym, body, rel_rows, raw_eq = matched
        out.append({
            'source_packet': pkt_dir.name,
            'component': r['component'],
            'label': r.get('label') or sym,
            'symbol': sym,
            'start': start,
            'end': end,
            'bytes': n,
            'target_body_sha256': sha(tgt),
            'source_body': body,
            'source_body_sha256': sha(body),
            'raw_equal': raw_eq,
            'relocations': rel_rows,
        })
    return out


def generate():
    valid_components = {c['id'] for c in json.loads((ROOT / 'research/components.json').read_text())['components']}
    data = (ROOT / TARGET).read_bytes()
    text = next(s for s in sections(data) if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    fde_map = {(f['start'], f['end']) for f in fdes if f['section'] == '.text'}

    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    taken = [
        (w['start'], w['end'])
        for w in registry['windows']
        if w['target'] == 'node115' and not w['id'].startswith(WINDOW_PREFIX)
    ]

    def overlaps_taken(s, e):
        return any(not (e <= a or s >= b) for a, b in taken)

    raw_records = []
    raw_records.extend(_extract_bodies_packet(
        ROOT / 'research/work-items/RE-015-node115-stream-f-logic-wave2-byte-matches', data, text
    ))
    raw_records.extend(_extract_re008_hex(
        ROOT / 'research/work-items/RE-008-node115-consensus-bincode-encode-byte-matches', data, text
    ))
    raw_records.extend(_extract_bodies_packet(
        ROOT / 'research/work-items/RE-010-node115-action-logic-byte-matches', data, text
    ))
    raw_records.extend(_extract_bodies_packet(
        ROOT / 'research/work-items/RE-005-node115-transport-runtime-logic-wave2-byte-matches', data, text
    ))
    raw_records.extend(_extract_re004_w2(
        ROOT / 'research/work-items/RE-004-node115-stream-e1-fees-book-logic-wave2-byte-matches', data, text
    ))

    records = []
    seen_starts = set()
    for r in raw_records:
        s, e = r['start'], r['end']
        if (s, e) not in fde_map:
            raise AssertionError(f'not an exact .text FDE: 0x{s:x}..0x{e:x}')
        if r['component'] not in valid_components:
            raise AssertionError(f"invalid component {r['component']}")
        if overlaps_taken(s, e) or s in seen_starts:
            raise AssertionError(f"overlap at 0x{s:x}..0x{e:x} ({r['source_packet']})")
        seen_starts.add(s)
        records.append(r)

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

    by_comp, by_pkt = {}, {}
    for r in records:
        c = by_comp.setdefault(r['component'], {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
        c['windows'] += 1
        c['bytes'] += r['bytes']
        c['raw_equal_windows'] += int(r['raw_equal'])
        p = by_pkt.setdefault(r['source_packet'], {'windows': 0, 'bytes': 0})
        p['windows'] += 1
        p['bytes'] += r['bytes']

    out = {
        'schema_version': 1,
        'task': 'RE-001',
        'window_prefix': WINDOW_PREFIX,
        'target': {'path': TARGET, 'sha256': sha(data)},
        'toolchain': {
            'rustc': '1.95.0 (59807616e 2026-04-14)',
            'target_triple': 'x86_64-unknown-linux-gnu',
        },
        'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
        'summary': {
            'total_windows': len(records),
            'total_bytes': sum(r['bytes'] for r in records),
            'raw_equal_windows': sum(int(r['raw_equal']) for r in records),
            'relaxed_windows': 0,
            'components': len(by_comp),
            'by_packet': by_pkt,
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

    text = next(s for s in sections(data) if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    fde_map = {(f['start'], f['end']) for f in fdes if f['section'] == '.text'}

    seen = []
    total_bytes = 0
    for rec in census['records']:
        start, end = rec['start'], rec['end']
        n = end - start
        if n != rec['bytes'] or (start, end) not in fde_map:
            raise AssertionError(f'invalid FDE at 0x{start:x}')
        if rec['component'] not in valid_components:
            raise AssertionError(f"invalid component {rec['component']}")
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
    print(
        f"VERIFIED RE-001-node115-first-party-wave8-consolidation: {len(seen)} windows, "
        f"{total_bytes:,} bytes across {census['summary']['components']} components "
        f"({census['summary']['raw_equal_windows']} raw-equal, 0 relaxed)"
    )


def main():
    if '--verify' in sys.argv[1:]:
        verify()
    else:
        generate()


if __name__ == '__main__':
    main()
