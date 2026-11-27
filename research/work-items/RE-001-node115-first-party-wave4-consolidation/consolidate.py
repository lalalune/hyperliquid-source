"""Consolidate verified Phase 4 peer first-party compiled-byte packets into Wave 4 census.

Re-compiles each landed Wave-4-safe peer packet's committed Rust source under
rustc 1.95.0 (59807616e 2026-04-14) -C opt-level=3 -C overflow-checks=yes
(plus -C lto=thin -C save-temps for ThinLTO packets, or reads committed
bodies.bin for verified Cargo ThinLTO+tikv-jemallocator packets), authenticates
every non-overlapping FDE against artifacts/node/115/hl-node via
tools/byte_progress.compare, and emits a single deterministic bodies.bin and
census.json for registration in research/byte-windows.json as node115-fp-w4-*.

Usage (repository root):
  Generate:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave4-consolidation/consolidate.py
  Verify committed packet against artifacts/node/115/hl-node:
    PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-001-node115-first-party-wave4-consolidation/consolidate.py --verify
"""
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
WINDOW_PREFIX = 'node115-fp-w4-'

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from byte_progress import compare  # noqa: E402

# Landed Wave-4-safe peer first-party compiled-byte packets (deterministic order).
PEER_PACKETS = [
    ('RE-001-node115-foundation-byte-matches', [('rlib', 'lib.rs'), ('thinlto', 'thinlto.rs')]),
    ('RE-005-node115-bincode-fork-cgu-100pct-identity', [('bodies', 'bodies.bin')]),
    ('RE-005-node115-bincode-fork-cgu-thinlto-matches', [('thinlto', 'main.rs')]),
    ('RE-005-node115-bincode-fork-gate-closure', [('rlib', 'lib.rs')]),
    ('RE-006-node115-stream-e1-thinlto-byte-matches', [('thinlto', 'main.rs')]),
    ('RE-007-node115-stream-e2-logic-byte-matches', [('rlib', 'lib.rs')]),
    ('RE-008-node115-consensus-staking-byte-matches', [('rlib', 'lib.rs')]),
    ('RE-008-node115-consensus-staking-debug-byte-matches', [('thinlto', 'main.rs')]),
    ('RE-009-node115-storage-abci-debug-byte-matches', [('thinlto', 'main.rs')]),
    ('RE-011-node115-stream-f-logic-byte-matches', [('rlib', 'lib.rs')]),
    ('RE-012-node115-stream-c-byte-matches', [('rlib', 'lib.rs')]),
    ('RE-015-node115-constants-gate-closure', [('rlib', 'lib.rs')]),
    ('RE-015-node115-constants-thinlto-byte-matches', [('bodies', 'bodies.bin')]),
    ('RE-015-node115-stream-f-byte-matches', [('rlib', 'lib.rs')]),
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


def parse_row(r: dict):
    v = r.get('start_va', r.get('start', r.get('vaddr')))
    if isinstance(v, str):
        v = int(v, 16)
    sz = r.get('size', r.get('size_bytes', r.get('bytes')))
    if sz is None and 'end_va' in r:
        e = int(r['end_va'], 16) if isinstance(r['end_va'], str) else r['end_va']
        sz = e - v
    elif sz is None and 'end' in r:
        e = int(r['end'], 16) if isinstance(r['end'], str) else r['end']
        sz = e - v
    return int(v), int(v) + int(sz), int(sz), r['component'], r.get('label', f"0x{int(v):x}")


def compile_packet_objects(pkt_dir: Path, specs, object_functions):
    """Return list of (symbol, body, relocs) compiled from packet .rs files."""
    funcs_by_len = {}
    with tempfile.TemporaryDirectory(prefix='hl-w4-') as tmp:
        tmp_p = Path(tmp)
        for idx, (mode, fname) in enumerate(specs):
            src = pkt_dir / fname
            if mode == 'rlib':
                out_obj = tmp_p / f'obj_{idx}.o'
                cmd = [
                    'rustc', '+1.95.0', '--edition=2021', '--crate-type=rlib',
                    '--crate-name', f'w4_rlib_{idx}',
                    '-C', 'opt-level=3', '-C', 'overflow-checks=yes',
                    '-C', 'codegen-units=1', '--emit=obj',
                    str(src), '-o', str(out_obj),
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                for syms, body, rel in object_functions(out_obj.read_bytes()):
                    funcs_by_len.setdefault(len(body), []).append((syms[0], body, rel))
            elif mode == 'thinlto':
                out_bin = tmp_p / f'bin_{idx}'
                cmd = [
                    'rustc', '+1.95.0', '--edition=2021',
                    '--crate-name', f'w4_thin_{idx}',
                    '-C', 'opt-level=3', '-C', 'overflow-checks=yes',
                    '-C', 'lto=thin', '-C', 'save-temps',
                    str(src), '-o', str(out_bin),
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                for obj in sorted(tmp_p.glob(f'bin_{idx}.*.rcgu.o')):
                    raw = obj.read_bytes()
                    if raw[:4] != b'\x7fELF':
                        continue
                    for syms, body, rel in object_functions(raw):
                        funcs_by_len.setdefault(len(body), []).append((syms[0], body, rel))
    return funcs_by_len


def generate():
    object_functions = _load_object_functions()
    data = (ROOT / TARGET).read_bytes()
    text = next(s for s in sections(data) if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    fde_set = {(f['start'], f['end']) for f in fdes if f['section'] == '.text'}

    reg = json.loads((ROOT / 'research/byte-windows.json').read_text())
    taken = [
        (w['start'], w['end'])
        for w in reg['windows']
        if w['target'] == 'node115' and not w['id'].startswith(WINDOW_PREFIX)
    ]

    def overlaps(s, e, intervals):
        return any(s < b and a < e for a, b in intervals)

    claimed = {}
    records = []
    packet_stats = {}

    for pkt_name, specs in PEER_PACKETS:
        pkt_dir = ROOT / 'research/work-items' / pkt_name
        d = json.loads((pkt_dir / 'records.json').read_text())
        rows = d if isinstance(d, list) else d.get('windows', d.get('records', []))

        is_bodies = len(specs) == 1 and specs[0][0] == 'bodies'
        bodies_raw = (pkt_dir / specs[0][1]).read_bytes() if is_bodies else None
        funcs_by_len = None if is_bodies else compile_packet_objects(pkt_dir, specs, object_functions)

        added_w = added_b = skipped = 0
        for r in rows:
            start, end, sz, comp, label = parse_row(r)
            if overlaps(start, end, taken) or start in claimed:
                skipped += 1
                continue
            if (start, end) not in fde_set:
                raise AssertionError(f'{pkt_name}: 0x{start:x}..0x{end:x} is not a complete .text FDE')
            off = text['offset'] + start - text['address']
            tgt = data[off:off + sz]

            if is_bodies:
                so = r['source_offset']
                body = bodies_raw[so:so + sz]
                rels = r['relocations']
                sym = r.get('symbol', r.get('id', label))
                cmp = compare(body, tgt, rels)
                if not cmp['relocation_qualified']:
                    raise AssertionError(f'{pkt_name} bodies.bin record 0x{start:x} failed compare')
            else:
                matched = None
                for sym_c, body_c, rel_c in funcs_by_len.get(sz, []):
                    rels_c = [{'offset': o, 'kind': k, 'width': 4, 'addend': a} for o, k, a in rel_c]
                    try:
                        cmp = compare(body_c, tgt, rels_c)
                    except ValueError:
                        continue
                    if cmp['relocation_qualified']:
                        matched = (sym_c, body_c, rels_c, cmp)
                        break
                if matched is None:
                    raise AssertionError(f'{pkt_name}: failed to match compiled FDE 0x{start:x} ({sz} B, {label})')
                sym, body, rels, cmp = matched

            rec = {
                'component': comp,
                'source_packet': pkt_name,
                'label': label,
                'symbol': sym,
                'start': start,
                'end': end,
                'bytes': sz,
                'target_body_sha256': sha(tgt),
                'source_body': body,
                'source_body_sha256': sha(body),
                'raw_equal': cmp['raw_equal'],
                'relocations': rels,
            }
            claimed[start] = rec
            records.append(rec)
            taken.append((start, end))
            added_w += 1
            added_b += sz

        packet_stats[pkt_name] = {'windows': added_w, 'bytes': added_b, 'skipped_existing': skipped}

    records.sort(key=lambda r: (r['start'], r['end']))
    for a, b in zip(records, records[1:]):
        if b['start'] < a['end']:
            raise AssertionError(f"internal overlap 0x{b['start']:x} < 0x{a['end']:x}")

    blob = bytearray()
    for r in records:
        body = r.pop('source_body')
        r['source_offset'] = len(blob)
        blob += body
    (HERE / 'bodies.bin').write_bytes(blob)

    by_comp = {}
    for r in records:
        c = by_comp.setdefault(r['component'], {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
        c['windows'] += 1
        c['bytes'] += r['bytes']
        c['raw_equal_windows'] += int(r['raw_equal'])

    out = {
        'schema_version': 1,
        'task': 'RE-001',
        'target': {'path': TARGET, 'sha256': sha(data)},
        'toolchain': {
            'rustc': '1.95.0 (59807616e 2026-04-14)',
            'target_triple': 'x86_64-unknown-linux-gnu',
            'profile': 'opt-level=3 overflow-checks=yes (+ lto=thin / tikv-jemallocator per source packet)',
        },
        'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
        'summary': {
            'total_windows': len(records),
            'total_bytes': sum(r['bytes'] for r in records),
            'raw_equal_windows': sum(int(r['raw_equal']) for r in records),
            'components': len(by_comp),
            'packets_consolidated': len(packet_stats),
            'by_component': dict(sorted(by_comp.items(), key=lambda kv: (-kv[1]['bytes'], kv[0]))),
            'by_packet': packet_stats,
        },
        'records': records,
    }
    (HERE / 'census.json').write_text(json.dumps(out, indent=1) + '\n')
    print(f"CONSOLIDATED: {len(records)} windows, {len(blob):,} B across {len(by_comp)} components from {len(packet_stats)} peer packets!")
    for k, v in out['summary']['by_component'].items():
        print(f"  {k:16s}: {v['windows']:4d} w | {v['bytes']:7,d} B | raw={v['raw_equal_windows']}")


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
    fde_set = {(f['start'], f['end']) for f in fdes if f['section'] == '.text'}
    valid_comps = {
        c['id'] for c in json.loads((ROOT / 'research/components.json').read_text())['components']
    }

    seen = []
    total_bytes = 0
    for rec in census['records']:
        start, end = rec['start'], rec['end']
        n = end - start
        if n != rec['bytes'] or (start, end) not in fde_set:
            raise AssertionError(f'invalid FDE at 0x{start:x}')
        if rec['component'] not in valid_comps:
            raise AssertionError(f"invalid component {rec['component']}")
        src = bodies[rec['source_offset']:rec['source_offset'] + n]
        if sha(src) != rec['source_body_sha256']:
            raise AssertionError(f'source sha mismatch at 0x{start:x}')
        off = text['offset'] + start - text['address']
        tgt = data[off:off + n]
        if sha(tgt) != rec['target_body_sha256']:
            raise AssertionError(f'target sha mismatch at 0x{start:x}')
        cmp = compare(src, tgt, rec['relocations'])
        if not cmp['relocation_qualified'] or cmp['raw_equal'] != rec['raw_equal']:
            raise AssertionError(f'compare mismatch at 0x{start:x}')
        seen.append((start, end))
        total_bytes += n

    seen.sort()
    for (_, e1), (s2, _) in zip(seen, seen[1:]):
        if s2 < e1:
            raise AssertionError(f'internal overlap at 0x{s2:x} < 0x{e1:x}')
    if total_bytes != census['summary']['total_bytes'] or len(seen) != census['summary']['total_windows']:
        raise AssertionError('summary mismatch')
    print(
        f"VERIFIED RE-001-node115-first-party-wave4-consolidation: "
        f"{len(seen)} windows, {total_bytes:,} bytes across {census['summary']['components']} components"
    )


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--verify':
        verify()
    else:
        generate()


if __name__ == '__main__':
    main()
