#!/usr/bin/env python3
"""Compile and verify first-party node #115 Rust functions against target .text FDEs.

Compiles `src/node115-first-party-byte-census/src/lib.rs` with rustc 1.95.0
(`--edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes --emit=obj`),
extracts each function section and its 4-byte PC-relative/GOT relocation records,
and verifies every target window against authenticated `artifacts/node/115/hl-node`
using `tools/byte_progress.py::compare`.

Static compilation and parsing only; no captured executable is run.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'research/work-items/RE-002-node115-std-census'))
from artifacts import manifest_item  # noqa: E402
from byte_progress import compare  # noqa: E402
from census import object_functions  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

HERE = Path(__file__).resolve().parent
TARGET_REL = 'artifacts/node/115/hl-node'
CRATE_SRC_REL = 'src/node115-first-party-byte-census/src/lib.rs'
RUSTC_FLAGS = [
    '--edition=2021',
    '--crate-type=rlib',
    '--crate-name=node115_first_party_byte_census',
    '-C', 'opt-level=3',
    '-C', 'overflow-checks=yes',
    '--emit=obj',
]

# Exact first-party function mapping:
# (symbol_match_tokens, id_prefix, component, label, expected_vas, anchor)
SPECS = [
    # Leaf helpers
    (('fp_slice20_equal',), 'slice20-equal', 'l1-shared',
     'l1/raw_signature_tracker slice20 equality',
     [0x5436860], 'research/work-items/RE-001-node115-slice20-equal/README.md'),
    (('fp_fee_window_scan',), 'fee-window-scan', 'fees',
     'l1/fees binary64 descending window scan',
     [0x36e1b10], 'research/work-items/RE-004-fee-window-scan-115/README.md'),
    (('fp_sub256_borrow',), 'sub256-borrow', 'assets',
     'l1/qtys 256-bit unsigned subtraction with borrow',
     [0x2ccdd80, 0x43be060, 0x564c830], 'research/work-items/RE-001-node115-sub256-borrow/README.md'),
    (('fp_bounded_offset',), 'bounded-offset', 'foundation',
     'base VecDeque bounded ring offset search',
     [0x45514d0], 'research/work-items/RE-001-node115-ring-offset/README.md'),
    (('fp_two_span_projection',), 'two-span-projection', 'foundation',
     'base VecDeque 80-byte two-span iterator',
     [0x152e360], 'research/work-items/RE-001-node115-two-span-projection/README.md'),

    # Enum wire-name visit_str codecs (RMP + JSON serde visitors)
    (('chain_name', 'visit_str_rmp'), 'chain-name-rmp', 'constants',
     'global_constants ChainName RMP visit_str',
     [0x14be010, 0x2690cd0, 0x4682610, 0x57c3520], 'research/work-items/RE-015-chain-codec-115/README.md'),
    (('chain_name', 'visit_str_json'), 'chain-name-json', 'constants',
     'global_constants ChainName JSON visit_str',
     [0x14be0b0, 0x2690d70, 0x46826b0, 0x57c3470], 'research/work-items/RE-015-chain-codec-115/README.md'),
    (('spot_mark', 'visit_str_rmp'), 'spot-mark-rmp', 'constants',
     'global_constants SpotMarkKind RMP visit_str',
     [0x22e20d0, 0x3d47cb0, 0x535bee0], 'research/work-items/RE-015-spot-mark-codec-115/README.md'),
    (('tif', 'visit_str_rmp'), 'tif-rmp', 'orderbook',
     'l1/book Tif RMP visit_str',
     [0x25cee60, 0x4447430, 0x5171260], 'src/node115-tif-name-codec/README.md'),
    (('tif', 'visit_str_json'), 'tif-json', 'orderbook',
     'l1/book Tif JSON visit_str',
     [0x25ced60, 0x4447330], 'src/node115-tif-name-codec/README.md'),
    (('outcome_kind', 'visit_str_rmp'), 'outcome-kind-rmp', 'risk',
     'l1/clearinghouse OutcomeKind RMP visit_str',
     [0x25d3ca0, 0x44649e0, 0x5479a10], 'src/node115-oracle-outcome-kind/README.md'),
    (('margin_mode', 'visit_str_rmp'), 'margin-mode-rmp', 'risk',
     'l1/clearinghouse MarginMode RMP visit_str',
     [0x2868990, 0x3bcf9e0, 0x59fdec0], 'research/work-items/RE-007-margin-mode-codec-115/README.md'),
    (('borrow_lend_op', 'visit_str_rmp'), 'borrow-lend-op-rmp', 'risk',
     'l1/bole Operation RMP visit_str',
     [0x2691210, 0x3d440a0, 0x57c3760], 'research/work-items/RE-007-borrow-lend-codec-115/README.md'),
    (('borrow_lend_op', 'visit_str_json'), 'borrow-lend-op-json', 'risk',
     'l1/bole Operation JSON visit_str',
     [0x2691150, 0x3d44140], 'research/work-items/RE-007-borrow-lend-codec-115/README.md'),
    (('borrow_lend_field', 'visit_str_rmp'), 'borrow-lend-field-rmp', 'risk',
     'l1/bole BorrowLendField RMP visit_str',
     [0x2869450, 0x467fba0, 0x534bf90], 'research/work-items/RE-007-borrow-lend-codec-115/README.md'),
    (('bridge_event', 'visit_str_rmp'), 'bridge-event-rmp', 'bridge',
     'l1/bridge BridgeEvent RMP visit_str',
     [0x2864d00, 0x4446560, 0x5ae4620], 'research/work-items/bridge-event-name-codec-115/README.md'),
    (('bridge_event', 'visit_str_json'), 'bridge-event-json', 'bridge',
     'l1/bridge BridgeEvent JSON visit_str',
     [0x2864e60, 0x44466c0], 'research/work-items/bridge-event-name-codec-115/README.md'),
    (('hip3_disabled', 'visit_str_rmp'), 'hip3-disabled-rmp', 'dex-registry',
     'l1/dex_registry DisabledState RMP visit_str',
     [0x2b955c0, 0x4446d20, 0x546a380], 'src/node115-hip3-disabled-state-codec/README.md'),
    (('hip3_disabled', 'visit_str_json'), 'hip3-disabled-json', 'dex-registry',
     'l1/dex_registry DisabledState JSON visit_str',
     [0x2b954f0, 0x4446dd0], 'src/node115-hip3-disabled-state-codec/README.md'),
    (('evm_tx_type', 'visit_str_rmp'), 'evm-tx-type-rmp', 'evm',
     'l1/evm EvmTxType RMP visit_str',
     [0x22dc290, 0x44458a0, 0x5ae3fc0], 'research/work-items/evm-tx-type-name-codec-115/README.md'),
    (('evm_tx_type', 'visit_str_json'), 'evm-tx-type-json', 'evm',
     'l1/evm EvmTxType JSON visit_str',
     [0x22dde20, 0x4445960], 'research/work-items/evm-tx-type-name-codec-115/README.md'),
    (('evm_precompile_outcome', 'visit_str_rmp'), 'evm-precompile-outcome-rmp', 'evm',
     'l1/evm ReadPrecompileOutcomeName RMP visit_str',
     [0x2692a20], 'research/work-items/evm-call-outcome-codec-115/README.md'),
    (('abstraction_kind', 'visit_str_rmp'), 'abstraction-kind-rmp', 'exchange',
     'l1/exchange AbstractionKind RMP visit_str',
     [0x23c65f0, 0x3bdd720, 0x4d6b5d0], 'research/work-items/RE-015-abstraction-kind-codec-115/README.md'),
    (('abstraction_kind', 'visit_str_json'), 'abstraction-kind-json', 'exchange',
     'l1/exchange AbstractionKind JSON visit_str',
     [0x23c6720, 0x3bdd5e0], 'research/work-items/RE-015-abstraction-kind-codec-115/README.md'),
    (('vote_choice', 'visit_str_rmp'), 'vote-choice-rmp', 'consensus',
     'l1/governance VoteChoice RMP visit_str',
     [0x23c18b0, 0x3bd6f00, 0x4d69bd0], 'src/node115-governance-codec/README.md'),
    (('proposal_cat', 'visit_str_rmp'), 'proposal-cat-rmp', 'consensus',
     'l1/governance ProposalCategory RMP visit_str',
     [0x23c2fb0, 0x3bd7c80, 0x4d6a370], 'src/node115-governance-codec/README.md'),
    (('proposal_cat', 'visit_str_json'), 'proposal-cat-json', 'consensus',
     'l1/governance ProposalCategory JSON visit_str',
     [0x23c2ed0, 0x3bd7ba0], 'src/node115-governance-codec/README.md'),

    # Wave 2: Action dispatch (92-variant Action, 114-variant short tags, 16-variant PerpDeploy),
    # 79-variant node environment selector, Hip3Star (8 variants), and Main/Hip3 DEX state
    (('action92', 'visit_str_rmp'), 'action92-rmp', 'action-dispatch',
     'l1/action Action (92-variant) RMP visit_str',
     [0x2ba1af0, 0x3662730, 0x4d67530], 'research/work-items/RE-010-action-type-matcher-115/README.md'),
    (('action92', 'visit_str_json'), 'action92-json', 'action-dispatch',
     'l1/action Action (92-variant) JSON visit_str',
     [0x2ba0a70, 0x36616b0], 'research/work-items/RE-010-action-type-matcher-115/README.md'),
    (('env79', 'visit_str_rmp'), 'env79-rmp', 'constants',
     'global_constants NodeEnv (79-variant) RMP visit_str',
     [0x14c12b0], 'research/work-items/RE-010-env79-variant-matchers-115/README.md'),
    (('env79', 'visit_str_json'), 'env79-json', 'constants',
     'global_constants NodeEnv (79-variant) JSON visit_str',
     [0x14c07c0, 0x1774100], 'research/work-items/RE-010-env79-variant-matchers-115/README.md'),
    (('short114', 'visit_str_rmp'), 'short114-rmp', 'action-dispatch',
     'l1/action ShortActionTag (114-variant) RMP visit_str',
     [0x287ec80, 0x468fbd0, 0x5357ff0], 'research/work-items/RE-010-enum-variant-matchers-115/README.md'),
    (('short114', 'visit_str_json'), 'short114-json', 'action-dispatch',
     'l1/action ShortActionTag (114-variant) JSON visit_str',
     [0x287e450, 0x468f3a0], 'research/work-items/RE-010-enum-variant-matchers-115/README.md'),
    (('perp16', 'visit_str_rmp'), 'perp16-rmp', 'action-dispatch',
     'l1/exchange PerpDeploy (16-variant + alias) RMP visit_str',
     [0x2ba5c90, 0x444f660, 0x5471cb0], 'research/work-items/RE-010-enum-variant-matchers-115/README.md'),
    (('perp16', 'visit_str_json'), 'perp16-json', 'action-dispatch',
     'l1/exchange PerpDeploy (16-variant + alias) JSON visit_str',
     [0x2ba5930, 0x444f9b0], 'research/work-items/RE-010-enum-variant-matchers-115/README.md'),
    (('hip3star', 'visit_str_rmp'), 'hip3star-rmp', 'dex-registry',
     'l1/dex_registry Hip3Star (8-variant) RMP visit_str',
     [0x2ba41c0, 0x444db70, 0x5470720], 'research/work-items/dex-registry-sub-deployers-115/README.md'),
    (('hip3star', 'visit_str_json'), 'hip3star-json', 'dex-registry',
     'l1/dex_registry Hip3Star (8-variant) JSON visit_str',
     [0x2ba4030, 0x444dce0], 'research/work-items/dex-registry-sub-deployers-115/README.md'),
    (('main_hip3', 'visit_str_rmp'), 'main-hip3-rmp', 'dex-registry',
     'l1/dex_registry Main/Hip3 RMP visit_str',
     [0x2b94d80, 0x4440220, 0x5469f10], 'research/work-items/dex-registry-main-hip3-state-codec-115/README.md'),
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_authenticated_target(root: Path):
    item = manifest_item(root, TARGET_REL)
    data = (root / TARGET_REL).read_bytes()
    if len(data) != item['size'] or sha(data) != item['sha256']:
        raise ValueError(f'Target digest mismatch: {TARGET_REL}')
    text = next(s for s in sections(data) if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    fde_map = {f['start']: f for f in fdes if f['section'] == '.text'}
    return data, item['sha256'], text, fde_map


def compile_crate_obj(root: Path) -> tuple[bytes, str]:
    rustc = shutil.which('rustc')
    if not rustc:
        raise RuntimeError('rustc not found on PATH')
    ver = subprocess.check_output([rustc, '+1.95.0', '--version'], text=True).strip()
    if '1.95.0 (59807616e 2026-04-14)' not in ver:
        raise RuntimeError(f'Expected rustc 1.95.0 (59807616e 2026-04-14), got: {ver}')
    with tempfile.TemporaryDirectory() as tmp:
        out_obj = Path(tmp) / 'fp_census.o'
        cmd = [rustc, '+1.95.0', *RUSTC_FLAGS, '-o', str(out_obj), str(root / CRATE_SRC_REL)]
        subprocess.run(cmd, check=True)
        return out_obj.read_bytes(), ver


def build_census(root: Path):
    data, target_sha, text, fde_map = load_authenticated_target(root)
    obj, rustc_ver = compile_crate_obj(root)
    funcs = list(object_functions(obj))

    registry = json.loads((root / 'research/byte-windows.json').read_text())
    existing_dep_intervals = [
        (w['start'], w['end']) for w in registry['windows']
        if w['target'] == 'node115' and not w['id'].startswith('node115-fp-')
    ]

    records = []
    blob = bytearray()
    seen_vas = set()

    for tokens, id_prefix, component, label, expected_vas, anchor in SPECS:
        matched_funcs = [
            (syms, body, rel) for syms, body, rel in funcs
            if all(tok in syms[0] for tok in tokens)
        ]
        if len(matched_funcs) != 1:
            raise ValueError(f'Expected 1 compiled function for {tokens}, found {len(matched_funcs)}')
        syms, body, rel = matched_funcs[0]
        rel_rows = [{'offset': o, 'kind': t, 'width': 4, 'addend': a} for o, t, a in rel]
        body_sha = sha(body)
        n = len(body)

        for va in expected_vas:
            if va in seen_vas:
                raise ValueError(f'Duplicate VA in specs: {va:#x}')
            seen_vas.add(va)
            if va not in fde_map:
                raise ValueError(f'VA {va:#x} is not a .text FDE start in node #115')
            fde = fde_map[va]
            if fde['end'] - fde['start'] != n:
                raise ValueError(
                    f'{id_prefix} at {va:#x}: compiled {n}B != FDE {fde["end"] - fde["start"]}B'
                )
            if any(not (va + n <= a or va >= b) for a, b in existing_dep_intervals):
                raise ValueError(f'{id_prefix} at {va:#x} overlaps existing window in byte-windows.json')
            off = text['offset'] + va - text['address']
            target_bytes = data[off:off + n]
            cmp = compare(body, target_bytes, rel_rows)
            if not cmp['relocation_qualified']:
                raise ValueError(
                    f'{id_prefix} at {va:#x} failed relocation-qualified compare: '
                    f'non-reloc diffs at {cmp["non_relocation_difference_offsets"]}'
                )
            source_offset = len(blob)
            blob += body
            records.append({
                'id': f'node115-fp-{id_prefix}-{va:x}',
                'label': f'{label} ({va:#x})',
                'component': component,
                'symbol': syms[0],
                'anchor': anchor,
                'start': va,
                'end': va + n,
                'bytes': n,
                'target_body_sha256': sha(target_bytes),
                'source_offset': source_offset,
                'source_body_sha256': body_sha,
                'raw_equal': cmp['raw_equal'],
                'raw_equal_bytes': cmp['raw_equal_bytes'],
                'relocation_bytes': cmp['relocation_bytes'],
                'relocations': rel_rows,
            })

    by_comp = {}
    for r in records:
        c = by_comp.setdefault(r['component'], {
            'windows': 0, 'bytes': 0, 'raw_equal_bytes': 0,
            'raw_equal_windows': 0, 'relocation_qualified_windows': 0,
        })
        c['windows'] += 1
        c['bytes'] += r['bytes']
        c['raw_equal_bytes'] += r['raw_equal_bytes']
        c['raw_equal_windows'] += int(r['raw_equal'])
        c['relocation_qualified_windows'] += 1

    census = {
        'schema_version': 1,
        'task': 'RE-001',
        'target': {'path': TARGET_REL, 'sha256': target_sha},
        'source_crate': {
            'path': CRATE_SRC_REL,
            'sha256': sha((root / CRATE_SRC_REL).read_bytes()),
        },
        'toolchain': {
            'rustc': rustc_ver,
            'flags': RUSTC_FLAGS,
            'basis': 'node115 .comment rustc 1.95.0 (59807616e 2026-04-14) + RE-002 overflow-checks=true profile',
        },
        'bodies': {
            'path': 'bodies.bin',
            'bytes': len(blob),
            'sha256': sha(bytes(blob)),
        },
        'totals': {
            'windows': len(records),
            'bytes': sum(r['bytes'] for r in records),
            'raw_equal_bytes': sum(r['raw_equal_bytes'] for r in records),
            'raw_equal_windows': sum(int(r['raw_equal']) for r in records),
            'relocation_qualified_windows': len(records),
            'components': len(by_comp),
        },
        'by_component': dict(sorted(by_comp.items())),
        'records': records,
        'limits': [
            'Covers bounded first-party leaf functions and serde enum visit_str visitors only; no component gate is closed.',
            'PC-relative and GOT relocation fields (4 bytes each) are masked by tools/byte_progress.py, not resolved to linked symbols.',
            'RmpErr and JsonErr model the observed error return ABI layouts without external serde/rmp_serde/serde_json crates.',
            'Static compilation and byte comparison only; no captured executable is run.',
        ],
    }
    return census, bytes(blob)


def render_readme(census: dict) -> str:
    t = census['totals']
    lines = [
        '# RE-001: Node #115 First-Party Compiled-Byte Comparison Census',
        '',
        f"- Target: Linux x86-64 node #115, SHA-256 `{census['target']['sha256']}`",
        f"- Source crate: `{census['source_crate']['path']}` (SHA-256 `{census['source_crate']['sha256']}`)",
        f"- Compiler: `{census['toolchain']['rustc']}` with `{' '.join(census['toolchain']['flags'])}`",
        '- Scope: independently authored, dependency-free, `#![forbid(unsafe_code)]` Rust implementations compiled to exact raw-equal or relocation-qualified `.text` FDE matches. Static analysis and compilation only; no captured binary is executed.',
        '',
        '## Summary',
        '',
        f"**{t['windows']} authenticated first-party `.text` windows · {t['bytes']:,} bytes compared · "
        f"{t['raw_equal_bytes']:,}/{t['bytes']:,} ({100.0 * t['raw_equal_bytes'] / t['bytes']:.2f}%) raw-equal bytes · "
        f"{t['raw_equal_windows']}/{t['windows']} raw-equal windows · "
        f"{t['relocation_qualified_windows']}/{t['windows']} (100.00%) relocation-qualified · "
        f"{t['components']} components.**",
        '',
        '| Component | Windows | Bytes | Raw-equal bytes | Raw-equal windows | Relocation-qualified |',
        '| --- | ---: | ---: | ---: | ---: | ---: |',
    ]
    for comp, s in census['by_component'].items():
        lines.append(
            f"| `{comp}` | {s['windows']} | {s['bytes']:,} | "
            f"{s['raw_equal_bytes']:,} ({100.0 * s['raw_equal_bytes'] / s['bytes']:.2f}%) | "
            f"{s['raw_equal_windows']}/{s['windows']} | "
            f"{s['relocation_qualified_windows']}/{s['windows']} |"
        )
    lines += [
        '',
        '## Verified windows',
        '',
        '| Component | ELF VA interval | Bytes | Raw-equal | Rels | Label | Anchor |',
        '| --- | --- | ---: | ---: | ---: | --- | --- |',
    ]
    for r in census['records']:
        raw_cell = 'yes' if r['raw_equal'] else f"{r['raw_equal_bytes']}/{r['bytes']}"
        lines.append(
            f"| `{r['component']}` | `{r['start']:#x}..{r['end']:#x}` | {r['bytes']} | "
            f"{raw_cell} | "
            f"{len(r['relocations'])} | {r['label']} | `{r['anchor']}` |"
        )
    lines += [
        '',
        '## Reproduce and verify',
        '',
        '```sh',
        'python3 research/work-items/RE-001-node115-first-party-byte-census/census.py --verify --rebuild',
        'CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/fp-census \\',
        '  cargo +1.95.0 test --offline --locked --manifest-path src/node115-first-party-byte-census/Cargo.toml',
        'python3 -m unittest tests.test_first_party_byte_census_115 tests.test_node115_catalogue -v',
        '```',
        '',
        '## Limitations',
        '',
        *[f'- {lim}' for lim in census['limits']],
        '',
    ]
    return '\n'.join(lines)


def verify_committed(root: Path, rebuild: bool = False):
    census = json.loads((HERE / 'census.json').read_text())
    bodies = (HERE / 'bodies.bin').read_bytes()
    if len(bodies) != census['bodies']['bytes'] or sha(bodies) != census['bodies']['sha256']:
        raise ValueError('Committed bodies.bin digest/length mismatch')
    if sha((root / CRATE_SRC_REL).read_bytes()) != census['source_crate']['sha256']:
        raise ValueError('Committed source crate digest mismatch')

    data, target_sha, text, fde_map = load_authenticated_target(root)
    if target_sha != census['target']['sha256']:
        raise ValueError('Target binary digest mismatch')

    seen = []
    for r in census['records']:
        start, end = r['start'], r['end']
        if any(not (end <= a or start >= b) for a, b in seen):
            raise ValueError(f'Overlapping record interval {start:#x}..{end:#x}')
        seen.append((start, end))
        fde = fde_map.get(start)
        if not fde or fde['end'] != end:
            raise ValueError(f'Record {r["id"]} does not match exact FDE extent at {start:#x}')
        off = text['offset'] + start - text['address']
        target_bytes = data[off:off + end - start]
        if sha(target_bytes) != r['target_body_sha256']:
            raise ValueError(f'Target body digest mismatch for {r["id"]}')
        src_bytes = bodies[r['source_offset']:r['source_offset'] + end - start]
        if sha(src_bytes) != r['source_body_sha256']:
            raise ValueError(f'Source body digest mismatch for {r["id"]}')
        cmp = compare(src_bytes, target_bytes, r['relocations'])
        if not cmp['relocation_qualified']:
            raise ValueError(f'Record {r["id"]} failed relocation-qualified comparison')
        if cmp['raw_equal'] != r['raw_equal'] or cmp['raw_equal_bytes'] != r['raw_equal_bytes']:
            raise ValueError(f'Record {r["id"]} raw-equal accounting mismatch')

    if rebuild:
        rebuilt_census, rebuilt_bodies = build_census(root)
        if rebuilt_bodies != bodies:
            raise ValueError('Rebuilt bodies.bin differs from committed bodies.bin')
        if rebuilt_census['records'] != census['records']:
            raise ValueError('Rebuilt census records differ from committed census.json')
    return census


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate', action='store_true')
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--rebuild', action='store_true')
    args = parser.parse_args()
    if args.generate:
        census, blob = build_census(ROOT)
        (HERE / 'bodies.bin').write_bytes(blob)
        (HERE / 'census.json').write_text(json.dumps(census, indent=1) + '\n', encoding='utf-8')
        (HERE / 'README.md').write_text(render_readme(census), encoding='utf-8')
        manifest_lines = []
        for name in ('README.md', 'bodies.bin', 'census.json', 'census.py'):
            manifest_lines.append(f'{sha((HERE / name).read_bytes())}  {name}')
        (HERE / 'MANIFEST.sha256').write_text('\n'.join(manifest_lines) + '\n', encoding='utf-8')
        print(json.dumps(census['totals'], indent=2))
    elif args.verify:
        census = verify_committed(ROOT, rebuild=args.rebuild)
        print(f"Verified {census['totals']['windows']} first-party windows "
              f"({census['totals']['bytes']:,} bytes, {census['totals']['raw_equal_bytes']:,} raw-equal, "
              f"{census['totals']['components']} components; rebuild={args.rebuild}).")
    else:
        parser.error('Specify --generate or --verify')


if __name__ == '__main__':
    main()
