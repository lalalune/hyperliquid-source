#!/usr/bin/env python3
"""Generate node #115 scope and evidence tables from authenticated inputs."""
import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import subprocess
from byte_progress import fraction, load_coverage, summarize

ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE_GATES = frozenset({'mapped', 'built', 'behavior', 'identity'})
PROGRESS_START = '<!-- BEGIN GENERATED PROGRESS -->'
PROGRESS_END = '<!-- END GENERATED PROGRESS -->'

def progress_totals(components, progress):
    accepted = sum(sum(progress['components'][c['id']]['gates'].values()) for c in components)
    total = len(components) * len(progress['gates'])
    return accepted, total


def byte_cells(stats):
    if not stats or not stats['windows']:
        return '0 compared | 0 registered | 0 registered'
    return ' | '.join((fraction(stats['raw_equal_bytes'], stats['bytes']),
                       fraction(stats['raw_equal_windows'], stats['windows']),
                       fraction(stats['relocation_qualified_windows'], stats['windows'])))


def render_progress_banner(inventory, coverage):
    windows = coverage['totals'].get('node115', {}).get('windows', 0) if coverage else 0
    cards = [(inventory['rust_areas'], 'RUST IMPLEMENTATION AREAS', 'Independent, bounded source work'),
             (inventory['cargo_manifests'], 'STANDALONE CARGO MANIFESTS', 'Build scopes recorded in source'),
             (inventory['work_items'], 'DOCUMENTED WORK ITEMS', 'Research, evidence and limitations'),
             (windows, '#115 BYTE COMPARISON WINDOWS', 'All comparisons target node #115')]
    lines = ['<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="280" viewBox="0 0 1200 280" role="img" aria-labelledby="title desc">',
             '<title id="title">Hyperliquid Source research progress</title>',
             '<desc id="desc">Committed source and research inventory, not a completion percentage. Full node integration remains open.</desc>',
             '<rect width="1200" height="280" rx="20" fill="#071b22"/>',
             '<path d="M900 0 1060 160H1200M1030 0 1190 160M1130 0 1200 70" fill="none" stroke="#16383f" stroke-width="2"/>',
             '<g font-family="Arial, Helvetica, sans-serif">',
             '<text x="32" y="38" fill="#71f1c6" font-size="12" font-weight="700" letter-spacing="2">BINARY EVIDENCE → INDEPENDENT RUST</text>',
             '<text x="32" y="76" fill="#f0faf7" font-size="28" font-weight="700">Reconstruction in progress</text>',
             '<text x="1168" y="42" text-anchor="end" fill="#b0c9cb" font-size="12">IMPLEMENTATION TARGET · #115</text>']
    for index, (value, label, detail) in enumerate(cards):
        x = 32 + index * 288
        lines += [f'<rect x="{x}" y="103" width="272" height="121" rx="10" fill="#102c33" stroke="#21434a"/>',
                  f'<text x="{x + 18}" y="151" fill="#f0faf7" font-size="38" font-weight="700">{value:,}</text>',
                  f'<text x="{x + 18}" y="180" fill="#71f1c6" font-size="11" font-weight="700" letter-spacing=".6">{label}</text>',
                  f'<text x="{x + 18}" y="204" fill="#b0c9cb" font-size="11">{detail}</text>']
    lines += ['<text x="32" y="254" fill="#b0c9cb" font-size="12">Inventory counts describe work produced. Full-component acceptance and whole-node integration remain open.</text>',
              '</g>', '</svg>', '']
    return '\n'.join(lines)


def project_bytes(components, coverage):
    if not coverage:
        return None
    targets = {c['id']: c['artifact'] for c in components}
    return summarize([r for r in coverage['windows'] if targets[r['component']] == r['target']])


def render_component_progress(components, progress, coverage, link_prefix='', combined=False):
    lines = []
    rows = []
    gate_count = len(progress['gates'])
    for artifact, label in [('node115', 'Node #115 reconstruction')]:
        selected = [c for c in components if c['artifact'] == artifact]
        if not selected:
            continue
        accepted, total = progress_totals(selected, progress)
        complete = sum(all(progress['components'][c['id']]['gates'].values()) for c in selected)
        lines += [f"**{label}: {100 * accepted / total:.2f}% ({accepted}/{total} accepted gates; "
                  f"{complete}/{len(selected)} components complete).**", '']
        if not combined:
            lines += [f"| {'Required node component' if artifact.startswith('node') else 'Tracked supervisor component'} | Accepted gates | Milestones | Compared implementation bytes | Registered implementation windows |",
                      '| --- | ---: | ---: | ---: | ---: |']
        for c in selected:
            n = sum(progress['components'][c['id']]['gates'].values())
            stats = coverage['components'].get(c['id']) if coverage else None
            target = 'Node #115' + ' | ' if combined else ''
            row = (f"| [{c['name']}]({link_prefix}COMPONENTS.md#{c['id']}) | {target}{n}/{gate_count} | "
                   f"{100 * n / gate_count:.0f}% | {stats['bytes'] if stats else 0:,} | "
                   f"{stats['windows'] if stats else 0:,} |")
            (rows if combined else lines).append(row)
        if not combined:
            lines += ['']
    if combined:
        lines += ['| Component | Target | Accepted gates | Milestones | Compared implementation bytes | Registered implementation windows |',
                  '| --- | --- | ---: | ---: | ---: | ---: |', *rows, '']
    return lines


def render_dependency_progress(coverage):
    lines = ['### Existing open-source dependency comparisons', '',
             'Reuse these dependencies under their licenses; recover private changes and validate',
             'the exact versions, build and integration. These bytes are not first-party node',
             'reconstruction. Published artifacts and bitcode alone do not prove a source build.', '',
             '| Target | Dependency | Raw matching bytes / compared | Raw-equal windows | Raw + relocation-qualified windows |',
             '| --- | --- | ---: | ---: | ---: |']
    if coverage:
        for target, dependencies in coverage['dependencies'].items():
            for dependency, stats in dependencies.items():
                lines.append(f"| {target} | {dependency} | {byte_cells(stats)} |")
        if coverage.get('extent_mismatches'):
            lines += ['', '### Unmatched candidates with different extents', '',
                      'Both complete source and target extents are authenticated. These candidates have no aligned-byte comparison and contribute no byte-equality credit or aligned-window denominator. Their full hashes, bounds and evidence remain in the byte registry and generated records.', '',
                      '| Target / candidate | Attribution | Target bytes | Source bytes | Result |',
                      '| --- | --- | ---: | ---: | --- |']
            for row in coverage['extent_mismatches']:
                lines.append(f"| {row['target']}: {row['label']} | "
                             f"{row.get('dependency', row['component'])} | "
                             f"{row['target_bytes']:,} | {row['source_bytes']:,} | "
                             'Unmatched; no aligned-byte comparison |')
    return lines + ['']


def update_readme_progress(readme, block):
    if readme.count(PROGRESS_START) != 1 or readme.count(PROGRESS_END) != 1:
        raise ValueError('README must contain exactly one generated progress marker pair')
    before, rest = readme.split(PROGRESS_START)
    if PROGRESS_END not in rest:
        raise ValueError('README progress markers are out of order')
    _, after = rest.split(PROGRESS_END)
    return before + PROGRESS_START + '\n' + block + '\n' + PROGRESS_END + after


def owner(path, components):
    for c in components:
        if (not isinstance(c, dict) or 'id' not in c or 'patterns' not in c
                or not isinstance(c['patterns'], list)
                or any(not isinstance(p, str) for p in c['patterns'])):
            raise ValueError('Invalid component record')
    for c in components:
        if any(fnmatch.fnmatchcase(path, p) for p in c['patterns']):
            return c['id']
    raise ValueError(f'Unclassified source path: {path}')


def validate_progress(components, progress, root):
    if not isinstance(progress, dict) or 'gates' not in progress or 'components' not in progress:
        raise ValueError('Invalid progress record')
    if not isinstance(progress['gates'], dict) or set(progress['gates']) != ACCEPTANCE_GATES:
        raise ValueError('Progress must declare exactly the four acceptance gates: mapped, built, behavior, identity')
    if not isinstance(progress['components'], dict):
        raise ValueError('Progress components must be a mapping')
    for c in components:
        if (not isinstance(c, dict)
                or not {'id', 'name', 'scope', 'artifact', 'first_task', 'depends_on'} <= c.keys()
                or not isinstance(c['scope'], str) or not isinstance(c['depends_on'], list)):
            raise ValueError('Invalid component record')
    ids = [c['id'] for c in components]
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate component id')
    ids = set(ids)
    if set(progress['components']) != ids:
        raise ValueError('Progress components differ from scope')
    for c in components:
        if not set(c['depends_on']) <= ids:
            raise ValueError('Unknown dependency')
        row = progress['components'][c['id']]
        if (not isinstance(row, dict) or not {'gates', 'raw_equal_bodies', 'normalized_only_bodies',
                'total_function_windows', 'evidence'} <= row.keys()):
            raise ValueError('Invalid progress record')
        if (not isinstance(row['gates'], dict) or set(row['gates']) != set(progress['gates'])
                or any(type(v) is not bool for v in row['gates'].values())):
            raise ValueError('Invalid acceptance gate record')
        if any(type(row[k]) is not int for k in ('raw_equal_bodies', 'normalized_only_bodies')):
            raise ValueError('Invalid match count')
        if row['raw_equal_bodies'] < 0 or row['normalized_only_bodies'] < 0:
            raise ValueError('Negative match count')
        total = row['total_function_windows']
        if total is not None and (type(total) is not int or total < 0 or row['raw_equal_bodies'] + row['normalized_only_bodies'] > total):
            raise ValueError('Invalid match denominator')
        if not isinstance(row['evidence'], list):
            raise ValueError('Invalid progress record')
        if any(row['gates'].values()) and not row['evidence']:
            raise ValueError('Completed gates require reviewed evidence records')
        for evidence in row['evidence']:
            if not isinstance(evidence, str):
                raise ValueError('Invalid progress evidence record')
            p = (root / evidence).resolve()
            if not p.is_relative_to(root.resolve()) or not p.is_file():
                raise ValueError('Missing or external progress evidence')


def authenticated_binary(root, relative):
    """Authenticate the immutable byte snapshot used by catalogue analysis."""
    from artifacts import manifest_item
    item = manifest_item(root, relative)
    data = (root / relative).read_bytes()
    if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError(f'Artifact size/SHA-256 mismatch: {root / relative}')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    for relative, content in generate().items():
        path = ROOT / relative
        if args.check:
            if not path.is_file() or path.read_bytes() != content.encode():
                raise SystemExit(f'Stale catalogue: {relative}; run make catalogue')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8', newline='\n')
    print('Catalogue and progress tables match pinned inputs.' if args.check else 'Catalogue and progress tables regenerated.')


def implementation_inventory(root):
    if (root / '.git').exists():
        raw = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z', '--', 'src', 'research/work-items'], env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'))
        paths = [os.fsdecode(n).split('/') for n in raw.split(b'\0') if n and (root / os.fsdecode(n)).is_file()]
    else:
        paths = [p.relative_to(root).parts for area in ('src', 'research/work-items') for p in (root / area).rglob('*') if p.is_file()]
    return {'rust_areas': len({p[1] for p in paths if p[0] == 'src' and len(p) >= 3 and p[-1].endswith('.rs')}),
            'cargo_manifests': sum(p[0] == 'src' and len(p) == 3 and p[-1] == 'Cargo.toml' for p in paths),
            'work_items': sum(tuple(p[:2]) == ('research', 'work-items') and len(p) == 4 and p[-1] == 'README.md' for p in paths)}


def render_readme_progress(components, progress, coverage=None, inventory=None):
    accepted, total = progress_totals(components, progress)
    lines = ['<!-- Generated by make catalogue from the active #115 tree and authenticated evidence. -->', '']
    if inventory:
        lines += ['![Node #115 progress](docs/assets/research-progress.svg)', '',
                  f"**{inventory['rust_areas']} active Rust implementation areas · {inventory['cargo_manifests']} Cargo manifests · {inventory['work_items']} #115 research work items.**", '',
                  'These inventory counts describe available work, not completed components.', '']
    lines += ['The retained implementations cover quantity preparation, nonce ordering,',
              'snapshot selectors, latency, weighted comparisons, tagged counts and unsigned128 conversion.',
              'Each has a bounded #115 contract; no integrated node executable is claimed.', '',
              '<details>', '<summary><strong>Node #115 component acceptance</strong></summary>', '',
              *render_component_progress(components, progress, coverage, 'docs/', combined=True),
              f'Accepted gates: **{accepted}/{total}**. Full-component byte and function denominators remain unmeasured.',
              'Zero registered implementation comparisons do not mean zero correct code.', '', '</details>', '',
              '<details>', '<summary><strong>Node #115 binary comparisons</strong></summary>', '',
              'Dependency windows count once in the target total and separately by source.',
              'Their equality does not establish first-party or whole-node completion.', '',
              '| Comparison | Raw matching bytes / compared | Raw-equal windows | Raw + relocation-qualified windows |',
              '| --- | ---: | ---: | ---: |']
    if coverage:
        stats = coverage['totals']['node115']
        size = coverage['targets']['node115']['text_bytes']
        lines.append(f"| **Node #115 total** | {byte_cells(stats)} |")
        for name, item in coverage['dependencies']['node115'].items():
            lines.append(f"| {name} | {byte_cells(item)} |")
        lines += ['', f"Compared code: **{stats['bytes']:,}/{size:,} .text bytes ({100 * stats['bytes'] / size:.5f}%)**."]
    lines += ['', 'All active findings bind to node #115. See [detailed progress](docs/PROGRESS.md)',
              'and [source-built node acceptance](docs/SCOPE.md#source-built-network-node).', '', '</details>']
    return '\n'.join(lines)


def generate(root=ROOT):
    config = json.loads((root / 'research/components.json').read_text())
    components = config['components']
    progress = json.loads((root / 'research/progress.json').read_text())
    validate_progress(components, progress, root)
    if progress.get('baseline') != 'node115' or any(c['artifact'] != 'node115' for c in components):
        raise ValueError('Only node115 belongs in the active reconstruction scope')
    data = authenticated_binary(root, 'artifacts/node/115/hl-node')
    from elf_index import unwind_index
    _, index = unwind_index(data)
    inv = json.loads((root / 'research/imported/hl-node-115.inventory.json').read_text())
    if len(index) != inv['fde_count_eh_frame_hdr']:
        raise ValueError('Inventory unwind count differs from the authenticated node115 binary')
    paths = sorted(f'{crate}/{file}' for crate, files in inv['first_party_files'].items()
                   if crate in config['known_first_party_crates'] for file in files)
    rows = []
    for c in components:
        observed = [p for p in paths if owner(p, components) == c['id']]
        rows.append({**c, 'embedded_paths_115': observed})
    coverage = load_coverage(root, 'research/byte-windows.json', components)
    inventory = implementation_inventory(root)
    output = {'schema_version': 2, 'baseline': 'node115',
              'limitations': 'Work allocation and observed paths are not a complete function map or recovered Cargo graph.',
              'path_totals': {'node115': len(paths)}, 'components': rows}
    accepted, total = progress_totals(components, progress)
    result = {'research/catalogue/components.json': json.dumps(output, indent=2)+'\n',
              'research/catalogue/byte-coverage.json': json.dumps(coverage, indent=2)+'\n',
              'research/catalogue/seed-candidates.json': json.dumps({'binary_sha256': hashlib.sha256(data).hexdigest(), 'status': 'No inferred reference-address seeds. Use node115 work-item records and its authenticated FDE index.', 'items': []}, indent=2)+'\n',
              'README.md': update_readme_progress((root/'README.md').read_text(), render_readme_progress(components, progress, coverage, inventory)),
              'docs/assets/research-progress.svg': render_progress_banner(inventory, coverage)}
    stats = coverage['totals']['node115']; target = coverage['targets']['node115']
    detailed = ['# Node #115 reconstruction progress', '', 'Generated by `make catalogue`; component gates and byte comparisons are distinct measures.', '',
                *render_component_progress(components, progress, coverage), f'Accepted full-scope gates: **{accepted}/{total}**.', '',
                *render_dependency_progress(coverage), '## Full target coverage', '',
                f"Compared .text: {stats['bytes']:,}/{target['text_bytes']:,} bytes. Raw-equal positions: {stats['raw_equal_bytes']:,}/{target['text_bytes']:,}. Whole ELF reproduced: no.", '',
                '| Whole ELF bytes | .text bytes | Other executable bytes | Allocated data/metadata bytes | Zero-fill bytes |',
                '| ---: | ---: | ---: | ---: | ---: |',
                '| '+' | '.join(f"{target[k]:,}" for k in ['file_bytes','text_bytes','other_executable_bytes','allocated_data_bytes','zero_fill_bytes'])+' |', '',
                '## Registered windows', '', '| Window | ELF VA interval | Source | Raw matching bytes |', '| --- | --- | --- | ---: |']
    for row in coverage['windows']:
        detailed.append(f"| [{row['label']}](../{row['evidence']}) | `{row['start']:#x}..{row['end']:#x}` | {row['source_kind']} | {fraction(row['raw_equal_bytes'],row['bytes'])} |")
    detailed += ['', 'The window list is not a function census. Data, calls, ABI, relocations and whole-program behavior remain acceptance requirements.', '']
    result['docs/PROGRESS.md'] = '\n'.join(detailed)
    mapped = ['# Node #115 component map', '', 'Generated by `make catalogue`. These are work allocations, not recovered crate boundaries or complete function ownership.', '',
              f"The authenticated inventory contains {len(paths)} allowlisted source-path observations. Diagnostic strings do not establish complete source coverage.", '']
    for row in rows:
        mapped += [f"<a id=\"{row['id']}\"></a>", f"## {row['name']}", '', row['scope']+'.', '',
                   '- Target: node115.', '- Implementation paths: '+(', '.join('`'+p+'`' for p in row.get('implementation_paths',[])) or 'not yet implemented')+'.',
                   f"- Observed diagnostic paths: {len(row['embedded_paths_115'])}.", '- First task: '+row['first_task'], '']
    result['docs/COMPONENTS.md'] = '\n'.join(mapped)
    return result

if __name__ == '__main__':
    main()
