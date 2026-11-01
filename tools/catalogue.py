#!/usr/bin/env python3
"""Generate release-scoped component and progress tables from pinned inputs."""
import argparse
import collections
import fnmatch
import hashlib
import json
from pathlib import Path
import re
from source_files import rust_files
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


def project_bytes(components, coverage):
    if not coverage:
        return None
    targets = {c['id']: c['artifact'] for c in components}
    return summarize([r for r in coverage['windows'] if targets[r['component']] == r['target']])


def render_byte_details(coverage):
    if not coverage:
        return []
    lines = ['## How much of the target has been compared?', '',
             'These denominators are the authenticated executable `.text` sections, not inferred module sizes. Matching byte positions within a selected window are not proof that the whole function or node is correct.', '',
             '| Target | Compared window bytes / .text | Raw matching positions / .text |',
             '| --- | ---: | ---: |']
    for name, target in coverage['targets'].items():
        stats = coverage['totals'][name]
        cells = [f"{stats[k]:,}/{target['text_bytes']:,} ({100 * stats[k] / target['text_bytes']:.5f}%)"
                 for k in ('bytes', 'raw_equal_bytes')]
        lines.append(f"| {name} | {' | '.join(cells)} |")
    lines += ['', '## Required ELF regions beyond selected code windows', '',
              'All regions remain in scope. Counts below are authenticated file/section sizes, not reconstruction percentages. Data includes allocated non-executable file-backed sections (including unwind metadata); zero-fill is allocated NOBITS storage. ELF headers, section tables and file padding remain part of whole-ELF acceptance.', '',
              '| Target | Whole ELF file bytes | .text bytes | Other executable section bytes | Allocated data / metadata bytes | Zero-fill memory bytes |',
              '| --- | ---: | ---: | ---: | ---: | ---: |']
    for name, target in coverage['targets'].items():
        cells = [f"{target[k]:,}" for k in ('file_bytes', 'text_bytes', 'other_executable_bytes', 'allocated_data_bytes', 'zero_fill_bytes')]
        lines.append(f"| {name} | {' | '.join(cells)} |")
    lines += ['', '## Registered comparison windows', '',
              'Each interval is counted once per target. Raw equality includes relocation bytes. The relocation-qualified column excludes only actual recorded PC32/GOTPCREL fields; excluded bytes are never credited as raw equal. These window counts are not a complete function census.', '',
              '| Target / window | ELF VA interval | Comparison source | Raw matching bytes | Equal outside relocation fields |',
              '| --- | --- | --- | ---: | ---: |']
    for row in coverage['windows']:
        lines.append(f"| {row['target']}: [{row['label']}](../{row['evidence']}) | "
                     f"`{row['start']:#x}..{row['end']:#x}` | {row['source_kind']} | "
                     f"{fraction(row['raw_equal_bytes'], row['bytes'])} | "
                     f"{fraction(row['equal_non_relocation_bytes'], row['non_relocation_bytes'])} |")
    lines += ['', 'The selected adapter candidate is the reviewed ThinLTO rebuild of published LLVM bitcode, not newly recovered libcore Rust source. Its older official native candidate retains two non-relocation differences at offsets 464 and 467 (616/622 raw bytes); that original result remains in the evidence and registry. The two candidates do not add two windows.', '',
              'The Zstandard windows use source labels and a complete compiled section endpoint; their symbols have no function sizes and there are no FDEs. Supporting callee windows are counted once here, without changing the original packets’ distinct primary/supporting denominators.', '',
              'Node #115 remains separate. Its 630-byte adapter has an extent mismatch and no admitted byte comparison, so it contributes no compared bytes. Cross-release duplicates, repeated builds, negative controls, data/vtable bytes and semantic-only Rust reconstructions are excluded from the code-window denominator.', '',
              'Inputs: [reviewed byte-window registry](../research/byte-windows.json), [generated byte counts](../research/catalogue/byte-coverage.json). Source excerpts, evidence records and full targets are hash-checked on every catalogue generation. Full-component helper/data/ABI/call/relocation closure remains open.', '']
    return lines


def render_component_progress(components, progress, coverage, link_prefix=''):
    lines = []
    gate_count = len(progress['gates'])
    for artifact, label in [('node94', 'Node #94 reconstruction'), ('visor', 'Separate supervisor')]:
        selected = [c for c in components if c['artifact'] == artifact]
        if not selected:
            continue
        accepted, total = progress_totals(selected, progress)
        complete = sum(all(progress['components'][c['id']]['gates'].values()) for c in selected)
        lines += [f"**{label}: {100 * accepted / total:.2f}% ({accepted}/{total} accepted gates; "
                  f"{complete}/{len(selected)} components complete).**", '',
                  f"| {'Required node component' if artifact == 'node94' else 'Tracked supervisor component'} | Accepted gates | Milestones | Compared implementation bytes | Registered implementation windows |",
                  '| --- | ---: | ---: | ---: | ---: |']
        for c in selected:
            n = sum(progress['components'][c['id']]['gates'].values())
            stats = coverage['components'].get(c['id']) if coverage else None
            lines.append(f"| [{c['name']}]({link_prefix}COMPONENTS.md#{c['id']}) | {n}/{gate_count} | "
                         f"{100 * n / gate_count:.0f}% | {stats['bytes'] if stats else 0:,} | "
                         f"{stats['windows'] if stats else 0:,} |")
        lines += ['']
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
    return lines + ['']


def render_readme_progress(components, progress, coverage=None):
    accepted, total = progress_totals(components, progress)
    lines = [
        '<!-- Generated by make catalogue from research/components.json, research/progress.json and research/byte-windows.json. -->', '',
        'The node components below require reconstruction or target-specific integration.',
        'The captured supervisor is tracked separately; a direct container may replace it.',
        'Each has four full-scope gates: mapped, reproducibly built, behavior validated,',
        'and code/data/call identity validated. Milestones are not an estimate of effort.', '',
        *render_component_progress(components, progress, coverage, 'docs/'),
        f'Project gate total, including the separate supervisor: **{accepted}/{total}**.', '',
        '**0 compared bytes means no registered implementation comparison, not 0% correct.**',
        'Whole-component byte sizes and remaining function counts are still unmeasured.',
        'The path taxonomy covers observed source paths; it does not establish all code',
        'ownership. Unassigned code, private dependency changes, data, ABI, relocations',
        'and build provenance remain required work. No component has been accepted as finished.', '',
        *render_dependency_progress(coverage),
        '### Whole-target comparison coverage', '',
        'These are measured `.text` sizes, including dependencies. Selected matching',
        'positions are not a completed function or a source-rebuilt node. Relocation-qualified',
        'windows allow only recorded relocation fields to differ. No whole ELF is reproduced.', '',
        '| Target | Compared bytes / all .text bytes | Raw matching positions / all .text bytes |',
        '| --- | ---: | ---: |',
    ]
    if coverage:
        for target, inventory in coverage['targets'].items():
            stats = coverage['totals'][target]
            size = inventory['text_bytes']
            cells = [f"{stats[k]:,}/{size:,} ({100 * stats[k] / size:.5f}%)"
                     for k in ('bytes', 'raw_equal_bytes')]
            lines.append(f"| {target} | {' | '.join(cells)} |")
    lines += ['',
        'Node #94 is the reconstruction baseline. #115 is a separate later comparison;',
        'neither historical target establishes compatibility with the current network.',
        'Full target hashes are in [the artifact manifest](provenance/artifacts.json).',
        'See [detailed progress](docs/PROGRESS.md), including non-code sections,',
        'and the [source-built network node acceptance criteria](docs/SCOPE.md#source-built-network-node).',
    ]
    return '\n'.join(lines)


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


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'Duplicate key in catalogue input: {key}')
        out[key] = value
    return out


def _load_input(path):
    return json.loads(path.read_text(), object_pairs_hook=_unique_object)


def generate(root=ROOT):
    config = _load_input(root / 'research/components.json')
    if (not isinstance(config, dict) or 'components' not in config
            or 'known_first_party_crates' not in config
            or not isinstance(config['known_first_party_crates'], list)
            or any(not isinstance(c, str) for c in config['known_first_party_crates'])):
        raise ValueError('Invalid component configuration')
    components = config['components']
    progress = _load_input(root / 'research/progress.json')
    validate_progress(components, progress, root)
    coverage = load_coverage(root, progress['byte_window_registry'], components) if 'byte_window_registry' in progress else None
    accepted, total = progress_totals(components, progress)
    gate_count = len(progress['gates'])
    inventories = {v: _load_input(root / f'research/imported/hl-node-{v}.inventory.json') for v in ['94', '115']}
    inventories['visor'] = _load_input(root / 'research/imported/hl-visor.inventory.json')
    for inv in inventories.values():
        if (not isinstance(inv, dict) or 'first_party_files' not in inv
                or 'fde_count_eh_frame_hdr' not in inv or not isinstance(inv['first_party_files'], dict)
                or any(not isinstance(files, list) or any(not isinstance(f, str) for f in files)
                       for files in inv['first_party_files'].values())):
            raise ValueError('Invalid inventory record')
    from elf_index import unwind_index
    binary94 = None
    for v, relative in [('94', 'artifacts/node/94/hl-node'),
                        ('115', 'artifacts/node/115/hl-node'),
                        ('visor', 'artifacts/visor/captured/hl-visor')]:
        data = authenticated_binary(root, relative)
        _, entries = unwind_index(data)
        if len(entries) != inventories[v]['fde_count_eh_frame_hdr']:
            raise ValueError(f'Inventory unwind count differs from the pinned binary: {relative}')
        if v == '94':
            binary94 = data
    paths = {}
    excluded = {}
    for v, inv in inventories.items():
        paths[v] = {f'{crate}/{file}' for crate, files in inv['first_party_files'].items()
                    if crate in config['known_first_party_crates'] for file in files}
        excluded[v] = {crate: files for crate, files in inv['first_party_files'].items()
                       if crate not in config['known_first_party_crates']}
    reference = root / 'references/can1357-hl'
    source_paths = {p.relative_to(reference).as_posix() for p in rust_files(reference)}
    first_party_source = {p for p in source_paths if p.split('/')[0] in config['known_first_party_crates']}
    for p in source_paths | paths['94'] | paths['115']:
        owner(p, components)
    literal_record = _load_input(root / 'research/imported/can1357-literal-classes.json')
    if not isinstance(literal_record, dict) or not isinstance(literal_record.get('items'), list):
        raise ValueError('Invalid literal-classes record')
    literal_items = literal_record['items']
    seen_literals = set()
    for item in literal_items:
        if (not isinstance(item, dict) or 'class' not in item or 'file' not in item
                or not isinstance(item['file'], str)):
            raise ValueError('Invalid literal-classes record')
        marker = json.dumps(item, sort_keys=True)
        if marker in seen_literals:
            raise ValueError(f'Duplicate literal-class entry: {item}')
        seen_literals.add(marker)
    rows = []
    for c in components:
        source = sorted(p for p in source_paths if owner(p, components) == c['id'])
        old = sorted(p for p in paths['94'] if owner(p, components) == c['id'])
        new = sorted(p for p in paths['115'] if owner(p, components) == c['id'])
        counts = collections.Counter(i['class'] for i in literal_items if owner(i['file'], components) == c['id'])
        rows.append({**c, 'reference_paths': source, 'embedded_paths_94': old, 'embedded_paths_115': new,
                     'missing_reference_paths_94': sorted(set(old) - source_paths),
                     'extra_reference_paths_94': sorted(set(source) - paths['94']),
                     'literal_counts': dict(sorted(counts.items()))})
    output = {'schema_version': 1, 'baseline': 'node94', 'excluded_inventory_candidates': excluded,
              'limitations': 'Path and literal observations do not prove module ABI, function ownership or logic. The ordered component taxonomy is a research partition, not a recovered Cargo dependency graph.',
              'path_totals': {'node94': len(paths['94']), 'node115': len(paths['115']), 'reference': len(source_paths), 'reference_first_party': len(first_party_source), 'reference_forks': len(source_paths - first_party_source), 'extra_first_party94': len(first_party_source - paths['94']),
                              'present94': len(paths['94'] & source_paths), 'extra_reference94': len(source_paths - paths['94']),
                              'added115': sorted(paths['115'] - paths['94']), 'absent115': sorted(paths['94'] - paths['115'])},
              'components': rows}
    result = {'research/catalogue/components.json': json.dumps(output, indent=2) + '\n',
              'README.md': update_readme_progress((root / 'README.md').read_text(), render_readme_progress(components, progress, coverage))}
    if coverage:
        result['research/catalogue/byte-coverage.json'] = json.dumps(coverage, indent=2) + '\n'
    # Addresses in imported prose are leads only. Executable-section membership is not validation.
    from elf_index import sections
    data = binary94
    execsecs = [s for s in sections(data) if s['flags'] & 4]
    seeds = []
    for path in sorted(source_paths):
        text = (reference / path).read_text()
        header = []
        for line in text.splitlines():
            if line.strip() and not line.lstrip().startswith(('//', '/*', '*', '*/')):
                break
            header.append(line)
        for lineno, line in enumerate(header, 1):
            for match in re.finditer(r'(?:0x|sub_)([0-9a-fA-F]{5,16})\b', line):
                address = int(match.group(1), 16)
                seeds.append({'component': owner(path, components), 'file': path, 'line': lineno,
                              'address': hex(address), 'inside_executable_section_94': any(s['address'] <= address < s['address'] + s['size'] for s in execsecs)})
    result['research/catalogue/seed-candidates.json'] = json.dumps({'binary_sha256': hashlib.sha256(data).hexdigest(),
        'status': 'Unverified addresses from imported leading comments; not recovered names or accepted function boundaries.', 'items': seeds}, indent=2) + '\n'
    lines = ['# Reconstruction progress', '',
             'Generated by `make catalogue`; edit research/components.json, research/progress.json and research/byte-windows.json, then regenerate.', '',
             '## Metric', '',
             'Each required component has four full-scope gates: mapped, reproducibly built, behavior validated and code/data/call identity validated. These reviewed milestones do not measure remaining effort or function coverage.', '',
             *render_component_progress(components, progress, coverage),
             f'Project gate total, including the separate supervisor: **{accepted}/{total}**.', '',
             'Zero compared implementation bytes/windows means no registered comparison, not zero correct code. Whole-component byte sizes and function counts remain unmeasured. Source paths and unwind starts cannot supply those denominators. Shared dependency comparisons are excluded from component totals and shown below.', '',
             *render_dependency_progress(coverage),
             '## Binary coverage', '', '| Target | Unwind-index entries | Raw matching bytes / compared | Raw-equal windows | Raw + relocation-qualified windows | Whole ELF reproduced |', '| --- | ---: | ---: | ---: | ---: | --- |']
    for name, label in [('node94', 'Node #94'), ('node115', 'Node #115 (separate comparison)'), ('visor', 'Captured visor')]:
        stats = coverage['totals'].get(name) if coverage else None
        inventory = inventories[name.removeprefix('node')]
        lines.append(f"| {label} | {inventory['fde_count_eh_frame_hdr']:,} | {byte_cells(stats)} | No |")
    lines += ['',
              'Unwind entries are not a complete function census. Never use them as a verified matching-window denominator without validating bounds and duplicates.', '',
              *render_byte_details(coverage),
              '## Next work', '', 'Start with [the ready task queue](TASKS.md) and [reverse-engineering setup](REVERSE-ENGINEERING.md). Updates require the [contribution evidence packet](../CONTRIBUTING.md).', '',
              'The format follows the separation of matched bodies, normalized matches and whole-ELF status in [pumpfun-source at dc8f791](https://github.com/lalalune/pumpfun-source/tree/dc8f791d32ae7fd6d9660cd1bf003fb02737f78f). Its progress numbers do not transfer to this project.', '']
    result['docs/PROGRESS.md'] = '\n'.join(lines)
    lines = ['# Component map', '', 'Generated by `make catalogue`. These inferred work areas partition every reference `.rs` file and every allowlisted embedded source path exactly once. Dependencies are suggested research order, not a recovered Cargo graph.', '',
             f"The reference has {len(source_paths)} Rust files: {len(first_party_source)} first-party-path files and {len(source_paths-first_party_source)} bincode-fork files. The #94 inventory has {len(paths['94'])} first-party paths, of which {len(paths['94'] & source_paths)} exist in the reference. There are {len(first_party_source-paths['94'])} extra first-party reference paths (plus the fork files). #115 adds {len(paths['115']-paths['94'])} and lacks {len(paths['94']-paths['115'])} paths relative to #94.", '',
             'The #115 candidate `threadthread_spawn_forevertokio_spawn_foreverdiscriminantbase/lu.rs` is excluded as concatenated-string noise, not counted as a new crate. Original evidence is unchanged.', '',
             'The machine-readable catalogue lists every path and missing/extra reference. Literal counts below use imported item-level refinements and first-file attribution; they are reconnaissance only.', '']
    for row in rows:
        lines += [f"<a id=\"{row['id']}\"></a>", f"## {row['name']}", '', row['scope'] + '.', '',
                  f"- Target: `{row['artifact']}`.", f"- Path rules (ordered first-match): {', '.join('`'+p+'`' for p in row['patterns']) or 'separate executable; no reference source'}.",
                  f"- Suggested prerequisites: {', '.join(row['depends_on']) or 'none'}.",
                  f"- First task: {row['first_task']}",
                  f"- Refined literal classes: `{json.dumps(row['literal_counts'], sort_keys=True)}`.", '']
        if row['missing_reference_paths_94']:
            lines += ['Missing reference paths observed in #94: ' + ', '.join('`'+p+'`' for p in row['missing_reference_paths_94']) + '.', '']
    lines += ['## Supporting repositories', '',
              '| Repository | Use in this project | Completion treatment |', '| --- | --- | --- |',
              '| `upstream/node` | Operating documentation, signing key and packaging | Reference; not recovered node implementation |',
              '| `upstream/contracts` | Public Solidity interfaces and contracts | Separate source, no credit toward native-node reconstruction |',
              '| `upstream/block-importer` | Historical EVM data ingestion formats | Candidate replay harness reference |',
              '| `upstream/hyper-evm-sync` | Public HyperEVM replay proof of concept | Dependency/fixture research, not target equivalence |',
              '| `upstream/order_book_server` | Derived order-book stream consumer; upstream disclaims core-team authorship | API/fixture reference only |',
              '| `upstream/historical_data` | Published historical-data formats | Dataset reference, not a node binary |', '']
    result['docs/COMPONENTS.md'] = '\n'.join(lines)
    return result


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


if __name__ == '__main__':
    main()
