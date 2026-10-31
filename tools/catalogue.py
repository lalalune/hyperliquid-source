#!/usr/bin/env python3
"""Generate release-scoped component and progress tables from pinned inputs."""
import argparse
import collections
import fnmatch
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def owner(path, components):
    if any('patterns' not in c for c in components):
        raise ValueError('Invalid component record')
    for c in components:
        if any(fnmatch.fnmatchcase(path, p) for p in c['patterns']):
            return c['id']
    raise ValueError(f'Unclassified source path: {path}')


def validate_progress(components, progress, root):
    ids = {c['id'] for c in components}
    if set(progress['components']) != ids:
        raise ValueError('Progress components differ from scope')
    for c in components:
        if not set(c['depends_on']) <= ids:
            raise ValueError('Unknown dependency')
        row = progress['components'][c['id']]
        if set(row['gates']) != set(progress['gates']) or any(type(v) is not bool for v in row['gates'].values()):
            raise ValueError('Invalid acceptance gate record')
        if row['raw_equal_bodies'] < 0 or row['normalized_only_bodies'] < 0:
            raise ValueError('Negative match count')
        total = row['total_function_windows']
        if total is not None and (total < 0 or row['raw_equal_bodies'] + row['normalized_only_bodies'] > total):
            raise ValueError('Invalid match denominator')
        if any(row['gates'].values()) and not row['evidence']:
            raise ValueError('Completed gates require reviewed evidence records')
        for evidence in row['evidence']:
            p = (root / evidence).resolve()
            if not p.is_relative_to(root.resolve()) or not p.is_file():
                raise ValueError('Missing or external progress evidence')


def generate(root=ROOT):
    config = json.loads((root / 'research/components.json').read_text())
    components = config['components']
    progress = json.loads((root / 'research/progress.json').read_text())
    validate_progress(components, progress, root)
    inventories = {v: json.loads((root / f'research/imported/hl-node-{v}.inventory.json').read_text()) for v in ['94', '115']}
    inventories['visor'] = json.loads((root / 'research/imported/hl-visor.inventory.json').read_text())
    paths = {}
    excluded = {}
    for v, inv in inventories.items():
        paths[v] = {f'{crate}/{file}' for crate, files in inv['first_party_files'].items()
                    if crate in config['known_first_party_crates'] for file in files}
        excluded[v] = {crate: files for crate, files in inv['first_party_files'].items()
                       if crate not in config['known_first_party_crates']}
    reference = root / 'references/can1357-hl'
    source_paths = {str(p.relative_to(reference)) for p in reference.rglob('*.rs')}
    first_party_source = {p for p in source_paths if p.split('/')[0] in config['known_first_party_crates']}
    # Every known path must be owned once by the ordered taxonomy, including added #115 paths.
    for p in source_paths | paths['94'] | paths['115']:
        owner(p, components)
    literal_items = json.loads((root / 'research/imported/can1357-literal-classes.json').read_text())['items']
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
    result = {'research/catalogue/components.json': json.dumps(output, indent=2) + '\n'}
    # Addresses in imported prose are leads only. Executable-section membership is not validation.
    from elf_index import sections
    data = (root / 'artifacts/node/94/hl-node').read_bytes()
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
             'Generated by `make catalogue`; edit research/components.json and research/progress.json, then regenerate.', '',
             '## Metric', '',
             '**Verified completion = accepted component gates / 4.** The gates are mapped scope, a reproducible Rust build, target-grounded behavior, and target code/data/call identity. Each gate needs reviewable evidence for the whole declared component. This is a milestone measure, not an estimate of remaining effort.', '',
             'Every component starts at **0%** because no complete accepted reconstruction packet exists. Imported inferred code, source-path overlap, string matches and candidate addresses earn no acceptance credit. Raw/normalized body coverage remains unmeasured until a target-bound function inventory and comparator exist.', '',
             'The baseline is node #94. Node #115 is a separate drift target; visor is a separate executable. Component labels are inferred research work areas rather than recovered crate manifests.', '',
             '| Component | Completion | Accepted gates | Reference files | #94 paths present / observed | #115 observed paths |',
             '| --- | ---: | ---: | ---: | ---: | ---: |']
    for row in rows:
        p = progress['components'][row['id']]
        n = sum(p['gates'].values())
        present = len(set(row['embedded_paths_94']) & source_paths)
        denom = len(row['embedded_paths_94'])
        lines.append(f"| [{row['name']}](COMPONENTS.md#{row['id']}) | {100*n/4:.0f}% | {n}/4 | {len(row['reference_paths'])} | {present}/{denom} | {len(row['embedded_paths_115'])} |")
    lines += ['', 'Path counts describe error/source strings that survived compilation. Missing paths need not indicate absent source, and matching paths do not validate implementation.', '',
              '## Binary coverage', '', '| Target | Unwind-index entries | Accepted raw bodies | Accepted normalized-only bodies | Whole ELF reproduced |', '| --- | ---: | ---: | ---: | --- |']
    for v in ['94','115']:
        lines.append(f"| Node #{v} | {inventories[v]['fde_count_eh_frame_hdr']:,} | 0 credited; comparator pending | 0 credited; comparator pending | No |")
    lines += [f"| Captured visor | {inventories['visor']['fde_count_eh_frame_hdr']:,} | 0 credited; comparator pending | 0 credited; comparator pending | No |", '',
              'Unwind entries are not a complete function census. Never use them as a verified matching-window denominator without validating bounds and duplicates.', '',
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
            if not path.is_file() or path.read_text() != content:
                raise SystemExit(f'Stale catalogue: {relative}; run make catalogue')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    print('Catalogue and progress tables match pinned inputs.' if args.check else 'Catalogue and progress tables regenerated.')


if __name__ == '__main__':
    main()
