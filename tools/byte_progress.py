"""Count selected compiled-code comparisons, never infer whole-module coverage."""
import hashlib
import json
from pathlib import Path

from elf_index import sections


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'Duplicate key in byte evidence')
    return result


def compare(source, target, relocations):
    require(len(source) == len(target) and len(target) > 0, 'Unequal/empty comparison extent')
    masks = set()
    for row in relocations:
        offset, width = row['offset'], row.get('width', 4)
        kind = row.get('kind', row.get('type'))
        require(type(offset) is int and type(width) is int and width == 4
                and kind in (2, 9) and row['addend'] == -4,
                'Only recorded four-byte PC32/GOTPCREL fields are supported')
        field = set(range(offset, offset + width))
        require(0 <= offset and offset + width <= len(target) and not masks & field,
                'Overlapping/out-of-bounds relocation field')
        masks |= field
    differences = {i for i, (a, b) in enumerate(zip(source, target)) if a != b}
    require(len(masks) < len(target), 'No comparable non-relocation bytes')
    return {'bytes': len(target), 'raw_equal_bytes': len(target) - len(differences),
            'relocation_bytes': len(masks), 'non_relocation_bytes': len(target) - len(masks),
            'equal_non_relocation_bytes': len(target) - len(masks) - len(differences - masks),
            'raw_equal': not differences, 'relocation_qualified': not (differences - masks),
            'raw_difference_offsets': sorted(differences),
            'non_relocation_difference_offsets': sorted(differences - masks)}


def summarize(rows):
    return {**{key: sum(r[key] for r in rows) for key in
               ('bytes', 'raw_equal_bytes', 'relocation_bytes', 'non_relocation_bytes',
                'equal_non_relocation_bytes')},
            'windows': len(rows), 'raw_equal_windows': sum(r['raw_equal'] for r in rows),
            'relocation_qualified_windows': sum(r['relocation_qualified'] for r in rows)}


def fraction(numerator, denominator):
    return f'{numerator:,}/{denominator:,} ({100 * numerator / denominator:.2f}%)' if denominator else 'Unmeasured'


def load_coverage(root, registry_path, components):
    """Recompare pinned source excerpts with authenticated captures; count each VA once."""
    root = Path(root).resolve()
    def read(path):
        candidate = (root / path).resolve()
        require(candidate.is_relative_to(root) and candidate.is_file(), 'Missing/external byte evidence')
        return candidate.read_bytes()
    registry = json.loads(read(registry_path), object_pairs_hook=unique_object)
    require(type(registry['schema_version']) is int and registry['schema_version'] == 1,
            'Unknown byte registry schema')
    pinned = registry['evidence_sha256']
    def evidence(path):
        data = read(path)
        require(path in pinned and digest(data) == pinned[path], 'Byte evidence digest changed: ' + path)
        return data
    records = {}
    def record(path, pointer):
        if path not in records:
            records[path] = json.loads(evidence(path), object_pairs_hook=unique_object)
        value = records[path]
        for key in pointer:
            value = value[key]
        return value
    for path in pinned:
        evidence(path)
    component_targets = {c['id']: c['artifact'] for c in components}
    manifest = {x['path']: x for x in json.loads(read('provenance/artifacts.json'),
                                                object_pairs_hook=unique_object)['files']}
    targets, images, code_sections = {}, {}, {}
    for name, target in registry['targets'].items():
        data = read(target['path'])
        expected = manifest[target['path']]
        require(target['sha256'] == expected['sha256'] == digest(data)
                and len(data) == expected['size'], 'Byte coverage target identity differs')
        images[name] = data
        code_sections[name] = [s for s in sections(data) if s['type'] == 1 and s['flags'] & 4]
        text = [s for s in code_sections[name] if s['name'] == '.text']
        require(len(text) == 1, 'Expected one executable .text section')
        all_sections = sections(data)
        executable = [s for s in all_sections if s['flags'] & 2 and s['flags'] & 4 and s['type'] != 8]
        targets[name] = {**target, 'file_bytes': len(data), 'text_bytes': text[0]['size'],
                         'other_executable_bytes': sum(s['size'] for s in executable if s['name'] != '.text'),
                         'allocated_data_bytes': sum(s['size'] for s in all_sections
                                                     if s['flags'] & 2 and not s['flags'] & 4 and s['type'] != 8),
                         'zero_fill_bytes': sum(s['size'] for s in all_sections if s['flags'] & 2 and s['type'] == 8)}
    rows, seen_ids, intervals = [], set(), {}
    for item in registry['windows']:
        name, target = item['id'], item['target']
        require('dependency' not in item or item['dependency'] in
                ('rust-core', 'compiler-builtins', 'zstandard'), 'Unknown dependency attribution')
        require(item['evidence'] in pinned, 'Comparison evidence must be hash-pinned')
        require(name not in seen_ids, 'Duplicate comparison id')
        seen_ids.add(name)
        require(item['component'] in component_targets and target in images, 'Unknown byte-window owner/target')
        require(component_targets[item['component']] == target
                or (component_targets[item['component']] == 'node94' and target == 'node115'),
                'Byte-window component belongs to another target')
        start, end = item['start'], item['end']
        require(type(start) is int and type(end) is int and 0 <= start < end, 'Invalid window bounds')
        require(all(end <= a or start >= b for a, b in intervals.setdefault(target, [])),
                'Overlapping target windows would double count bytes')
        intervals[target].append((start, end))
        mapped = [s for s in code_sections[target] if s['address'] <= start and end <= s['address'] + s['size']]
        require(len(mapped) == 1, 'Window outside unique executable section')
        section = mapped[0]
        require(section['name'] == '.text', 'Window outside the .text coverage denominator')
        offset = section['offset'] + start - section['address']
        captured = images[target][offset:offset + end - start]
        require(len(captured) == end - start and digest(captured) == item['target_body_sha256'],
                'Target window digest/extent changed')
        source = evidence(item['source']['path'])
        require(item['source'].get('encoding') in ('binary', 'hex'), 'Unknown excerpt encoding')
        if item['source'].get('encoding') == 'hex':
            source = bytes.fromhex(source.decode('ascii'))
        begin = item['source'].get('offset', 0)
        require(type(begin) is int and begin >= 0, 'Invalid source excerpt offset')
        source = source[begin:begin + end - start]
        require(digest(source) == item['source']['body_sha256'], 'Source body digest changed')
        reference = item.get('relocations')
        relocations = record(reference['path'], reference['pointer']) if reference else []
        if isinstance(relocations, dict):
            relocations = [relocations]
        rows.append({**item, **compare(source, captured, relocations)})
    return {'targets': targets, 'windows': rows, 'components': {
        c['id']: summarize([r for r in rows if r['component'] == c['id'] and r['target'] == c['artifact'] and 'dependency' not in r])
        for c in components}, 'totals': {name: summarize([r for r in rows if r['target'] == name])
                                        for name in targets},
        'dependencies': {name: {dep: summarize([r for r in rows if r['target'] == name and r.get('dependency') == dep])
                               for dep in sorted({r['dependency'] for r in rows if r['target'] == name and 'dependency' in r})}
                         for name in targets}}
