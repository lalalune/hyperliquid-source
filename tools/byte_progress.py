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


# x86-64 psABI GOTPCRELX relaxations: (start relative to the four-byte field,
# source bytes, relaxed target bytes). mov reg,[rip] keeps its ModRM byte at -1.
RELAXATIONS = {'gotpcrelx-mov-lea': (-2, b'\x8b', b'\x8d'), 'gotpcrelx-call': (-2, b'\xff\x15', b'\x67\xe8')}


def relaxation_bytes(source, target, offset, kind, name):
    """Byte positions a named GOTPCRELX relaxation rewrites, or None if the site does not fit it.

    mov-lea: kind 41 (no REX) or 42 (REX.W/REX at -3), ModRM at -1 RIP-relative (mod=00, rm=101).
    call: kind 41, ff 15 -> addr32 call (67 e8).
    """
    if type(kind) is not int or type(name) is not str or name not in RELAXATIONS:
        return None
    delta, before, after = RELAXATIONS[name]
    start = offset + delta
    if start < 0 or source[start:start + len(before)] != before or target[start:start + len(after)] != after:
        return None
    if name == 'gotpcrelx-mov-lea':
        if kind not in (41, 42) or source[offset - 1] & 0xc7 != 0x05 or target[offset - 1] != source[offset - 1]:
            return None
        if kind == 42 and not (offset >= 3 and 0x40 <= source[offset - 3] <= 0x4f):
            return None
    elif kind != 41:
        return None
    return set(range(start, start + len(before)))


def compare(source, target, relocations):
    require(len(source) == len(target) and len(target) > 0, 'Unequal/empty comparison extent')
    masks = set()
    for row in relocations:
        offset, width = row['offset'], row.get('width', 4)
        kind = row.get('kind', row.get('type'))
        # PC32, PLT32, GOTPCREL and GOTPCRELX/REX_GOTPCRELX each occupy one four-byte
        # PC-relative field; the addend only selects the referenced displacement,
        # never the masked bytes. A linker-relaxed GOTPCRELX site also rewrites the
        # opcode byte(s) before the field; those are excluded only when the row names
        # the relaxation and both captures hold exactly its source/target bytes.
        require(type(offset) is int and type(width) is int and width == 4
                and kind in (2, 4, 9, 41, 42) and type(row['addend']) is int,
                'Only recorded four-byte PC32/PLT32/GOTPCREL(X) fields are supported')
        field = set(range(offset, offset + width))
        if 'relaxation' in row:
            require(kind in (41, 42) and type(row['relaxation']) is str and row['relaxation'] in RELAXATIONS,
                    'Only named GOTPCRELX relaxations are supported')
            rewritten = relaxation_bytes(source, target, offset, kind, row['relaxation'])
            require(rewritten is not None, 'Relaxation bytes differ from the named psABI rewrite')
            field |= rewritten
        require(0 <= min(field) and offset + width <= len(target) and not masks & field,
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
    rows, extent_mismatches, seen_ids, intervals = [], [], set(), {}
    for item in registry['windows']:
        name, target = item['id'], item['target']
        mode = item.get('comparison_mode', 'offset-aligned')
        require(mode in ('offset-aligned', 'extent-mismatch'), 'Unknown comparison mode')
        require('dependency' not in item or item['dependency'] in
                ('rust-core', 'rust-alloc', 'rust-std', 'compiler-builtins', 'vendored-crates', 'native-libraries', 'zstandard', 'mio'), 'Unknown dependency attribution')
        require(item['evidence'] in pinned, 'Comparison evidence must be hash-pinned')
        require(name not in seen_ids, 'Duplicate comparison id')
        seen_ids.add(name)
        require(item['component'] in component_targets and target in images, 'Unknown byte-window owner/target')
        require(component_targets[item['component']] == target,
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
        require(mode != 'extent-mismatch' or 'length' in item['source'],
                'Extent mismatch requires explicit source length')
        length = item['source'].get('length', end - start)
        require(type(length) is int and length > 0 and begin + length <= len(source),
                'Invalid source comparison extent')
        source = source[begin:begin + length]
        require(digest(source) == item['source']['body_sha256'], 'Source body digest changed')
        if mode == 'extent-mismatch':
            require(len(source) != len(captured), 'Extent-mismatch mode requires unequal extents')
            require(item.get('relocations') is None, 'Extent mismatch has no shared relocation mask')
            require(not any(key in item for key in
                            ('bytes', 'raw_equal_bytes', 'relocation_bytes', 'non_relocation_bytes',
                             'equal_non_relocation_bytes', 'raw_difference_offsets',
                             'non_relocation_difference_offsets')),
                    'Extent mismatch cannot supply aligned-byte metrics')
            # Preserve both complete authenticated extents without inventing an
            # offset alignment, byte denominator, prefix comparison or padding.
            extent_mismatches.append({**item, 'status': 'unmatched-extent',
                                      'target_bytes': len(captured), 'source_bytes': len(source),
                                      'raw_equal': False, 'relocation_qualified': False,
                                      'aligned_byte_comparison': None})
            continue
        reference = item.get('relocations')
        relocations = record(reference['path'], reference['pointer']) if reference else []
        pointer = reference['pointer'] if reference else []
        if len(pointer) == 3 and pointer[0] == 'records' and pointer[2] == 'relocations':
            # A per-record census pointer must name this window's own record.
            owner = record(reference['path'], pointer[:2])
            require(owner.get('start') == start and owner.get('end') == end
                    and owner.get('source_offset') == item['source'].get('offset', 0)
                    and owner.get('source_body_sha256') == item['source']['body_sha256'],
                    'Relocation record belongs to another window')
        if isinstance(relocations, dict):
            relocations = [relocations]
        rows.append({**item, **compare(source, captured, relocations)})
    return {**({'extent_mismatches': extent_mismatches} if extent_mismatches else {}),
        'targets': targets, 'windows': rows, 'components': {
        c['id']: summarize([r for r in rows if r['component'] == c['id'] and r['target'] == c['artifact'] and 'dependency' not in r])
        for c in components}, 'totals': {name: summarize([r for r in rows if r['target'] == name])
                                        for name in targets},
        'dependencies': {name: {dep: summarize([r for r in rows if r['target'] == name and r.get('dependency') == dep])
                               for dep in sorted({r['dependency'] for r in rows if r['target'] == name and 'dependency' in r})}
                         for name in targets}}
