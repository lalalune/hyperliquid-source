#!/usr/bin/env python3
"""RE-002 static distribution/object compatibility probe; never installs or runs targets."""
import argparse
import collections
import json
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import sys
import tarfile

from scan_object_provenance import (MAX_FILE, MAX_TOTAL, MAX_MEMBERS, FormatError,
    ar_members, classify, digest, elf_details, elf_sections, negative_controls, require)

HERE = Path(__file__).resolve().parent
BODY_SHA256 = '09027f7508488f9fabf097f96e8db1d2e2740cf931ae88d008e04df4a8ab2916'
# Retained 27-instruction witness, independently cross-checked with native LLVM
# during research. This is a fixed byte witness, not a generic x86 decoder.
WITNESS = [{"offset": 0, "bytes": "4889f8", "mnemonic": "movq", "operands": "%rdi, %rax"}, {"offset": 3, "bytes": "48d1e8", "mnemonic": "shrq", "operands": "%rax"}, {"offset": 6, "bytes": "48b95555555555555555", "mnemonic": "movabsq", "operands": "$0x5555555555555555, %rcx # imm = 0x5555555555555555"}, {"offset": 16, "bytes": "4821c1", "mnemonic": "andq", "operands": "%rax, %rcx"}, {"offset": 19, "bytes": "4829cf", "mnemonic": "subq", "operands": "%rcx, %rdi"}, {"offset": 22, "bytes": "4889f8", "mnemonic": "movq", "operands": "%rdi, %rax"}, {"offset": 25, "bytes": "48c1e802", "mnemonic": "shrq", "operands": "$0x2, %rax"}, {"offset": 29, "bytes": "48b93333333333333333", "mnemonic": "movabsq", "operands": "$0x3333333333333333, %rcx # imm = 0x3333333333333333"}, {"offset": 39, "bytes": "4821c8", "mnemonic": "andq", "operands": "%rcx, %rax"}, {"offset": 42, "bytes": "4821f9", "mnemonic": "andq", "operands": "%rdi, %rcx"}, {"offset": 45, "bytes": "4801c1", "mnemonic": "addq", "operands": "%rax, %rcx"}, {"offset": 48, "bytes": "4889c8", "mnemonic": "movq", "operands": "%rcx, %rax"}, {"offset": 51, "bytes": "48c1e804", "mnemonic": "shrq", "operands": "$0x4, %rax"}, {"offset": 55, "bytes": "4801c8", "mnemonic": "addq", "operands": "%rcx, %rax"}, {"offset": 58, "bytes": "48b90f0f0f0f0f0f0f0f", "mnemonic": "movabsq", "operands": "$0xf0f0f0f0f0f0f0f, %rcx # imm = 0xF0F0F0F0F0F0F0F"}, {"offset": 68, "bytes": "4821c1", "mnemonic": "andq", "operands": "%rax, %rcx"}, {"offset": 71, "bytes": "4889c8", "mnemonic": "movq", "operands": "%rcx, %rax"}, {"offset": 74, "bytes": "48c1e820", "mnemonic": "shrq", "operands": "$0x20, %rax"}, {"offset": 78, "bytes": "01c8", "mnemonic": "addl", "operands": "%ecx, %eax"}, {"offset": 80, "bytes": "89c1", "mnemonic": "movl", "operands": "%eax, %ecx"}, {"offset": 82, "bytes": "c1e910", "mnemonic": "shrl", "operands": "$0x10, %ecx"}, {"offset": 85, "bytes": "01c1", "mnemonic": "addl", "operands": "%eax, %ecx"}, {"offset": 87, "bytes": "89c8", "mnemonic": "movl", "operands": "%ecx, %eax"}, {"offset": 89, "bytes": "c1e808", "mnemonic": "shrl", "operands": "$0x8, %eax"}, {"offset": 92, "bytes": "01c8", "mnemonic": "addl", "operands": "%ecx, %eax"}, {"offset": 94, "bytes": "83e07f", "mnemonic": "andl", "operands": "$0x7f, %eax"}, {"offset": 97, "bytes": "c3", "mnemonic": "retq", "operands": ""}]


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def verify(path, item, size_key='bytes'):
    require(path.is_file() and path.stat().st_size == item[size_key], 'input size mismatch: ' + path.name)
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    got = h.hexdigest()
    require(got == item['sha256'], 'input SHA-256 mismatch: ' + path.name)


def hits(target, sections, body, code):
    found = []
    for sec in sections:
        eligible = bool(sec['flags'] & 4) if code else bool(sec['flags'] & 2 and not sec['flags'] & 4)
        if not eligible or sec['type'] == 8 or not sec['size']:
            continue
        at = target.find(body, sec['offset'], sec['offset'] + sec['size'])
        while at >= 0:
            found.append(dict(section_index=sec['index'], section=sec['name'],
                file_offset=at, virtual_address=sec['address'] + at - sec['offset']))
            if len(found) >= 8:
                return dict(locations=found, truncated=True)
            at = target.find(body, at + 1, sec['offset'] + sec['size'])
    return dict(locations=found, truncated=False)


def decode_rows(text, base):
    rows = []
    for line in text.splitlines():
        if ':' not in line or '\t' not in line:
            continue
        first, *rest = line.split('\t')
        if ':' not in first:
            continue
        address, field = first.split(':', 1)
        tokens = field.split()
        if not re.fullmatch(r'\s*[0-9a-f]+', address) or not tokens or not all(re.fullmatch('[0-9a-f]{2}', t) for t in tokens):
            continue
        rows.append(dict(offset=int(address, 16) - base, bytes=''.join(tokens),
            mnemonic=rest[0].strip(), operands='\t'.join(rest[1:]).strip()))
    return rows


def native(tool, args, out, label, raw=None):
    env = {name: os.environ[name] for name in ('HOME', 'USER', 'LOGNAME') if name in os.environ}
    env.update(PATH=os.defpath, TMPDIR=str(out / 'native-tmp'), LANG='C', LC_ALL='C')
    if os.name == 'nt' and 'SystemRoot' in os.environ:
        env['SystemRoot'] = os.environ['SystemRoot']
    result = subprocess.run([str(tool), *args], input=raw, capture_output=True, env=env, timeout=30)
    (out / (label + '.stdout')).write_bytes(result.stdout)
    (out / (label + '.stderr')).write_bytes(result.stderr)
    require(result.returncode == 0, 'explicit native reader failed: ' + label)
    return result.stdout.decode('utf-8')


def scan_archive(path, record, out):
    verify(path, record)
    counts = collections.Counter()
    comment_counts = collections.Counter()
    group_counts = collections.Counter()
    candidates = []
    groups = []
    first_carrier = None
    seen = set()
    logical_bytes = 0
    inventory = out / ('members-' + record['version'] + '.jsonl')
    with inventory.open('w') as output, tarfile.open(path, mode='r|xz') as tar:
        for number, info in enumerate(tar):
            require(number < MAX_MEMBERS, 'tar member limit')
            counts['tar_members'] += 1
            require(info.name not in seen, 'duplicate tar member')
            seen.add(info.name)
            name = PurePosixPath(info.name)
            require(not name.is_absolute() and '..' not in name.parts, 'unsafe tar member name')
            if not info.isfile():
                counts['tar_nonregular_not_followed'] += 1
                continue
            counts['tar_regular_files'] += 1
            require(0 <= info.size <= MAX_FILE, 'tar size limit')
            logical_bytes += info.size
            require(logical_bytes <= MAX_TOTAL, 'tar logical byte limit')
            if not info.name.endswith(('.rlib', '.a', '.o', '.so')):
                counts['tar_nonbinary_not_read'] += 1
                continue
            handle = tar.extractfile(info)
            require(handle is not None, 'missing tar payload')
            blob = handle.read(MAX_FILE + 1)
            require(len(blob) == info.size, 'truncated tar payload')
            is_selected = name.name.startswith(('libcompiler_builtins-', 'libprofiler_builtins-')) and info.name.endswith('.rlib')
            group = dict(version=record['version'], tar_name=info.name, rlib_sha256=digest(blob), counts=collections.Counter())
            if blob.startswith(b'!<thin>\n'):
                counts['thin_ar_not_followed'] += 1
                continue
            is_ar = blob.startswith(b'!<arch>\n')
            if is_ar:
                counts['regular_ar_archives'] += 1
                members = ar_members(blob)
            else:
                counts['standalone_binary_files'] += 1
                members = [(None, memoryview(blob))]
            for member, value in members:
                if member is not None:
                    counts['ar_members_total'] += 1
                    if member['special']:
                        counts['ar_special_tables'] += 1
                        continue
                kind = classify(value)
                counts['payload_' + kind] += 1
                identity = dict(tar_index=number, tar_name=info.name, ar_member=member, size=len(value), sha256=digest(value), kind=kind)
                if kind != 'ELF64LE':
                    output.write(json.dumps(identity, sort_keys=True) + '\n')
                    continue
                raw = bytes(value)
                detail = elf_details(raw, details=is_selected)
                counts['elf_type_' + str(detail['elf_type'])] += 1
                counts['elf_with_comment'] += bool(detail['comments'])
                identity.update(elf_type=detail['elf_type'], comments=detail['comments'])
                for comment in detail['comments']:
                    comment_counts[comment['text']] += 1
                output.write(json.dumps(identity, sort_keys=True) + '\n')
                if not detail['matching_clang_comments']:
                    continue
                counts['matching_clang_carriers'] += 1
                group_counts[name.name] += 1
                if first_carrier is None and detail['elf_type'] == 1:
                    first_carrier = raw
                if not is_selected or detail['elf_type'] != 1:
                    counts['matching_outside_selected_rlibs'] += 1
                    continue
                group['counts']['stamped_members'] += 1
                for symbol in detail['symbols']:
                    code, data = symbol['type'] == 2, symbol['type'] == 1
                    if not (code or data) or 'file_offset' not in symbol:
                        continue
                    group['counts']['defined_code' if code else 'defined_data'] += 1
                    owner = detail['sections'][symbol['section_index']]
                    if symbol['size'] < (32 if code else 16) or owner['type'] == 8 or (code and not owner['flags'] & 4) or (data and not owner['flags'] & 2):
                        group['counts']['excluded_small_zerofill_or_flags'] += 1
                        continue
                    lower = symbol['section_relative_offset']
                    upper = lower + symbol['size']
                    relocations = [r for r in detail['relocations'] if r['target_section'] == owner['index'] and lower <= r['offset'] < upper]
                    if relocations:
                        group['counts']['excluded_relocated_payloads'] += 1
                        continue
                    group['counts']['eligible_code' if code else 'eligible_data'] += 1
                    payload = raw[symbol['file_offset']:symbol['file_offset'] + symbol['size']]
                    candidates.append(dict(version=record['version'], archive_sha256=record['sha256'],
                        tar_name=info.name, rlib_sha256=group['rlib_sha256'], member=member,
                        member_sha256=digest(raw), comments=detail['matching_clang_comments'], symbol=symbol,
                        code=code, payload=payload, all_zero=not any(payload), raw=raw, detail=detail))
            if is_selected:
                group['counts'] = dict(group['counts'])
                groups.append(group)
    require(len(groups) == 2, 'expected compiler/profiler rlib pair')
    controls = negative_controls(first_carrier) if first_carrier is not None else []
    summary = dict(version=record['version'], archive_sha256=record['sha256'], counts=dict(counts),
        logical_regular_bytes=logical_bytes, exact_comment_member_counts=dict(comment_counts),
        matching_groups=dict(group_counts), selected_groups=groups, parser_controls=controls,
        member_inventory_sha256=digest(inventory.read_bytes()))
    return summary, candidates


def selected_controls(item):
    raw, symbol, detail = item['raw'], item['symbol'], item['detail']
    owner = detail['sections'][symbol['section_index']]
    require(symbol['section_relative_offset'] == 0 and symbol['size'] == owner['size'] == 98, 'selected section/body mismatch')
    require(owner['type'] == 1 and owner['flags'] & 4, 'selected section not executable PROGBITS')
    require(not any(r['target_section'] == owner['index'] for r in detail['relocations']), 'selected code section has relocation')
    body = item['payload']
    require(digest(body) == BODY_SHA256, 'selected fixed witness mismatch')
    require(b''.join(bytes.fromhex(row['bytes']) for row in WITNESS) == body, 'retained instruction witness bytes mismatch')
    corrupted = bytearray(raw)
    corrupted[symbol['file_offset']] ^= 1
    require(elf_details(corrupted)['matching_clang_comments'] == detail['matching_clang_comments'], 'code corruption changed comment')
    stamp = bytearray(raw)
    stamp[detail['matching_clang_comments'][0]['file_offset']] = ord('X')
    require(not elf_details(stamp)['matching_clang_comments'], 'stamp corruption still exact')
    require(bytes(stamp[symbol['file_offset']:symbol['file_offset'] + 98]) == body, 'stamp corruption changed code')
    controls = []
    at = detail['section_header_offset'] + symbol['section_index'] * detail['section_header_stride']
    for label, field, value, fmt in [('NOBITS', 4, 8, '<I'), ('nonexecuting', 8, owner['flags'] & ~4, '<Q')]:
        changed = bytearray(raw)
        struct.pack_into(fmt, changed, at + field, value)
        revised = elf_details(changed)['sections'][owner['index']]
        rejected = revised['type'] != 1 or not revised['flags'] & 4
        require(rejected, 'metadata control accepted')
        controls.append(dict(case=label, changed_member_sha256=digest(changed), rejected=True))
    return bytes(corrupted[symbol['file_offset']:symbol['file_offset'] + 98]), controls


def caller_witness(target, sections, fdes, destination, tool, binary, out, label):
    raw = []
    for sec in sections:
        if sec['type'] == 8 or not sec['flags'] & 4:
            continue
        at = target.find(b'\xe8', sec['offset'], sec['offset'] + sec['size'])
        while at >= 0:
            if at + 5 <= sec['offset'] + sec['size']:
                site = sec['address'] + at - sec['offset']
                if site + 5 + struct.unpack_from('<i', target, at + 1)[0] == destination:
                    raw.append(dict(file_offset=at, virtual_address=site))
            at = target.find(b'\xe8', at + 1, sec['offset'] + sec['size'])
    bounded = []
    for site in raw:
        for fde in fdes:
            if fde['start'] <= site['virtual_address'] and site['virtual_address'] + 5 <= fde['end'] and 0 < fde['end'] - fde['start'] <= 4096:
                bounded.append((fde['end'] - fde['start'], site, fde))
    bounded.sort(key=lambda row: (row[0], row[1]['virtual_address']))
    attempts, witness = [], None
    if tool:
        for _, site, fde in bounded[:5]:
            text = native(tool, ['-d', '--start-address=' + hex(fde['start']), '--stop-address=' + hex(fde['end']), str(binary)], out, 'caller-' + label + '-' + str(len(attempts)))
            rows = decode_rows(text, fde['start'])
            cursor, contiguous = 0, bool(rows)
            for row in rows:
                contiguous = contiguous and row['offset'] == cursor
                cursor += len(bytes.fromhex(row['bytes']))
            contiguous = contiguous and cursor == fde['end'] - fde['start']
            call = next((row for row in rows if row['offset'] + fde['start'] == site['virtual_address']), None)
            accepted = bool(contiguous and call and call['mnemonic'].startswith('call') and len(bytes.fromhex(call['bytes'])) == 5 and call['bytes'].startswith('e8') and int(call['operands'].split()[0], 16) == destination)
            attempts.append(dict(site=site, fde=fde, fully_decoded=contiguous, decoded_call=accepted))
            if accepted:
                witness = dict(site=site, caller_fde=fde, call=call, decoded_caller_bytes=cursor)
                break
    return dict(raw_E8_candidates=len(raw), bounded_candidates=len(bounded), attempts=attempts,
        decoded_witness=witness, native_reader_used=bool(tool), complete_xref_census_claimed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=HERE.parents[2])
    parser.add_argument('--inputs', type=Path, required=True, help='external directory containing the signed archives')
    parser.add_argument('--out', type=Path, required=True, help='fresh directory beneath the repository work/')
    parser.add_argument('--native-objdump', type=Path, help='optional explicit LLVM-compatible static reader')
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    require(not (repo / 'work').is_symlink(), 'repository work/ must not be a symlink')
    require(out.is_relative_to((repo / 'work').resolve()) and out != (repo / 'work').resolve(), 'output must be a fresh ignored repository work/ subdirectory')
    require(not out.exists(), 'output directory already exists')
    if args.native_objdump:
        require(args.native_objdump.is_file(), 'explicit native reader missing')
    config = json.loads((HERE / 'inputs.json').read_text())
    manifest = json.loads((repo / 'provenance/artifacts.json').read_text())
    require({a['version'] for a in config['archives']} == {'1.94.1', '1.95.0'} and len(config['archives']) == 2, 'archive set differs')
    require({t['release'] for t in config['targets']} == {'94', '115', 'visor'} and len(config['targets']) == 3, 'target set differs')
    for target in config['targets']:
        item = next(r for r in manifest['files'] if r['path'] == target['path'])
        require(item['size'] == target['bytes'] and item['sha256'] == target['sha256'], 'project manifest agreement failed')
        verify(repo / target['path'], target)
    for archive in config['archives']:
        require(PurePosixPath(archive['filename']).name == archive['filename'] and not any(c in archive['filename'] for c in '/\\:'), 'archive filename is not a portable basename')
        verify(args.inputs / archive['filename'], archive)
    out.mkdir(parents=True)
    for name in ['native-home', 'native-tmp']:
        (out / name).mkdir()
    census, candidates = [], []
    for archive in config['archives']:
        summary, selected = scan_archive(args.inputs / archive['filename'], archive, out)
        census.append(summary)
        candidates.extend(selected)
    write(out / 'census.json', census)
    write(out / 'candidates.json', [dict(index=i, **{k: v for k, v in c.items() if k not in ['payload', 'raw', 'detail']}) for i, c in enumerate(candidates)])
    substantive = [c for c in candidates if c['code'] and c['symbol']['name'] == '__popcountdi2']
    require(len(substantive) == 2, 'selected symbol family differs')
    require(substantive[0]['payload'] == substantive[1]['payload'], 'cross-version code is not identical')
    controls = [selected_controls(c) for c in substantive]
    write(out / 'object-controls.json', [dict(version=c['version'], metadata_controls=control[1],
        code_corruption_sha256=digest(control[0]), comment_preserved=True, stamp_only_corruption_preserves_code=True)
        for c, control in zip(substantive, controls)])
    write(out / 'selected-objects.json', [{k: v for k, v in c.items() if k not in ['payload', 'raw']} for c in substantive])
    native_version = None
    object_rows = None
    if args.native_objdump:
        native_version = native(args.native_objdump, ['--version'], out, 'native-version').splitlines()[:3]
        object_rows = decode_rows(native(args.native_objdump, ['-d', '-'], out, 'native-object', substantive[0]['raw']), 0)
        require(object_rows == WITNESS, 'native object witness differs')
    # These project parsers are read-only tools, not target execution.
    sys.path.insert(0, str(repo / 'tools'))
    from fde_extents import eh_frame_records
    from artifacts import check
    wrong = next(t for t in config['targets'] if t['release'] == '115')
    actual = next(t for t in config['targets'] if t['release'] == '94')
    wrong_item = next(r for r in manifest['files'] if r['path'] == wrong['path'])
    try:
        check(repo / actual['path'], wrong_item)
    except ValueError:
        wrong_identity_rejected = True
    else:
        raise AssertionError('project guard accepted wrong release identity')
    observations, match_summary = [], []
    comparisons = out / 'all-comparisons.jsonl'
    with comparisons.open('w') as handle:
        for target_id in config['targets']:
            binary = repo / target_id['path']
            target = binary.read_bytes()
            require(digest(target) == target_id['sha256'], 'target changed during probe')
            sections = elf_sections(target)[-1]
            positives = []
            for index, candidate in enumerate(candidates):
                result = hits(target, sections, candidate['payload'], candidate['code'])
                row = dict(candidate_index=index, target=target_id['release'], **result)
                handle.write(json.dumps(row, sort_keys=True) + '\n')
                if result['locations']:
                    positives.append(dict(candidate_index=index, version=candidate['version'], symbol=candidate['symbol']['name'],
                        code=candidate['code'], all_zero=candidate['all_zero'], size=len(candidate['payload']), **result))
            body = substantive[0]['payload']
            location = hits(target, sections, body, True)
            require(len(location['locations']) == 1 and not location['truncated'], 'selected code not unique')
            where = location['locations'][0]
            require(not hits(target, sections, body, False)['locations'], 'code unexpectedly matches nonexecuting data')
            for corrupted, _ in controls:
                require(not hits(target, sections, corrupted, True)['locations'], 'code corruption still matches')
            require(target[where['file_offset'] + 1:where['file_offset'] + 99] != body, 'shifted coordinate matches')
            va = where['virtual_address']
            cies, fdes = eh_frame_records(target)
            overlap = [f for f in fdes if max(f['start'], va) < min(f['end'], va + 98)]
            exact = [f for f in fdes if f['start'] == va and f['end'] == va + 98]
            if args.native_objdump:
                rows = decode_rows(native(args.native_objdump, ['-d', '--start-address=' + hex(va), '--stop-address=' + hex(va + 98), str(binary)], out, 'native-target-' + target_id['release']), va)
                require(rows == object_rows, 'native target instruction rows differ')
            witness = caller_witness(target, sections, fdes, va, args.native_objdump, binary, out, target_id['release'])
            observations.append(dict(release=target_id['release'], target_sha256=target_id['sha256'], window=where,
                bytes=98, body_sha256=BODY_SHA256, parsed_cies=len(cies), parsed_fdes=len(fdes), target_comments=elf_details(target, details=False)['comments'],
                overlapping_fdes=overlap, exact_fdes=exact, target_complete_function_extent_claimed=False,
                code_corruption_matches=0, shifted_offset_matches=False, wrong_nonexecuting_section_matches=0,
                fixed_instruction_witness_verified=True, native_reader_used=bool(args.native_objdump), incoming=witness))
            match_summary.append(dict(release=target_id['release'], positive_comparisons=positives))
    write(out / 'target-observations.json', observations)
    code_count = sum(c['code'] for c in candidates)
    results = dict(source_commit=config['source_commit'], inputs_metadata_sha256=digest((HERE / 'inputs.json').read_bytes()),
        archives=[dict(version=c['version'], archive_sha256=c['archive_sha256'], counts=c['counts'],
            matching_groups=c['matching_groups'], selected_groups=c['selected_groups'], parser_controls=len(c['parser_controls']),
            member_inventory_sha256=c['member_inventory_sha256']) for c in census],
        eligible_symbol_candidates=dict(code=code_count, data=len(candidates) - code_count, total=len(candidates)),
        comment_census_sha256=digest((out / 'census.json').read_bytes()), comparison_count=len(candidates) * len(config['targets']), comparison_sha256=digest(comparisons.read_bytes()),
        positive_comparisons=match_summary, selected_body_sha256=BODY_SHA256, code_bytes=98,
        code_identical_across_releases=True, object_code_section_relocations=0,
        fixed_instruction_witness_count=27, native_reader_version=native_version,
        target_observations=observations, wrong_release_identity_rejected=wrong_identity_rejected,
        normalization_masks=[], extracted_objects=0, executed_targets=0, signatures_verified_by_probe=False,
        limits=['Archive SHA/size are checked; detached-signature verification is separate documented work, not inferred from inputs.json.',
            'Code-compatible library objects do not identify the unique historical release, member or stamp carrier.',
            'Seven sanitizer/runtime carrier groups remain outside the bounded binding subset.',
            'Relocated/small/zero-fill payloads are unmeasured; repeated all-zero profiler data are not provenance bindings.',
            'No overlapping target FDE or complete target-function-extent claim; one caller witness is not a complete xref census.',
            'Without explicit native reader, caller byte candidates remain unvalidated and the instruction table is a retained fixed witness.',
            'Open PR1024 owns node94 popcount behavior/caller analysis; this packet adds distribution/member compatibility only.'])
    write(out / 'results.json', results)
    print(json.dumps(dict(candidates=len(candidates), comparisons=results['comparison_count'],
        target_windows=len(observations), native_reader_used=bool(args.native_objdump),
        decoded_caller_witnesses=sum(o['incoming']['decoded_witness'] is not None for o in observations),
        result='partial code/object compatibility; historical stamp origin unresolved')))


if __name__ == '__main__':
    main()
