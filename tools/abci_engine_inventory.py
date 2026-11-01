#!/usr/bin/env python3
"""Digest-pinned node #94 engine Location/anchor qualification (MIT, Python 3.10+).

Static only. Reuses the repository's MIT ELF/FDE and restricted byte decoders.
No subprocess, native disassembler, network, or captured executable is invoked.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
import mmap
from pathlib import Path
import re
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import abci_state_inventory as core

ROOT = TOOLS.parent
TARGET = core.TARGET
SHA256 = core.SHA256
PREFIX = core.PREFIX  # Compiler path bytes in the artifact; not analyst state.
SCOPE = b'l1/src/abci/engine.rs'
BASE_COMMIT = 'e80dc0f3ffa6d95a7284f7e4654a0dfb9d01b67d'
REFERENCE_COMMIT = '999556f6e0a474b8312db96ec3149e1c44e97c23'
REFERENCE_PATH = 'references/can1357-hl/l1/abci/engine.rs'
REFERENCE_SHA256 = '5fb059e5779c0a5d2a6bf46fe3f3538675a2cd600fab04506d8b760c98724d7e'
SEEDS = (0x2209d40, 0x220bed0, 0x33084a0, 0x37e2960, 0x42e4600,
         0x42e5d40, 0x42e73d0, 0x42e7980, 0x432f310)
OUTPUTS = ('inventory.json', 'instructions.json')
PRIOR = ('RE-001-checkpoint-retention-94', 'RE-001-archive-prefix-94',
         'RE-001-snapshot-admission-94')
NAMED = {0x3bade80: 'RE-001-archive-prefix-94'}
EvidenceError = core.EvidenceError
require, sha, authenticate = core.require, core.sha, core.authenticate
Image, Fdes = core.Image, core.Fdes
relative_relocations, scan_leas = core.relative_relocations, core.scan_leas
decode_lea, decode_rel32_transfer = core.decode_lea, core.decode_rel32_transfer
decode_mov_immediate, decode_pointer_store = core.decode_mov_immediate, core.decode_pointer_store
LEA_RE = core.LEA_RE
render = core.render


def decode_instruction(code, offset=0, base=0):
    # The existing decoder cannot finish 0x2209d40: 0x220aaa4 is AND r9w,r8w,
    # 0x220aab0 is PCMPEQD xmm2,xmm2. Add only these register-form families.
    # Reject memory forms/truncation rather than strip a prefix and resync.
    require(0 <= offset < len(code), 'instruction offset outside input')
    head = code[offset:offset+3]
    if head in (b'\x66\x45\x21', b'\x66\x0f\x76'):
        require(offset+4 <= len(code) and code[offset+3] >> 6 == 3,
                'engine word-AND/PCMPEQD profile requires register operand')
        return {'site': base+offset, 'raw': bytes(code[offset:offset+4]), 'kind': 'other'}
    return core.decode_instruction(code, offset, base)


def decode_fde(image, fde):
    raw = image.read(fde['start'], fde['end']-fde['start'])
    insns, cursor = [], 0
    while cursor < len(raw):
        try:
            x = decode_instruction(raw, cursor, fde['start'])
        except EvidenceError as exc:
            raise EvidenceError(f"FDE {fde['start']:#x} site {fde['start']+cursor:#x}: {exc}") from exc
        insns.append(x)
        cursor += len(x['raw'])
    require(cursor == len(raw), 'incomplete FDE decode')
    core.validate_branch_boundaries(insns, fde['start'], fde['end'])
    return insns


def instruction_evidence(image, insn):
    require(insn['raw'] == image.read(insn['site'], len(insn['raw'])), 'instruction bytes differ')
    require(decode_instruction(insn['raw'], base=insn['site']) == insn, 'instruction metadata differs')
    row = {**image.evidence(insn['site'], len(insn['raw'])), 'kind': insn['kind']}
    if insn['kind'] in ('call_rel32', 'jmp_rel32'):
        row['target'] = hex(decode_rel32_transfer(insn['raw'], insn['site']))
    return row


def decode_location(image, slot, relocation, exact=True):
    section, _ = image.mapping(slot, 24)
    require(section['name'] == '.data.rel.ro' and slot % 8 == 0, 'Location storage/alignment')
    pointer, length, line, column = struct.unpack('<QQII', image.read(slot, 24))
    require(pointer == 0 and len(PREFIX) < length < 256 and 0 < line < 1000000
            and 0 < column < 1000000, 'invalid Location fields')
    target = relocation['target']
    section, _ = image.mapping(target, length)
    require(section['name'] == '.rodata', 'Location path outside .rodata')
    raw = image.read(target, length)
    require(raw.startswith(PREFIX) and raw.endswith(b'.rs') and b'\0' not in raw,
            'invalid first-party Location path')
    require(not exact or raw == PREFIX+SCOPE, 'Location path differs from exact scope')
    return {**image.evidence(slot, 24), 'path': raw[len(PREFIX):].decode('ascii'),
            'path_bytes': image.evidence(target, length), 'path_length': length,
            'line': line, 'column': column,
            'relocation': {'entry_va': hex(relocation['entry_va']),
                           'entry_file_offset': hex(relocation['entry_file_offset']),
                           'type': 'R_X86_64_RELATIVE', 'addend': hex(target), 'bytes': relocation['raw']}}


def locations(image, relocations):
    result = {}
    ro = image.by_name['.rodata']
    for slot, rel in sorted(relocations.items()):
        a = rel['target']
        if ro['address'] <= a <= ro['address']+ro['size']-len(PREFIX+SCOPE):
            if image.read(a, len(PREFIX+SCOPE)) == PREFIX+SCOPE:
                # A malformed matching record must fail, never shrink the census.
                result[slot] = decode_location(image, slot, rel)
    require(result, 'no exact-file Locations')
    return result


def attribution(image, decoded, relocations):
    result = {}
    ro = image.by_name['.rodata']
    for start, insns in sorted(decoded.items()):
        refs = []
        for x in insns:
            if len(x['raw']) != 7 or not LEA_RE.fullmatch(x['raw'][:3]): continue
            slot, _ = decode_lea(x['raw'], x['site'])
            rel = relocations.get(slot)
            if rel is None: continue
            a = rel['target']
            if not ro['address'] <= a <= ro['address']+ro['size']-len(PREFIX): continue
            if image.read(a, len(PREFIX)) != PREFIX: continue
            loc = decode_location(image, slot, rel, exact=False)
            refs.append({'lea': instruction_evidence(image, x), 'location': loc})
        paths = sorted({x['location']['path'] for x in refs})
        require(SCOPE.decode() in paths, 'FDE lacks scoped Location')
        result[start] = {'first_party_paths': paths, 'only_exact_file_locations_observed': paths == [SCOPE.decode()],
                         'location_references': refs}
    return result


def context(image, insns, index, refs):
    """Contiguous local setup, stopping at the first transfer; no reachability claim."""
    result = []
    for x in insns[index:index+8]:
        result.append(instruction_evidence(image, x))
        if x['kind'] in ('call_rel32', 'jmp_rel32', 'call_indirect', 'jmp_indirect', 'branch'): break
    sites = {x['va'] for x in result}
    return {'instructions': result, 'locations': [r for r in refs if r['lea']['va'] in sites]}


def pointer_length_pair(image, insns, index, literal):
    try:
        return core.pointer_length_pair(image, insns, index, literal)
    except EvidenceError:
        pass
    # A local RDX pointer / ECX length pair before a branch is sufficient to
    # establish these operands. No ABI, join/call or branch outcome is inferred.
    first = insns[index]
    target, reg = decode_lea(first['raw'], first['site'])
    require(reg == 2 and image.read(target, len(literal)) == literal, 'not local RDX literal setup')
    cursor = first['site'] + 7
    for j in range(index+1, min(index+3, len(insns))):
        x = insns[j]
        require(x['site'] == cursor, 'noncontiguous local pair')
        cursor += len(x['raw'])
        if x['kind'] == 'mov_imm':
            require(decode_mov_immediate(x['raw']) == {'register': 1, 'value': len(literal), 'width': 32},
                    'local ECX length differs')
            return {'kind': 'local_register_pointer_length', 'length': len(literal),
                    'pointer_register': 2, 'length_register': 1,
                    'setup': [instruction_evidence(image, y) for y in insns[index:j+1]]}
        dest, _ = core.decode_base_lea(x['raw'])
        require(dest == 7, 'local pair accepts only independent RDI address setup')
    raise EvidenceError('no immediate local length')


def counted_fragment(image, anchor, occurrence, probe):
    """Finite byte pattern: u8 length, printable bytes, C0 or terminal zero.

    Zero ends traversal; a probe must be contained in one chunk. The byte after
    the text is retained. No placeholder grammar or reconstructed log claimed.
    """
    cursor = anchor
    if image.read(cursor, 1) == b'\xc0': cursor += 1
    chunks = []
    for _ in range(4):
        length = image.read(cursor, 1)[0]
        require(0 < length < 128, 'zero terminator or unsupported chunk length')
        raw = image.read(cursor+1, length)
        require(all(32 <= b < 127 or b in (9, 10, 13) for b in raw), 'non-ASCII counted text')
        terminal = image.read(cursor+1+length, 1)[0]
        require(terminal in (0, 0xc0), 'invalid chunk delimiter')
        chunks.append({'length': length, 'text': raw.decode('ascii'), 'delimiter': hex(terminal),
                       'record': image.evidence(cursor, length+2)})
        if cursor+1 <= occurrence and occurrence+len(probe) <= cursor+1+length:
            require(image.read(occurrence, len(probe)) == probe, 'chunk probe mismatch')
            return {'kind': 'counted_ascii_chunks', 'length': length, 'chunks': chunks,
                    'probe_offset_in_last_chunk': occurrence-cursor-1,
                    'pattern': image.evidence(anchor, cursor+length+2-anchor)}
        require(terminal != 0, 'terminal zero prevents neighbor binding')
        cursor += length+2
    raise EvidenceError('probe beyond bounded chunks')


# These extra probes were read from the authenticated binary, not reference prose.
BINARY_PROBES = (
    'assertion failed: features_ok',
    'assertion failed: freeze_height >= self.locus.context.height()',
    '/tmp/evm_db_bad_app_hash', '/tmp/abci_state_bad_app_hash.rmp',
    'computed app hash at height=', 'new app hashes reached quorum:',
    'applied block', 'straggler evm state checkpoint',
    'periodic_abci_state_status_base_dir does not exist:',
    'tar_evm_checkpoints failed:', 'prune_lowest_evm_checkpoints failed:',
    'tar', '-C', '-cf', 'abci_engine',
)


def reference_bytes():
    raw = (ROOT/REFERENCE_PATH).read_bytes()
    require(sha(raw) == REFERENCE_SHA256, 'reference lead hash mismatch')
    return raw


def probes():
    raw = reference_bytes()
    result, seen = [], set()
    # All unique quoted literals in this exact reference file, except its
    # compiler-path doc comment (which contains no double-quoted literal).
    for line, row in enumerate(raw.splitlines(), 1):
        for needle in re.findall(rb'"([^"\n]+)"', row):
            if needle in seen: continue
            seen.add(needle)
            result.append({'id': f'reference-line-{line}', 'reference_line': line, 'needle': needle,
                           'origin': 'reference search hint; only matching target bytes may be exported',
                           'binding_rule': 'exact-pointer-length' if line in (34, 35) else 'pointer-length-or-counted-fragment'})
    for i, text in enumerate(BINARY_PROBES, 1):
        needle = text.encode('ascii')
        require(needle not in seen, 'duplicate diagnostic candidate')
        seen.add(needle)
        result.append({'id': f'binary-{i}', 'needle': needle, 'origin': 'authenticated target bytes',
                       'binding_rule': 'exact-pointer-length' if i in (12, 13, 14, 15) else 'pointer-length-or-counted-fragment'})
    return result


def diagnostic_inventory(image, decoded, attrs):
    leas = []
    for start, insns in sorted(decoded.items()):
        for i, x in enumerate(insns):
            if len(x['raw']) == 7 and LEA_RE.fullmatch(x['raw'][:3]):
                target, _ = decode_lea(x['raw'], x['site'])
                leas.append((target, start, i))
    result = []
    for spec in probes():
        needle = spec['needle']
        hits = core.occurrences(image, needle)
        anchors, rejected = [], []
        for hit in hits:
            if hit['section'] != '.rodata': continue
            occurrence = int(hit['va'], 16)
            for target, start, i in leas:
                if not 0 <= occurrence-target <= 128: continue
                insns = decoded[start]
                local = context(image, insns, i, attrs[start]['location_references'])
                row = {'owner': hex(start), 'lea': instruction_evidence(image, insns[i]),
                       'anchor': hex(target), 'occurrence': hex(occurrence), 'local_context': local}
                try:
                    # A nearby foreign Location is stronger attribution than
                    # merely sharing an FDE with an engine Location.
                    require(not any(r['location']['path'] != SCOPE.decode() for r in local['locations']),
                            'local setup references a foreign first-party Location')
                    require(spec['binding_rule'] != 'exact-pointer-length' or target == occurrence,
                            'token probe requires exact pointer/length, not a substring in a diagnostic')
                    proof = (pointer_length_pair(image, insns, i, needle) if target == occurrence
                             else counted_fragment(image, target, occurrence, needle))
                except EvidenceError as exc:
                    rejected.append({**row, 'reason': str(exc)})
                else:
                    anchors.append({**row, **proof,
                                    'attribution': 'same local setup as exact-file Location' if local['locations']
                                    else 'FDE co-location only; no per-Location or exclusive ownership claim'})
        # Reference strings absent from the target are never copied to output.
        result.append({**{k: v for k, v in spec.items() if k != 'needle'},
                       'display': image.read(int(hits[0]['va'], 16), len(needle)).decode('ascii') if hits else spec['id']+' (hash only)',
                       'probe_sha256': sha(needle), 'probe_length': len(needle),
                       'status': 'bound' if anchors else 'present-but-unbound' if hits else 'absent',
                       'occurrences': hits, 'anchors': anchors, 'rejected_candidates': rejected})
    return result


def constants(image, decoded, attrs):
    result = []
    # Reference numeric leads only. Record exact MOV operands where present,
    # but never promote repeated numbers to the suggested semantic role.
    for line, value in ((28, 390), (29, 3), (30, 2), (31, 10000), (32, 100)):
        rows = []
        for start, insns in sorted(decoded.items()):
            for x in insns:
                if x['kind'] != 'mov_imm': continue
                try: operand = decode_mov_immediate(x['raw'])
                except EvidenceError: continue
                if operand['value'] != value: continue
                rows.append({'owner': hex(start), 'instruction': instruction_evidence(image, x), 'operand': operand,
                             'only_exact_file_locations_observed': attrs[start]['only_exact_file_locations_observed'],
                             'reason': 'No unique dataflow to reference role; shared FDE or unrelated setup is insufficient'})
        result.append({'candidate': f'reference-line-{line}', 'numeric_hint': value, 'status': 'unresolved',
                       'anchors': [], 'decoded_mov_occurrences_not_bindings': rows,
                       'reason': 'MOV-immediate probe is not exhaustive arithmetic analysis; numeric, unit and semantic role binding unresolved. Prior snapshot arithmetic remains prior work.'})
    return result


def prior_work(image, fdes, scoped, locs):
    result, named = [], []
    for packet in PRIOR:
        path = f'research/work-items/{packet}/records.json'
        raw = (ROOT/path).read_bytes()
        doc = json.loads(raw)
        require(doc['target_sha256'] == SHA256, 'prior target digest differs')
        owners = []
        for row in doc['owners']:
            start, end = int(row['start'], 16), int(row['end_exclusive'], 16)
            fde = fdes.owner(start)
            require(fde is not None and fde['start'] == start and fde['end'] == end,
                    'prior FDE extent differs')
            require(sha(image.read(start, end-start)) == row['sha256'], 'prior owner hash differs')
            require(hex(fde['fde']) == row['fde'] and hex(fde['cie']) == row['cie'], 'prior unwind identity differs')
            owners.append({**row, 'revalidated': True, 'in_scope': start in scoped,
                           'engine_locations': [x['va'] for x in locs.values() if hex(start) in x['owning_fdes']]})
            if start in NAMED:
                named.append({**Fdes.record(image, fde), 'prior_packet': packet,
                              'role': 'prior archive-prefix tail projection; body semantics not re-claimed'})
        result.append({'path': path, 'sha256': sha(raw), 'owners': owners,
                       'claim': 'Identity/extent/overlap revalidation only; original semantic claims remain in prior packet'})
    return result, named


def edges_and_transfers(image, decoded, scoped):
    edges, transfers, counts = [], [], Counter()
    for start, insns in sorted(decoded.items()):
        for i, x in enumerate(insns):
            kind = x['kind']
            if kind in ('call_indirect', 'jmp_indirect'):
                counts[kind] += 1
            if kind not in ('call_rel32', 'jmp_rel32'): continue
            target = decode_rel32_transfer(x['raw'], x['site'])
            proof = instruction_evidence(image, x)
            disposition = ('scoped_entry' if target in scoped else 'prior_named_entry' if target in NAMED
                           else 'internal' if start <= target < scoped[start]['end'] else 'external_unresolved')
            counts[disposition+'_'+kind] += 1
            transfers.append({'caller': hex(start), 'instruction': proof, 'disposition': disposition})
            if disposition not in ('scoped_entry', 'prior_named_entry'): continue
            edges.append({'caller': hex(start), 'callee': hex(target), 'instruction': proof,
                          'signed_displacement': struct.unpack_from('<i', x['raw'], 1)[0],
                          'next_instruction': hex(x['site']+5), 'callee_scope': disposition,
                          'prior_packet': NAMED.get(target),
                          'preceding_context': [instruction_evidence(image, y) for y in insns[max(0,i-4):i]],
                          'claim': 'Exact static E8/E9 entry edge; argument roles, reachability and helper behavior unproved'})
    return edges, transfers, dict(sorted(counts.items()))


def build(data):
    authenticate(data)
    image = Image(data)
    rel = relative_relocations(image)
    locs = locations(image, rel)
    fdes = Fdes(image)
    candidates = scan_leas(image, locs)
    scoped, pending = {}, []
    for slot in locs:
        require(candidates.get(slot), 'Location lacks RIP LEA')
        for site in candidates[slot]:
            fde = fdes.owner(site, 7)
            require(fde is not None, 'Location LEA lacks FDE')
            scoped[fde['start']] = fde
            pending.append((site, slot, fde['start']))
    decoded = {s: decode_fde(image, f) for s, f in sorted(scoped.items())}
    attrs = attribution(image, decoded, rel)
    accepted = []
    for site, slot, start in sorted(pending):
        insns = decoded[start]
        x, reg = core.verified_lea(image, insns, site, slot)
        i = next(i for i, t in enumerate(insns) if t['site'] == site)
        accepted.append({'instruction': instruction_evidence(image, x), 'location': hex(slot),
                         'owner': hex(start), 'destination_register': reg,
                         'local_context': context(image, insns, i, attrs[start]['location_references'])})
    for slot, row in locs.items():
        row['lea_sites'] = [x['instruction']['va'] for x in accepted if x['location'] == hex(slot)]
        row['owning_fdes'] = sorted({x['owner'] for x in accepted if x['location'] == hex(slot)})
    diagnostics = diagnostic_inventory(image, decoded, attrs)
    numeric = constants(image, decoded, attrs)
    prior, named = prior_work(image, fdes, scoped, locs)
    edges, transfers, counts = edges_and_transfers(image, decoded, scoped)
    metrics = {'locations': len(locs), 'unique_line_column': len({(r['line'], r['column']) for r in locs.values()}),
               'location_leas': len(accepted), 'scoped_fdes': len(scoped),
               'scoped_fde_bytes': sum(f['end']-f['start'] for f in scoped.values()),
               'decoded_instructions': sum(map(len, decoded.values())),
               'shared_first_party_fdes': sum(not a['only_exact_file_locations_observed'] for a in attrs.values()),
               'diagnostics_probed': len(diagnostics),
               'diagnostics_bound': sum(d['status'] == 'bound' for d in diagnostics),
               'diagnostics_unresolved': sum(d['status'] == 'present-but-unbound' for d in diagnostics),
               'diagnostics_absent': sum(d['status'] == 'absent' for d in diagnostics),
               'pointer_length_anchors': sum(a['kind'] != 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'counted_fragment_anchors': sum(a['kind'] == 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'anchors_with_local_engine_location': sum(bool(a['local_context']['locations']) for d in diagnostics for a in d['anchors']),
               'constants_bound': sum(c['status'] == 'bound' for c in numeric),
               'constants_unresolved': sum(c['status'] == 'unresolved' for c in numeric),
               'call_edges': sum(e['instruction']['kind'] == 'call_rel32' for e in edges),
               'tail_edges': sum(e['instruction']['kind'] == 'jmp_rel32' for e in edges),
               'prior_owner_overlaps': sum(o['in_scope'] for p in prior for o in p['owners'])}
    reference_bytes()
    seeds = json.loads((ROOT/'research/catalogue/seed-candidates.json').read_text())
    # Never use catalogue seeds as owners.
    require(sorted({int(r['address'], 16) for r in seeds['items'] if r['file'] == 'l1/abci/engine.rs'}) == list(SEEDS),
            'catalogue seeds differ')
    evidence = {'schema_version': 1, 'work_item': 'abci-engine-inventory-94', 'component': 'abci', 'task': 'RE-001 exact-file inventory qualification',
                'target': {'path': TARGET, 'sha256': SHA256, 'release': 94}, 'scope_rule': SCOPE.decode(),
                'source_commit': BASE_COMMIT, 'reference_commit': REFERENCE_COMMIT,
                'reference': {'path': REFERENCE_PATH, 'sha256': REFERENCE_SHA256, 'role': 'unlicensed search hints only; no reference code copied'},
                'producer_sources_sha256': {f'tools/{name}': sha((TOOLS/name).read_bytes()) for name in
                                           ('abci_engine_inventory.py', 'abci_state_inventory.py', 'elf_index.py', 'fde_extents.py')},
                'method': {'dependency': 'Python 3.10+ stdlib only', 'decoder': 'restricted sequential x86-64 byte decoder, engine profile v1',
                           'all_fde_records_checked': len(fdes.rows), 'coordinates': 'ELF link-time VA and file offset; end exclusive; no rebase',
                           'normalization_masks': [], 'captured_binaries_executed': False, 'network_used': False,
                           'completeness': 'All exact-path RELATIVE Location records and matching executable-section RIP LEA candidates; full linear scoped FDE decode with internal branch alignment; not CFG reachability',
                           'literal_scope': 'all unique reference quoted literals plus finite engine-related binary probes; not all rodata',
                           'constant_scope': 'five top-level numeric reference hints; MOV-immediate occurrences only, all semantic roles unresolved'},
                'metrics': metrics, 'transfer_counts': counts, 'locations': list(locs.values()), 'location_leas': accepted,
                'fdes': [{**Fdes.record(image, f), **attrs[s]} for s, f in sorted(scoped.items())],
                'seed_checks': [{'address': hex(s), 'exact_fde_start': bool(fdes.owner(s) and fdes.owner(s)['start'] == s),
                                 'references_engine_location': s in scoped} for s in SEEDS],
                'diagnostics': diagnostics, 'constants': numeric, 'call_edges': edges, 'rel32_transfers': transfers,
                'prior_work': prior, 'named_callees': named,
                'non_claims': ['No runtime behavior, protocol semantics, original source reconstruction or rebuilt Rust.',
                              'No exclusive FDE ownership, recovered function names, full CFG, ABI or argument roles.',
                              'No claim for state.rs, other abci files, node, clearinghouse, exchange or base/foundation internals.',
                              'No novelty for prior checkpoint retention, archive-prefix or snapshot-admission semantics.',
                              'No formatter grammar, rendered diagnostics, filesystem effects or command execution.',
                              'No semantic constant roles or units; no inferred layout from reference prose.',
                              'No full function denominator, gate change, build equivalence, node #115 or visor claim.'],
                'remaining_gaps': {'helpers': 'callee behavior/closure unproved', 'call_targets': 'only scoped and prior-named exact entries admitted; other direct and all indirect calls unresolved',
                                   'relocations': 'Location RELATIVE records only; no whole-program relocation equivalence',
                                   'vtable_data': 'no vtable or general data closure', 'whole_elf': 'no build/comparison',
                                   'code': 'FDE-less code, inlining and split bodies outside this denominator'}}
    transcript = {'target_sha256': SHA256, 'decoder': evidence['method']['decoder'],
                  'columns': ['offset_from_fde_start', 'raw_hex', 'decoded_kind'],
                  'fdes': [{'start': hex(s), 'end_exclusive': hex(scoped[s]['end']),
                            'instructions': [[hex(x['site']-s), x['raw'].hex(), x['kind']] for x in insns]}
                           for s, insns in sorted(decoded.items())]}
    return {'inventory.json': evidence, 'instructions.json': transcript}


def table(tag, headers, rows):
    def cell(x): return str(x).replace('|', '\\|').replace('\n', ' ')
    lines = [f'<!-- BEGIN GENERATED {tag} -->', '| '+' | '.join(headers)+' |', '| '+' | '.join(['---']*len(headers))+' |']
    lines += ['| '+' | '.join(map(cell, row))+' |' for row in rows]
    lines.append(f'<!-- END GENERATED {tag} -->')
    return '\n'.join(lines)


def evidence_tables(e):
    return {
        'METRICS': table('METRICS', ['Metric', 'Count'], sorted(e['metrics'].items())),
        'LOCATIONS': table('LOCATIONS', ['Slot VA', 'Line:column', 'LEA sites', 'FDE owners'],
                           [(r['va'], f"{r['line']}:{r['column']}", ', '.join(r['lea_sites']), ', '.join(r['owning_fdes'])) for r in e['locations']]),
        'FDES': table('FDES', ['FDE start', 'End exclusive', 'Bytes', 'Observed first-party Location paths'],
                     [(f['start'], f['end_exclusive'], f['size'], ', '.join(f['first_party_paths'])) for f in e['fdes']]),
        'DIAGNOSTICS': table('DIAGNOSTICS', ['Probe', 'Target bytes or hash-only identifier', 'Status', 'Occurrences', 'Anchors'],
                            [(d['id'], d['display'], d['status'], len(d['occurrences']), len(d['anchors'])) for d in e['diagnostics']]),
        'ANCHORS': table('ANCHORS', ['Probe', 'FDE', 'LEA', 'Literal target', 'Length', 'Proof', 'Local engine Location'],
                        [(d['id'], a['owner'], a['lea']['va'], a['anchor'], a['length'], a['kind'],
                          ', '.join(r['location']['va'] for r in a['local_context']['locations']) or 'none; range only') for d in e['diagnostics'] for a in d['anchors']]),
        'EDGES': table('EDGES', ['Caller', 'Call VA', 'Bytes', 'Signed rel32', 'Exact entry', 'Endpoint scope'],
                      [(x['caller'], x['instruction']['va'], x['instruction']['bytes'], x['signed_displacement'], x['callee'], x['callee_scope']) for x in e['call_edges']]),
        'CONSTANTS': table('CONSTANTS', ['Candidate', 'Numeric hint', 'Status', 'Decoded MOV occurrences (not bindings)'],
                          [(x['candidate'], x['numeric_hint'], x['status'], len(x['decoded_mov_occurrences_not_bindings'])) for x in e['constants']]),
        'TRANSFERS': table('TRANSFERS', ['Transfer disposition', 'Sites'], sorted(e['transfer_counts'].items())),
    }


def generate(binary, out):
    with Path(binary).open('rb') as h, mmap.mmap(h.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = build(data)
    Path(out).mkdir(parents=True, exist_ok=True)
    for name in OUTPUTS: Path(out, name).write_bytes(render(result[name]))
    return result['inventory.json']['metrics']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try: metrics = generate(args.binary, args.out)
    except (ValueError, OSError) as exc: parser.exit(1, f'FAIL: {exc}\n')
    print(json.dumps(metrics, sort_keys=True))


if __name__ == '__main__':
    main()
