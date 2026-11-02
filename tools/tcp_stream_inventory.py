#!/usr/bin/env python3
"""Exact-file node #94 tcp_stream byte evidence (MIT; Python 3.10+ stdlib).

Static only: no subprocess, disassembler, network or captured execution.
Existing MIT ELF/FDE and restricted instruction decoders are reused unchanged.
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
TARGET, SHA256, PREFIX = core.TARGET, core.SHA256, core.PREFIX
SCOPE = b'net_utils/src/tcp/tcp_stream.rs'
BASE_COMMIT = 'd30ce21e87a5e9777e6949b523c6e8e2461e4169'
REFERENCE_COMMIT = '999556f6e0a474b8312db96ec3149e1c44e97c23'
REFERENCE_PATH = 'references/can1357-hl/net_utils/tcp/tcp_stream.rs'
REFERENCE_SHA256 = '36b7bd99220cc9b66cbd15deb11e63f1355beefddb13886bc97542e47157b51b'
SEEDS = (0x2034eb0, 0x2036460, 0x20485e0, 0x20487f0, 0x22615b0,
         0x4387910, 0x4387c80, 0x439edd0, 0x439efe0, 0x4b399a0)
OUTPUTS = ('inventory.json', 'instructions.json')
EvidenceError = core.EvidenceError
require, sha, authenticate = core.require, core.sha, core.authenticate
Image, Fdes = core.Image, core.Fdes
relative_relocations, scan_leas = core.relative_relocations, core.scan_leas
decode_instruction, decode_fde = core.decode_instruction, core.decode_fde
decode_lea, decode_rel32_transfer = core.decode_lea, core.decode_rel32_transfer
decode_mov_immediate, decode_pointer_store = core.decode_mov_immediate, core.decode_pointer_store
instruction_evidence, pointer_length_pair = core.instruction_evidence, core.pointer_length_pair
LEA_RE, render = core.LEA_RE, core.render


def relocation_evidence(rel):
    return {'entry_va': hex(rel['entry_va']), 'entry_file_offset': hex(rel['entry_file_offset']),
            'type': 'R_X86_64_RELATIVE', 'addend': hex(rel['target']), 'bytes': rel['raw']}


def decode_location(image, slot, rel, exact=True):
    section, _ = image.mapping(slot, 24)
    require(section['name'] == '.data.rel.ro' and slot % 8 == 0, 'Location storage/alignment')
    pointer, length, line, column = struct.unpack('<QQII', image.read(slot, 24))
    require(pointer == 0 and len(PREFIX) < length < 256 and 0 < line < 1000000
            and 0 < column < 1000000, 'invalid Location fields')
    target = rel['target']
    section, _ = image.mapping(target, length)
    require(section['name'] == '.rodata', 'Location path outside .rodata')
    raw = image.read(target, length)
    require(raw.startswith(PREFIX) and raw.endswith(b'.rs') and b'\0' not in raw,
            'invalid first-party Location path')
    require(not exact or raw == PREFIX+SCOPE, 'Location path differs from exact scope')
    require(struct.unpack('<QQq', bytes.fromhex(rel['raw'])) == (slot, 8, target),
            'Location relocation metadata differs')
    require(image.read(rel['entry_va'], 24).hex() == rel['raw'], 'Location relocation bytes differ')
    require(image.mapping(rel['entry_va'], 24)[1] == rel['entry_file_offset'],
            'Location relocation file offset differs')
    return {**image.evidence(slot, 24), 'path': raw[len(PREFIX):].decode('ascii'),
            'path_bytes': image.evidence(target, length), 'path_length': length,
            'line': line, 'column': column, 'relocation': relocation_evidence(rel)}


def locations(image, relocations):
    result = {}
    ro = image.by_name['.rodata']
    for slot, rel in sorted(relocations.items()):
        a = rel['target']
        if ro['address'] <= a <= ro['address']+ro['size']-len(PREFIX+SCOPE):
            if image.read(a, len(PREFIX+SCOPE)) == PREFIX+SCOPE:
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
            refs.append({'lea': instruction_evidence(image, x),
                         'location': decode_location(image, slot, rel, exact=False)})
        paths = sorted({x['location']['path'] for x in refs})
        require(SCOPE.decode() in paths, 'FDE lacks scoped Location')
        result[start] = {'first_party_paths': paths, 'only_exact_file_locations_observed': paths == [SCOPE.decode()],
                         'location_references': refs}
    return result


def decode_slot_call(raw, site):
    require(len(raw) == 6 and raw[:2] == b'\xff\x15', 'not RIP-indirect FF15 call')
    return site+6+struct.unpack_from('<i', raw, 2)[0]


def location_call(image, insns, index, rels, fdes):
    """Every admitted Location LEA is immediately followed by FF15; no helper naming."""
    first, call = insns[index:index+2]
    require(call['site'] == first['site']+7 and decode_lea(first['raw'], first['site'])[1] == 7,
            'Location is not contiguous RDI call setup')
    slot = decode_slot_call(call['raw'], call['site'])
    rel = rels.get(slot)
    require(rel is not None and image.read(slot, 8) == b'\0'*8, 'missing/invalid call-slot relocation')
    target = rel['target']
    owner = fdes.owner(target)
    require(owner is not None and owner['start'] == target and owner['section'] == '.text',
            'Location helper target is not an executable FDE entry')
    return {'call': instruction_evidence(image, call), 'pointer_slot': image.evidence(slot, 8),
            'relocation': relocation_evidence(rel), 'target': hex(target),
            'claim': 'Adjacent RDI Location / FF15 slot / relocated entry only; helper semantics unclaimed'}


def reference_bytes():
    raw = (ROOT/REFERENCE_PATH).read_bytes()
    require(sha(raw) == REFERENCE_SHA256, 'reference search-hint hash differs')
    return raw


# Read independently from target bytes, not copied from unlicensed reference prose.
BINARY_PROBES = ('early eof', 'could not resolve to any address', 'ip not v4', 'tcp_read_exact')


def probes():
    rows, seen = [], set()
    for line, raw in enumerate(reference_bytes().splitlines(), 1):
        for needle in re.findall(rb'"([^"\n]+)"', raw):
            if needle in seen: continue
            seen.add(needle)
            rows.append({'id': f'reference-line-{line}', 'reference_line': line, 'needle': needle,
                         'origin': 'unlicensed search hint; absent text withheld'})
    for i, text in enumerate(BINARY_PROBES, 1):
        needle = text.encode('ascii')
        require(needle not in seen, 'duplicate probe')
        rows.append({'id': f'binary-{i}', 'needle': needle, 'origin': 'authenticated target bytes'})
    return rows


def binding_attribution(attrs, start, setup):
    sites = {r['va'] for r in setup}
    refs = [r for r in attrs[start]['location_references'] if r['lea']['va'] in sites]
    require(not any(r['location']['path'] != SCOPE.decode() for r in refs), 'foreign Location in local setup')
    if refs:
        return {'kind': 'same local setup', 'locations': [r['location']['va'] for r in refs]}
    require(attrs[start]['only_exact_file_locations_observed'],
            'shared FDE without exact-file Location in local setup; byte co-location rejected')
    return {'kind': 'FDE has only exact-file first-party Locations; no individual-line attribution',
            'locations': sorted({r['location']['va'] for r in attrs[start]['location_references']})}


def diagnostic_inventory(image, decoded, attrs):
    leas = []
    for start, insns in sorted(decoded.items()):
        for i, x in enumerate(insns):
            if len(x['raw']) == 7 and LEA_RE.fullmatch(x['raw'][:3]):
                target, _ = decode_lea(x['raw'], x['site'])
                leas.append((target, start, i))
    rows = []
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
                row = {'owner': hex(start), 'lea': instruction_evidence(image, insns[i]),
                       'anchor': hex(target), 'occurrence': hex(occurrence)}
                proof = None
                try:
                    proof = (pointer_length_pair(image, insns, i, needle) if target == occurrence
                             else core.counted_fragment(image, target, occurrence, needle))
                    # Counted chunks establish bytes but never ownership of a shared range.
                    setup = proof.get('setup', [row['lea']])
                    attr = binding_attribution(attrs, start, setup)
                except EvidenceError as exc:
                    rejected.append({**row, 'reason': str(exc), 'byte_proof_not_attribution': proof})
                else:
                    anchors.append({**row, **proof, 'attribution': attr})
        rows.append({**{k: v for k, v in spec.items() if k != 'needle'},
                     'display': image.read(int(hits[0]['va'], 16), len(needle)).decode('ascii') if hits else spec['id']+' (hash only)',
                     'probe_sha256': sha(needle), 'probe_length': len(needle),
                     'status': 'bound' if anchors else 'present-but-unbound' if hits else 'absent',
                     'occurrences': hits, 'anchors': anchors, 'rejected_candidates': rejected})
    return rows


def constants(image, decoded, attrs):
    result = []
    # Extract the top-level numeric declarations as hints, retaining no names/code.
    for line, raw in enumerate(reference_bytes().splitlines(), 1):
        if not raw.startswith(b'pub const '): continue
        match = re.search(rb'= (?:Duration::from_secs\()?([0-9_]+)', raw)
        require(match is not None, 'numeric hint extraction differs')
        value = int(match[1].replace(b'_', b''))
        occurrences = []
        for start, insns in sorted(decoded.items()):
            for x in insns:
                if x['kind'] != 'mov_imm': continue
                try: operand = decode_mov_immediate(x['raw'])
                except EvidenceError: continue
                if operand['value'] == value:
                    occurrences.append({'owner': hex(start), 'instruction': instruction_evidence(image, x),
                                        'operand': operand, 'only_exact_file_locations_observed': attrs[start]['only_exact_file_locations_observed']})
        result.append({'candidate': f'reference-line-{line}', 'numeric_hint': value, 'status': 'unresolved',
                       'anchors': [], 'decoded_mov_occurrences_not_bindings': occurrences,
                       'reason': 'Numeric operands alone do not uniquely bind the reference semantic role/units. Prior header/EOF facts are revalidated separately, not claimed as new constants. MOV probe does not cover optimized arithmetic, byte stores or floating immediates.'})
    return result


def edges_and_transfers(image, decoded, scoped, attrs):
    edges, transfers, counts = [], [], Counter()
    for start, insns in sorted(decoded.items()):
        for i, x in enumerate(insns):
            kind = x['kind']
            if kind in ('call_indirect', 'jmp_indirect'): counts[kind] += 1
            if kind not in ('call_rel32', 'jmp_rel32'): continue
            target = decode_rel32_transfer(x['raw'], x['site'])
            proof = instruction_evidence(image, x)
            disposition = ('scoped_entry' if target in scoped else 'internal'
                           if start <= target < scoped[start]['end'] else 'external_unresolved')
            counts[disposition+'_'+kind] += 1
            transfers.append({'caller': hex(start), 'instruction': proof, 'disposition': disposition})
            if disposition != 'scoped_entry': continue
            edges.append({'caller': hex(start), 'callee': hex(target), 'instruction': proof,
                          'signed_displacement': struct.unpack_from('<i', x['raw'], 1)[0],
                          'next_instruction': hex(x['site']+5),
                          'callee_only_exact_file_locations_observed': attrs[target]['only_exact_file_locations_observed'],
                          'callee_locations': sorted({r['location']['va'] for r in attrs[target]['location_references']
                                                      if r['location']['path'] == SCOPE.decode()}),
                          'preceding_context': [instruction_evidence(image, y) for y in insns[max(0,i-4):i]],
                          'claim': 'Static E8/E9 edge to exact FDE entry, not runtime reachability or recovered operation'})
    return edges, transfers, dict(sorted(counts.items()))


def prior_work(image, fdes, scoped, decoded, locs):
    """Revalidate existing overlap; never import an old semantic conclusion as new."""
    rows = []
    def read(packet, name):
        path = f'research/work-items/{packet}/{name}'
        raw = (ROOT/path).read_bytes()
        doc = json.loads(raw)
        digest = doc.get('target_sha256', doc.get('binary_sha256', doc.get('target', {}).get('sha256') if isinstance(doc.get('target'), dict) else None))
        require(digest == SHA256, 'prior target digest differs')
        row = {'path': path, 'sha256': sha(raw), 'revalidated': [],
               'claim': 'Overlap/byte revalidation only; prior semantics and negative results remain with the cited packet'}
        rows.append(row)
        return doc, row
    for packet in ('gossip-rpc-client-inventory-94', 'gossip-config-inventory-94', 'evm-kvs-inventory-94'):
        doc, row = read(packet, 'inventory.json')
        for f in doc['fdes']:
            s = int(f['start'], 16)
            if s not in scoped: continue
            actual = Fdes.record(image, scoped[s])
            require(all(actual[k] == f[k] for k in actual), 'prior FDE identity differs')
            row['revalidated'].append({'fde': f['start'], 'end_exclusive': f['end_exclusive'],
                                       'code_sha256': f['code_sha256'], 'kind': 'shared owner; no exact-file Location census in prior'})
    doc, row = read('RE-009-storage-state-roots', 'state-roots.json')
    for f in doc['functions']:
        if SCOPE.decode() not in f['first_party_locations']: continue
        s = int(f['start'], 16)
        require(s in scoped and scoped[s]['end'] == int(f['end'], 16), 'prior storage owner differs')
        lines = sorted({l['line'] for l in locs.values() if f['start'] in l['owning_fdes']})
        require(lines == f['first_party_locations'][SCOPE.decode()], 'prior storage lines differ')
        row['revalidated'].append({'fde': f['start'], 'end_exclusive': f['end'], 'lines': lines,
                                   'kind': 'prior shared-FDE line attribution, not novel'})
    doc, row = read('transport-tcp-frame-read-94', 'records.json')
    for old in doc['early_eof_sites']:
        s, end = map(lambda v: int(v,16), old['fde'])
        require(s in scoped and scoped[s]['end'] == end, 'prior EOF FDE differs')
        insns = decoded[s]
        i = next((i for i,x in enumerate(insns) if x['site'] == int(old['lea'],16)), None)
        require(i is not None, 'prior EOF LEA not aligned')
        proof = pointer_length_pair(image, insns, i, b'early eof')
        require(proof['length'] == old['message_len'], 'prior EOF length differs')
        require(decode_mov_immediate(insns[i+2]['raw']) == {'register': 7, 'value': old['kind_imm'], 'width': 32}, 'prior EOF operand differs')
        slot = decode_slot_call(insns[i+3]['raw'], insns[i+3]['site'])
        require(hex(slot) == old['call_slot'], 'prior EOF call-slot differs')
        row['revalidated'].append({'fde': hex(s), 'lea': old['lea'], 'kind': 'prior literal/length/EDI/FF15 operand sequence',
                                   'proof': proof, 'numeric_operand': old['kind_imm'], 'call_slot': hex(slot)})
    return rows


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
        i = next(i for i,t in enumerate(insns) if t['site'] == site)
        accepted.append({'instruction': instruction_evidence(image, x), 'location': hex(slot),
                         'owner': hex(start), 'destination_register': reg,
                         'adjacent_call': location_call(image, insns, i, rel, fdes)})
    for slot, row in locs.items():
        row['lea_sites'] = [x['instruction']['va'] for x in accepted if x['location'] == hex(slot)]
        row['owning_fdes'] = sorted({x['owner'] for x in accepted if x['location'] == hex(slot)})
    diagnostics = diagnostic_inventory(image, decoded, attrs)
    numeric = constants(image, decoded, attrs)
    prior = prior_work(image, fdes, scoped, decoded, locs)
    edges, transfers, counts = edges_and_transfers(image, decoded, scoped, attrs)
    metrics = {'locations': len(locs), 'unique_line_column': len({(r['line'], r['column']) for r in locs.values()}),
               'location_leas': len(accepted), 'adjacent_location_calls': len(accepted), 'scoped_fdes': len(scoped),
               'scoped_fde_bytes': sum(f['end']-f['start'] for f in scoped.values()),
               'decoded_instructions': sum(map(len, decoded.values())),
               'only_exact_file_first_party_fdes': sum(a['only_exact_file_locations_observed'] for a in attrs.values()),
               'shared_first_party_fdes': sum(not a['only_exact_file_locations_observed'] for a in attrs.values()),
               'diagnostics_probed': len(diagnostics),
               'diagnostics_bound': sum(d['status'] == 'bound' for d in diagnostics),
               'diagnostics_unresolved': sum(d['status'] == 'present-but-unbound' for d in diagnostics),
               'diagnostics_absent': sum(d['status'] == 'absent' for d in diagnostics),
               'pointer_length_anchors': sum(a['kind'] != 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'counted_fragment_anchors': sum(a['kind'] == 'counted_ascii_chunks' for d in diagnostics for a in d['anchors']),
               'byte_proven_but_unattributed_setups': sum(r['byte_proof_not_attribution'] is not None for d in diagnostics for r in d['rejected_candidates']),
               'constants_bound': sum(c['status'] == 'bound' for c in numeric),
               'constants_unresolved': sum(c['status'] == 'unresolved' for c in numeric),
               'call_edges': sum(e['instruction']['kind'] == 'call_rel32' for e in edges),
               'tail_edges': sum(e['instruction']['kind'] == 'jmp_rel32' for e in edges)}
    seeds = json.loads((ROOT/'research/catalogue/seed-candidates.json').read_text())
    require(sorted({int(r['address'],16) for r in seeds['items'] if r['file'] == 'net_utils/tcp/tcp_stream.rs'}) == list(SEEDS), 'catalogue seeds differ')
    e = {'schema_version': 1, 'work_item': 'tcp-stream-inventory-94', 'component': 'transport',
         'task': 'RE-001 / RE-012 exact-file static inventory', 'scope_rule': SCOPE.decode(),
         'target': {'path': TARGET, 'sha256': SHA256, 'release': 94}, 'source_commit': BASE_COMMIT,
         'reference': {'path': REFERENCE_PATH, 'sha256': REFERENCE_SHA256, 'provenance_commit': REFERENCE_COMMIT,
                       'role': 'Unlicensed hints only; no source, comments or absent literal text copied'},
         'producer_sources_sha256': {f'tools/{n}': sha((TOOLS/n).read_bytes()) for n in
                                    ('tcp_stream_inventory.py', 'abci_state_inventory.py', 'elf_index.py', 'fde_extents.py')},
         'method': {'dependency': 'Python 3.10+ stdlib only', 'decoder': 'abci_state_inventory restricted sequential x86-64 decoder; exact FF15 decoder added locally',
                    'all_fde_records_checked': len(fdes.rows), 'coordinates': 'ELF link-time VA/file offset; end exclusive; no rebase',
                    'normalization_masks': [], 'captured_binaries_executed': False, 'network_used': False,
                    'completeness': 'Exact-path RELATIVE Location census; all executable-section matching RIP LEAs; full linear scoped FDE decode and direct internal branch boundary checks. Not full CFG/reachability.',
                    'binding': 'Length-bearing literal setup plus only-exact-file first-party Locations in FDE, or exact-file Location in same local setup. Shared range co-location alone rejected.',
                    'literal_scope': 'All unique quoted reference literals plus four finite target-derived probes; not all literals',
                    'constant_scope': 'Top-level reference numeric hints; restricted MOV operands only; semantic roles unresolved'},
         'metrics': metrics, 'locations': list(locs.values()), 'location_leas': accepted,
         'fdes': [{**Fdes.record(image,f), **attrs[s]} for s,f in sorted(scoped.items())],
         'seed_checks': [{'address': hex(s), 'exact_fde_start': bool(fdes.owner(s) and fdes.owner(s)['start'] == s),
                          'references_exact_file_location': s in scoped} for s in SEEDS],
         'diagnostics': diagnostics, 'constants': numeric, 'call_edges': edges, 'rel32_transfers': transfers,
         'transfer_counts': counts, 'prior_work': prior,
         'non_claims': ['No runtime behavior, protocol semantics beyond bytes, source reconstruction or Rust implementation.',
                        'No exclusive function ownership/names, full CFG, ABI or complete helper closure.',
                        'No claims for other tcp files, node, l1 or base/foundation internals; foreign Locations only qualify attribution.',
                        'No novelty for prior read/header/EOF, shared-owner or storage attribution findings.',
                        'No inferred constant roles/units, formatter grammar, rendered logs or reconstruction from reference text.',
                        'No full module/function denominator, progress gate, rebuild equivalence, #115 or visor claim.'],
         'remaining_gaps': {'helpers': 'behavior and helper closure unresolved', 'call_targets': 'outside scoped entries unresolved; indirect targets unresolved except adjacent Location slots',
                            'relocations': 'Location and adjacent call-slot RELATIVE only; no whole-ELF closure',
                            'vtable_data': 'unresolved', 'whole_elf': 'no build/comparison',
                            'code': 'FDE-less code, indirect branches, inlined attribution and split bodies incomplete'}}
    transcript = {'target_sha256': SHA256, 'decoder': e['method']['decoder'],
                  'columns': ['offset_from_fde_start', 'raw_hex', 'decoded_kind'],
                  'fdes': [{'start': hex(s), 'end_exclusive': hex(scoped[s]['end']),
                            'instructions': [[hex(x['site']-s), x['raw'].hex(), x['kind']] for x in insns]}
                           for s,insns in sorted(decoded.items())]}
    return {'inventory.json': e, 'instructions.json': transcript}


def table(tag, headers, rows):
    def cell(x): return str(x).replace('|', '\\|').replace('\n', ' ')
    return '\n'.join([f'<!-- BEGIN GENERATED {tag} -->', '| '+' | '.join(headers)+' |',
                      '| '+' | '.join(['---']*len(headers))+' |'] +
                     ['| '+' | '.join(map(cell,row))+' |' for row in rows] + [f'<!-- END GENERATED {tag} -->'])


def evidence_tables(e):
    return {
        'METRICS': table('METRICS', ['Metric', 'Count'], sorted(e['metrics'].items())),
        'LOCATIONS': table('LOCATIONS', ['Slot VA', 'Line:column', 'LEA sites', 'FDE owners'],
                           [(r['va'], f"{r['line']}:{r['column']}", ', '.join(r['lea_sites']), ', '.join(r['owning_fdes'])) for r in e['locations']]),
        'FDES': table('FDES', ['Start', 'End exclusive', 'Bytes', 'First-party Location paths'],
                     [(f['start'], f['end_exclusive'], f['size'], ', '.join(f['first_party_paths'])) for f in e['fdes']]),
        'DIAGNOSTICS': table('DIAGNOSTICS', ['Probe', 'Target text / hash-only identifier', 'Status', 'Occurrences', 'Bound anchors'],
                            [(d['id'], d['display'], d['status'], len(d['occurrences']), len(d['anchors'])) for d in e['diagnostics']]),
        'ANCHORS': table('ANCHORS', ['Probe', 'Owner', 'LEA', 'Target', 'Length', 'Proof', 'Owner Location slots'],
                        [(d['id'], a['owner'], a['lea']['va'], a['anchor'], a['length'], a['kind'], ', '.join(a['attribution']['locations'])) for d in e['diagnostics'] for a in d['anchors']]),
        'EDGES': table('EDGES', ['Caller', 'Call VA', 'Bytes', 'Signed rel32', 'Callee entry', 'Callee Locations'],
                      [(x['caller'], x['instruction']['va'], x['instruction']['bytes'], x['signed_displacement'], x['callee'], ', '.join(x['callee_locations'])) for x in e['call_edges']]),
        'CONSTANTS': table('CONSTANTS', ['Hint', 'Value', 'Status', 'Decoded MOV occurrences (not bindings)'],
                          [(x['candidate'], x['numeric_hint'], x['status'], len(x['decoded_mov_occurrences_not_bindings'])) for x in e['constants']]),
        'TRANSFERS': table('TRANSFERS', ['Disposition', 'Sites'], sorted(e['transfer_counts'].items())),
    }


def generate(binary, out):
    with Path(binary).open('rb') as h, mmap.mmap(h.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = build(data)
    Path(out).mkdir(parents=True, exist_ok=True)
    for name in OUTPUTS: Path(out,name).write_bytes(render(result[name]))
    return result['inventory.json']['metrics']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try: metrics = generate(args.binary, args.out)
    except (ValueError, OSError) as exc: parser.exit(1, f'FAIL: {exc}\n')
    print(json.dumps(metrics, sort_keys=True))


if __name__ == '__main__': main()
