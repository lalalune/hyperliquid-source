#!/usr/bin/env python3
"""Static, digest-bound spot_clearinghouse census for node #94 (MIT).

Python standard library plus installed GNU objdump, used only on temporary
copies of authenticated FDE bytes. Never executes the captured ELF. Names in
reference leads are not recovered function names. See the packet's RESULT.md.
"""
from __future__ import annotations

import argparse
import bisect
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

# Support direct, -I, and unittest imports without depending on the caller's cwd.
TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections
from fde_extents import fde_extents

ROOT = TOOLS.parent
TARGET = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
REFERENCE_COMMIT = '999556f6e0a474b8312db96ec3149e1c44e97c23'
PREFIX = b'/home/ubuntu/hl/code_Mainnet/'
SCOPE = b'l1/src/spot_clearinghouse/'
BASENAMES = ('cl_trait.rs', 'impl_outcome.rs', 'spot_clearinghouse.rs', 'types.rs')
LEA_RE = re.compile(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
INSN_RE = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+(.+)$')
OBJDUMP_OPTIONS = ['-D', '-w', '-b', 'binary', '-m', 'i386:x86-64',
                   '-M', 'intel', '--insn-width=16']
OUTPUTS = ('inventory.json', 'disassembly.json')
# A deliberately finite probe set: all distinct string literals in the four
# scoped reference files, reduced to the first static fragment for format strings.
# These strings are evidence leads; no reference implementation is copied.
DIAGNOSTICS = (
    ('spot_index', 'cl_trait.rs', 93, 'spot index in bounds'),
    ('hold_overflow', 'cl_trait.rs', 184, 'spot balance hold overflow'),
    ('conversion', 'cl_trait.rs', 231, 'spot token conversion succeeds'),
    ('book_index', 'cl_trait.rs', 372, 'spot book index in bounds'),
    ('balance_underflow', 'cl_trait.rs', 485, 'spot balance underflow'),
    ('wei_addition', 'cl_trait.rs', 518, 'spot wei addition overflow'),
    ('zero_total', 'spot_clearinghouse.rs', 172, 'total balance of token is zero'),
    ('balance_total', 'spot_clearinghouse.rs', 192,
     'error while computing existing token balances total_wei='),
    ('no_distribution', 'spot_clearinghouse.rs', 199, 'no user has wei after distributing'),
    ('allocation_overflow', 'spot_clearinghouse.rs', 221,
     'BUG: distributing to existing token final_allocation_check overflow'),
    ('remainder', 'spot_clearinghouse.rs', 242, 'could not distribute remainder='),
    ('allocation_total', 'spot_clearinghouse.rs', 253,
     'BUG: distributing to existing token final_allocation_check='),
    ('insufficient_balance', None, None, 'insufficient balance'),
    ('result_unwrap', None, None, 'called `Result::unwrap()` on an `Err` value'),
)


class EvidenceError(ValueError):
    """Incomplete or inconsistent evidence is never silently accepted."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    require(sha(data) == SHA256, 'node #94 SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64, 'truncated ELF')
        require(data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 LE')
        require(struct.unpack_from('<HH', data, 16) == (3, 62), 'expected x86-64 ET_DYN')
        self.sections = sections(data)
        names = [s['name'] for s in self.sections]
        require(len(names) == len(set(names)), 'duplicate section names')
        self.by_name = {s['name']: s for s in self.sections}
        for name in ('.text', '.rodata', '.data.rel.ro', '.rela.dyn', '.eh_frame', '.eh_frame_hdr'):
            require(name in self.by_name, f'missing section {name}')
        require(self.by_name['.text']['flags'] & 4, 'non-executable .text')

    def mapping(self, va, size=1):
        require(size > 0 and va >= 0, 'invalid read range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'not one file-backed section for {va:#x}+{size}')
        s = matches[0]
        return s, s['offset'] + va - s['address']

    def read(self, va, size):
        _, off = self.mapping(va, size)
        return self.data[off:off + size]

    def section_bytes(self, name):
        s = self.by_name[name]
        return self.data[s['offset']:s['offset'] + s['size']]

    def evidence(self, va, size):
        s, off = self.mapping(va, size)
        return {'va': hex(va), 'file_offset': hex(off), 'section': s['name'],
                'bytes': self.read(va, size).hex()}


def relative_relocations(image):
    s = image.by_name['.rela.dyn']
    require(s['size'] % 24 == 0, 'truncated RELA section')
    result, seen = {}, set()
    for delta in range(0, s['size'], 24):
        pos = s['offset'] + delta
        slot, info, addend = struct.unpack_from('<QQq', image.data, pos)
        require(slot not in seen, 'duplicate relocation slot')
        seen.add(slot)
        if info & 0xffffffff != 8:  # R_X86_64_RELATIVE
            continue
        require(info == 8 and addend >= 0, 'invalid RELATIVE symbol/addend')
        result[slot] = {'target': addend, 'entry_va': s['address'] + delta,
                        'entry_file_offset': pos,
                        'raw': image.data[pos:pos + 24].hex()}
    return result


def decode_location(image, slot, relocation):
    section, _ = image.mapping(slot, 24)
    require(section['name'] == '.data.rel.ro' and slot % 8 == 0, 'Location storage/alignment')
    pointer, length, line, column = struct.unpack('<QQII', image.read(slot, 24))
    require(pointer == 0, 'unexpected pre-relocation Location pointer')
    require(0 < length < 256 and 0 < line < 1000000 and 0 < column < 1000000,
            'invalid Location length/line/column')
    target = relocation['target']
    path_section, _ = image.mapping(target, length)
    require(path_section['name'] == '.rodata', 'Location path outside .rodata')
    path = image.read(target, length)
    require(path.startswith(PREFIX + SCOPE) and path.endswith(b'.rs') and b'\0' not in path,
            'Location path outside exact scope')
    relative = path[len(PREFIX):].decode('ascii')
    require(relative[len(SCOPE):] in BASENAMES, 'unexpected scoped basename')
    return {**image.evidence(slot, 24), 'path': relative, 'path_bytes': image.evidence(target, length),
            'path_length': length, 'line': line, 'column': column,
            'relocation': {'entry_va': hex(relocation['entry_va']),
                           'entry_file_offset': hex(relocation['entry_file_offset']),
                           'type': 'R_X86_64_RELATIVE', 'addend': hex(target),
                           'bytes': relocation['raw']}}


def locations(image, relocations):
    ro = image.by_name['.rodata']
    dr = image.by_name['.data.rel.ro']
    result = {}
    prefix = PREFIX + SCOPE
    for slot, relocation in sorted(relocations.items()):
        target = relocation['target']
        if not (dr['address'] <= slot < dr['address'] + dr['size']
                and ro['address'] <= target <= ro['address'] + ro['size'] - len(prefix)):
            continue
        if image.read(target, len(prefix)) == prefix:
            # Every matching path relocation must be accounted for; malformed
            # records stop the census instead of silently reducing its count.
            result[slot] = decode_location(image, slot, relocation)
    return result


class Fdes:
    def __init__(self, image):
        summary, rows, _ = fde_extents(image.data)
        for key in ('unwind_start_differs_from_fde_start', 'duplicate_start', 'zero_length',
                    'starts_inside_earlier_extent', 'extent_crosses_section_end',
                    'fde_records_not_in_unwind_table'):
            require(summary[key] == 0, f'ambiguous FDE inventory: {key}')
        self.rows = rows
        self.starts = [f['start'] for f in rows]

    def owner(self, va, size=1):
        require(size > 0, 'invalid FDE query size')
        i = bisect.bisect_right(self.starts, va) - 1
        if i >= 0 and va + size <= self.rows[i]['end']:
            return self.rows[i]
        return None

    @staticmethod
    def record(image, fde):
        def record_bytes(va):
            size = 4 + struct.unpack('<I', image.read(va, 4))[0]
            return image.evidence(va, size)
        hdr = image.by_name['.eh_frame_hdr']['address'] + 12 + 8 * fde['index']
        return {'start': hex(fde['start']), 'end_exclusive': hex(fde['end']),
                'size': fde['end'] - fde['start'], 'section': fde['section'],
                'code_sha256': sha(image.read(fde['start'], fde['end'] - fde['start'])),
                'fde_record': record_bytes(fde['fde']), 'cie_record': record_bytes(fde['cie']),
                'unwind_index': fde['index'], 'unwind_index_entry': image.evidence(hdr, 8)}


def decode_lea(raw, site):
    require(len(raw) == 7 and LEA_RE.fullmatch(raw[:3]) is not None, 'unsupported RIP LEA')
    register = ((raw[2] >> 3) & 7) + (8 if raw[0] & 4 else 0)
    displacement = struct.unpack_from('<i', raw, 3)[0]
    return site + 7 + displacement, register


def scan_leas(image):
    """Candidates only; acceptance additionally requires FDE-start disassembly."""
    result = {}
    for s in image.sections:
        if not s['flags'] & 4 or s['type'] == 8:
            continue
        raw = image.section_bytes(s['name'])
        for match in LEA_RE.finditer(raw):
            offset = match.start()
            if offset + 7 <= len(raw):
                site = s['address'] + offset
                target, _ = decode_lea(raw[offset:offset + 7], site)
                result.setdefault(target, []).append(site)
    return result


def verified_lea(image, instructions, site, expected_target):
    matches = [x for x in instructions if x['site'] == site]
    require(len(matches) == 1, 'LEA candidate is inside another instruction or absent')
    insn = matches[0]
    target, register = decode_lea(insn['raw'], site)
    require(target == expected_target and insn['text'].split()[0] == 'lea', 'LEA target/decode mismatch')
    require(insn['raw'] == image.read(site, 7), 'LEA bytes differ from input')
    return insn, register


def decode_rel32(raw, site):
    require(len(raw) == 5 and raw[0] == 0xe8, 'not a complete E8 rel32 call')
    displacement = struct.unpack_from('<i', raw, 1)[0]
    return site + 5 + displacement


def decode_indirect_call(raw, site):
    require(len(raw) == 6 and raw[:2] == b'\xff\x15', 'not FF /2 RIP call')
    return site + 6 + struct.unpack_from('<i', raw, 2)[0]


def parse_disassembly(raw, image, fde):
    """Require uninterrupted, byte-exact decoding of the complete FDE extent."""
    result, cursor = [], fde['start']
    for line in raw.splitlines():
        match = INSN_RE.fullmatch(line)
        if not match:
            require(not re.match(r'^\s*[0-9a-f]+:', line), 'unparsed instruction row')
            continue
        site, code, text = int(match[1], 16), bytes.fromhex(match[2]), match[3]
        require(site == cursor and 0 < len(code) <= 15, 'disassembly gap/overlap/length')
        require(site + len(code) <= fde['end'], 'instruction crosses FDE end')
        require(code == image.read(site, len(code)), 'disassembly bytes differ from ELF')
        require('(bad)' not in text and '.byte' not in text, 'undecoded instruction')
        result.append({'site': site, 'raw': code, 'text': text})
        cursor += len(code)
    require(cursor == fde['end'], 'incomplete FDE disassembly')
    return result


def disassemble(image, fde):
    # Isolated data snapshot closes the input-file race: objdump never opens the
    # captured executable and receives exactly the authenticated bytes we read.
    with tempfile.TemporaryDirectory(prefix='spot-inventory-') as temp:
        Path(temp, 'fde.bin').write_bytes(image.read(fde['start'], fde['end'] - fde['start']))
        command = ['objdump', *OBJDUMP_OPTIONS, f'--adjust-vma={hex(fde["start"])}', 'fde.bin']
        process = subprocess.run(command, cwd=temp, env={**os.environ, 'LC_ALL': 'C'},
                                 capture_output=True, text=True, check=True)
        require(not process.stderr, 'objdump emitted stderr')
    return parse_disassembly(process.stdout, image, fde), process.stdout


def instruction_evidence(image, insn):
    return {**image.evidence(insn['site'], len(insn['raw'])), 'disassembly': insn['text']}


def counted_prefix(image, anchor, literal):
    raw = image.read(anchor, len(literal) + 2)
    require(len(literal) < 128 and raw[0] == len(literal), 'counted prefix length differs')
    require(raw[1:-1] == literal and raw[-1] == 0xc0, 'counted prefix contents/marker differ')
    # This describes bytes, not a recovered formatter grammar or runtime string.
    return image.evidence(anchor, len(raw))


def ptr_length_pair(image, instructions, index, literal):
    """Accept only RDI pointer, intervening LEAs, ESI length, FF15 call.

    The allowed intervening LEAs cannot clobber RDI. No branch, unknown write,
    call, or fuzzy lookahead is accepted. SysV argument interpretation is stated
    separately; the bytes/register values are the observation.
    """
    first = instructions[index]
    target, reg = decode_lea(first['raw'], first['site'])
    require(reg == 7 and image.read(target, len(literal)) == literal, 'not an RDI literal pointer')
    j = index + 1
    while j < len(instructions) and instructions[j]['text'].split()[0] == 'lea':
        insn = instructions[j]
        require(insn['site'] == instructions[j - 1]['site'] + len(instructions[j - 1]['raw']),
                'noncontiguous pointer/length setup')
        # Exact observed RCX/R8 RIP LEAs and RDX stack LEAs only.
        raw = insn['raw']
        if len(raw) == 7 and LEA_RE.fullmatch(raw[:3]):
            _, dest = decode_lea(raw, insn['site'])
            require(dest in (1, 8), 'pointer setup clobber/unsupported register')
        else:
            require((len(raw) == 5 and raw[:4] == b'\x48\x8d\x54\x24') or
                    (len(raw) == 8 and raw[:4] == b'\x48\x8d\x94\x24'), 'unsupported stack LEA')
        j += 1
        require(j - index <= 5, 'overlong pointer setup')
    require(j + 1 < len(instructions), 'truncated pointer/length setup')
    length, call = instructions[j:j + 2]
    require(length['raw'] == b'\xbe' + struct.pack('<I', len(literal)), 'ESI literal length differs')
    require(length['site'] == instructions[j - 1]['site'] + len(instructions[j - 1]['raw'])
            and call['site'] == length['site'] + 5, 'noncontiguous length/call')
    slot = decode_indirect_call(call['raw'], call['site'])
    return {'length': len(literal), 'length_instruction': instruction_evidence(image, length),
            'call_instruction': instruction_evidence(image, call), 'call_slot': hex(slot),
            'setup': [instruction_evidence(image, x) for x in instructions[index:j + 2]]}


def occurrences(image, needle):
    s = image.by_name['.rodata']
    raw, pos, result = image.section_bytes('.rodata'), -1, []
    while (pos := raw.find(needle, pos + 1)) >= 0:
        result.append(s['address'] + pos)
    return result


def diagnostic_inventory(image, leas, fdes, scoped, decoded, relocations):
    result = []
    scoped_locations = set(locations(image, relocations))
    for name, file, line, text in DIAGNOSTICS:
        literal = text.encode('ascii')
        hits, anchors, rejected = occurrences(image, literal), [], []
        unscoped_generic_sites = 0
        for occurrence in hits:
            for anchor in (occurrence, occurrence - 1):
                for site in leas.get(anchor, []):
                    owner = fdes.owner(site, 7)
                    if owner is None or owner['start'] not in scoped:
                        if name == 'result_unwrap':
                            unscoped_generic_sites += 1
                            continue
                        rejected.append({'site': hex(site), 'anchor': hex(anchor),
                                         'owner': None if owner is None else hex(owner['start']),
                                         'reason': 'no scoped FDE; byte candidate only'})
                        continue
                    instructions = decoded[owner['start']]
                    insn, _ = verified_lea(image, instructions, site, anchor)
                    index = instructions.index(insn)
                    row = {'site': instruction_evidence(image, insn), 'owner': hex(owner['start']),
                           'occurrence': hex(occurrence), 'anchor': hex(anchor)}
                    try:
                        if anchor == occurrence:
                            row.update(ptr_length_pair(image, instructions, index, literal))
                            row['kind'] = 'rdi_pointer_esi_length'
                            slot = int(row['call_slot'], 16)
                            require(slot in relocations, 'call slot lacks RELATIVE relocation')
                            row['relocated_callee'] = hex(relocations[slot]['target'])
                            row['call_relocation'] = image.evidence(relocations[slot]['entry_va'], 24)
                            row['scoped_location_in_r8'] = None
                            for setup in row['setup'][1:-2]:
                                code = bytes.fromhex(setup['bytes'])
                                if len(code) == 7 and LEA_RE.fullmatch(code[:3]):
                                    address, register = decode_lea(code, int(setup['va'], 16))
                                    if register == 8 and address in scoped_locations:
                                        row['scoped_location_in_r8'] = hex(address)
                        else:
                            row['prefix_bytes'] = counted_prefix(image, anchor, literal)
                            row['kind'] = 'u8_counted_literal_prefix_before_c0'
                            row['length'] = len(literal)
                    except EvidenceError as exc:
                        rejected.append({'site': hex(site), 'anchor': hex(anchor),
                                         'owner': hex(owner['start']), 'reason': str(exc)})
                        continue
                    anchors.append(row)
        kind = 'reference_literal_prefix' if file else ('user_requested_phrase_probe' if name == 'insufficient_balance'
                                                       else 'observed_generic_runtime_literal')
        result.append({'id': name, 'text': text, 'lead_kind': kind,
                       'reference': None if file is None else {'file': f'l1/spot_clearinghouse/{file}', 'line': line},
                       'status': 'bound' if anchors else 'unresolved',
                       'reason': ('scoped instruction and explicit length evidence' if anchors else
                                  'no occurrence in .rodata' if not hits else 'no accepted scoped length-bearing LEA'),
                       'rodata_occurrence_count': len(hits),
                       'unscoped_generic_lea_candidates_omitted': unscoped_generic_sites,
                       'occurrences': [image.evidence(a, len(literal)) for a in hits
                                       if name != 'result_unwrap' or any(int(x['occurrence'], 16) == a for x in anchors)],
                       'anchors': anchors, 'rejected_candidates': rejected})
    return result


def decode_scalar_rip(raw, site):
    # movsd/divsd xmm, qword [rip+disp32], only encodings used by these probes.
    require(len(raw) == 8 and raw[:2] == b'\xf2\x0f' and raw[2] in (0x10, 0x5e)
            and raw[3] & 0xc7 == 0x05, 'unsupported scalar RIP operand')
    return site + 8 + struct.unpack_from('<i', raw, 4)[0]


def constant_inventory(image, decoded):
    result = []
    for value, names in ((1.01, ['MAX_PROPORTIONAL_FACTOR', 'MAX_DEPLOYER_SHARE_FACTOR']),
                         (100000.0, ['DEPLOYER_SHARE_DENOMINATOR'])):
        raw = struct.pack('<d', value)
        hits, refs = occurrences(image, raw), []
        for start, instructions in sorted(decoded.items()):
            for insn in instructions:
                try:
                    target = decode_scalar_rip(insn['raw'], insn['site'])
                except EvidenceError:
                    continue
                if target in hits:
                    refs.append({'owner': hex(start), 'target': hex(target),
                                 'instruction': instruction_evidence(image, insn)})
        bound = len(hits) == 1 and bool(refs)
        result.append({'value': value, 'encoding': 'IEEE-754 binary64 little endian',
                       'reference_names_unproved': names, 'status': 'bound' if bound else 'unresolved',
                       'reason': ('one .rodata occurrence and decoded scoped RIP operands' if bound else
                                  'nonunique .rodata value; scoped operands retained without named-constant binding'),
                       'occurrences': [image.evidence(a, 8) for a in hits], 'scoped_operands': refs})
    return result


def scoped_edges(image, decoded):
    result = []
    for start, instructions in sorted(decoded.items()):
        for insn in instructions:
            if len(insn['raw']) != 5 or insn['raw'][0] != 0xe8:
                continue
            target = decode_rel32(insn['raw'], insn['site'])
            if target in decoded:
                result.append({'caller': hex(start), 'callee': hex(target),
                               'instruction': instruction_evidence(image, insn),
                               'signed_displacement': struct.unpack_from('<i', insn['raw'], 1)[0],
                               'next_instruction': hex(insn['site'] + 5)})
    return result


def build(data):
    authenticate(data)  # No bypass flag, even for tests.
    image = Image(data)
    relocations = relative_relocations(image)
    locs = locations(image, relocations)
    require(locs, 'no scoped Locations')
    fdes = Fdes(image)
    leas = scan_leas(image)
    scoped, pending, unowned = {}, [], []
    for slot in locs:
        for site in leas.get(slot, []):
            owner = fdes.owner(site, 7)
            if owner is None:
                unowned.append({'location': hex(slot), 'site': hex(site), 'status': 'unresolved_no_FDE'})
            else:
                scoped[owner['start']] = owner
                pending.append((site, slot, owner['start']))
    decoded, raw_outputs = {}, []
    for start, fde in sorted(scoped.items()):
        instructions, raw = disassemble(image, fde)
        decoded[start] = instructions
        raw_outputs.append({'fde_start': hex(start), 'fde_end_exclusive': hex(fde['end']),
                            'command': ['objdump', *OBJDUMP_OPTIONS, f'--adjust-vma={hex(start)}', 'fde.bin'],
                            'stdout_lines': raw.splitlines(), 'stderr': '', 'returncode': 0})
    accepted = []
    for site, slot, start in sorted(pending):
        insn, reg = verified_lea(image, decoded[start], site, slot)
        accepted.append({'location': hex(slot), 'owner': hex(start), 'destination_register_index': reg,
                         'instruction': instruction_evidence(image, insn)})
    # No FDE is admitted merely because its bytes resemble an embedded LEA.
    require({int(x['owner'], 16) for x in accepted} == set(scoped), 'unanchored scoped FDE')
    diagnostics = diagnostic_inventory(image, leas, fdes, scoped, decoded, relocations)
    constants = constant_inventory(image, decoded)
    edges = scoped_edges(image, decoded)
    counts = Counter(x['path'].split('/')[-1] for x in locs.values())
    metrics = {'locations': len(locs),
               'unique_path_line_column': len({(x['path'], x['line'], x['column']) for x in locs.values()}),
               'locations_by_basename': {n: counts[n] for n in BASENAMES},
               'location_leas': len(accepted), 'unowned_location_lea_candidates': len(unowned),
               'scoped_fdes': len(scoped), 'scoped_fde_bytes': sum(f['end'] - f['start'] for f in scoped.values()),
               'diagnostics_bound': sum(x['status'] == 'bound' for x in diagnostics),
               'diagnostics_unresolved': sum(x['status'] == 'unresolved' for x in diagnostics),
               'reference_diagnostics_bound': sum(x['status'] == 'bound' and x['reference'] is not None for x in diagnostics),
               'reference_diagnostics_probed': sum(x['reference'] is not None for x in diagnostics),
               'ptr_length_anchors': sum(a['kind'] == 'rdi_pointer_esi_length' for x in diagnostics for a in x['anchors']),
               'ptr_length_anchors_with_same_call_scoped_location': sum(bool(a.get('scoped_location_in_r8')) for x in diagnostics for a in x['anchors']),
               'counted_prefix_anchors': sum(a['kind'] == 'u8_counted_literal_prefix_before_c0' for x in diagnostics for a in x['anchors']),
               'constants_bound': sum(x['status'] == 'bound' for x in constants),
               'constants_unresolved': sum(x['status'] == 'unresolved' for x in constants),
               'scoped_rel32_edges': len(edges)}
    evidence = {'schema_version': 1, 'work_item': 'spot-clearinghouse-inventory-94',
                'target': {'path': TARGET, 'sha256': SHA256, 'release': 94},
                'coordinate_system': 'ELF virtual addresses; end-exclusive FDE extents; explicit file offsets',
                'producer_sources_sha256': {f'tools/{name}': sha((TOOLS / name).read_bytes()) for name in
                                           ('spot_clearinghouse_inventory.py', 'elf_index.py', 'fde_extents.py')},
                'scope_rule': SCOPE.decode() + '*', 'metrics': metrics,
                'method': {'captured_binary_executed': False, 'network_used': False,
                           'boundary_check': 'complete linear objdump decode from each actual FDE start; not CFG reachability',
                           'lea_candidate_encodings': '48/4c 8d ModRM RIP+disp32 in executable sections',
                           'location_layout': 'RELA pointer, u64 path length, u32 line, u32 column',
                           'all_fde_records_checked': len(fdes.rows),
                           'normalization_masks': [], 'reference_commit_lead_only': REFERENCE_COMMIT},
                'locations': list(locs.values()), 'location_leas': accepted,
                'unowned_location_lea_candidates': unowned,
                'fdes': [Fdes.record(image, f) for _, f in sorted(scoped.items())],
                'diagnostics': diagnostics, 'constants': constants, 'call_edges': edges}
    version = subprocess.check_output(['objdump', '--version'], text=True, env={**os.environ, 'LC_ALL': 'C'}).splitlines()[0]
    raw = {'target_sha256': SHA256, 'tool_version': version,
           'input': 'Each fde.bin is exactly the authenticated FDE code range; temporary directory not retained.',
           'runs': raw_outputs}
    return {'inventory.json': evidence, 'disassembly.json': raw}


def render(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def generate(binary, out):
    result = build(Path(binary).read_bytes())
    Path(out).mkdir(parents=True, exist_ok=True)
    for name in OUTPUTS:
        Path(out, name).write_bytes(render(result[name]))
    return result['inventory.json']['metrics']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        metrics = generate(args.binary, args.out)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'FAIL: {exc}\n')
    print(json.dumps(metrics, sort_keys=True))


if __name__ == '__main__':
    main()
