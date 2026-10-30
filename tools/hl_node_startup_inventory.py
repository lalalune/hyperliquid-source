#!/usr/bin/env python3
"""RE-012: digest-pinned, static hl_node startup/CLI inventory for node #94.

Stdlib only; never executes a captured artifact. Scans relocated Location
records and seven-byte REX.W RIP LEA candidates, then uses actual CIE/FDE
extents for attribution. Instruction boundaries are independently checked by
objdump in the tests, not inferred from opcode scanning alone.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

# Support direct execution, importlib loading and Python isolated mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FIRST_PARTY = b'/home/ubuntu/hl/code_Mainnet/'
SCOPE_PATH = 'node/src/hl_node.rs'
CLI_LITERALS = (
    'chain', 'data-dir', 'run-validator', 'serve-evm-rpc', 'serve-eth-rpc',
    'serve-info', 'check-reachability', 'delegate', 'override_gossip_config.json',
    'write-trades', 'write-fills', 'write-raw-book-diffs', 'write-order-statuses',
    'write-misc-events', 'write-hip3-oracle-updates',
    'write-system-and-core-writer-actions',
)
DIAGNOSTICS = (
    ('@@ archiving data to s3', 'nul_buffer', 'archive marker'),
    ('@@ running non-validator to get initial abci state for consensus',
     'nul_buffer', 'bootstrap marker'),
    ('failed to load firewall ips', 'exact', 'firewall loading diagnostic'),
    ('check_reachability_firewall_ips', 'exact', 'reachability label'),
    ('timeout 3 nc -zv ', 'nul_buffer', 'external command template'),
)
LEA_RE = re.compile(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')
CALL_SITE, CALL_FROM, CALL_TO = 0x22AEF61, 0x22AE8A0, 0x2271D00
PORT_SITE, PORT_OWNER = 0x227261E, 0x2271D00
GENERATED = ('startup-inventory.json', 'byte-excerpts.txt')


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class Elf:
    """Bounded section/segment mapping; reads may not straddle a PT_LOAD."""
    def __init__(self, data):
        self.data = data
        self.sections = {s['name']: s for s in sections(data)}
        require(struct.unpack_from('<H', data, 18)[0] == 62, 'not x86-64')
        phoff = struct.unpack_from('<Q', data, 32)[0]
        entry, count = struct.unpack_from('<HH', data, 54)
        require(entry == 56 and phoff + entry * count <= len(data),
                'invalid program headers')
        self.loads = []
        for i in range(count):
            typ, flags, off, va, _, size, mem, _ = struct.unpack_from(
                '<IIQQQQQQ', data, phoff + i * entry)
            if typ == 1:
                require(size <= mem and off + size <= len(data), 'invalid PT_LOAD')
                self.loads.append((va, off, size, flags))
        for name in ('.text', '.rodata', '.data.rel.ro', '.rela.dyn',
                     '.eh_frame', '.eh_frame_hdr'):
            require(name in self.sections, f'missing {name}')

    def offset(self, va, size=1):
        require(size > 0, 'read length must be positive')
        hits = [off + va - base for base, off, length, _ in self.loads
                if base <= va and va + size <= base + length]
        require(len(hits) == 1, f'no unique file mapping for {va:#x}+{size}')
        return hits[0]

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def inside(self, name, va, size=1):
        s = self.sections[name]
        return size > 0 and s['address'] <= va and va + size <= s['address'] + s['size']

    def contents(self, name):
        s = self.sections[name]
        return self.data[s['offset']:s['offset'] + s['size']]


def frames(elf):
    """Decode CIE augmentation and FDE pc_range, cross-check the header index."""
    secs, table = unwind_index(elf.data)
    cies, fdes = eh_frame_records(elf.data, secs)
    by_va = {f['fde']: f for f in fdes}
    require(len(by_va) == len(fdes), 'duplicate FDE records')
    header = elf.sections['.eh_frame_hdr']
    pointer = header['address'] + 4 + struct.unpack_from('<i', elf.contents('.eh_frame_hdr'), 4)[0]
    require(pointer == elf.sections['.eh_frame']['address'], 'wrong frame pointer')
    require(len(table) == len(fdes), 'unindexed FDEs')
    require(len({row['fde'] for row in table}) == len(table), 'duplicate index FDE')
    for row in table:
        require(row['fde'] in by_va, 'index does not name an FDE')
        require(by_va[row['fde']]['start'] == row['start'], 'FDE start mismatch')
    ordered = sorted(fdes, key=lambda f: f['start'])
    for i, f in enumerate(ordered):
        require(f['end'] > f['start'] and elf.inside('.text', f['start'], f['end'] - f['start']),
                'FDE extent outside .text or empty')
        if i:
            require(ordered[i - 1]['end'] <= f['start'], 'overlapping FDE extents')
    return ordered, cies


def containing(fdes, starts, site, size=1):
    i = bisect.bisect_right(starts, site) - 1
    if i >= 0 and size > 0 and site + size <= fdes[i]['end']:
        return fdes[i]
    return None


def relative_relocations(elf):
    raw = elf.contents('.rela.dyn')
    require(len(raw) % 24 == 0, 'truncated RELA table')
    out = {}
    for i in range(0, len(raw), 24):
        slot, info, addend = struct.unpack_from('<QQq', raw, i)
        if info & 0xffffffff == 8:
            require(info >> 32 == 0 and slot not in out, 'ambiguous RELATIVE relocation')
            out[slot] = {'target': addend, 'relocation_va': elf.sections['.rela.dyn']['address'] + i,
                         'relocation_bytes': raw[i:i + 24].hex()}
    return out


def scoped_locations(elf, relocs):
    """Exact relocated path, not a substring match or a reference comment seed."""
    wanted = FIRST_PARTY + SCOPE_PATH.encode()
    out = []
    for slot, r in sorted(relocs.items()):
        pointer = r['target']
        if not elf.inside('.data.rel.ro', slot, 24) or not elf.inside('.rodata', pointer, len(wanted)):
            continue
        if elf.read(pointer, len(wanted)) != wanted:
            continue
        length, line, col = struct.unpack('<QII', elf.read(slot + 8, 16))
        # The exact file slice and full Rust Location layout must agree.
        require(length == len(wanted) and line > 0 and col > 0,
                f'invalid scoped Location at {slot:#x}')
        out.append({'slot_va': slot, 'slot_offset': elf.offset(slot, 24),
                    'path_va': pointer, 'path_length': length, 'file': SCOPE_PATH,
                    'line': line, 'column': col, 'bytes': elf.read(slot, 24).hex(),
                    'relocation_va': r['relocation_va'], 'relocation_bytes': r['relocation_bytes']})
    return out


def lea_targets(elf):
    raw = elf.contents('.text')
    base = elf.sections['.text']['address']
    out = {}
    for m in LEA_RE.finditer(raw):
        i = m.start()
        if i + 7 <= len(raw):
            target = base + i + 7 + struct.unpack_from('<i', raw, i + 3)[0]
            out.setdefault(target, []).append(base + i)
    return out


def bind_literal(elf, text, kind, leas, owner, scoped):
    """Keep all occurrences; bind only direct scoped anchors, never proximity."""
    raw, base = elf.contents('.rodata'), elf.sections['.rodata']['address']
    encoded = text.encode('ascii')
    occurrences, anchors = [], []
    for match in re.finditer(re.escape(encoded), raw):
        index = match.start()
        occurrence = base + index
        occurrences.append(occurrence)
        anchor, end = occurrence, occurrence + len(encoded)
        if kind == 'nul_buffer':
            # Only the whole preceding-NUL/following-NUL bounded buffer, not
            # arbitrary earlier addresses in a search window. No format semantics.
            begin = raw.rfind(b'\0', max(0, index - 256), index)
            stop = raw.find(b'\0', index + len(encoded), min(len(raw), index + 512))
            if begin < 0 or stop < 0:
                continue
            anchor, end = base + begin + 1, base + stop + 1
        refs = []
        for site in leas.get(anchor, ()):
            f = owner(site, 7)
            if f is None or f['start'] not in scoped:
                continue
            item = {'site_va': site, 'site_offset': elf.offset(site, 7),
                    'fde_start_va': f['start'], 'bytes': elf.read(site, 7).hex()}
            if kind == 'cli':
                # Bound CLI fragments additionally have at least one exact
                # pointer/length pair: lea ...,rsi; mov len,edx.
                pair = elf.read(site, 12) if site + 12 <= f['end'] else b''
                item['length_pair'] = (pair[:3] == b'\x48\x8d\x35' and
                                       pair[7:8] == b'\xba' and
                                       struct.unpack_from('<I', pair, 8)[0] == len(encoded))
                if item['length_pair']:
                    item['pair_bytes'] = pair.hex()
            refs.append(item)
        if refs:
            anchors.append({'occurrence_va': occurrence, 'anchor_va': anchor,
                            'anchor_offset': elf.offset(anchor, end - anchor),
                            'bytes': elf.read(anchor, end - anchor).hex(), 'references': refs})
    qualified = [a for a in anchors if kind != 'cli' or
                 any(r['length_pair'] for r in a['references'])]
    # Do not choose the first of several plausible anchors.
    bound = len(qualified) == 1
    reason = ('one scoped anchor with an exact pointer/length pair' if kind == 'cli'
              else 'one directly referenced scoped anchor') if bound else (
        'literal absent from .rodata' if not occurrences else
        'no qualifying scoped anchor' if not qualified else 'multiple qualifying scoped anchors')
    return {'text': text, 'kind': kind, 'status': 'bound' if bound else 'unresolved',
            'reason': reason, 'occurrences_va': occurrences, 'anchors': anchors,
            'qualified_anchor_count': len(qualified)}


def _inventory(data):
    """Internal structural analysis; only build() is the authenticated entrypoint.

    Tests exercise this layer with deliberately corrupted bytes to check that
    record/operand changes cannot silently reproduce the retained evidence.
    """
    elf = Elf(data)
    fdes, cies = frames(elf)
    starts = [f['start'] for f in fdes]
    owner = lambda site, size=1: containing(fdes, starts, site, size)
    relocs, leas = relative_relocations(elf), lea_targets(elf)
    locations = scoped_locations(elf, relocs)
    scoped = set()
    for loc in locations:
        refs = []
        for site in leas.get(loc['slot_va'], ()):
            f = owner(site, 7)
            require(f is not None, 'scoped LEA outside FDE')
            refs.append({'site_va': site, 'site_offset': elf.offset(site, 7),
                         'fde_start_va': f['start'], 'bytes': elf.read(site, 7).hex()})
            scoped.add(f['start'])
        loc['references'] = refs
    ranges = []
    for f in fdes:
        if f['start'] not in scoped:
            continue
        raw_size = 4 + struct.unpack('<I', elf.read(f['fde'], 4))[0]
        cie_size = 4 + struct.unpack('<I', elf.read(f['cie'], 4))[0]
        ranges.append({'start_va': f['start'], 'end_va': f['end'],
                       'start_offset': elf.offset(f['start']),
                       'fde_va': f['fde'], 'cie_va': f['cie'],
                       'fde_bytes': elf.read(f['fde'], raw_size).hex(),
                       'cie_bytes': elf.read(f['cie'], cie_size).hex(),
                       'cie_augmentation': cies[f['cie']]['augmentation'],
                       'body_sha256': sha256(elf.read(f['start'], f['end'] - f['start']))})
    cli = [bind_literal(elf, lit, 'cli', leas, owner, scoped) for lit in CLI_LITERALS]
    diagnostics = [{**bind_literal(elf, lit, kind, leas, owner, scoped), 'marker_role': role}
                   for lit, kind, role in DIAGNOSTICS]
    call = elf.read(CALL_SITE, 5)
    require(call[0] == 0xe8, 'missing scoped direct call opcode')
    dest = CALL_SITE + 5 + struct.unpack_from('<i', call, 1)[0]
    src, dst = owner(CALL_SITE, 5), owner(dest)
    require(dest == CALL_TO and src is not None and src['start'] == CALL_FROM
            and dst is not None and dst['start'] == dest
            and CALL_FROM in scoped and CALL_TO in scoped, 'scoped direct call changed')
    edge = {'site_va': CALL_SITE, 'site_offset': elf.offset(CALL_SITE, 5),
            'from_va': CALL_FROM, 'to_va': dest, 'bytes': call.hex(), 'kind': 'call rel32'}
    port_bytes = elf.read(PORT_SITE, 10)
    require(port_bytes == bytes.fromhex('c7834c070000a10fa40f') and
            owner(PORT_SITE, 10)['start'] == PORT_OWNER and PORT_OWNER in scoped,
            'packed numeric observation changed')
    immediate = struct.unpack_from('<I', port_bytes, 6)[0]
    packed = {'site_va': PORT_SITE, 'site_offset': elf.offset(PORT_SITE, 10),
              'fde_start_va': PORT_OWNER, 'bytes': port_bytes.hex(),
              'immediate_u32': immediate,
              'little_endian_u16_halves': [immediate & 0xffff, immediate >> 16],
              'interpretation': 'numeric co-location only; service/port roles unresolved'}
    counts = {'locations': len(locations),
              'location_leas': sum(len(l['references']) for l in locations),
              'locations_without_lea': sum(not l['references'] for l in locations),
              'scoped_fdes': len(ranges), 'decoded_fdes_total': len(fdes),
              'cli_candidates': len(cli), 'cli_bound': sum(c['status'] == 'bound' for c in cli),
              'cli_unresolved': sum(c['status'] == 'unresolved' for c in cli)}
    return {'schema_version': 1, 'task': 'RE-012', 'artifact': 'artifacts/node/94/hl-node',
            'binary_sha256': sha256(data), 'binary_size': len(data),
            'coordinate_system': 'ELF linked VA, half-open FDE extents; file offsets from PT_LOAD',
            'scope_path': SCOPE_PATH, 'counts': counts, 'locations': locations,
            'fde_ranges': ranges, 'cli_literals': cli, 'diagnostics': diagnostics,
            'side_effect_markers': [c['text'] for c in cli if c['status'] == 'bound' and
                                    c['text'].startswith('write-')] +
                                   [c['text'] for c in diagnostics if c['status'] == 'bound'],
            'scoped_call': edge, 'packed_numeric_observation': packed,
            'port_roles': [{'candidate': value, 'status': 'unresolved',
                            'numeric_half_observed': value in packed['little_endian_u16_halves']}
                           for value in range(4001, 4007)],
            'limitations': [
                'LEA byte-pattern census; independently checked against linear objdump decoding in tests.',
                'FDE extents are unwind ranges, not source-function or CFG coverage.',
                'Only exact hl_node.rs Locations enter the primary census; TCP and optional utilities excluded.',
                'CLI candidate fragments and markers do not prove parser behavior or executed side effects.',
                'No generic call closure, gossip config loader mapping or service-to-port assignment.',
                'No target execution, Rust implementation, binary equivalence or progress gate.']}


def build(data):
    require(sha256(data) == EXPECTED_SHA256, 'binary SHA-256 mismatch (node #94 required)')
    return _inventory(data)


def hexify(value, address=False):
    if isinstance(value, dict):
        return {k: hexify(v, k.endswith(('_va', '_offset'))) for k, v in value.items()}
    if isinstance(value, list):
        return [hexify(v, address) for v in value]
    if address and isinstance(value, int):
        return hex(value)
    return value


def render(result):
    return (json.dumps(hexify(result), indent=2, sort_keys=True) + '\n').encode()


def excerpts(result):
    """Deterministic raw extracts, with no objdump-version-dependent formatting."""
    lines = ['RE-012 hl_node startup: raw byte excerpts',
             'node #94 SHA-256 ' + result['binary_sha256'],
             'Coordinates: linked VA; half-open FDE ranges. No normalization masks.',
             'LEAs are byte-scan candidates; see tests for independent instruction-boundary checks.', '']
    for f in result['fde_ranges']:
        lines += [f"FDE [{f['start_va']:#x}, {f['end_va']:#x}) body_sha256={f['body_sha256']}",
                  f"  FDE record {f['fde_va']:#x}: {f['fde_bytes']}",
                  f"  CIE record {f['cie_va']:#x}: {f['cie_bytes']}"]
    for loc in result['locations']:
        lines.append(f"Location {loc['slot_va']:#x} {loc['file']}:{loc['line']}:{loc['column']} bytes={loc['bytes']}")
        lines.append(f"  RELATIVE {loc['relocation_va']:#x}: {loc['relocation_bytes']}")
        for r in loc['references']:
            lines.append(f"  LEA {r['site_va']:#x} file={r['site_offset']:#x} FDE={r['fde_start_va']:#x}: {r['bytes']}")
    for lit in result['cli_literals'] + result['diagnostics']:
        lines.append(f"Literal {lit['text']!r}: {lit['status']} ({lit['reason']})")
        for a in lit['anchors']:
            lines.append(f"  anchor={a['anchor_va']:#x} occurrence={a['occurrence_va']:#x}: {a['bytes']}")
            for r in a['references']:
                lines.append(f"  LEA {r['site_va']:#x} FDE={r['fde_start_va']:#x}: {r.get('pair_bytes', r['bytes'])}")
    c = result['scoped_call']
    lines.append(f"CALL {c['site_va']:#x}: {c['bytes']} FDE {c['from_va']:#x} -> {c['to_va']:#x}")
    p = result['packed_numeric_observation']
    lines.append(f"MOV immediate {p['site_va']:#x}: {p['bytes']} u16 halves={p['little_endian_u16_halves']}; roles unresolved")
    return ('\n'.join(lines) + '\n').encode()


def generated_files(result):
    return dict(zip(GENERATED, (render(result), excerpts(result))))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, help='directory for JSON and raw excerpts')
    args = parser.parse_args(argv)
    try:
        result = build(args.binary.read_bytes())
        files = generated_files(result)
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            for name, content in files.items():
                (args.out / name).write_bytes(content)
        else:
            sys.stdout.buffer.write(files[GENERATED[0]])
    except (OSError, ValueError, struct.error) as error:
        print(f'hl_node_startup_inventory: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
