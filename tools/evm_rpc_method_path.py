#!/usr/bin/env python3
"""RE-011 static method-string and Location evidence, pinned to node #94."""
import argparse
import collections
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

import info_request_path as common

ROOT = Path(__file__).resolve().parents[1]
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
INPUTS = {
 'references/can1357-hl/evm_rpc/method_router.rs': '7d2231c413fbf765115380d359bf2e778e439e79650ee1ff18b1101f9d7faffd',
 'research/imported/hl-node-94.inventory.json': 'de874270101b4649d911ad8a4e62ee68d9af72cf19c2a1042116deaa3165e533',
 'research/imported/hl-node-115.inventory.json': '92d01191ecac0424f3df4e15df295362a2b6606b6260b28664438ef5e4903c11',
 'research/work-items/RE-002-build-provenance/provenance-94.json': 'ec666ce9aec679a943908b7ead1efe0fbb4965268a63d271b8e68f9685e1a864',
 'research/work-items/RE-002-build-provenance/provenance-115.json': '16f95170307d3f5432e2dac11644ecc7960bed22267a09853e83bdf2dfa177f8',
}
TABLE = 0x27ab650
INIT = 0x20266a0
ROUTER = 0x202ec80
ROUTER_CALLEE = 0x2027610


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked(data, expected, name):
    if digest(data) != expected:
        raise common.EvidenceError(f'{name}: SHA-256 mismatch')
    return data


def methods(source):
    # Restrict the inventory to the body of the named function.
    match = re.search(r'pub\s+fn\s+build_route_table\s*\([^)]*\)[^{]*\{', source)
    if not match:
        raise common.EvidenceError('missing build_route_table')
    start = match.end()
    depth = 1
    for i in range(start, len(source)):
        if source[i] == '{': depth += 1
        if source[i] == '}': depth -= 1
        if depth == 0: break
    else:
        raise common.EvidenceError('unclosed build_route_table')
    result = re.findall(r'"(eth_[A-Za-z0-9_]+)"', source[start:i])
    if len(result) != 26 or len(set(result)) != len(result):
        raise common.EvidenceError('unexpected reference method inventory')
    return result


def addr(x):
    return hex(x)


def build(binary94, binary115, inputs):
    checked(binary94, SHA94, 'node #94')
    checked(binary115, SHA115, 'node #115')
    for name, sha in INPUTS.items():
        checked(inputs[name], sha, name)
    elf = common.Elf(binary94)
    starts, ends = common.fde_index(elf)
    relocs = common.relative_relocs(elf)
    locations = common.first_party_locations(elf, relocs)
    leas = common.lea_targets(elf)
    def owner(site):
        result = common.containing(starts, ends, site)
        return {'start': addr(result[0]), 'end': addr(result[1])} if result else None
    scoped = []
    files = collections.defaultdict(lambda: collections.defaultdict(set))
    for slot, (file, line, col) in sorted(locations.items()):
        if not file.startswith('evm_rpc/'):
            continue
        sites = []
        for site in sorted(leas.get(slot, ())):
            bound = owner(site)
            sites.append({'va': addr(site), 'bytes': elf.read(site, 7).hex(), 'fde': bound})
            if bound:
                files[(bound['start'], bound['end'])][file].add(line)
        scoped.append({'slot': addr(slot), 'file': file, 'line': line, 'column': col,
                       'lea_sites': sites})
    functions = [{'start': s, 'end': e,
                  'locations': {f: sorted(lines) for f, lines in sorted(v.items())}}
                 for (s, e), v in sorted(files.items(), key=lambda item: int(item[0][0],16))]
    tags = []
    for method in methods(inputs[next(iter(INPUTS))].decode('utf-8')):
        anchors = common.tag_anchor(elf, method, leas, relocs)
        entries = []
        for a in anchors:
            entries.append({'kind': a['kind'], 'occurrence': addr(a['occurrence']),
                            'file_offset': addr(elf.off(a['occurrence'])),
                            'anchor': addr(a['anchor']),
                            'relocation_slots': [addr(x) for x in a['reloc_slots']],
                            'lea_sites': [{'va': addr(s), 'bytes': elf.read(s, 7).hex(),
                                           'fde': owner(s)} for s in a['lea_sites']]})
        if not entries:
            raise common.EvidenceError('no anchor for ' + method)
        # The selected table sequence loads the byte length into ecx immediately
        # before a rel32 call. Retain it separately from name/LEA attribution.
        table_sites = [int(site['va'], 16) for entry in entries for site in entry['lea_sites']
                       if site['fde'] and site['fde']['start'] == addr(TABLE)]
        if len(table_sites) != 1:
            raise common.EvidenceError('unexpected number of table sites: ' + method)
        site = table_sites[0]
        window = elf.read(site + 7, 24)
        marker = b'\xb9' + struct.pack('<I', len(method.encode()))
        pos = window.find(marker)
        if pos < 0:
            raise common.EvidenceError('missing length/call sequence: ' + method)
        length_site = site + 7 + pos
        call_pos = window.find(b'\xe8', pos + 5, pos + 10)
        if call_pos < 0:
            raise common.EvidenceError('missing subsequent call: ' + method)
        call_site = site + 7 + call_pos
        raw = elf.read(call_site, 5)
        target = call_site + 5 + struct.unpack('<i', raw[1:])[0]
        tags.append({'method': method, 'anchors': entries,
                     'table_use': {'length': len(method.encode()), 'length_site': addr(length_site),
                                   'length_bytes': elf.read(length_site, 5).hex(),
                                   'call_site': addr(call_site), 'call_bytes': raw.hex(),
                                   'call_target': addr(target), 'target_fde': owner(target)}})
    def pin_call(site, target):
        raw = elf.read(site, 5)
        if raw[0] != 0xe8 or site + 5 + struct.unpack('<i', raw[1:])[0] != target:
            raise common.EvidenceError(f'call mismatch at {site:#x}')
        if not common.is_fde_start(starts, target):
            raise common.EvidenceError('call target is not an FDE start')
        return {'site': addr(site), 'bytes': raw.hex(), 'target': addr(target),
                'source_fde': owner(site), 'target_fde': owner(target)}
    for t in tags:
        if not any(s['fde'] and s['fde']['start'] == addr(TABLE)
                   for a in t['anchors'] for s in a['lea_sites']):
            raise common.EvidenceError('missing table FDE anchor: ' + t['method'])
    facts = {}
    for release in (94, 115):
        inv = json.loads(inputs[f'research/imported/hl-node-{release}.inventory.json'])
        prov = json.loads(inputs[f'research/work-items/RE-002-build-provenance/provenance-{release}.json'])
        expected = SHA94 if release == 94 else SHA115
        if prov['sha256'] != expected:
            raise common.EvidenceError('provenance target mismatch')
        relevant = []
        for f in prov['facts']:
            if f['key'] in ('crate.registry', 'crate.git_checkout', 'crate.z_vendor_dir', 'crate.z_forks_dir') and re.search(r'revm|reth', json.dumps(f['value']), re.I):
                relevant.append(f)
        facts[str(release)] = {'binary_sha256': expected,
          'first_party_evm_rpc_files': inv['first_party_files']['evm_rpc'],
          'inventory_registry_crates': {k:v for k,v in inv['registry_crates'].items() if re.search('revm|reth', k)},
          'inventory_forked_crates': {k:v for k,v in inv['forked_crates'].items() if re.search('revm|reth', k)},
          'provenance_path_facts': relevant}
    return {'schema': 're011-evm-rpc-method-path/v1', 'binary_sha256': SHA94,
      'input_sha256': INPUTS, 'coordinate_system': 'ELF virtual addresses, FDE end exclusive',
      'analysis_limitations': ['RIP LEA and rel32 byte scans are candidates; not a complete instruction or call graph',
          'Location attribution indicates an FDE contains a reference, not its original source function boundary'],
      'fde_count': len(starts), 'first_party_location_count': len(locations),
      'scoped_location_counts': dict(sorted(collections.Counter(x['file'] for x in scoped).items())),
      'scoped_locations': scoped, 'location_functions': functions,
      'methods': tags, 'method_count': len(tags),
      'pinned_calls': {'router_initialization_to_method_table': pin_call(0x20267ad, TABLE),
                       'router_location_fde_to_router_location_fde': pin_call(0x202f4d9, ROUTER_CALLEE),
                       'router_location_fde_to_router_location_fde_2': pin_call(0x2030034, ROUTER_CALLEE)},
      'fork_matrix': facts}


def render(result):
    return (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    p.add_argument('--binary-115', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    p.add_argument('--out', type=Path, required=True, help='output directory')
    args = p.parse_args()
    try:
        inputs = {name:(ROOT / name).read_bytes() for name in INPUTS}
        result = build(args.binary.read_bytes(), args.binary_115.read_bytes(), inputs)
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'evm-rpc-method-path.json').write_bytes(render(result))
    except (OSError, ValueError, KeyError, struct.error) as exc:
        print(f'evm_rpc_method_path: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
