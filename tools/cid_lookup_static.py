#!/usr/bin/env python3
"""RE-001: node94 two-stage CID-labelled lookup and opaque 20-byte output."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-cid-lookup-layout-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x1405240, 0x1405508
CONTROLS = {
    0x140524c: "48895424184889742410884c240f8b05e858370485c00f8576010000b10131c0f00fb00db45837040f85ba010000488b05af5837044885c00f84d5010000488b0da75837040fb654240f",
    0x1405296: "440fb788120100004c8d40f84d89ca49f7da48c7c6ffffffff904d8d1c324983fbff7436440fb69c30150100004c39da0f9cc3410f9fc34128db4983c01848ffc64180fb0174d3450fb6cb4585c97421eb0b0f1f8400000000004c89ce4883e9010f8262010000488b84f020010000eb8f",
    0x1405307: "498b40f84885c00f847d010000498b08488b542410488b742418440fb79096010000",
    0x1405329: "4c8d88a40000004589d341c1e30449c7c0ffffffff31db4939db744b4c8b34184c8b7c18084939d64d89fc4919f4400f92c54c39f24989f64d19fe4080dd004983c11449ffc04883c3104080fd0174c7440fb6d54585d27428eb0f6666662e0f1f8400000000004d89d04883e9010f82f40000004a8b84c0a0010000e977ffffff",
    0x14053aa: "418b4110894711410f10010f114701c6070131c9b001f00fb00d605737040f85a60000004889f84883c4505b415c415e415f5dc3",
    0x14053de: "488d05435737044889442428488d4424284889442430488d054d573704488d0dee3826044c8d05cf382604488d5424304889fb4889c7be01000000ff15999436044889dfb10131c0f00fb00dfa5637040f8446feffff488d05ed5637044889fb4889c7ba00ca9a3bff15e49a36044889df488b05da5637044885c00f852bfeffff",
    0x140545f: "c6070031c9b001f00fb00dba5637040f845affffff488d05ad5637044889fb4889c731f6ff15af9a36044889dfe93dffffff",
    0x1405491: "488d4424104889442430488b05569b36044889442438488d44240f4889442440488b05489b36044889442448488d3d228bdefe488d15ed382604488d742430ff15c28b36040f0b",
}
RIP = {(0x140525a, '8b05'): 0x577ab48,
       (0x140526c, 'f00fb00d'): 0x577ab28,
       (0x140527a, '488b05'): 0x577ab30,
       (0x140528a, '488b0d'): 0x577ab38,
       (0x14053c0, 'f00fb00d'): 0x577ab28,
       (0x1405402, '4c8d05'): 0x5668cd8,
       (0x1405419, 'ff15'): 0x576e8b8,
       (0x1405483, 'ff15'): 0x576ef38,
       (0x140549b, '488b05'): 0x576eff8,
       (0x14054b1, '488b05'): 0x576f000,
       (0x14054bd, '488d3d'): 0x1edfe6,
       (0x14054c4, '488d15'): 0x5668db8,
       (0x14054d0, 'ff15'): 0x576e098}
RELATIVE = {0x5668db8: 0x1e4c4a, 0x5668cd8: 0x1f87cf,
            0x576e098: 0x157b810, 0x576e8b8: 0x4ee3b20,
            0x576ef38: 0x4e0f2c0, 0x576eff8: 0x1456d60, 0x576f000: 0x14824a0}


def read(data, va, size):
    found = [s['offset'] + va - s['address'] for s in sections(data) if s['type'] != 8
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('expected one file-backed mapping')
    off = found[0]
    return off, bytes(data[off:off + size])


def relocations(data):
    """Index .rela.dyn by slot. A duplicate slot record must be refused,
    not folded last-wins: which (info, addend) pair a binding check reads
    would otherwise depend on record order in the table."""
    sec = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    rels = {}
    for a, i, v in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
        if a in rels:
            raise ValueError(f'duplicate relocation slot {a:#x}')
        rels[a] = (i, v)
    return rels


def limb_comparison(entry_low, entry_high, query_low, query_high):
    """Conditional CMP/SBB borrow reduction for two unsigned 64-bit limbs."""
    borrow_entry = entry_high - query_high - int(entry_low < query_low) < 0
    borrow_query = query_high - entry_high - int(query_low < entry_low) < 0
    return (int(borrow_entry) - int(borrow_query)) & 0xff


def analyze(data):
    _, frames, _ = fde_extents(data)
    if (START, END) not in {(f['start'], f['end']) for f in frames}:
        raise ValueError('lookup FDE changed')
    for va, value in CONTROLS.items():
        raw = bytes.fromhex(value)
        if read(data, va, len(raw))[1] != raw:
            raise ValueError(f'lookup instruction changed at {va:#x}')
    for (va, prefix), target in RIP.items():
        prefix = bytes.fromhex(prefix)
        raw = read(data, va, len(prefix) + 4)[1]
        if not raw.startswith(prefix) or va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0] != target:
            raise ValueError('lookup RIP target changed')
    descriptor = b'\x0cmissing cid \xc0\x07 chain=\xc0\0'
    if read(data, 0x1edfe6, len(descriptor))[1] != descriptor:
        raise ValueError('missing-CID descriptor changed')
    rels = relocations(data)
    if any(rels.get(a) != (8, v) for a, v in RELATIVE.items()):
        raise ValueError('lookup source/helper/callback relocation changed')
    sources = []
    for slot, path_va, path, line, col in [
        (0x5668db8, 0x1e4c4a, '/home/ubuntu/hl/code_Mainnet/base/src/cid.rs', 69, 17),
        (0x5668cd8, 0x1f87cf, '/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs', 219, 20),
    ]:
        raw = path.encode()
        if read(data, path_va, len(raw))[1] != raw or read(data, slot + 8, 16)[1] != struct.pack('<QII', len(raw), line, col):
            raise ValueError('lookup source Location changed')
        sources.append({'slot': hex(slot), 'path_va': hex(path_va), 'path': path, 'line': line, 'column': col})
    off, body = read(data, START, END - START)
    return {'target_sha256': SHA256,
            'range': {'start_va': hex(START), 'end_va': hex(END), 'file_offset': hex(off),
                      'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()},
            'inputs': {'output_pointer': 'rdi', 'query_limbs': ['rsi', 'rdx'], 'outer_key': 'cl'},
            'outer_search': {'node_count_offset': '0x112', 'first_key_offset': '0x114',
                             'value_cursor_step': 24, 'children_offset': '0x120', 'absent_path': '0x140545f'},
            'inner_search': {'node_count_offset': '0x196', 'key_step': 16,
                             'initial_value_cursor_offset': '0xa4', 'per_key_value_step': 20,
                             'first_value_offset_after_step': '0xb8', 'children_offset': '0x1a0',
                             'comparison_result_bytes': {'entry_less': 1, 'equal': 0, 'entry_greater': 255},
                             'absent_path': '0x1405491'},
            'output': {'outer_absent_tag': 0, 'inner_present_tag': 1,
                       'opaque_payload_bytes': 20, 'copy_offsets': ['0x1..0x10', '0x11..0x14'],
                       'concrete_rust_type': 'not recovered; 16+4 copy does not establish canonical:u128 plus tag:u32'},
            'descriptor': {'va': '0x1edfe6', 'body_hex': descriptor.hex(), 'full_rendering_proved': False},
            'sources': sources,
            'relative_bindings': {hex(a): hex(v) for a, v in RELATIVE.items()},
            'instruction_controls': {hex(a): v for a, v in CONTROLS.items()},
            'rip_targets': [{'site': hex(a), 'prefix_hex': p, 'target': hex(v)} for (a, p), v in RIP.items()],
            'captured_binary_executed': False,
            'limits': 'One CID-labelled global lookup. B-tree-like layouts and option-like tags are observations/inferences, not a concrete Rust map/value type. Initializer, lock/unlock correctness, valid states, all callers, panic/formatter/helper closure and runtime equivalence remain unproved.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('expected pinned node94')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node94.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        chosen = [line for line in frames.splitlines() if f'pc={START:016x}..{END:016x}' in line]
        if len(chosen) != 1:
            raise ValueError('native FDE confirmation failed')
        (output / 'frames.txt').write_text(chosen[0] + '\n')
        asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                      f'--start-address={START:#x}', f'--stop-address={END:#x}', str(snapshot)], text=True)
        ins = decode_export(asm, START, END, read(data, START, END - START)[1])
        required = set(CONTROLS) | {a for a, _ in RIP}
        if not required <= set(ins):
            raise ValueError('lookup controls must be decoded instruction starts')
        (output / '1405240.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/cid-lookup-layout-94')
    args = parser.parse_args()
    print(json.dumps({'range': generate(args.binary, args.output)['range'], 'executed': False}))
