#!/usr/bin/env python3
"""Static three-call-site qualification; never execute node94."""
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
CASES = [(0x326e460, 0x326e53b, 0x326e4ab, 0x37d4e30, 2),
         (0x32fc190, 0x32fc55d, 0x32fc40f, 0x37d4e30, 2),
         (0x47f1590, 0x47f3086, 0x47f264f, 0x459a4c0, 16)]
# Follow-up anchors to the independently recovered pair-forwarding packet #1915.
# These bytes are independently re-read; that packet supplies the full path.
ANCHORS = {
    'state-entry-save': (0x37d4e41, '48897424684889542470'),
    'state-capture-pointer': (0x37d4ee0, '488d4424684889442410'),
    'state-pair-load': (0x3be4b69, '488b4708488b084c8b4008'),
    'state-wrapper-save': (0x342199b, '4d89c64989cf'),
    'state-default-selector': (0x3421a56, '41f6c701bf02000000490f45fe'),
    'checkpoint-entry-save': (0x459a4d1, '48897424684889542470'),
    'checkpoint-capture-pointer': (0x459a578, '488d4424684889442428'),
    'checkpoint-pair-load': (0x4875cad, '488b0b4c8b4308'),
    'checkpoint-wrapper-save': (0x42c70dd, '4d89c64989cf'),
    'checkpoint-default-selector': (0x42c71b1, '41f6c701bf10000000490f45fe'),
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--objdump', default='/Library/Developer/CommandLineTools/usr/bin/llvm-objdump')
    args = parser.parse_args()
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    need(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST, 'target identity')
    secs = sections(data)
    def offset(va, size):
        ss = [s for s in secs if s['type'] != 8 and s['address'] <= va and
              va + size <= s['address'] + s['size']]
        need(len(ss) == 1, 'unique section mapping')
        return ss[0]['offset'] + va - ss[0]['address']
    def raw(va, size):
        off = offset(va, size)
        return data[off:off + size]
    def validate(read):
        for _, _, site, target, _ in CASES:
            bs = read(site - 2, 7)
            need(bs[:3] == b'\x31\xf6\xe8', f'xor/call at {site:#x}')
            need(site + 5 + struct.unpack('<i', bs[3:])[0] == target, f'call target at {site:#x}')
        for name, (va, hx) in ANCHORS.items():
            need(read(va, len(bytes.fromhex(hx))).hex() == hx, 'anchor ' + name)
    validate(raw)
    _, fdes, _ = fde_extents(data)
    selected = []
    instructions = []
    for start, end, site, target, default in CASES:
        ff = [f for f in fdes if f['start'] == start]
        need(len(ff) == 1 and ff[0]['end'] == end, 'selected FDE extent')
        command = [args.objdump, '-d', '--x86-asm-syntax=intel',
                   f'--start-address={start:#x}', f'--stop-address={end:#x}',
                   'artifacts/node/94/hl-node']
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)
        rows = []
        for line in result.stdout.splitlines():
            m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$', line)
            if m:
                rows.append((int(m[1], 16), bytes.fromhex(m[2]), m[3].strip()))
        cursor = start
        for va, bs, text in rows:
            need(va == cursor and raw(va, len(bs)) == bs and '<unknown>' not in text,
                 'complete linear LLVM decode')
            cursor += len(bs)
        need(cursor == end, 'exact decoded end')
        by_va = {r[0]: r for r in rows}
        need(by_va[site - 2][2] == 'xor\tesi, esi', 'decoded ESI zero')
        need(re.match(rf'call\s+{target:#x}\b', by_va[site][2]) is not None, 'decoded call')
        # Direct intra-owner CFG only. Calls may return; indirect jump targets
        # and exceptional edges are not synthesized into a reachability proof.
        edges = {}
        unknown_jumps = []
        for va, bs, text in rows:
            op = text.split()[0]
            after = va + len(bs)
            branch = re.match(r'\S+\s+(0x[0-9a-f]+)\b', text)
            successors = []
            if op.startswith('ret') or op in ('ud2', 'int3'):
                pass
            elif op.startswith('j'):
                if branch:
                    successors.append(int(branch[1], 16))
                else:
                    unknown_jumps.append(hex(va))
                if op != 'jmp':
                    successors.append(after)
            else:
                successors.append(after)
            edges[va] = [v for v in successors if v in by_va]
        incoming = [va for va, successors in edges.items() if site in successors]
        need(incoming == [site - 2], 'call has direct predecessor bypassing ESI clear')
        seen = {start}
        queue = deque([start])
        while queue:
            for dst in edges[queue.popleft()]:
                if dst not in seen:
                    seen.add(dst)
                    queue.append(dst)
        need(site in seen, 'call not on modeled direct path')
        # Retain the complete qualified decode, not a resynchronization slice.
        transcript = ' '.join(command) + '\nTarget SHA256: ' + DIGEST + '\n' + result.stdout
        (HERE / f'{start:x}.llvm.txt').write_text(transcript)
        selected.append({
            'fde': {k: hex(v) if isinstance(v, int) else v for k, v in ff[0].items()},
            'owner_sha256': hashlib.sha256(raw(start, end-start)).hexdigest(),
            'owner_bytes': end-start, 'instruction_count': len(rows),
            'call_site': hex(site), 'target': hex(target), 'esi_clear': hex(site-2),
            'call_bytes_with_clear': raw(site-2, 7).hex(), 'default_gib': default,
            'modeled_direct_predecessors': [hex(v) for v in incoming],
            'call_reachable_in_direct_cfg': True, 'unresolved_indirect_jumps': unknown_jumps,
            'cfg_limits': 'calls assumed to return; no exception/computed edge reconstruction',
        })
        instructions.extend(rows)
    # Byte-scanned candidates only; exact FDE/LLVM validation above qualifies
    # the three E8 hits. E9/RELATIVE absence is scoped to these enumerated forms.
    targets = {c[3] for c in CASES}
    census = []
    for sec in secs:
        if sec['type'] == 8 or not sec['flags'] & 4:
            continue
        bs = data[sec['offset']:sec['offset'] + sec['size']]
        for opcode in (0xe8, 0xe9):
            pos = -1
            while True:
                pos = bs.find(bytes([opcode]), pos + 1)
                if pos < 0 or pos + 5 > len(bs):
                    break
                va = sec['address'] + pos
                target = va + 5 + struct.unpack_from('<i', bs, pos + 1)[0]
                if target in targets:
                    census.append({'section': sec['name'], 'site': hex(va), 'opcode': hex(opcode), 'target': hex(target)})
    need({r['site'] for r in census if r['opcode'] == '0xe8'} == {hex(c[2]) for c in CASES}, 'candidate census changed')
    rela = [s for s in secs if s['name'] == '.rela.dyn']
    need(len(rela) == 1 and rela[0]['size'] % 24 == 0, 'relocation section')
    slots = []
    for off in range(rela[0]['offset'], rela[0]['offset'] + rela[0]['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if info == 8 and addend in targets:
            slots.append({'slot': hex(slot), 'target': hex(addend)})
    controls = []
    changes = [(f'esi-clear-{site:#x}', site - 1) for _, _, site, _, _ in CASES]
    changes += [(f'call-displacement-{site:#x}', site + 1) for _, _, site, _, _ in CASES]
    changes += [(name, va + len(bytes.fromhex(hx)) - 1) for name, (va, hx) in ANCHORS.items()]
    for name, change in changes:
        def mutated(va, size):
            bs = bytearray(raw(va, size))
            if va <= change < va + size:
                bs[change - va] ^= 1
            return bytes(bs)
        try:
            validate(mutated)
        except ValueError:
            controls.append({'name': name, 'mutated_va': hex(change), 'rejected_without_digest_gate': True})
        else:
            raise ValueError('corruption accepted: ' + name)
    records = {
        'task': 'RE-009', 'component': 'storage', 'target_sha256': DIGEST, 'target_size': len(data),
        'source_base': 'e5c9b6436876b2a4a39daef813171f9879317699',
        'coordinate_system': 'ELF virtual addresses, ends exclusive',
        'provider': 'static Apple LLVM',
        'decoder_version': subprocess.check_output([args.objdump, '--version'], text=True).splitlines()[0],
        'python': platform.python_version(), 'host': platform.system() + ' ' + platform.machine(),
        'parser_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                           for name in ('tools/elf_index.py', 'tools/fde_extents.py')},
        'qualified_callers': selected, 'byte_scan_candidates': census,
        'relative_slots_to_entries': slots,
        'census_limits': 'E8/E9 rel32 bytes in file-backed executable sections and R_X86_64_RELATIVE addends only; not a whole-program caller census',
        'forwarding_anchors': {name: {'va': hex(va), 'bytes': hx} for name, (va, hx) in ANCHORS.items()},
        'negative_controls': controls,
        'counts': {'qualified_calls': len(selected), 'owner_bytes': sum(c['owner_bytes'] for c in selected),
                   'owner_instructions': len(instructions), 'forwarding_anchors': len(ANCHORS), 'rejected_corruptions': len(controls)},
        'nonclaims': ['No captured execution', 'No complete caller census or runtime reachability',
                      'No recovered CLI/configuration field', 'No Rust implementation or gate change'],
    }
    (HERE / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
    print(json.dumps(records['counts'], sort_keys=True))


if __name__ == '__main__':
    main()
