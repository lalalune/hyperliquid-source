#!/usr/bin/env python3
"""Authenticate node94's complete keepalive pair and bounded caller policy.

Static parsing only: this does not execute or emulate captured instructions.
The two caller FDEs are context exports, not whole-function reconstructions.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from fde_extents import eh_frame_records
from socket_calls_static import Image

ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BODIES = {
    0x4ecd970: (0x4ecda53, '959176cd983dccdf945adc4e7de62d81d9992660511b8194ae2aa35f4d67a55f', 'complete-helper'),
    0x4ecda60: (0x4ecdb43, 'eb64669eaff9293f6dc8bc0bb91b4b405e46ef0ae0d1bd74bece7ec897c7ae3d', 'complete-helper'),
    0x29aeb40: (0x29af8ce, '8a1ae6016d66982f8a68dd8d5db73aff9bd148f1cbddbf02ff70419d8cf17852', 'caller-context'),
    0x29c3300: (0x29c4108, '518f4b2d6fba29618f89790461e7b02400f07952818efe4c105c4d6eb784e946', 'caller-context'),
}
CALLERS = {0x4ecd970: [0x29af13a], 0x4ecda60: [0x29c3403]}
IMPORTS = {'setsockopt': 0x576f0d0, '__errno_location': 0x576e8d8}
# Address records are separately validated through their own RELATIVE writer,
# length and raw bytes, rather than inferred from nearby strings.
LOCATIONS = {0x56cc100: (0x1f7b60, 94, 89, 9), 0x5751a48: (0x1e7c7c, 94, 105, 17)}
METADATA = {0x577ccf0: (0x56ca728, 0x3fb178, 97, 217),
            0x577d5c0: (0x56ce898, 0x3fee23, 53, 648)}


class EvidenceError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise EvidenceError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decoded(im, start, end):
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    rows = list(md.disasm(im.read(start, end - start), start))
    need(rows and rows[0].address == start and rows[-1].address + rows[-1].size == end
         and sum(i.size for i in rows) == end - start, 'complete decode')
    return rows


def frame_bytes(im, va):
    # eh_frame_records reports ELF virtual addresses, independent of file offsets.
    sec = next(s for s in im.secs if s['name'] == '.eh_frame')
    at = im.offset(va, 4)
    n = struct.unpack_from('<I', im.data, at)[0]
    need(4 <= n < 0xffffffff and at + 4 + n <= sec['offset'] + sec['size'], 'frame bounds')
    return im.data[at:at + 4 + n]


def direct_calls(im, targets):
    base, text = im.text_bytes(); hits = {t: [] for t in targets}
    cache = {}
    for m in re.finditer(b'\xe8', text):
        off = m.start()
        if off + 5 > len(text):
            continue
        target = base + off + 5 + struct.unpack_from('<i', text, off + 1)[0]
        if target not in hits:
            continue
        va = base + off; start, end = im.fde_of(va)
        if start not in cache:
            cache[start] = {i.address: i for i in decoded(im, start, end)}
        ins = cache[start].get(va)
        need(ins is not None and ins.mnemonic == 'call' and ins.size == 5, 'call census byte is not instruction')
        hits[target].append(va)
    return hits


def inspect(data, authenticate=True):
    if authenticate:
        need(len(data) == 91774280 and sha(data) == TARGET_SHA, 'whole target identity')
    im = Image(data); cies, frames = eh_frame_records(data, im.secs)
    body_records = []; all_rows = {}
    for start, (end, digest, role) in BODIES.items():
        need(im.fde_of(start) == (start, end), 'exact FDE extent')
        raw = im.read(start, end - start)
        need(sha(raw) == digest, 'complete body digest')
        rows = decoded(im, start, end); all_rows.update({i.address: i for i in rows})
        frame = [f for f in frames if f['start'] == start and f['end'] == end]
        need(len(frame) == 1, 'unique FDE'); frame = frame[0]
        fraw, craw = frame_bytes(im, frame['fde']), frame_bytes(im, frame['cie'])
        body_records.append({'start': hex(start), 'end': hex(end), 'role': role,
                             'bytes': len(raw), 'sha256': sha(raw), 'instructions': len(rows),
                             'fde': frame, 'fde_raw_hex': fraw.hex(), 'cie_raw_hex': craw.hex(),
                             'rows': [{'va': hex(i.address), 'bytes': bytes(i.bytes).hex(),
                                       'mnemonic': i.mnemonic, 'operands': i.op_str} for i in rows]})
    for name, slot in IMPORTS.items():
        need(im.named.get(name) == [slot], 'named import identity')
    calls = direct_calls(im, CALLERS)
    need(calls == CALLERS, 'complete direct caller census')
    need(not any(v in CALLERS for v in im.relative.values()), 'unexpected address-taken helper')
    helper_calls = []
    for start in CALLERS:
        rows = decoded(im, start, BODIES[start][0]); observed = []
        for i in rows:
            if i.mnemonic == 'call':
                need(bytes(i.bytes[:2]) == b'\xff\x15' and i.size == 6, 'only helper GOT imports')
                slot = i.address + i.size + struct.unpack_from('<i', bytes(i.bytes), 2)[0]
                names = [n for n, s in IMPORTS.items() if s == slot]
                need(len(names) == 1, 'helper call closure')
                observed.append(names[0]);helper_calls.append({'va': hex(i.address), 'slot': hex(slot), 'symbol': names[0]})
        need(observed == ['setsockopt'] * 3 + ['__errno_location'], 'helper import order')
    rela = next(s for s in im.secs if s['name'] == '.rela.dyn')
    relocation_rows = []
    needed_slots = set(IMPORTS.values()) | set(LOCATIONS) | set(METADATA)
    for slot, (record, _, _, _) in METADATA.items():
        needed_slots.update(record + k for k in range(0, 0x78, 8) if record + k in im.relative)
    for at in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, at)
        if any(where < slot + 8 and slot < where + 8 for slot in needed_slots):
            relocation_rows.append({'file_offset': at, 'where': hex(where), 'info': info, 'addend': addend,
                                    'raw_hex': data[at:at + 24].hex()})
    for slot in needed_slots:
        hits = [r for r in relocation_rows if int(r['where'], 16) < slot + 8 and slot < int(r['where'], 16) + 8]
        need(len(hits) == 1 and int(hits[0]['where'], 16) == slot, 'unique whole-slot relocation writer')
        need(hits[0]['info'] & 0xffffffff == (6 if slot in IMPORTS.values() else 8), 'relocation kind')
        if slot in IMPORTS.values():
            need(hits[0]['addend'] == 0, 'GLOB_DAT addend')
    locations = []
    for va, (path, length, line, col) in LOCATIONS.items():
        need(im.relative.get(va) == path, 'Location path relocation')
        need(im.read(va + 8, 16) == struct.pack('<QII', length, line, col), 'Location length/line/column')
        raw = im.read(path, length)
        locations.append({'va': hex(va), 'path_va': hex(path), 'path': raw.decode(), 'line': line, 'column': col,
                          'raw_hex': im.read(va, 24).hex(), 'path_sha256': sha(raw)})
    metadata = []
    for slot, (record, path, length, line) in METADATA.items():
        need(im.relative.get(slot) == record, 'initial tracing metadata slot')
        need(im.relative.get(record + 0x60) == path, 'tracing source path relocation')
        need(struct.unpack('<Q', im.read(record + 0x68, 8))[0] == length, 'tracing source path length')
        need(struct.unpack('<I', im.read(record + 0xc, 4))[0] == line, 'tracing source line')
        raw = im.read(path, length)
        metadata.append({'initial_slot': hex(slot), 'record_va': hex(record), 'path_va': hex(path),
                         'path': raw.decode(), 'line': line, 'record_raw_hex': im.read(record, 0x78).hex(),
                         'initial_relocations': {hex(record + k): hex(im.relative[record + k])
                                                 for k in range(0, 0x78, 8) if record + k in im.relative}})
    return {'target_sha256': TARGET_SHA, 'bodies': body_records, 'helper_calls': helper_calls,
            'direct_calls': {hex(k): list(map(hex, v)) for k, v in calls.items()},
            'imports': {n: hex(s) for n, s in IMPORTS.items()}, 'relocations': relocation_rows, 'locations': locations, 'tracing_metadata': metadata,
            'scope': '454 complete helper bytes plus 7062 caller-context bytes; bounded keepalive caller stage only',
            'captured_execution': False, 'instruction_emulation': False}


def export(args):
    data = args.target.read_bytes(); result = inspect(data)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'records.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    commands = []
    for start, (end, _, _) in BODIES.items():
        for name, exe in [('gnu', args.objdump), ('llvm', args.llvm_objdump)]:
            argv = [str(exe), '-d', '--start-address=' + hex(start), '--stop-address=' + hex(end), str(args.target)]
            p = subprocess.run(argv, capture_output=True)
            need(p.returncode == 0, name + ' disassembler failed')
            prefix = f'{start:x}.{name}'
            (args.out / (prefix + '.stdout')).write_bytes(p.stdout)
            (args.out / (prefix + '.stderr')).write_bytes(p.stderr)
            commands.append({'argv': argv, 'exit': p.returncode,
                             'stdout_sha256': sha(p.stdout), 'stderr_sha256': sha(p.stderr)})
    (args.out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    print(json.dumps({'bodies': len(result['bodies']), 'bytes': sum(x['bytes'] for x in result['bodies']),
                      'instructions': sum(x['instructions'] for x in result['bodies']), 'imports': len(IMPORTS)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--objdump', type=Path, required=True)
    p.add_argument('--llvm-objdump', type=Path, required=True)
    export(p.parse_args())
