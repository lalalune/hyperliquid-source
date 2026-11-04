#!/usr/bin/env python3
"""Authenticate node115 accept4 address conversion and caller ownership boundaries.

Static parsing only: this does not execute or emulate captured instructions.
The four caller FDEs and error classifier are scoped context, not whole-runtime recovery.
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
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES = {
    0x475b050: (0x475b154, '683c50744953528c7928e1f474427f6572bcc888bae889f736321d5bb24a539e', 'complete-accept-helper'),
    0x2afae20: (0x2afbc22, '92908861d63235792ddd6bcbb3d3b6ce395a05acef307cf5a09585bd2feb263a', 'caller-context'),
    0x2cc02d0: (0x2cc111b, 'd1ec5f7dcbdd2d86aa75c88a47170efdab7c542907a58e45627e7c39ce027e95', 'caller-context'),
    0x5a5e290: (0x5a60a43, '756cc162667af4c15d359cd796c15cf85d5d609c866d1311113e8cc467754c1e', 'caller-context'),
    0x5cdfe50: (0x5ce008a, 'e18322da7cb3b488959029668bd5bf1eb377763a5a856aad6ce7f84752231a28', 'caller-context'),
    0x5cdf1b0: (0x5cdf270, 'e758390109ee25add42b3477791c42c1a3906444b1b2dc737dedf6a17faa8257', 'error-kind-context'),
}
CALLS = [0x2afb455, 0x2cc0958, 0x5a5f9ac, 0x5cdfefe]
IMPORTS = {'accept4': 0x64eb068, '__errno_location': 0x64dffc8, 'close': 0x64dfe78}
TABLES = {0x6043fc: 4, 0x60bce8: 4, 0x939504: 4, 0x94c7a4: 4, 0x94c7b4: 122}



class EvidenceError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise EvidenceError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        by = {s['name']: s for s in self.secs if s['type'] != 8}
        for name in ('.text', '.rela.dyn', '.dynsym', '.dynstr'):
            need(name in by, f'no file-backed {name}')
        self.text = by['.text']
        rela, dynsym, dynstr = by['.rela.dyn'], by['.dynsym'], by['.dynstr']
        need(rela['size'] % 24 == 0 and dynsym['size'] % 24 == 0, 'malformed .rela.dyn/.dynsym')
        self.relative, self.named = {}, {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            kind, sym = info & 0xffffffff, info >> 32
            if kind == 8:
                self.relative[where] = addend
            elif kind in (6, 7):
                need(sym * 24 < dynsym['size'], f'symbol index {sym} out of .dynsym')
                st_name = struct.unpack_from('<I', data, dynsym['offset'] + 24 * sym)[0]
                start = dynstr['offset'] + st_name
                try:
                    name = data[start:data.index(b'\0', start)].decode()
                except UnicodeDecodeError:
                    raise EvidenceError('dynamic symbol name is not valid UTF-8') from None
                self.named.setdefault(name, []).append(where)
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        need(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde_of(self, va):
        hits = [f for f in self.fdes if f[0] <= va < f[1]]
        need(len(hits) == 1, f'{va:#x} is not inside exactly one FDE')
        return hits[0]

    def text_bytes(self):
        t = self.text
        return t['address'], self.data[t['offset']:t['offset'] + t['size']]

    def rel32_slot(self, call):
        return call + 6 + struct.unpack('<i', self.read(call + 2, 4))[0]


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


CALLER_STAGES = [
    dict(owner=0x2afae20, call=0x2afb455, output_rsp=0x110, error_table=0x6043fc,
         success=0x2afb4a1, register_call=0x2afb526, register_close=0x2afb545,
         family_test=0x2afb594, ipv4=0x2afb779, cleanup_call=0x2afb5b7,
         family_close=0x2afb5c5, rejection_text=0x606ec3, would_block=0x2afb5ea,
         other_error=0x2afb691),
    dict(owner=0x2cc02d0, call=0x2cc0958, output_rsp=0x110, error_table=0x60bce8,
         success=0x2cc09a4, register_call=0x2cc0a29, register_close=0x2cc0a48,
         family_test=0x2cc0a9a, ipv4=0x2cc0c6d, cleanup_call=0x2cc0abd,
         family_close=0x2cc0acb, rejection_text=0x60f89e, would_block=0x2cc0af0,
         other_error=0x2cc0b82),
    dict(owner=0x5a5e290, call=0x5a5f9ac, output_rsp=0x290, error_table=0x939504,
         success=0x5a5f9ff, register_call=0x5a5fa9d, register_close=0x5a5fabf,
         family_test=0x5a5fb16, ipv4=0x5a602c7, cleanup_call=0x5a5fb39,
         family_close=0x5a5fb47, rejection_text=0x93c599, would_block=0x5a5fb6c,
         other_error=0x5a5fc03),
    dict(owner=0x5cdfe50, call=0x5cdfefe, output_rsp=0x10, error_kind_call=0x5cdff12,
         success=0x5cdff63, register_call=0x5cdffad, register_close=0x5cdffc6,
         success_copy=0x5cdfff6, would_block=0x5cdff1f, other_error=0x5cdffe1),
]



def inspect(data, authenticate=True):
    if authenticate:
        need(len(data) == 105896032 and sha(data) == TARGET_SHA, 'whole target identity')
    im = Image(data); cies, frames = eh_frame_records(data, im.secs)
    body_records = []; all_rows = {}
    for start, (end, digest, role) in BODIES.items():
        need(im.fde_of(start) == (start, end), 'exact FDE extent')
        raw = im.read(start, end - start)
        need(sha(raw) == digest, 'complete body digest')
        rows = decoded(im, start, end); all_rows.update({i.address: i for i in rows})
        matched = [f for f in frames if f['start'] == start and f['end'] == end]
        need(len(matched) == 1, 'unique FDE'); frame = matched[0]
        body_records.append({'start': hex(start), 'end': hex(end), 'role': role,
            'bytes': len(raw), 'sha256': sha(raw), 'instructions': len(rows), 'fde': frame,
            'fde_raw_hex': frame_bytes(im, frame['fde']).hex(),
            'cie_raw_hex': frame_bytes(im, frame['cie']).hex(),
            'rows': [{'va': hex(i.address), 'bytes': i.bytes.hex(), 'mnemonic': i.mnemonic,
                      'operands': i.op_str} for i in rows]})
    calls = direct_calls(im, [0x475b050])
    need(calls[0x475b050] == CALLS, 'four complete caller instruction contexts')
    need(not any(v == 0x475b050 for v in im.relative.values()), 'unexpected address-taken helper slot')
    for name, slot in IMPORTS.items():
        need(im.named.get(name) == [slot], 'named import identity: ' + name)
    rela = next(s for s in im.secs if s['name'] == '.rela.dyn')
    raw_relas = []
    for at in range(rela['offset'], rela['offset'] + rela['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, at)
        raw_relas.append(dict(file_offset=at, where=where, info=info, addend=addend,
                              raw_hex=data[at:at + 24].hex()))
    imports = []
    for name, slot in IMPORTS.items():
        writers = [r for r in raw_relas if r['where'] < slot + 8 and slot < r['where'] + 8]
        need(len(writers) == 1 and writers[0]['where'] == slot, 'one whole import-slot writer')
        writer = writers[0]
        need(writer['info'] & 0xffffffff == 6 and writer['addend'] == 0, 'GLOB_DAT import')
        imports.append(dict(name=name, slot=hex(slot), raw_hex=im.read(slot, 8).hex(), relocation=writer))
    primary_calls = []
    for i in decoded(im, 0x475b050, 0x475b154):
        if i.mnemonic == 'call':
            need(i.size == 6 and i.bytes[:2] == b'\xff\x15', 'primary import boundary')
            slot = im.rel32_slot(i.address)
            name = next((n for n, v in IMPORTS.items() if v == slot), None)
            need(name is not None, 'primary named call')
            primary_calls.append({'va': hex(i.address), 'slot': hex(slot), 'name': name})
    need([r['name'] for r in primary_calls] == ['accept4', '__errno_location', 'close'], 'three import calls')
    tables = []
    for start, count in TABLES.items():
        raw = im.read(start, 4 * count)
        need(not any(r['where'] < start + len(raw) and start < r['where'] + 8 for r in raw_relas),
             'relative-offset table has no relocation byte overlap')
        targets = [start + struct.unpack_from('<i', raw, 4 * n)[0] for n in range(count)]
        need(all(t in all_rows for t in targets), 'all jump-table targets are decoded instruction starts')
        tables.append({'start': hex(start), 'entries': count, 'raw_hex': raw.hex(),
                       'sha256': sha(raw), 'targets': list(map(hex, targets))})
    errno_targets = next(t['targets'] for t in tables if t['start'] == '0x94c7b4')
    would_block = [n + 1 for n, va in enumerate(errno_targets) if va == '0x5cdf243']
    need(would_block == [11], 'error kind 13 only for errno 11')
    stage_records = []
    for stage in CALLER_STAGES:
        row = dict(stage)
        for key, va in stage.items():
            if key not in ('output_rsp', 'error_table', 'rejection_text'):
                need(va in all_rows, 'caller boundary is an instruction: ' + key)
        register = all_rows[stage['register_call']]
        need(register.bytes[0] == 0xe8 and register.address + 5 + struct.unpack_from('<i', register.bytes, 1)[0]
             == 0x5cf24b0, 'actual shared registration target')
        for key in ('register_close', 'family_close'):
            if key in stage:
                need(im.rel32_slot(stage[key]) == IMPORTS['close'], 'actual caller close import')
        if 'family_test' in stage:
            need(all_rows[stage['family_test']].mnemonic == 'test' and
                 all_rows[stage['family_test']].op_str.endswith(', 1'), 'actual low-bit family gate')
            text = im.read(stage['rejection_text'], 9)
            need(text == b'ip not v4', 'actual IPv4-only rejection literal')
            row['rejection_raw_hex'] = text.hex()
        row['registration_is_opaque'] = True
        row['post_registration_fd_reloaded'] = True
        row['whole_caller_reconstruction'] = False
        stage_records.append(row)
    return {'target_sha256': TARGET_SHA, 'bodies': body_records, 'imports': imports,
            'primary_calls': primary_calls, 'direct_calls': list(map(hex, CALLS)),
            'address_taken_relative_slots': [], 'jump_tables': tables,
            'would_block_errno': would_block, 'caller_stages': stage_records,
            'scope': 'Complete 260-byte accept helper plus four caller contexts and error-kind context; opaque registration/cleanup effects stay external.',
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
            stdout = p.stdout.replace(str(args.target).encode(), b'<authenticated-node115>')
            stderr = p.stderr.replace(str(args.target).encode(), b'<authenticated-node115>')
            prefix = f'{start:x}.{name}'
            (args.out / (prefix + '.stdout')).write_bytes(stdout)
            (args.out / (prefix + '.stderr')).write_bytes(stderr)
            commands.append({'argv': [v.replace(str(args.target), '<authenticated-node115>') for v in argv],
                             'target_filename_presentation_normalized': True,
                             'exit': p.returncode, 'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)})
    (args.out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    print(json.dumps({'bodies': len(result['bodies']), 'bytes': sum(x['bytes'] for x in result['bodies']),
                      'instructions': sum(x['instructions'] for x in result['bodies']), 'imports': len(IMPORTS)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--objdump', type=Path, required=True)
    p.add_argument('--llvm-objdump', type=Path, required=True)
    export(p.parse_args())
