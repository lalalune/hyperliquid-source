#!/usr/bin/env python3
"""Authenticate node115's complete keepalive pair and bounded caller policy.

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

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from fde_extents import eh_frame_records
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES = {
    0x5c68520: (0x5c68603, '9cf52b0424eaeec1e6757af4979753818ee0171e7e3d639ac08a7b5df0057b18', 'complete-helper'),
    0x5c68610: (0x5c686f3, 'a4a4b51ea5f4bd093ebcfd1c57ee2b7bab3b73d9f15969ef021c1630146c8fc2', 'complete-helper'),
    0x2e6ba40: (0x2e6c57d, 'bb83145a5a0f63dd5161538a948c2195d0dd360f712af2f3c33b6ca986ea55da', 'caller-context'),
    0x2e7db50: (0x2e7e7ed, 'e85497701e2a8bd400c01a6f92a02aec8269f6f0a984327a9042c59a48e50937', 'caller-context'),
    0x2e6b0c0: (0x2e6b18e, 'bb667271a0a07e73fe38fc63691b5b24e58780a4f53ea2854eb78002e76d733e', 'error-drop-context'),
    0x2e7bdd0: (0x2e7be9e, '5f0e7e5bdd180b88ba8613f58bba62c7bd553e0a0533963e96a80607a6827c64', 'error-drop-context'),
}
CALLERS = {0x5c68520: [0x2e6bff2], 0x5c68610: [0x2e7dc70]}
IMPORTS = {'setsockopt': 0x64e1410, '__errno_location': 0x64dffc8}
LOCATIONS = {
    0x6458ff8: (0x437c59, 66, 89, 9),
    0x64c2ad0: (0x4435cb, 66, 105, 17),
    0x6456b28: (0x43f26e, 61, 217, 29),
    0x645a590: (0x448bd0, 45, 648, 13),
}
METADATA = {0x64f2530: (0x6456948, 0x61db4c, 61, 217),
            0x64f2d40: (0x645a518, 0x620afb, 45, 648)}



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
        self.relative, self.named, self.relocations = {}, {}, {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            kind, sym = info & 0xffffffff, info >> 32
            need(where not in self.relocations, 'duplicate RELA destination')
            self.relocations[where] = {'slot': hex(where), 'kind': kind, 'symbol_index': sym, 'addend': addend, 'file_offset': pos, 'raw_hex': data[pos:pos+24].hex()}
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
    starts = {i.address for i in rows}
    for i in rows:
        if i.group(CS_GRP_JUMP) and i.operands[0].type == X86_OP_IMM:
            dest = i.operands[0].imm
            need(not start <= dest < end or dest in starts, 'internal branch into instruction')
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



STAGES = [
    dict(owner=0x2e6ba40, enable=0x2e6bfdd, helper=0x2e6bff2,
         errno=0x2e6bffe, publish=0x2e6c00e, error_rsp=0x68,
         log_emit=0x2e6c264, drop_call=0x2e6c02b, drop_target=0x2e6b0c0,
         continuation=0x2e6c030, trace_cell=0x64f2530),
    dict(owner=0x2e7db50, enable=0x2e7dc57, helper=0x2e7dc70,
         errno=0x2e7dd72, publish=0x2e7dd82, error_rsp=0x50,
         log_emit=0x2e7de86, drop_call=0x2e7de9a, drop_target=0x2e7bdd0,
         continuation=0x2e7de9f, trace_cell=0x64f2d40),
]


def bound_semantics(im, all_rows):
    # The normalized helper skeleton is only a structural check; it is not a
    # compiled-code comparison or reconstructed-byte credit. Four named import
    # displacements are separately bound above. All other bytes remain exact.
    helper_template = bytes.fromhex(HELPER_TEMPLATE)
    helper_calls = (0x43, 0x86, 0xb6, 0xcb)
    for start in CALLERS:
        b = bytearray(im.read(start, 227))
        for off in helper_calls:
            need(b[off:off+2] == b'\xff\x15', 'expected helper import opcode')
            b[off+2:off+6] = bytes(4)
        need(bytes(b) == helper_template, 'helper predicates, widths, constants or branch layout changed')
    for start in (0x2e6b0c0, 0x2e7bdd0):
        # Complete reached lowtag2 branch: no input pointee read or call.
        need(im.read(start, 38).hex() == DROP_PREFIX, 'outlined packed-error drop branch changed')
    stages = []
    for s in STAGES:
        for key, symbol in [('enable','setsockopt'),('errno','__errno_location')]:
            at=s[key];need(im.read(at,2)==b'\xff\x15' and im.rel32_slot(at)==IMPORTS[symbol], 'caller named import')
        for key,dest in [('drop_call',s['drop_target']),('log_emit',0x5d004c0)]:
            at=s[key];need(im.read(at,1)==b'\xe8' and at+5+struct.unpack('<i',im.read(at+1,4))[0]==dest, 'caller selected direct edge')
        need(im.read(s['publish'],5)==bytes([0x48,0x89,0x44,0x24,s['error_rsp']]), 'error publication slot')
        need(im.read(s['drop_call']-5,5)==bytes([0x48,0x8b,0x7c,0x24,s['error_rsp']]), 'post-log error reloaded')
        need(all(v in all_rows for k,v in s.items() if k not in ('owner','error_rsp','drop_target','trace_cell')), 'stage instruction boundary')
        stages.append({k: (v if k=='error_rsp' else hex(v)) for k,v in s.items()})
    for va, value in CALLER_ANCHORS.items():
        need(im.read(va,len(bytes.fromhex(value))).hex()==value, 'caller field/order/predicate anchor changed')
    return stages

HELPER_TEMPLATE = '4156534883ec184989f689fb817e1000ca9a3b7439498b4608483dffffff7fb9ffffff7f480f42c8894c240c488d4c240c89dfbe06000000ba0400000041b804000000ff150000000083f8ff747d41817e2000ca9a3b7439498b4618483dffffff7fb9ffffff7f480f42c8894c2410488d4c241089dfbe06000000ba0500000041b804000000ff150000000083f8ff743a41833e01752a418b460489442414488d4c241489dfbe06000000ba0600000041b804000000ff150000000083f8ff740a31c04883c4185b415ec3ff15000000008b0048c1e0204883c8024883c4185b415ec3'
DROP_PREFIX = '415741564154535089f883e0038d48fe83f90272054885c0750c4883c4085b415c415e415fc3'
CALLER_ANCHORS = {48676661: '418b5620418b4e24418b4630498b7e38418b76403d00ca9a3b751d81fe00ca9a3b7519f6c2', 48676717: '4d8b462883e20189942490000000898c24940000004c89842498000000898424a00000004889bc24a800000089b424b0000000', 48676768: '8b6c243083fdff0f84cb04000085ed0f88ed040000c78424d0000000010000004c8dbc24d000000089efbe01000000ba090000004c89f941b804000000', 48676835: '83f8ff7416488db4249000000089efe829c5df024885c07512eb32', 48676868: '8b0048c1e0204883c8024889442468488b052e376703488b004885c00f8444', 48676912: '8b7c243083ffff0f843b040000410fb64671898424d00000004c8db424d0000000be06000000ba010000004c89f141b804000000ff15a6536703', 48677226: '0fb605cf6368030fb6c88d51ff83fa020f8396020000488b3d', 48677910: '85c90f8408fcffff488d3d0b616803ff153d33670384c00f854dfdffff', 48749557: '418b4424683d00ca9a3b0f849a020000498b4c246048898c248800000089842490000000c78424a000000000ca9a3bc784248000000000000000c78424a8000000010000004c8dac24a800000089dfbe01000000ba090000004c89e941b804000000', 48749661: '83f8ff0f840c010000488db4248000000089dfe89ba9de024885c00f8504010000e91c020000', 48749944: '8b0048c1e0204883c8024889442450488b05ba196603488b004883f8030f87fa000000', 48749979: '0fb605ae4f67030fb6c88d51ff83fa020f83dc000000', 48750219: 'eb0885c90f8534070000488b7c2450e831dfffff40f6c501', 48750239: '40f6c5010f84b900000041807c247600', 48752073: '488d3d70476703ff159211660384c00f85d3f7ffffe9b2f8ffff'}


def inspect(data, authenticate=True, check_body_hashes=True):
    if authenticate:
        need(len(data) == 105896032 and sha(data) == TARGET_SHA, 'whole target identity')
    im = Image(data); cies, frames = eh_frame_records(data, im.secs)
    body_records = []; all_rows = {}
    for start, (end, digest, role) in BODIES.items():
        need(im.fde_of(start) == (start, end), 'exact FDE extent')
        raw = im.read(start, end - start)
        if check_body_hashes:
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
    stages = bound_semantics(im, all_rows)
    references = []
    for va, i in all_rows.items():
        if i.mnemonic in ('call','jmp'):
            row = {'site':hex(va),'mnemonic':i.mnemonic,'operands':i.op_str}
            if i.operands[0].type == X86_OP_IMM:
                row['direct_target'] = hex(i.operands[0].imm)
            elif i.operands[0].type == X86_OP_MEM and i.operands[0].mem.base == X86_REG_RIP:
                slot=va+i.size+i.operands[0].mem.disp
                row['slot']=hex(slot);row['binding']=im.relocations.get(slot)
            else: row['boundary']='opaque runtime indirect target'
            references.append(row)
    level_slot=0x64df748;level_word=0x64fee60
    need(im.relative.get(level_slot)==level_word, 'initial level pointer binding')
    need(im.read(level_word,8)==struct.pack('<Q',5), 'initial level word')
    need(not any(level_word-7<=slot<level_word+8 for slot in im.relocations), 'level word relocation overlap')
    for row in locations:
        address=int(row['path_va'],16);length=len(bytes.fromhex(row.get('path_hex',''))) if 'path_hex' in row else len(row['path'].encode())
        need(not any(address-7<=slot<address+length for slot in im.relocations), 'Location path relocation overlap')
    return {'target_sha256': TARGET_SHA, 'stages':stages,'calls_and_jumps':references,
            'initial_level':{'slot':hex(level_slot),'target':hex(level_word),'raw_hex':im.read(level_word,8).hex(),'binding':im.relocations[level_slot],'runtime_constant_claimed':False},
            'bodies': body_records, 'helper_calls': helper_calls,
            'direct_calls': {hex(k): list(map(hex, v)) for k, v in calls.items()},
            'imports': {n: hex(s) for n, s in IMPORTS.items()}, 'relocations': relocation_rows, 'locations': locations, 'tracing_metadata': metadata,
            'scope': '454 complete helper bytes, 6106 caller-context bytes and 412 drop-context bytes; only keepalive continuation and reached lowtag2 drop path',
            'captured_execution': False, 'instruction_emulation': False}


def export(args):
    data = args.target.read_bytes(); result = inspect(data)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'records.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    commands = []
    for start, (end, _, _) in BODIES.items():
        for name, exe in [('gnu', args.objdump), ('llvm', args.llvm_objdump)]:
            argv = [str(exe), '-d', '--start-address=' + hex(start), '--stop-address=' + hex(end)]
            argv += ['-M', 'intel', '--insn-width=16'] if name == 'gnu' else ['--x86-asm-syntax=intel']
            argv.append(str(args.target))
            p = subprocess.run(argv, capture_output=True)
            p.stdout = p.stdout.replace(str(args.target).encode(), b'<authenticated-node115>')
            p.stderr = p.stderr.replace(str(args.target).encode(), b'<authenticated-node115>')
            need(p.returncode == 0, name + ' disassembler failed')
            prefix = f'{start:x}.{name}'
            (args.out / (prefix + '.stdout')).write_bytes(p.stdout)
            (args.out / (prefix + '.stderr')).write_bytes(p.stderr)
            commands.append({'argv': [s.replace(str(args.target), '<authenticated-node115>') for s in argv], 'exit': p.returncode,
                             'stdout_sha256': sha(p.stdout), 'stderr_sha256': sha(p.stderr)})
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
