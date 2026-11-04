#!/usr/bin/env python3
"""Authenticate node115 runtime entry/handoff and selected runtime initialization/exit boundaries.

Static decoding only. No captured instructions or system-call models are executed.
"""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-runtime-entry-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
RANGES = {
    'main': (0x2cef8f0, 0x2cef917),
    'runtime': (0x5c99970, 0x5c9a045),
    'callback_once': (0x292e230, 0x292e23d),
    'callback_shared': (0x292c5c0, 0x292c5cd),
    'callback_direct': (0x2c7bb70, 0x2c7bb75),
    'elf_entry_context': (0x1419300, 0x1419326),
}
PRIMARY = ('main', 'runtime', 'callback_once', 'callback_shared', 'callback_direct')
ANCHORS = {
    'entry_handoff': (0x1419318, '488d3dd1658d01ff1533610c05f4'),
    'main_arguments': (0x2cef8f0, '504889f14863d7488d05728afeff48890424488d353f1275034889e74531c0ff151b737f0359c3'),
    'thread_counter': (0x5c99987, '49c7c0e0fbffff644d8b084d85c97526488b05b266860066904883f8ff0f84ca0400004c8d4801f04c0fb10d9966860075e7644d8908488955b048894da848897da0488975984c890d14668600'),
    'poll_arguments_errno_dispatch': (0x5c99a10, 'be030000004889df31d241ffd683f8ff0f853101000041ffd78b0883f90474e083f9160f877f0100004989c6b8001840000fa3c80f836e010000'),
    'fcntl0_repair': (0x5c99a4a, '31ffbe0100000031c0ff15bfef8400bbffffffff83f8ff752741833e097521488d3dee5f7bfabe0200000031d231c0ff15492e850089c383f8ff0f842e010000'),
    'fcntl1_repair': (0x5c99a8a, 'bf01000000be0100000031c0ff157cef840083f8ff753941833e09753383fbff740d89dfff15342e850083f8ff7521488d3d9e5f7bfabe0200000031d231c0ff15f92d850089c383f8ff0f84de000000'),
    'fcntl2_repair': (0x5c99ada, 'bf02000000be0100000031c0ff152cef840083f8ff753741833e09753183fbff740d89dfff15e42d850083f8ff751f488d3d4e5f7bfabe0200000031d231c0ff15a92d850083f8ff0f8490000000'),
    'sigpipe_dispatch': (0x5c99b28, '4180fd030f87f2030000be01000000410fb6c5488d0da6ebcafa486304814801c8ffe0c605aa64860001e985000000'),
    'poll_success_repair': (0x5c99b57, '41beffffffff4c8b3d642d85004c8b257d2d850031db4889d84883f81874b2488d5808f6840506ffffff204889d874e94183feff74104489f741ffd483f8ff74054889d8ebd3488d3dba5e7bfabe0200000031d231c041ffd74189c683f8ff75e0ff155a298500'),
    'signal_and_page_size': (0x5c99bbe, '31f6c6053564860001bf0d000000ff15362c85004883f8ff0f84da020000bf1e000000ff15092485004889055a6486004c8b2553648600'),
    'pthread_query': (0x5c99c18, 'ff1502138500488db500ffffff4889c7ff15c22c850089c385c0410f94c77405e989000000'),
    'guard_calculation': (0x5c99c3d, '48c745b80000000048c745c800000000488dbd00ffffff488d75b8488d55c8ff15962c85008945c485c00f85890200004c8b6db8488dbd00ffffffff15222985008945c085c00f857a0200004d85e40f84b00200004c89e84c09e048c1e820740a4c89e831d249f7f4eb084489e831d241f7f44c89e04829d04885d2480f44c24901c54d89ee4d29e6'),
    'fault_handlers': (0x5c99d0d, '488d9500ffffffbf0b00000031f6ff15ef2785004883bd00ffffff00755e0fb6050e63860084c0752ac6050363860001bf01000000e809a10000488905ea62860085db750b4c89f74c89eee8f38b00004531ffc7458804000008488d0592a3000048898500ffffff488db500ffffffbf0b00000031d2ff1587278500488d9500ffffffbf0700000031f6ff15732785004883bd00ffffff00755c0fb6059262860084c07528c6058762860001bf01000000e88da000004889056e6286004584ff740b4c89f74c89eee8768b0000c7458804000008488d0518a3000048898500ffffff488db500ffffffbf0700000031d2ff150d278500'),
    'argv_callback_exit_guard': (0x5c99e03, '488b45b0488905f2618600488b45a8488905ef618600488b7da0488b4598ff50284863d88b05634f860085c0754dff15916184004889c131c0f0480fb10d3362860075154889d84881c4d80000005b415c415d415e415f5dc34839c80f847f000000488b1d942a85000f1f4000ffd3ebfc'),
    'cleanup_once_dispatch': (0x5c99e7e, 'c645c801488d45c848898500ffffff488d3dfc4e8600488d0d1d8d82004c8d05b6998200488d9500ffffff31f6ff153f5b8400e97bffffff'),
    'callback_once': (0x292e230, '50488b3fe837d9340031c059c3'),
    'callback_shared': (0x292c5c0, '50488b3fe8a7f5340031c059c3'),
    'callback_direct': (0x2c7bb70, '50ffd758c3'),
}

def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'duplicate JSON key')
    return result


class Image:
    def __init__(self, data):
        self.data = bytes(data)
        self.sections = sections(self.data)
        self.by_name = {s['name']: s for s in self.sections}
        require(len(self.by_name) == len(self.sections), 'duplicate section name')
        require(struct.unpack_from('<H', self.data, 18)[0] == 62, 'not x86-64')
        self.cies, self.fdes = eh_frame_records(self.data, self.sections)
        self.fdes.sort(key=lambda f: f['start'])
        self.starts = [f['start'] for f in self.fdes]
        require(len(set(self.starts)) == len(self.starts), 'duplicate FDE start')
        self.relocations = {}
        for sec in self.sections:
            if sec['type'] != 4:
                continue
            require(sec['size'] % 24 == 0, 'partial RELA')
            for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                dst, info, addend = struct.unpack_from('<QQq', self.data, off)
                require(dst not in self.relocations, 'duplicate relocation destination')
                self.relocations[dst] = dict(slot=hex(dst), kind=info & 0xffffffff,
                    symbol_index=info >> 32, addend=addend, file_offset=hex(off),
                    record_hex=self.data[off:off + 24].hex())
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def offset(self, va, length):
        require(type(length) is int and length > 0, 'nonpositive read')
        hits = [s['offset'] + va - s['address'] for s in self.sections
                if s['type'] != 8 and s['address'] <= va and va + length <= s['address'] + s['size']]
        require(len(hits) == 1, f'unmapped/ambiguous read {va:#x}+{length}')
        return hits[0]

    def read(self, va, length):
        off = self.offset(va, length)
        return self.data[off:off + length]

    def owner(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index >= 0 and va < self.fdes[index]['end']:
            return self.fdes[index]
        return None

    def decode(self, start, end):
        raw = self.read(start, end - start)
        decoded = list(self.md.disasm(raw, start))
        require(decoded and sum(i.size for i in decoded) == len(raw), 'incomplete decode')
        starts = {i.address for i in decoded}
        for ins in decoded:
            if ins.group(CS_GRP_JUMP) and ins.operands[0].type == X86_OP_IMM:
                target = ins.operands[0].imm
                require(not start <= target < end or target in starts, 'branch inside instruction')
        return decoded

    def binding(self, slot):
        row = self.relocations.get(slot)
        if row is None:
            return None
        row = dict(row)
        if row['symbol_index']:
            sym = self.by_name['.dynsym']
            index = row['symbol_index']
            require(index * 24 + 24 <= sym['size'], 'dynsym out of bounds')
            name = struct.unpack_from('<I', self.data, sym['offset'] + index * 24)[0]
            strings = self.by_name['.dynstr']
            require(name < strings['size'], 'dynstr out of bounds')
            off = strings['offset'] + name
            end = self.data.find(b'\0', off, strings['offset'] + strings['size'])
            require(end >= 0, 'unterminated dynsym name')
            row['symbol'] = self.data[off:end].decode('ascii')
        elif row['kind'] == 8:
            row['target'] = hex(row['addend'])
            owner = self.owner(row['addend'])
            if owner:
                row['target_fde'] = [hex(owner['start']), hex(owner['end'])]
        return row


def instruction(ins):
    return {'va': hex(ins.address), 'bytes': bytes(ins.bytes).hex(),
            'mnemonic': ins.mnemonic, 'operands': ins.op_str}


def exception_sites(image, frame, starts):
    """Read the bounded LSDA header/call-site table; action semantics stay open."""
    va = frame['lsda']
    if va is None:
        return None
    sec = image.by_name['.gcc_except_table']
    require(sec['address'] <= va < sec['address'] + sec['size'], 'LSDA outside section')
    begin = image.offset(va, 1)
    pos, limit, data = begin, sec['offset'] + sec['size'], image.data
    require(data[pos] == 0xff, 'unsupported LPStart encoding')
    typ = data[pos + 1]
    pos += 2
    type_base = None
    if typ == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
        require(type_base <= limit, 'LSDA type table outside section')
    else:
        require(typ == 0xff, 'unsupported type encoding')
    require(data[pos] == 1, 'unsupported call-site encoding')
    size, pos = uleb(data, pos + 1, limit)
    end = pos + size
    require(end <= limit, 'truncated call-site table')
    rows, previous = [], frame['start']
    while pos < end:
        first, values = pos, []
        for _ in range(4):
            value, pos = uleb(data, pos, end)
            values.append(value)
        offset, length, landing, action = values
        start = frame['start'] + offset
        pad = frame['start'] + landing if landing else None
        require(previous <= start <= start + length <= frame['end'], 'LSDA interval invalid')
        require(pad is None or pad in starts, 'landing pad not an instruction')
        previous = start + length
        rows.append({'start': hex(start), 'end_exclusive': hex(start + length),
                     'landing_pad': hex(pad) if pad else None, 'action_index': action,
                     'hex': data[first:pos].hex()})
    require(pos == end, 'LSDA table overrun')
    return {'va': hex(va), 'header_and_call_sites_hex': data[begin:end].hex(),
            'type_encoding': typ, 'type_table_file_offset': hex(type_base) if type_base else None,
            'action_records_decoded': False, 'rows': rows}


def mapped_data(image, address, size):
    """Distinguish file bytes from the actual writable PT_LOAD zero tail."""
    data = image.data
    off = struct.unpack_from('<Q', data, 32)[0]
    entsize, count = struct.unpack_from('<HH', data, 54)
    require(entsize == 56, 'program header width')
    hits = []
    for i in range(count):
        p = struct.unpack_from('<IIQQQQQQ', data, off + i * entsize)
        if p[0] == 1 and p[3] <= address and address + size <= p[3] + p[6]:
            hits.append(p)
    require(len(hits) == 1, 'ambiguous/outside PT_LOAD data')
    p = hits[0]
    if address + size <= p[3] + p[5]:
        pos = p[2] + address - p[3]
        raw = data[pos:pos + size]
        require(len(raw) == size, 'file data truncated')
        return {'kind': 'file', 'file_offset': hex(pos), 'hex': raw.hex()}
    require(address >= p[3] + p[5] and p[1] & 2, 'partial or nonwritable zero tail')
    return {'kind': 'writable_PT_LOAD_zero_tail', 'hex': bytes(size).hex(),
            'zero_start': hex(p[3] + p[5]), 'zero_end': hex(p[3] + p[6])}


def unique_slot(image, slot, kind, target):
    require(not any(slot - 7 <= x < slot + 8 and x != slot for x in image.relocations),
            'overlapping slot writer')
    b = image.binding(slot)
    require(b is not None and b['kind'] == kind, 'missing/wrong relocation kind')
    if kind == 8:
        require(b['symbol_index'] == 0 and b['addend'] == target, 'RELATIVE target mismatch')
    else:
        require(b['symbol_index'] > 0 and b.get('symbol') == target and b['addend'] == 0,
                'named import mismatch')
    return b


def no_writers(image, start, size):
    require(not any(start - 7 <= slot < start + size for slot in image.relocations),
            'unexpected relocation overlapping selected data')


def extract(image):
    require(struct.unpack_from('<Q', image.data, 24)[0] == 0x1419300, 'ELF entry changed')
    comment = image.by_name['.comment']
    comment_raw = image.data[comment['offset']:comment['offset'] + comment['size']]
    require(b'rustc version 1.95.0 (59807616e 2026-04-14)\0' in comment_raw, 'compiler comment changed')
    bodies, decoded, exceptions = [], {}, {}
    for name, (start, end) in RANGES.items():
        overlaps = [f for f in image.fdes if f['start'] < end and start < f['end']]
        require(len(overlaps) == 1 and (overlaps[0]['start'], overlaps[0]['end']) == (start, end),
                'unique complete FDE extent changed')
        f = overlaps[0]
        ins = image.decode(start, end); decoded[name] = ins
        row = {'name': name, 'role': 'primary' if name in PRIMARY else 'context only',
               'start': hex(start), 'end_exclusive': hex(end), 'bytes': end-start,
               'sha256': digest(image.read(start, end-start)), 'instructions': len(ins)}
        for key in ('fde', 'cie'):
            va = f[key]; n = struct.unpack('<I', image.read(va, 4))[0] + 4
            row[key+'_va'] = hex(va); row[key+'_hex'] = image.read(va, n).hex()
        bodies.append(row)
        exceptions[name] = exception_sites(image, f, {i.address for i in ins})
    for name, (va, expected) in ANCHORS.items():
        require(image.read(va, len(bytes.fromhex(expected))).hex() == expected,
                'semantic anchor changed: '+name)
    relative = {0x64e6c30: 0x5c99970, 0x6440b60: 0x292e230,
                0x6440b68: 0x292c5c0, 0x6440b70: 0x292c5c0,
                0x64df9f0: 0x5c87d50}
    imports = {0x64df458:'__libc_start_main', 0x64e2320:'poll', 0x64dffc8:'__errno_location',
        0x64e8a18:'fcntl', 0x64ec8c8:'open64', 0x64ec8e8:'dup', 0x64ec518:'abort',
        0x64ec808:'signal', 0x64ebff0:'sysconf', 0x64eaf20:'pthread_self',
        0x64ec8f0:'pthread_getattr_np', 0x64ec8f8:'pthread_attr_getstack',
        0x64ec5a0:'pthread_attr_destroy', 0x64ec510:'sigaction', 0x64ec900:'pause'}
    bindings = [unique_slot(image, s, 8, t) for s,t in relative.items()]
    bindings += [unique_slot(image, s, 6, t) for s,t in imports.items()]
    header = image.read(0x6440b48,24)
    require(header == struct.pack('<QQQ',0,8,8), 'callback vtable header mismatch')
    require(not any(0x6440b48-7 <= s < 0x6440b60 for s in image.relocations),
            'unexpected vtable header writer')
    no_writers(image, 0x9486e8, 16)
    table = image.read(0x9486e8,16)
    destinations = [0x9486e8+x for x in struct.unpack('<4i',table)]
    require(destinations == [0x5c99bc7,0x5c99b4b,0x5c99bc0,0x5c99bbe], 'sigpipe jump table changed')
    literals = {'dev_null':(0x44fa5e,b'/dev/null\0'),
        'pollfd_1_2':(0x453950,struct.pack('<QQ',1,2))}
    literal_rows=[]
    for name,(va,raw) in literals.items():
        no_writers(image, va, len(raw))
        require(image.read(va,len(raw)) == raw,'literal mismatch: '+name)
        literal_rows.append({'name':name,'va':hex(va),'hex':raw.hex()})
    calls, refs = [], []
    for name, insns in decoded.items():
        for ins in insns:
            if ins.mnemonic in ('call','jmp'):
                row={'owner':name,**instruction(ins)}; op=ins.operands[0]
                if op.type == X86_OP_IMM:
                    row['direct_target']=hex(op.imm)
                    f=image.owner(op.imm)
                    if f: row['target_fde']=[hex(f['start']),hex(f['end'])]
                elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    slot=ins.address+ins.size+op.mem.disp
                    row['slot']=hex(slot); row['binding']=image.binding(slot)
                else:
                    row['resolution']='register/memory indirect; selected reaching definitions in CONTRACT.md'
                if ins.mnemonic == 'call' and exceptions[name]:
                    hits=[r for r in exceptions[name]['rows'] if int(r['start'],16)<=ins.address<int(r['end_exclusive'],16)]
                    require(len(hits)<=1,'ambiguous exception call interval')
                    row['exception_interval']=hits[0] if hits else None
                calls.append(row)
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    address=ins.address+ins.size+op.mem.disp
                    refs.append({'owner':name,'site':hex(ins.address),'referent':hex(address),
                        'operand_width':op.size,'data':mapped_data(image,address,max(1,op.size)),
                        'binding':image.binding(address)})
    globals_={}
    for name,va,size in [('thread_counter',0x6500050,8),('main_thread',0x64fffe8,8),
            ('sigpipe_explicit',0x64ffffc,1),('argc',0x6500000,8),('argv',0x6500008,8),
            ('exit_owner',0x6500078,8),('cleanup_once',0x64fed90,4)]:
        no_writers(image, va, size)
        globals_[name]={'va':hex(va),'size':size,**mapped_data(image,va,size)}
    naming=[image.binding(s) for s,r in image.relocations.items()
            if r['kind']==8 and r['addend'] in {RANGES[n][0] for n in PRIMARY}]
    return {'target_sha256':SHA256,'primary_bytes':sum(b['bytes'] for b in bodies if b['role']=='primary'),
        'coordinate_system':'linked ELF virtual address','bodies':bodies,
        'elf_entry':'0x1419300', 'comment_hex':comment_raw.hex(),
        'compiler_string_is_not_build_provenance':True,
        'instructions':{n:[instruction(i) for i in v] for n,v in decoded.items()},
        'semantic_anchors':{n:{'va':hex(a),'hex':h} for n,(a,h) in ANCHORS.items()},
        'selected_bindings':bindings,'vtable':{'va':'0x6440b48','bytes':48,
            'raw_hex':image.read(0x6440b48,48).hex(),'header_hex':header.hex()},
        'sigpipe_table':{'va':'0x9486e8','raw_hex':table.hex(),'targets':[hex(x) for x in destinations]},
        'literals':literal_rows,'globals':globals_,'calls_and_jumps':calls,'rip_references':refs,
        'exception_tables':exceptions,'primary_naming_relocations':naming,
        'relocations_scanned':len(image.relocations),'captured_binary_executed':False,
        'instruction_emulation':False,'whole_runtime_equivalence':False}


def analyze(data):
    require(len(data)==105896032 and digest(data)==SHA256,'node115 identity mismatch')
    return extract(Image(data))


def native_bytes(text, start, end):
    """Only collect actual disassembler instruction byte columns; no text emulation."""
    rows = []
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)', line)
        if m and start <= int(m[1], 16) < end:
            raw = bytes.fromhex(m[2])
            rows.append((int(m[1], 16), raw))
    cursor = start
    for va, raw in rows:
        require(va == cursor and raw, 'native disassembly gap/overlap')
        cursor += len(raw)
    require(cursor == end, 'native disassembly incomplete')
    # Apple LLVM prints LOCK as a standalone byte row. Join only an exact F0
    # row and its contiguous following instruction, preserving every byte.
    merged = []
    i = 0
    while i < len(rows):
        va, raw = rows[i]
        if raw == b'\xf0':
            require(i + 1 < len(rows), 'orphan LOCK prefix')
            following, tail = rows[i + 1]
            require(following == va + 1, 'noncontiguous LOCK prefix')
            joined = raw + tail
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            decoded = list(md.disasm(joined, va))
            require(len(decoded) == 1 and decoded[0].size == len(joined)
                    and decoded[0].mnemonic.startswith('lock '), 'invalid LOCK grouping')
            raw = joined
            i += 1
        merged.append((va, raw))
        i += 1
    return merged


def export(binary, output):
    data = Path(binary).read_bytes()
    report = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    gnu = os.environ.get('GNU_OBJDUMP', 'objdump')
    llvm = os.environ.get('LLVM_OBJDUMP', 'llvm-objdump')
    exports, commands = {}, []
    # Both providers consume exactly the already authenticated byte snapshot.
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115'
        snapshot.write_bytes(data)
        for label, exe in [('gnu', gnu), ('llvm', llvm)]:
            for name, (start, end) in RANGES.items():
                args = [exe, '-d', '--start-address=' + hex(start), '--stop-address=' + hex(end)]
                args += ['-M', 'intel', '--insn-width=16'] if label == 'gnu' else ['--x86-asm-syntax=intel']
                args.append(str(snapshot))
                process = subprocess.run(args, capture_output=True)
                stdout = process.stdout.replace(str(snapshot).encode(), b'<authenticated-node115>')
                stderr = process.stderr.replace(str(snapshot).encode(), b'<authenticated-node115>')
                (output / f'{name}.{label}.txt').write_bytes(stdout)
                (output / f'{name}.{label}.stderr').write_bytes(stderr)
                require(process.returncode == 0, f'{label} export failed: {stderr.decode(errors="replace")}')
                rows = native_bytes(stdout.decode(), start, end)
                expected = [(int(i['va'], 16), bytes.fromhex(i['bytes'])) for i in report['instructions'][name]]
                require(rows == expected, f'{label} {name} instruction boundaries/bytes disagree')
                exports[f'{name}.{label}.txt'] = stdout
                commands.append({'provider': label, 'name': name,
                    'argv': [str(x).replace(str(snapshot), '<authenticated-node115>') for x in args],
                    'exit_code': process.returncode, 'stdout_sha256': digest(stdout),
                    'stderr_hex': stderr.hex(), 'instruction_rows': len(rows),
                    'lock_prefix_presentation_only': True})
    for name, value in exports.items():
        (output / name).write_bytes(value)
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'native-commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    return report



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = export(args.binary, args.output) if args.output else analyze(args.binary.read_bytes())
    print(json.dumps({'primary_bytes': report['primary_bytes'], 'fdes': len(report['bodies']),
                      'captured_binary_executed': False}))

if __name__ == '__main__': main()
