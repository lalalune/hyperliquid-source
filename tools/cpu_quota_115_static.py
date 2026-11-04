#!/usr/bin/env python3
"""Bind node115 quota conversion, logical count and CPU-cache publication.

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
PACKET = ROOT / 'research/work-items/RE-002-cpu-quota-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
RANGES = {'initializer': (96108880, 96115346), 'once_adapter': (96115360, 96115378), 'logical_getter': (96116160, 96116472), 'ceil_context': (104794336, 104794455)}
PRIMARY = ("initializer", "once_adapter", "logical_getter")
BODY_SHA = {'initializer': '5ff2cd4a0bd20ef0f61cb4b121ee2a615aed6ba69cc453df9a265fecf462a542', 'once_adapter': 'bc2395e15c31b9263eb33e7e963124562e3642aed0347cfe7402eddec57be203', 'logical_getter': 'b3003bed1f9219847b3e5a01145691ce8772966d5a4d7173897be1ea58024ea8', 'ceil_context': 'b30c110bcf2fffcb0eb2dd79b997445de60b6a22c6f081837d2e553668ab7257'}
ANCHORS = {'quota_v1_v2_dispatch': (96112953, '4c39fd0f84dcf0ffff4901def6442407017439488d0dcc5cd9fa488dbc24f000000041b8070000004c89ee4c89f2e8140f0000488b9c24f00000004c39fb0f85f000000041b701e95e040000488d1524a08afab9100000004c89ef4c89f6e8640d000041b7014883f8010f858b0100004989d4488d15735cd9fab9110000004c89ef4c89f6e83d0d00004883f8010f85160400004885d274ab'), 'binary64_conversion_and_division': (96113106, '66490f6eccf30f7e1531808afa660f62ca660f281d856f8afa660f5ccb660f28c1660f15c1f20f58c166480f6eca660f62ca660f5ccb660f28d1660f15d1f20f58d1f20f5ec2ff153ae69300'), 'saturating_cast': (96113182, 'f2480f2cc04889c148c1f93f660f28c8f20f5c0d2a018bfaf2480f2cd14821ca4809c24531ff660f57c9660f2ec1b800000000480f43c2660f2e05fbfa8afa48c7c3ffffffff480f46d8e976030000'), 'publication_guard': (96114166, '4885db0f94c04108c70f8519ecffff'), 'affinity_arguments': (96114181, '660f57c0660f29842460010000660f29842450010000660f29842440010000660f29842430010000660f29842420010000660f29842410010000660f29842400010000660f298424f00000004531f6488d9424f0000000be8000000031ffff157f299400'), 'affinity_fallback': (96114281, '85c0741abf54000000ff15782994004883f802b901000000480f4dc8eb59'), 'affinity_bit_loop': (96114311, '31c0eb0f41ffc64883c002483d0004000074434889c148c1e906488b94ccf000000089c183e13e480fa3ca73094183feff741641ffc689c180e13e48d3eaf6c20274c44183feff75bb488d3d31369100ff15435e93004489f1'), 'minimum_and_publication': (96114400, '4839d9480f42d948871d1a689500e92bebffff'), 'once_adapter': (96115360, '50488b07488904244889e7e8a0e6ffff58c3'), 'getter_once_and_cache': (96116160, '534881ec900000008b05e241950085c07515488b052f6195004885c074464881c4900000005bc3c644240f01488d44240f4889442410488d3db3419500488d0dc42e91004c8d05152f9100488d54241031f6ff15d85b9300488b05e96095004885c075ba'), 'getter_fallback': (96116260, '0f57c00f298424800000000f294424700f294424600f294424500f294424400f294424300f294424200f2944241031db488d542410be8000000031ffff158221940085c07424bf54000000ff157b2194004889c14883f802b801000000480f4dc14881c4900000005bc331c0eb1a66666666662e0f1f8400000000004883c002483d0004000074344889c148c1e906488b54cc1089c183e13e480fa3ca730783fbff7423ffc389c180e13e48d3eaf6c20274c983fbff740fffc3ebc089d84881c4900000005bc3488d3d162e9100ff1528569300'), 'ceil_complete': (104794336, '66480f7ec04889c148c1e93481e1ff07000081f932040000774381f9fe030000763c81c101fcffff48baffffffffffff0f0048d3ea4885c2742389c931f64885c0480f48d648be000000000000f0ff48d3fe4801c24821d666480f6ec6c34885c0780b74f8f20f1005638906fac3f20f1005028b06fac3')}

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


def extract(image):
    bodies, decoded, exceptions = [], {}, {}
    for name, (start, end) in RANGES.items():
        overlap = [f for f in image.fdes if f['start'] < end and start < f['end']]
        require(len(overlap) == 1 and (overlap[0]['start'], overlap[0]['end']) == (start, end), 'complete FDE mismatch')
        no_writers(image, start, end-start)
        frame = overlap[0]; ins = image.decode(start, end); decoded[name] = ins
        text = image.by_name['.text']
        require(text['flags'] & 4 and text['address'] <= start < end <= text['address'] + text['size'], 'body outside executable text')
        row = dict(name=name, start=hex(start), end_exclusive=hex(end), bytes=end-start, sha256=digest(image.read(start,end-start)), instructions=len(ins), role='primary' if name in PRIMARY else 'ceil dependency context')
        for key in ('fde','cie'):
            va=frame[key]; count=4+struct.unpack('<I',image.read(va,4))[0]
            row[key+'_va']=hex(va);row[key+'_hex']=image.read(va,count).hex()
        bodies.append(row)
        exceptions[name]=exception_sites(image,frame,{i.address for i in ins})
    for name,(va,raw) in ANCHORS.items():
        require(image.read(va,len(bytes.fromhex(raw))).hex()==raw,'semantic anchor changed: '+name)
    relative={0x64bcce0:0x5ba9aa0,0x64bcce8:0x5ba8150,0x64e7858:0x63f08e0,0x64df9f0:0x5c87d50}
    imports={0x64ebfe8:'sched_getaffinity',0x64ebff0:'sysconf'}
    bindings=[unique_slot(image,a,8,v)for a,v in relative.items()]+[unique_slot(image,a,6,v)for a,v in imports.items()]
    constants={0x451210:'0000304300003045',0x450170:'00000000000030430000000000003045',0x459360:'000000000000e043',0x458d58:'ffffffffffffef43',0x4592b0:'000000000000f03f',0x459458:'0000000000000080',0x64bccc8:'000000000000000008000000000000000800000000000000'}
    literals={0x93edfa:b'/proc/self/cgroup',0x93ee0b:b'/proc/self/mountinfo',0x93ee1f:b'cpu.max',0x4531b0:b'cpu.cfs_quota_us',0x93ee26:b'cpu.cfs_period_us'}
    for a,h in constants.items():
        raw=bytes.fromhex(h);no_writers(image,a,len(raw));require(image.read(a,len(raw))==raw,'constant or vtable changed')
    for a,raw in literals.items():
        no_writers(image,a,len(raw));require(image.read(a,len(raw))==raw,'literal changed')
    calls=[];references=[]
    for name,insns in decoded.items():
        for ins in insns:
            if ins.mnemonic=='call':
                row={'owner':name,**instruction(ins)};op=ins.operands[0]
                if op.type==X86_OP_IMM:
                    row['target']=hex(op.imm);f=image.owner(op.imm)
                    row['target_fde']=[hex(f['start']),hex(f['end'])]if f else None
                elif op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    slot=ins.address+ins.size+op.mem.disp;row['slot']=hex(slot);row['binding']=image.binding(slot)
                else:row['resolution']='register/memory-indirect boundary'
                calls.append(row)
            for op in ins.operands:
                if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                    a=ins.address+ins.size+op.mem.disp
                    references.append({'owner':name,'site':hex(ins.address),'referent':hex(a),'operand_width':op.size,'binding':image.binding(a)})
    globals_={}
    for name,a,size in [('cpu_cache',0x64fff08,8),('once_state',0x64fdfb0,4)]:
        no_writers(image,a,size);globals_[name]={'va':hex(a),'bytes':size,**mapped_data(image,a,size)}
    require(globals_['cpu_cache']['kind']=='writable_PT_LOAD_zero_tail','cache not loader zero tail')
    require(globals_['once_state']['kind']=='file' and globals_['once_state']['hex']=='03000000','once initial file word changed')
    for row in bodies:require(row['sha256']==BODY_SHA[row['name']],'whole body digest changed')
    return dict(target_sha256=SHA256,primary_bytes=sum(b['bytes']for b in bodies if b['name']in PRIMARY),bodies=bodies,instructions={k:[instruction(i)for i in v]for k,v in decoded.items()},exception_tables=exceptions,calls=calls,rip_references=references,selected_bindings=bindings,globals=globals_,constants={hex(a):h for a,h in constants.items()},literals={hex(a):raw.decode()for a,raw in literals.items()},relocations_scanned=len(image.relocations),captured_binary_executed=False,instruction_emulation=False,whole_runtime_equivalence=False)

def analyze(data):
    require(len(data)==105896032 and digest(data)==SHA256,'node115 identity mismatch')
    return extract(Image(data))


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
