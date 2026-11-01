#!/usr/bin/env python3
"""Qualify node94 sort scratch-wrapper bytes; no target instruction evaluation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents, uleb

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET = ROOT / 'artifacts/node/94/hl-node'
WRAPPER = (0x4486d10, 0x4486e1d)
INNER = (0x4dbd490, 0x4dbdb5e)
ERROR = (0x1346068, 0x134607d)
COLLECTOR = (0x4450210, 0x44503d3)
MASK = 2**64 - 1
PINS = (
    ('4096-byte local frame', 0x4486d19, '4881ec00100000'),
    ('third argument preserved', 0x4486d20, '4989d6'),
    ('ceiling half', 0x4486d23, '4889f148d1e94889f04829c8'),
    ('million minimum and ceiling maximum', 0x4486d2f, '4881fe40420f00bb40420f00480f42de4839c3480f46d8'),
    ('heap starts at 513', 0x4486d46, '4881fb01020000722e'),
    ('eight-byte element scale', 0x4486d4f, '4c8d24dd00000000'),
    ('overflow high guard', 0x4486d57, '48c1e83d0f95c0'),
    ('maximum signed layout', 0x4486d5e, '48b9f8ffffffffffff7f4939cc0f97c108c17415'),
    ('layout rejection arguments', 0x4486d72, '31ff4c89e6ff153b722e01'),
    ('stack scratch and capacity', 0x4486d7d, '4989e7b900020000eb20'),
    ('heap allocation preservation', 0x4486d87, '4989ff4c89e74989f5ff1542722e014c89ff4c89ee4989c74889d94885c07442'),
    ('small flag and all forwarded arguments', 0x4486da7, '4531c04883fe41410f92c04c89fa4d89f1e8d3669300'),
    ('normal cleanup uses original capacity', 0x4486dbd, '4881fb00020000761248c1e3034c89ff4889de31d2ff1538722e01'),
    ('normal frame restore and return', 0x4486dd8, '4881c4001000005b415c415d415e415fc3'),
    ('null allocation error arguments', 0x4486de9, 'bf080000004c89e6ff15c1712e01'),
    ('landing pad exception and cleanup gate', 0x4486df7, '4989c64881fb000200007612'),
    ('unwind cleanup and resume', 0x4486e03, '48c1e3034c89ff4889de31d2ff15fb712e014c89f7e8f3921d01'),
    ('collector count from span', 0x4450275, '49c1ee05'),
    ('collector delegation threshold', 0x445033f, '4981fda0020000735c'),
    ('collector selected call and discarded result', 0x44503a4, '488d5424084c89ff4c89f6ff159b4b3201e94effffff'),
    ('collector overwrites returned RAX', 0x4450308, '4b8d04f7'),
    ('shared error entry zero/nonzero dispatch', 0x1346068, '554889e54885ff7506ff1549804204ff15a37f4204'),
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def render(value):
    return json.dumps(value, sort_keys=True, indent=2) + '\n'


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        require(len({s['name'] for s in self.sections}) == len(self.sections), 'duplicate section names')

    def offset(self, va, count):
        matches = [s for s in self.sections if s['type'] != 8 and s['address'] <= va and va + count <= s['address'] + s['size']]
        require(count > 0 and len(matches) == 1, f'ambiguous file mapping {va:#x}+{count}')
        return matches[0]['offset'] + va - matches[0]['address']

    def read(self, va, count):
        pos = self.offset(va, count)
        return bytes(self.data[pos:pos + count])

    def window(self, start, end):
        raw = self.read(start, end - start)
        return dict(start=hex(start), end=hex(end), file_offset=hex(self.offset(start, len(raw))),
                    bytes=len(raw), raw_hex=raw.hex(), sha256=sha(raw))

    def record(self, va):
        return self.window(va, va + 4 + struct.unpack('<I', self.read(va, 4))[0])


def local_obligations(image):
    for name, va, expected in PINS:
        require(image.read(va, len(bytes.fromhex(expected))) == bytes.fromhex(expected), 'operand/control mismatch: ' + name)


def qualify(extents, start, end):
    rows = [r for r in extents if r['start'] == start]
    require(len(rows) == 1 and rows[0]['end'] == end, f'FDE boundary mismatch {start:#x}')
    return rows[0]


def native(image, start, end, llvm):
    commands = [['objdump', '-d', '-M', 'intel', '--insn-width=16'],
                [llvm, '-d', '--x86-asm-syntax=intel', '--print-imm-hex']]
    streams, partitions = [], []
    for command in commands:
        command += [f'--start-address={start}', f'--stop-address={end}', str(TARGET)]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        stream = result.stdout.replace(str(TARGET), '<authenticated-node94>')
        rows = []
        for line in stream.splitlines():
            match = re.match(r'^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}[ \t]+)+)(.*)$', line)
            if match:
                rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()))
        pos = start
        for va, raw, _ in rows:
            require(va == pos, f'incomplete instruction partition at {pos:#x}')
            pos += len(raw)
        require(pos == end and b''.join(r[1] for r in rows) == image.read(start, end-start), 'native byte mismatch')
        streams.append(stream)
        partitions.append(rows)
    require([(a,b) for a,b,_ in partitions[0]] == [(a,b) for a,b,_ in partitions[1]], 'native boundary mismatch')
    return streams, partitions[0]


def graph(rows):
    starts = {r[0] for r in rows}
    nodes, calls = [], []
    for va, raw, text in rows:
        after, destination = va + len(raw), None
        if raw[0] in (0xe8, 0xe9):
            destination = after + struct.unpack('<i', raw[1:5])[0]
        elif raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f:
            destination = after + struct.unpack('<b', raw[1:2])[0]
        elif raw[:1] == b'\x0f' and 0x80 <= raw[1] <= 0x8f:
            destination = after + struct.unpack('<i', raw[2:6])[0]
        conditional = 0x70 <= raw[0] <= 0x7f or (raw[:1] == b'\x0f' and 0x80 <= raw[1] <= 0x8f)
        successors = [hex(after)]
        if conditional or raw[0] in (0xe9, 0xeb):
            require(destination in starts, f'branch targets outside wrapper/instruction start: {va:#x}')
            successors = [hex(destination)] + ([hex(after)] if conditional else [])
        if raw == b'\xc3':
            successors = []
        if raw[0] == 0xe8:
            calls.append(dict(site=hex(va), target=hex(destination), kind='direct', raw_hex=raw.hex()))
        elif raw[:2] == b'\xff\x15':
            calls.append(dict(site=hex(va), slot=hex(after + struct.unpack('<i', raw[2:6])[0]), kind='indirect', raw_hex=raw.hex()))
        nodes.append(dict(site=hex(va), raw_hex=raw.hex(), native=text, successors=successors,
                          call_fallthrough_requires_normal_return=raw[0] == 0xe8 or raw[:2] == b'\xff\x15'))
    return nodes, calls


def lsda(image):
    raw = image.read(0xb42000, 20)
    require(raw[:4] == bytes.fromhex('ffff0110'), 'LSDA header mismatch')
    pos, rows = 4, []
    while pos < len(raw):
        values = []
        for _ in range(4):
            value, pos = uleb(raw, pos, len(raw)); values.append(value)
        start, length, pad, action = values
        rows.append(dict(start=hex(WRAPPER[0]+start), end=hex(WRAPPER[0]+start+length),
                         landing_pad=hex(WRAPPER[0]+pad) if pad else None, action=action))
    expected = [dict(start='0x4486d10',end='0x4486db2',landing_pad=None,action=0),
                dict(start='0x4486db2',end='0x4486dbd',landing_pad='0x4486df7',action=0),
                dict(start='0x4486dbd',end='0x4486e1d',landing_pad=None,action=0)]
    require(pos == 20 and rows == expected, 'LSDA cleanup range mismatch')
    require(0x4486db2 <= 0x4486db8 < 0x4486dbd and 0x4486db8 + 5 == 0x4486dbd, 'inner call not contained')
    return dict(record=image.window(0xb42000,0xb42014), rows=rows,
                encodings='LPStart omitted, type table omitted, ULEB128 call-site entries; action zero is cleanup when landing pad nonzero')


def scratch_relation(n):
    """Independently authored numeric projection, never an instruction evaluator."""
    require(isinstance(n, int) and 0 <= n <= MASK, 'count outside u64')
    half_up = n - (n >> 1)
    selected = n if n < 1_000_000 else 1_000_000
    selected = half_up if selected <= half_up else selected
    if selected < 513:
        return dict(selected=selected, path='stack', capacity=512, allocation_bytes=0, small_flag=int(n < 65))
    wrapped = (selected * 8) & MASK
    bad = (half_up >> 61) != 0 or wrapped > 0x7ffffffffffffff8
    return dict(selected=selected, path='layout-dispatch' if bad else 'heap', capacity=selected,
                allocation_bytes=wrapped, small_flag=int(n < 65))


def oracle(n):
    if n <= 512:
        return dict(selected=n, path='stack', capacity=512, allocation_bytes=0, small_flag=int(n <= 64))
    if n <= 1_000_000:
        selected = n
    elif n <= 2_000_000:
        selected = 1_000_000
    else:
        selected = (n + 1) // 2
    return dict(selected=selected, path='heap' if n <= 2**61-2 else 'layout-dispatch', capacity=selected,
                allocation_bytes=(8 * selected) % 2**64, small_flag=0)


def control_counts():
    values = set(range(4097))
    for center in [21,64,65,512,513,1_000_000,2_000_000,2**61-2,2**61-1,2**62-1,MASK]:
        values.update(n for n in range(center-3,center+4) if 0<=n<=MASK)
    for bit in range(64):
        values.update(n for n in range(2**bit-2,2**bit+3) if 0<=n<=MASK)
    state = 0x916ca5b2f4073d61
    for _ in range(512):
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK
        values.add(state)
    return sorted(values)


def synthetic():
    transcript = []
    for n in control_counts():
        got, expected = scratch_relation(n), oracle(n)
        require(got == expected, f'arithmetic oracle mismatch at {n}')
        if got['path'] != 'layout-dispatch':
            require(got['capacity'] >= (n+1)//2, 'scratch below ceiling half')
            require(got['allocation_bytes'] <= 0x7ffffffffffffff8, 'accepted heap layout too large')
        transcript.append([n,got])
    samples = [r for r in transcript if r[0] in [0,1,21,64,65,512,513,999999,1000000,1000001,1999999,2000000,2000001,2**61-2,2**61-1,MASK]]
    alternatives = [
        dict(name='floor instead of ceiling',count=2000001,wrong_selected=1000000,actual_selected=scratch_relation(2000001)['selected']),
        dict(name='minimum instead of maximum',count=513,wrong_selected=257,actual_selected=scratch_relation(513)['selected']),
        dict(name='heap at 512',count=512,wrong_path='heap',actual_path=scratch_relation(512)['path']),
        dict(name='small flag inclusive 65',count=65,wrong_flag=1,actual_flag=scratch_relation(65)['small_flag']),
        dict(name='drop high overflow guard',count=2**62-1,wrong_path='heap',actual_path=scratch_relation(2**62-1)['path']),
    ]
    for alternative in alternatives:
        wrong=next(value for name,value in alternative.items() if name.startswith('wrong_'))
        actual=next(value for name,value in alternative.items() if name.startswith('actual_'))
        require(wrong!=actual,'ineffective wrong relation control')
    return dict(counts=len(transcript), transcript_sha256=sha(render(transcript).encode()), samples=samples,
                distinguishable_wrong_relations=alternatives,
                scope='Static mathematical consequence controls over synthetic counts; no allocator, sort, target execution, or target instruction evaluation.')


def collect(llvm):
    data = TARGET.read_bytes()
    require(len(data) == 91774280 and sha(data) == SHA, 'target identity mismatch')
    image = Image(data); local_obligations(image)
    _, extents, _ = fde_extents(data)
    records, files = [], {}
    for label, bounds, export in [('scratch-wrapper',WRAPPER,WRAPPER), ('error-entry',ERROR,ERROR),
                                  ('inner-entry',INNER,(0x4dbd490,0x4dbd4c0)),
                                  ('collector-call',COLLECTOR,(0x44503a4,0x44503ba))]:
        fde = qualify(extents,*bounds)
        streams, rows = native(image,*export,llvm)
        body = image.window(*bounds)
        if bounds != export: del body['raw_hex']
        row = dict(label=label, body=body, native_export=image.window(*export), instructions=len(rows),
                   unwind={k:hex(v) if isinstance(v,int) else v for k,v in fde.items()},
                   fde_record=image.record(fde['fde']),cie_record=image.record(fde['cie']))
        if label == 'scratch-wrapper': row['normal_cfg'],row['calls']=graph(rows)
        records.append(row)
        for provider,stream in zip(['gnu','llvm'],streams): files[f'raw/{label}-{provider}.txt']=stream
    relocations=[]
    wanted={0x5774f50,0x576dfb8,0x576dfd8,0x576e010,0x576e0c0,0x576e020}
    for sec in image.sections:
        if sec['type']==4:
            require(sec['size']%24==0,'partial relocation')
            for pos in range(sec['offset'],sec['offset']+sec['size'],24):
                slot,info,addend=struct.unpack_from('<QQq',data,pos)
                if slot in wanted: relocations.append(dict(slot=hex(slot),info=hex(info),addend=hex(addend),file_offset=hex(pos),raw_hex=data[pos:pos+24].hex()))
    require({int(r['slot'],16) for r in relocations}==wanted and len(relocations)==len(wanted),'missing/duplicate selected relocation')
    expected={0x5774f50:0x4486d10,0x576dfb8:0x1346068,0x576dfd8:0x54c06b0,0x576e010:0x54c8cb0}
    for slot,target in expected.items():
        require(any(int(r['slot'],16)==slot and int(r['addend'],16)==target and r['info']=='0x8' for r in relocations),'relocation target mismatch')
    cleanup=lsda(image)
    controls=[]
    for name,va,_ in PINS:
        changed=bytearray(data); changed[image.offset(va,1)]^=1
        try: local_obligations(Image(changed))
        except ValueError as error: controls.append(dict(name=name,outcome='rejected below SHA admission',reason=str(error)))
        else: raise ValueError('operand mutation survived: '+name)
    # Landing-pad offset is a ULEB value at LSDA+0x0c; alter it below digest admission.
    changed=bytearray(data); changed[image.offset(0xb4200c,1)]^=1
    try: lsda(Image(changed))
    except ValueError as error: controls.append(dict(name='LSDA landing-pad offset',outcome='rejected below SHA admission',reason=str(error)))
    else: raise ValueError('LSDA mutation survived')
    wrapper=qualify(extents,*WRAPPER); changed=bytearray(data); changed[image.offset(wrapper['fde']+12,1)]^=1
    try: qualify(fde_extents(changed)[1],*WRAPPER)
    except ValueError as error: controls.append(dict(name='wrapper FDE range',outcome='rejected below SHA admission',reason=str(error)))
    else: raise ValueError('FDE mutation survived')
    files['records.json']=render(dict(task='RE-006',component='orderbook',base='56c0ec672bd8fdcfaa80f2db700a61e6240b3663',
        target_sha256=SHA,target_bytes=len(data),coordinates='linked ELF VAs, plus exact section-derived file offsets',
        functions=records,relocations=relocations,lsda=cleanup,normalization_masks=[],
        selected_resume_context=image.window(0x4450308,0x445030c),
        native_versions={name:subprocess.check_output([program,'--version'],text=True).splitlines()[0]
                         for name,program in [('gnu','objdump'),('llvm',llvm)]},
        limits='Complete wrapper native partition and normal local CFG; LSDA call-site table binds one cleanup. Inner comparator, allocator, free, error, and personality internals remain outside claim.'))
    files['controls.json']=render(dict(local_corruptions=controls,synthetic=synthetic()))
    return files


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    parser.add_argument('--llvm',default=os.environ.get('LLVM_OBJDUMP','llvm-objdump'))
    args=parser.parse_args(); files=collect(args.llvm)
    for name,value in files.items():
        if args.write:
            (HERE/name).parent.mkdir(parents=True,exist_ok=True); (HERE/name).write_text(value)
        else: require((HERE/name).read_text()==value,'stale evidence: '+name)
    print(f'Static replay passed: {len(files)} exports, {len(PINS)+2} local corruption controls, {len(control_counts())} synthetic counts. No target execution/evaluation.')


if __name__=='__main__': main()
