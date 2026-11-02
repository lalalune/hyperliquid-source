#!/usr/bin/env python3
"""Bind node94's quota/affinity cache producer without executing the capture."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-002-num-cpus-cache-94'
RANGES = {
    0x4e04830: (0x4e061bd, 'e7617cb1a72162d8081d70bc591de29d92d329a6adb2800ca3dda0fc4f9b4795', 'new initializer context'),
    0x4e061c0: (0x4e061d2, 'c93fa4181e746b55528819ba2d5c531393fe7fe1370afa124b6753507f530606', 'new callback adapter'),
    0x4e06870: (0x4e069a8, '886a281a54aed07199e96fe211121a454f18406820dc3fbf22432c66415e7554', 'previously mapped cache consumer; context only'),
    0x565f670: (0x565f6e7, '305266cf1728cbf73813d37f53ff4f144253a377fc9258c8732b1f4b3bf5eaeb', 'previously qualified ceil helper; context only'),
}
LITERALS = {0x715ce8: b'/proc/self/cgroup', 0x715cf9: b'/proc/self/mountinfo',
            0x715d0d: b'cpu.max', 0x205c60: b'cpu.cfs_quota_us', 0x715d14: b'cpu.cfs_period_us'}
CONSTANTS = {0x203e80: '0000304300003045', 0x202ea0: '00000000000030430000000000003045',
             0x20a7f0: '000000000000e043', 0x20a218: 'ffffffffffffef43',
             0x5747f68: '000000000000000008000000000000000800000000000000'}
RELATIVE = {0x5747f80: 0x4e061c0, 0x5747f88: 0x4e04830,
            0x57747c8: 0x565f670, 0x576e8b8: 0x4ee3b20}
RIP = {0x4e0581c: ('488d0d', 0x715d0d), 0x4e05857: ('488d15', 0x205c60),
       0x4e0587e: ('488d15', 0x715d14), 0x4e058ea: ('ff15', 0x57747c8),
       0x4e05d2b: ('ff15', 0x5776b70), 0x4e05d3a: ('ff15', 0x57708a8),
       0x4e05daf: ('48871d', 0x57883f8), 0x4e068ad: ('488d0d', 0x5747f68),
       0x4e068c2: ('ff15', 0x576e8b8), 0x4e068c8: ('488b05', 0x57883f8)}
DIRECT = {0x4e05839: 0x4e06b30, 0x4e0586b: 0x4e069b0, 0x4e05892: 0x4e069b0,
          0x4e061cb: 0x4e04830}


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        header = struct.unpack_from('<Q', data, 40)[0]
        stride = struct.unpack_from('<H', data, 58)[0]
        for index, section in enumerate(self.sections):
            section['entsize'] = struct.unpack_from('<Q', data, header + index * stride + 56)[0]
        for name in ['.text', '.eh_frame', '.rela.dyn', '.dynsym', '.dynstr']:
            require(sum(s['name'] == name for s in self.sections) == 1, 'ambiguous section ' + name)

    def section(self, name):
        return next(s for s in self.sections if s['name'] == name)

    def offset(self, address, count):
        matches = [s for s in self.sections if s['type'] != 8 and s['address'] <= address
                   and address + count <= s['address'] + s['size']]
        require(count >= 0 and len(matches) == 1, 'ambiguous/non-file-backed VA')
        offset = matches[0]['offset'] + address - matches[0]['address']
        require(0 <= offset <= len(self.data) - count, 'truncated mapped bytes')
        return offset

    def read(self, address, count):
        offset = self.offset(address, count)
        return bytes(self.data[offset:offset + count])


def analyze(data, authenticate=True):
    if authenticate:
        require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == TARGET_SHA, 'wrong node94 input')
    image = Image(data)
    require(not any(s['type'] == 9 for s in image.sections), 'unsupported REL table')
    _, frames, _ = fde_extents(data)
    sec = image.section('.rela.dyn')
    require(sec['size'] % 24 == 0 and sec['entsize'] == 24, 'invalid RELA extent')
    relocations = {}
    for offset, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
        require(offset not in relocations, 'duplicate RELA slot')
        relocations[offset] = (info, addend)
    for slot, target in RELATIVE.items():
        require(relocations.get(slot) == (8, target), 'callback/ceil/once RELATIVE binding changed')
    protected = [(a, end) for a, (end, _, _) in RANGES.items()]
    protected += [(a, a + len(v)) for a, v in LITERALS.items()]
    protected += [(a, a + len(bytes.fromhex(v))) for a, v in CONSTANTS.items()]
    protected += [(a, a + 8) for a in RELATIVE]
    for table in image.sections:
        if table['type'] != 4:
            continue
        require(table['entsize'] == 24 and table['size'] % 24 == 0, 'invalid relocation table')
        for offset in range(table['offset'], table['offset'] + table['size'], 24):
            destination, info, addend = struct.unpack_from('<QQq', data, offset)
            if any(destination < hi and lo < destination + 8 for lo, hi in protected):
                require(table['name'] == '.rela.dyn' and destination in RELATIVE
                        and (info, addend) == (8, RELATIVE[destination]), 'unexpected relocation overlaps protected evidence')
    imports = []
    dynsym, dynstr = image.section('.dynsym'), image.section('.dynstr')
    for slot, index, name in [(0x5776b70, 99, b'sched_getaffinity'), (0x57708a8, 59, b'sysconf')]:
        require(relocations.get(slot) == ((index << 32) | 6, 0), 'logical-count import binding changed')
        require((index + 1) * 24 <= dynsym['size'], 'dynamic symbol outside table')
        name_offset = struct.unpack_from('<I', data, dynsym['offset'] + index * 24)[0]
        require(name_offset + len(name) + 1 <= dynstr['size'], 'import name outside string table')
        offset = dynstr['offset'] + name_offset
        require(data[offset:offset + len(name) + 1] == name + b'\0', 'logical-count import name changed')
        imports.append({'slot': hex(slot), 'dynsym_index': index, 'name': name.decode()})
    for address, raw in LITERALS.items():
        require(image.read(address, len(raw)) == raw, 'cgroup literal changed')
    for address, raw in CONSTANTS.items():
        require(image.read(address, len(bytes.fromhex(raw))) == bytes.fromhex(raw), 'quota constant/vtable header changed')
    for address, (prefix, target) in RIP.items():
        opcode = bytes.fromhex(prefix)
        raw = image.read(address, len(opcode) + 4)
        require(raw.startswith(opcode) and address + len(raw) + struct.unpack_from('<i', raw, len(opcode))[0] == target,
                'quota/cache RIP binding changed')
    for address, target in DIRECT.items():
        raw = image.read(address, 5)
        require(raw[0] == 0xe8 and address + 5 + struct.unpack_from('<i', raw, 1)[0] == target, 'quota/adapter direct call changed')
    bss = [s for s in image.sections if s['address'] <= 0x57883f8 and 0x5788400 <= s['address'] + s['size']]
    require(len(bss) == 1 and bss[0]['type'] == 8, 'cache no longer resides in NOBITS')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    stride, count = struct.unpack_from('<HH', data, 54)
    require(stride == 56, 'invalid program header size')
    segments = [struct.unpack_from('<IIQQQQQQ', data, phoff + index * stride) for index in range(count)]
    loads = [s for s in segments if s[0] == 1 and s[3] <= 0x57883f8 < 0x5788400 <= s[3] + s[6]]
    require(len(loads) == 1 and loads[0][1] & 2 and loads[0][3] + loads[0][5] <= 0x57883f8,
            'cache is not in a writable PT_LOAD zero-fill tail')
    ranges = []
    for start, (end, digest, role) in RANGES.items():
        selected = [f for f in frames if f['start'] < end and start < f['end']]
        require(len(selected) == 1 and selected[0]['start'] == start and selected[0]['end'] == end,
                'missing, duplicate, overlapping or changed FDE')
        text = image.section('.text')
        require(text['flags'] & 4 and text['address'] <= start < end <= text['address'] + text['size'],
                'selected function is not in executable text')
        frame = selected[0]
        raw = image.read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == digest, 'whole function bytes changed')
        row = {'start_va': hex(start), 'end_va_exclusive': hex(end), 'bytes': len(raw),
               'file_offset': hex(image.offset(start, len(raw))), 'sha256': digest, 'role': role,
               'fde_va': hex(frame['fde']), 'cie_va': hex(frame['cie']), 'lsda_va': hex(frame['lsda']) if frame['lsda'] else None}
        for kind in ['fde', 'cie']:
            address = frame[kind]
            size = struct.unpack('<I', image.read(address, 4))[0] + 4
            require(4 < size < 4096, 'unexpected unwind record extent')
            row[kind + '_hex'] = image.read(address, size).hex()
        ranges.append(row)
    return {'target_sha256': TARGET_SHA, 'target_bytes': len(data), 'ranges': ranges,
            'literals': [{'va': hex(a), 'length': len(v), 'ascii': v.decode()} for a, v in LITERALS.items()],
            'constants': {hex(a): raw for a, raw in CONSTANTS.items()},
            'relative_bindings': {hex(a): hex(v) for a, v in RELATIVE.items()}, 'imports': imports,
            'rip_bindings': [{'site': hex(a), 'prefix': p, 'target': hex(v)} for a, (p, v) in RIP.items()],
            'direct_calls': {hex(a): hex(v) for a, v in DIRECT.items()},
            'cache': {'va': '0x57883f8', 'section': bss[0]['name'], 'type': 'SHT_NOBITS',
                      'load_file_va_end': hex(loads[0][3] + loads[0][5]),
                      'load_memory_va_end': hex(loads[0][3] + loads[0][6]),
                      'store_site': '0x4e05daf', 'instruction': 'xchg qword [rip+disp32],rbx'},
            'captured_binary_executed': False,
            'new_context_bytes': 6541 + 18, 'existing_context_bytes': 312 + 119,
            'limits': 'Selected numeric/publication semantics only. Full initializer retained as context; parsers, path translation, allocation, once synchronization and unwind helpers are not reconstructed. No source-built body equality or component gate claimed.'}


def generate(binary, output):
    data = binary.read_bytes()
    report = analyze(data)
    image = Image(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cpu-cache-static-') as temp:
        snapshot = Path(temp) / 'node94.elf'
        snapshot.write_bytes(data)
        for start, (end, _, _) in RANGES.items():
            raw = image.read(start, end - start)
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            decoded = decode_export(asm, start, end, raw)
            for site in set(RIP) | set(DIRECT):
                if start <= site < end:
                    require(site in decoded, 'binding is not at an instruction boundary')
            (output / f'{start:x}.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
            calls = []
            for line in asm.splitlines():
                match = re.match(r'\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+(.*)', line)
                if match and re.match(r'call\s', match[2]):
                    calls.append({'site': '0x' + match[1], 'decoded': re.sub(r' <[^>]+>', '', match[2])})
            row = next(r for r in report['ranges'] if r['start_va'] == hex(start))
            row['decoded_instructions'] = len(decoded)
            row['call_sites'] = calls
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/cpu-cache-94/observed')
    args = parser.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'ranges': len(report['ranges']), 'new_context_bytes': report['new_context_bytes'],
                      'existing_context_bytes': report['existing_context_bytes'], 'captured_binary_executed': False}))


if __name__ == '__main__':
    main()
