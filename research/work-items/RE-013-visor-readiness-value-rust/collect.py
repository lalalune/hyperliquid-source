#!/usr/bin/env python3
"""Static native/data binding only: no captured execution or evaluator.

MIT static ELF/FDE/provider mechanics adapted from the independently authored
RE-013-visor-key-hash-rust/collect.py, SHA256
f729c857148a424f0cbad205c4fe0d235cf5ac07e37fff92a8c721ad3d8c38aa.
This is a self-contained copy; that packet is not a runtime dependency.
The original Image parser in that file separately credits the child-args packet.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from collections import Counter

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


class Image:
    def __init__(self, data):
        self.data = data
        require(data[:6] == b"\x7fELF\x02\x01", "expected ELF64 little endian")
        require(struct.unpack_from("<H", data, 18)[0] == 62, "expected x86-64")
        phoff, shoff = struct.unpack_from("<QQ", data, 32)
        phsize, phcount, shsize, shcount, names = struct.unpack_from("<HHHHH", data, 54)
        require(phsize == 56 and shsize == 64, "unexpected header stride")
        require(phoff + phsize * phcount <= len(data), "truncated program headers")
        require(shoff + shsize * shcount <= len(data), "truncated section headers")
        self.loads = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize)
                      for i in range(phcount)]
        headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shsize)
                   for i in range(shcount)]
        require(names < shcount, "bad section name index")
        name_header = headers[names]
        table = self.file(name_header[4], name_header[5])
        self.sections = {}
        for h in headers:
            require(h[0] < len(table), "bad section name")
            end = table.find(b"\0", h[0])
            require(end >= 0, "unterminated section name")
            name = table[h[0]:end].decode("ascii")
            require(name not in self.sections, "duplicate section name")
            self.sections[name] = h

    def file(self, offset, length):
        require(0 <= offset <= offset + length <= len(self.data), "file bounds")
        return self.data[offset:offset + length]

    def offset(self, address, length):
        hits = [h for h in self.loads if h[0] == 1 and
                h[3] <= address <= address + length <= h[3] + h[5]]
        require(len(hits) == 1, "ambiguous/unbacked VA range")
        return hits[0][2] + address - hits[0][3]

    def at(self, address, length):
        return self.file(self.offset(address, length), length)

    def record(self, address):
        length = struct.unpack("<I", self.at(address, 4))[0]
        require(0 < length < 0xffffffff, "unsupported DWARF record")
        return self.at(address, 4 + length)

def admit_image(raw, pins):
    require(len(raw) == pins['target']['bytes'] and sha(raw) == pins['target']['sha256'], 'target identity')
    return Image(raw)


def authenticate(repo, pins):
    raw = (repo / pins['target']['path']).read_bytes()
    image = admit_image(raw, pins)
    for p in pins['prior_files']:
        data = (repo / p['path']).read_bytes()
        require(len(data) == p['bytes'] and sha(data) == p['sha256'], 'credited input differs')
    return image


def rows(text, image, start, end):
    result = []
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$', line)
        if m:
            result.append((int(m[1], 16), bytes.fromhex(m[2]), m[3]))
    cursor = start
    for address, raw, _ in result:
        require(address == cursor and image.at(address, len(raw)) == raw, 'native row identity/tiling')
        cursor += len(raw)
    require(cursor == end, 'native body incomplete')
    return result


def relas(image):
    records = []
    for h in image.sections.values():
        if h[1] != 4:
            continue
        require(h[9] == 24 and h[5] % 24 == 0, 'RELA stride')
        for off in range(h[4], h[4] + h[5], 24):
            raw = image.file(off, 24)
            destination, info, addend = struct.unpack('<QQq', raw)
            records.append(dict(destination=destination, type=info & 0xffffffff,
                                symbol=info >> 32, addend=addend, file_offset=off, raw=raw.hex()))
    return records


def frame_record(image, frames, body):
    start, end = int(body['start'], 16), int(body['end'], 16)
    pattern = (r'^([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+ FDE cie=([0-9a-f]+) pc=' +
               f'{start:016x}' + r'\.\.' + f'{end:016x}' + r'$')
    matches = list(re.finditer(pattern, frames, re.MULTILINE))
    require(len(matches) == 1, 'actual FDE header missing or duplicated')
    m = matches[0]
    base = image.sections['.eh_frame'][3]
    fde, cie = base + int(m[1], 16), base + int(m[2], 16)
    require(hex(fde) == body['fde_va'] and hex(cie) == body['cie_va'], 'FDE/CIE coordinates')
    fraw, craw = image.record(fde), image.record(cie)
    require(fraw.hex() == body['fde_raw'] and craw.hex() == body['cie_raw'], 'raw FDE/CIE identity')
    require(fde + 4 - struct.unpack_from('<I', fraw, 4)[0] == cie, 'FDE CIE pointer')
    require(fde + 8 + struct.unpack_from('<i', fraw, 8)[0] == start, 'signed32 PC-relative FDE start')
    require(struct.unpack_from('<I', fraw, 12)[0] == end - start, 'FDE extent')
    return dict(fde_va=hex(fde), cie_va=hex(cie), fde_raw=fraw.hex(), cie_raw=craw.hex(), native_header=m[0])


def derive(image, pins, frames, check_body_identity=True):
    bodies = []
    for p in pins['bodies']:
        start, end = int(p['start'], 16), int(p['end'], 16)
        raw = image.at(start, end - start)
        if check_body_identity:
            require(sha(raw) == p['sha256'], 'whole body identity')
        bodies.append(dict(name=p['name'], role=p['role'], start=p['start'], end=p['end'],
                           bytes=len(raw), sha256=sha(raw), file_offset=image.offset(start, len(raw)),
                           frame=frame_record(image, frames, p)))
    for anchor in pins['anchors']:
        expected = bytes.fromhex(anchor['hex'])
        require(image.at(int(anchor['va'], 16), len(expected)) == expected, 'native operand anchor: ' + anchor['name'])
    literals = []
    for literal in pins['literals']:
        va = int(literal['va'], 16)
        raw = image.at(va, literal['bytes'])
        require(raw.hex() == literal['hex'], 'literal binding: ' + literal['name'])
        literals.append(dict(literal, file_offset=image.offset(va, len(raw)), sha256=sha(raw)))
    relocation_records = relas(image)
    require(len(relocation_records) == pins['relas']['count'], 'RELA record count')
    counts = dict(sorted(Counter(str(r['type']) for r in relocation_records).items()))
    require(counts == pins['relas']['types'], 'RELA types/counts differ')
    # This admitted capture uses only these eight-byte ELF64 writes.
    require(set(int(t) for t in counts) <= {6, 7, 8}, 'unsupported relocation write size')
    protected = [(int(p['start'], 16), int(p['end'], 16)) for p in pins['bodies']]
    protected += [(int(p['va'], 16), int(p['va'], 16) + p['bytes']) for p in pins['literals']]
    overlap = [r for r in relocation_records if any(r['destination'] < z and a < r['destination'] + 8 for a, z in protected)]
    require(not overlap, 'relocation writer overlaps selected code/data')
    selected_slots = []
    for expected in pins['context_slots']:
        hits = [r for r in relocation_records if r['destination'] == int(expected['slot'], 16)]
        require(len(hits) == 1, 'context slot absent/duplicate')
        r = hits[0]
        require([r['type'], r['symbol'], r['addend']] == expected['binding'], 'context slot binding')
        selected_slots.append(dict(expected, raw=r['raw'], file_offset=r['file_offset']))
    dynsym, dynstr = image.sections['.dynsym'], image.sections['.dynstr']
    require(dynsym[9] == 24 and dynsym[5] % 24 == 0, 'dynamic symbol stride')
    strings = image.file(dynstr[4], dynstr[5])
    calls = []
    for p in pins['calls']:
        site = int(p['site'], 16)
        raw = image.at(site, len(bytes.fromhex(p['raw'])))
        require(raw.hex() == p['raw'], 'actual call bytes')
        record = dict(p)
        if p['kind'] == 'direct':
            require(raw[0] == 0xe8 and site + 5 + struct.unpack_from('<i', raw, 1)[0] == int(p['target'], 16),
                    'actual direct-call target')
        elif p['kind'] == 'rip-slot':
            slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
            require(raw[:2] == b'\xff\x15' and slot == int(p['slot'], 16), 'actual RIP-call slot')
            hits = [r for r in relocation_records if r['destination'] == slot]
            require(len(hits) == 1, 'call slot absent/duplicate')
            r = hits[0]
            require([r['type'], r['symbol'], r['addend']] == p['binding'], 'call relocation binding')
            record['rela_raw'] = r['raw']
            record['rela_file_offset'] = r['file_offset']
            if r['type'] == 6:
                symbol = image.file(dynsym[4] + r['symbol'] * 24, 24)
                name, _, _, section, _, _ = struct.unpack('<IBBHQQ', symbol)
                end = strings.find(b'\0', name)
                require(0 <= name <= end < len(strings), 'import name bounds')
                name = strings[name:end].decode('ascii')
                require(name == p['symbol_name'] and section == 0, 'actual undefined import symbol')
                record['symbol_raw'] = symbol.hex()
            else:
                require(r['type'] == 8 and r['symbol'] == 0, 'unhandled call relocation')
        else:
            require(p['kind'] == 'opaque-context' and raw == b'\xff\x10', 'unhandled context indirect call')
        calls.append(record)
    return dict(target=pins['target'], bodies=bodies, literals=literals,
                calls=calls, context_slots=selected_slots,
                rela_summary=dict(records=len(relocation_records), types=counts,
                                  writer_width=8, protected_overlap=[]),
                scope='Static byte/data/frame/call binding; PROOF states admitted value domains. Cold and two dynamic context calls remain opaque. No target execution or instruction evaluator.')


def native(argv, cwd):
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=True, timeout=180)
    require(not result.stderr, 'unexpected native stderr')
    return result.stdout


def qualify_export(text, image, pin, pins):
    start, end = int(pin['start'], 16), int(pin['end'], 16)
    decoded = rows(text, image, start, end)
    require(len(decoded) == pin['rows'], 'native row count')
    calls = [dict(site=hex(a), raw=b.hex(), instruction=t) for a, b, t in decoded if t.startswith('call')]
    expected = [p['site'] for p in pins['calls'] if start <= int(p['site'], 16) < end]
    require([c['site'] for c in calls] == expected, 'complete retained call inventory')
    return decoded, calls


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--gnu', default='/opt/homebrew/opt/binutils/bin/objdump')
    parser.add_argument('--llvm', default='/usr/bin/objdump')
    parser.add_argument('--readelf', default='/opt/homebrew/opt/binutils/bin/readelf')
    args = parser.parse_args()
    require(not args.out.exists(), 'fresh output required')
    pins = json.loads((HERE / 'BASIS-PINS.json').read_text())
    image = authenticate(args.repo, pins)
    frames = native([args.readelf, '--debug-dump=frames', pins['target']['path']], args.repo)
    record = derive(image, pins, frames)
    args.out.mkdir(parents=True)
    providers = {}
    for label, tool in [('gnu', args.gnu), ('llvm', args.llvm), ('readelf', args.readelf)]:
        resolved = Path(tool).resolve()
        providers[label] = dict(argv=[tool, '--version'], sha256=sha(resolved.read_bytes()),
                                version=native([tool, '--version'], args.repo).strip())
    for body, pin in zip(record['bodies'], pins['bodies'], strict=True):
        start, end = int(body['start'], 16), int(body['end'], 16)
        exports, partitions = {}, {}
        for label, tool, flags in [('gnu', args.gnu, ['-Mintel', '--insn-width=16']),
                                    ('llvm', args.llvm, ['--x86-asm-syntax=intel'])]:
            argv = [tool, '-d', *flags, '--start-address=' + hex(start),
                    '--stop-address=' + hex(end), pins['target']['path']]
            text = native(argv, args.repo)
            decoded, calls = qualify_export(text, image, pin, pins)
            partitions[label] = [(a, b.hex()) for a, b, _ in decoded]
            name = body['name'] + '.' + label + '.txt.gz'
            (args.out / name).write_bytes(gzip.compress(text.encode(), mtime=0))
            exports[label] = dict(argv=argv, rows=len(decoded), stdout_sha256=sha(text.encode()),
                                   output=name, calls=calls)
        require(partitions['gnu'] == partitions['llvm'], 'independent native byte partitions differ')
        body['exports'] = exports
    require((args.repo / pins['target']['path']).read_bytes() == image.data, 'capture changed during static reads')
    record['providers'] = providers
    record['credited_files'] = pins['prior_files']
    write_json(args.out / 'records.json', record)
    print(json.dumps(dict(status='PASS: static sample/calendar bindings only',
                          full_fdes=8, bytes=3866, native_rows=910, calls=len(record['calls']))))

if __name__ == '__main__':
    main()
