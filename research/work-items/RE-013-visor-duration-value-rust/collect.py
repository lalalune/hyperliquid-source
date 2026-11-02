#!/usr/bin/env python3
"""Native evidence binding, no target execution or instruction evaluator.

ELF/FDE/provider mechanics adapt independently authored MIT
RE-013-visor-readiness-value-rust/collect.py at SHA256
cfe1fa17db09398baf5c2b125924549de84ccd1fa9db8822bcf518dc44030ed3.
This packet is self-contained; no unmerged packet is a runtime dependency.
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


def frame_record(image, frames, body, core=True):
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
    frame_section = image.sections['.eh_frame']
    require(frame_section[1] == 1 and all(base <= a and a+len(raw) <= base+frame_section[5]
                                        for a, raw in ((fde, fraw), (cie, craw))), 'frame section bounds')
    if craw[4:17] == bytes.fromhex('00000000017a5200017810011b'):
        require(fraw[16] == 0, 'unexpected FDE augmentation')
    else:
        require(not core and craw[4:19] == bytes.fromhex('00000000017a504c5200017810079b')
                and craw[23:25] == b'\x1b\x1b' and fraw[16] == 4,
                'CIE signed-PC-relative encoding')
    require(fde + 4 - struct.unpack_from('<I', fraw, 4)[0] == cie, 'FDE CIE pointer')
    require(fde + 8 + struct.unpack_from('<i', fraw, 8)[0] == start, 'signed32 PC-relative FDE start')
    require(struct.unpack_from('<I', fraw, 12)[0] == end - start, 'FDE extent')
    return dict(fde_va=hex(fde), cie_va=hex(cie), fde_raw=fraw.hex(), cie_raw=craw.hex(), native_header=m[0])


def facts(image, pins):
    # Actual immediate/data fields, read before comparison to claimed values.
    return {p['name']: int.from_bytes(image.at(int(p['va'], 16), p['bytes']), 'little')
            for p in pins['facts']}


def derive(image, pins, frames, check_body_identity=True):
    measured = facts(image, pins)
    require(measured == {p['name']: p['value'] for p in pins['facts']}, 'actual operand/data facts differ')
    result = {'target': pins['target'], 'facts': measured, 'bodies': [], 'contexts': []}
    text_section = image.sections['.text']
    require(text_section[1] == 1 and text_section[2] & 4, 'executable PROGBITS section')
    header = image.sections['.eh_frame_hdr']
    hb = header[3]
    require(image.at(hb, 4) == bytes.fromhex('011b033b'), 'unwind index encoding')
    require(hb+4+struct.unpack('<i', image.at(hb+4, 4))[0] == image.sections['.eh_frame'][3], 'unwind index frame base')
    count = struct.unpack('<I', image.at(hb+8, 4))[0]
    require(12+8*count == header[5], 'unwind index extent')
    index = [tuple(hb+x for x in struct.unpack('<ii', image.at(hb+12+8*i, 8))) for i in range(count)]
    require(all(index[i][0] < index[i+1][0] for i in range(count-1)), 'unwind index ordering')
    result['unwind_index'] = dict(header_va=hex(hb), header_raw=image.at(hb, 12).hex(), count=count, selected=[])
    for category in ('bodies', 'contexts'):
        for p in pins[category]:
            a, z = int(p['start'], 16), int(p['end'], 16)
            require(text_section[3] <= a < z <= text_section[3]+text_section[5], 'executable section range')
            require(any(h[0] == 1 and h[1] & 1 and h[3] <= a < z <= h[3]+h[5] for h in image.loads),
                    'executable PT_LOAD range')
            require(image.offset(a, z-a) == text_section[4]+a-text_section[3], 'code section/PT_LOAD mapping')
            raw = image.at(a, z-a)
            if check_body_identity:
                require(sha(raw) == p['sha256'], 'range identity')
            item = dict(name=p['name'], start=p['start'], end=p['end'], bytes=z-a,
                        file_offset=image.offset(a, z-a), sha256=sha(raw), role=p['role'])
            if category == 'bodies':
                item['frame'] = frame_record(image, frames, p)
                matches = [i for i, (pc, fde) in enumerate(index) if pc == a and fde == int(p['fde_va'], 16)]
                require(len(matches) == 1, 'unwind index body/FDE binding')
                i = matches[0]
                result['unwind_index']['selected'].append(dict(name=p['name'], index=i,
                    raw=image.at(hb+12+8*i, 8).hex(), va=hex(hb+12+8*i)))
            else:
                host = p['host']
                require(int(host['start'], 16) <= a < z <= int(host['end'], 16), 'context exceeds host FDE')
                item['host_frame_only'] = frame_record(image, frames, host, core=False)
                require((int(host['start'], 16), int(host['fde_va'], 16)) in index, 'context host unwind index')
            result[category].append(item)
    for a in pins['anchors']:
        require(image.at(int(a['va'], 16), len(bytes.fromhex(a['raw']))).hex() == a['raw'],
                'native instruction anchor: '+a['name'])
    result['literals'] = []
    for p in pins['literals']:
        a = int(p['va'], 16)
        raw = image.at(a, p['bytes'])
        require(raw.hex() == p['raw'], 'literal identity: '+p['name'])
        result['literals'].append(dict(p, file_offset=image.offset(a, len(raw))))
    all_relas = relas(image)
    types = dict(sorted(Counter(str(r['type']) for r in all_relas).items()))
    require(len(all_relas) == pins['relas']['count'] and types == pins['relas']['types'], 'RELA inventory')
    require(set(map(int, types)) <= {6, 7, 8}, 'unadmitted relocation width')
    ranges = [(int(p['start'], 16), int(p['end'], 16)) for k in ('bodies', 'contexts') for p in pins[k]]
    ranges += [(int(p['va'], 16), int(p['va'], 16)+p['bytes']) for p in pins['literals']]
    ranges += [(hb, hb+header[5])]
    ranges += [(int(p[key], 16), int(p[key], 16)+len(bytes.fromhex(p[raw_key])))
               for p in pins['bodies'] for key, raw_key in [('fde_va', 'fde_raw'), ('cie_va', 'cie_raw')]]
    ranges += [(int(p['host'][key], 16), int(p['host'][key], 16)+len(bytes.fromhex(p['host'][raw_key])))
               for p in pins['contexts'] for key, raw_key in [('fde_va', 'fde_raw'), ('cie_va', 'cie_raw')]]
    require(not any(r['destination'] < z and a < r['destination']+8 for r in all_relas for a, z in ranges),
            'RELA writer overlaps protected range')
    result['calls'] = []
    for p in pins['calls']:
        a = int(p['site'], 16)
        raw = image.at(a, len(bytes.fromhex(p['raw'])))
        require(raw.hex() == p['raw'], 'call instruction identity')
        if p['kind'] == 'direct':
            require(raw[0] == 0xe8 and a+5+struct.unpack_from('<i', raw, 1)[0] == int(p['target'], 16),
                    'direct context call target')
            result['calls'].append(p)
            continue
        if p['kind'] == 'opaque-context':
            require(p['role'] == 'context-only' and raw in (b'\x41\xff\xd6',), 'unadmitted opaque context call')
            result['calls'].append(p)
            continue
        require(p['kind'] == 'rip-slot', 'unadmitted call kind')
        require(raw[:2] == b'\xff\x15', 'RIP call opcode')
        slot = a+6+struct.unpack_from('<i', raw, 2)[0]
        require(slot == int(p['slot'], 16), 'RIP call displacement')
        matches = [r for r in all_relas if r['destination'] == slot]
        require(len(matches) == 1, 'unique call relocation')
        r = matches[0]
        require([r['type'], r['symbol'], r['addend']] == p['binding'], 'call target relocation')
        result['calls'].append(dict(p, rela_raw=r['raw'], rela_file_offset=r['file_offset']))
    result['rela_summary'] = dict(count=len(all_relas), types=types, protected_overlaps=[], writer_bytes=8)
    result['scope'] = 'Two complete bodies and17 bounded caller contexts; only outer value projection claimed. No captured evaluation.'
    return result


def cfg(decoded):
    instructions = {a: (raw, text) for a, raw, text in decoded}
    edges = {}
    returns = []
    for a, raw, text in decoded:
        mnemonic = text.split()[0]
        if mnemonic == 'ret':
            successors = []
            returns.append(hex(a))
        elif mnemonic.startswith('j'):
            target = re.search(r'\b(?:0x)?([0-9a-f]+)\s*(?:<|$)', text)
            require(target is not None, 'direct branch target syntax')
            successors = [int(target[1], 16)]
            if mnemonic != 'jmp':
                successors.append(a+len(raw))
        else:
            successors = [a+len(raw)]
        require(all(x in instructions for x in successors), 'CFG leaves admitted body')
        edges[a] = successors
    visiting, complete = set(), set()
    def visit(a):
        require(a not in visiting, 'cycle in ordinary-return CFG')
        if a in complete:
            return
        visiting.add(a)
        for b in edges[a]:
            visit(b)
        visiting.remove(a)
        complete.add(a)
    visit(decoded[0][0])
    require(complete == set(instructions), 'unreachable decoded row')
    require(returns, 'vacuous return inventory')
    return dict(rows=len(decoded), returns=returns, all_rows_reachable=True, acyclic=True,
                limits='Syntactic branch graph with calls assumed to return; not path feasibility or automatic semantics.')


def qualify_export(text, image, p, pins):
    decoded = rows(text, image, int(p['start'], 16), int(p['end'], 16))
    require(len(decoded) == p['rows'], 'native row count')
    calls = [hex(a) for a, raw, text in decoded if text.startswith('call')]
    expected = [c['site'] for c in pins['calls'] if int(p['start'], 16) <= int(c['site'], 16) < int(p['end'], 16)]
    require(calls == expected, 'complete selected call inventory')
    return decoded


def native(argv, cwd):
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=180)
    require(p.returncode == 0 and not p.stderr, 'native provider failed: '+str(argv))
    return p.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--gnu', default='/opt/homebrew/opt/binutils/bin/objdump')
    parser.add_argument('--llvm', default='/usr/bin/objdump')
    parser.add_argument('--readelf', default='/opt/homebrew/opt/binutils/bin/readelf')
    args = parser.parse_args()
    require(not args.out.exists(), 'fresh output required')
    pins = json.loads((HERE/'BASIS-PINS.json').read_text())
    image = authenticate(args.repo, pins)
    frames = native([args.readelf, '--debug-dump=frames', pins['target']['path']], args.repo)
    record = derive(image, pins, frames)
    args.out.mkdir(parents=True)
    providers = {}
    for name, tool in [('gnu', args.gnu), ('llvm', args.llvm), ('readelf', args.readelf)]:
        providers[name] = dict(argv=[tool, '--version'], sha256=sha(Path(tool).resolve().read_bytes()),
                               version=native([tool, '--version'], args.repo).strip())
    for category in ('bodies', 'contexts'):
        for item, p in zip(record[category], pins[category], strict=True):
            partitions, exports = {}, {}
            for label, tool, options in [('gnu', args.gnu, ['-Mintel', '--insn-width=16']),
                                          ('llvm', args.llvm, ['--x86-asm-syntax=intel'])]:
                argv = [tool, '-d', *options, '--start-address='+p['start'], '--stop-address='+p['end'], pins['target']['path']]
                text = native(argv, args.repo)
                decoded = qualify_export(text, image, p, pins)
                partitions[label] = [(a, raw.hex()) for a, raw, asm in decoded]
                name = p['name']+'.'+label+'.txt.gz'
                (args.out/name).write_bytes(gzip.compress(text.encode(), mtime=0))
                exports[label] = dict(argv=argv, rows=len(decoded), output=name, stdout_sha256=sha(text.encode()))
                if label == 'gnu' and category == 'bodies':
                    item['cfg'] = cfg(decoded)
            require(partitions['gnu'] == partitions['llvm'], 'native raw partitions differ')
            item['exports'] = exports
    require((args.repo/pins['target']['path']).read_bytes() == image.data, 'capture changed during read')
    record['providers'] = providers
    write_json(args.out/'records.json', record)
    print(json.dumps(dict(status='PASS static bindings only', complete_bodies=len(record['bodies']),
                          body_bytes=sum(x['bytes'] for x in record['bodies']),
                          contexts=len(record['contexts']), calls=len(record['calls']))))


if __name__ == '__main__':
    main()
