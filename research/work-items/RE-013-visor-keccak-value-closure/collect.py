#!/usr/bin/env python3
"""Static native evidence, never executes/evaluates captured instructions.

ELF/parser mechanics adapted from independently authored MIT
RE-013-visor-duration-value-rust/collect.py, SHA256 4983b30f2864cb444b8b572d3baa63569d00a7d2fc0dab5a3d5c818845f70bc5.
The new native bindings and proof are independent; no prior packet is imported.
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
        self.headers = headers
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


def symbol(image, number):
    h = image.sections['.dynsym']
    require(h[9] == 24 and number < h[5] // 24, 'symbol bounds')
    raw = image.file(h[4] + number * 24, 24)
    name, info, other, section, value, size = struct.unpack('<IBBHQQ', raw)
    strings = image.headers[h[6]]
    data = image.file(strings[4], strings[5])
    end = data.find(b'\0', name)
    require(0 <= name <= end, 'symbol string bounds')
    return dict(index=number, name=data[name:end].decode(), raw=raw.hex(),
                file_offset=h[4]+number*24, name_file_offset=strings[4]+name)


def frame(image, frames, start, end):
    matches = list(re.finditer(r'^([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+ FDE cie=([0-9a-f]+) pc='
                  + f'{start:016x}..{end:016x}$', frames, re.M))
    require(len(matches) == 1, 'unique exact FDE')
    m = matches[0]
    base = image.sections['.eh_frame'][3]
    fde, cie = base+int(m[1], 16), base+int(m[2], 16)
    f, c = image.record(fde), image.record(cie)
    require(fde+4-struct.unpack_from('<I', f, 4)[0] == cie, 'FDE CIE relation')
    require(fde+8+struct.unpack_from('<i', f, 8)[0] == start, 'FDE start')
    require(struct.unpack_from('<I', f, 12)[0] == end-start, 'FDE extent')
    item = dict(fde_va=hex(fde), cie_va=hex(cie), fde_raw=f.hex(), cie_raw=c.hex(), header=m[0])
    if c[4:17] == bytes.fromhex('00000000017a5200017810011b'):
        require(f[16] == 0, 'simple FDE augmentation')
    else:
        require(c[4:19] == bytes.fromhex('00000000017a504c5200017810079b') and
                c[23:25] == b'\x1b\x1b' and f[16] == 4, 'EH encoding')
        item['personality_slot'] = hex(cie+19+struct.unpack_from('<i', c, 19)[0])
        item['lsda_va'] = hex(fde+17+struct.unpack_from('<i', f, 17)[0])
    return item


def uleb(image, address):
    result, shift, raw = 0, 0, bytearray()
    while True:
        b = image.at(address+len(raw), 1)[0]
        raw.append(b)
        result |= (b & 127) << shift
        if b < 128:
            return result, bytes(raw)
        shift += 7
        require(shift < 64, 'ULEB overflow')


def lsda(image, address, function):
    # This selected cleanup-only table has omitted LPStart/type table, ULEB calls.
    require(image.at(address, 3) == b'\xff\xff\x01', 'selected LSDA encodings')
    length, raw_length = uleb(image, address+3)
    cursor, end = address+3+len(raw_length), address+3+len(raw_length)+length
    entries = []
    while cursor < end:
        values = []
        for _ in range(4):
            value, raw = uleb(image, cursor)
            cursor += len(raw)
            values.append(value)
        begin, extent, landing, action = values
        entries.append(dict(begin=hex(function+begin), end=hex(function+begin+extent),
                            landing=hex(function+landing) if landing else None, action=action))
    require(cursor == end and all(e['action'] == 0 for e in entries), 'cleanup-only LSDA extent')
    return dict(va=hex(address), raw=image.at(address, end-address).hex(), entries=entries)


def native(argv, cwd):
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=180)
    require(p.returncode == 0 and not p.stderr, 'native provider failed: '+str(argv))
    return p.stdout


def branch(raw, address):
    if raw[0] in range(0x70, 0x80) or raw[0] == 0xeb:
        return address+2+int.from_bytes(raw[1:2], 'little', signed=True)
    if raw[:1] == b'\xe9':
        return address+5+int.from_bytes(raw[1:5], 'little', signed=True)
    if raw[:1] == b'\x0f' and raw[1] in range(0x80, 0x90):
        return address+6+int.from_bytes(raw[2:6], 'little', signed=True)
    raise ValueError('unadmitted branch encoding')


def binding(image, all_relas, slot):
    hits = [r for r in all_relas if r['destination'] < slot+8 and slot < r['destination']+8]
    require(len(hits) == 1 and hits[0]['destination'] == slot, 'unique exact slot RELA')
    r = hits[0]
    require(r['type'] in (6, 7, 8), 'call slot RELA type')
    return dict(slot=hex(slot), file_raw=image.at(slot, 8).hex(), rela=r,
                symbol=symbol(image, r['symbol']) if r['symbol'] else None)


def semantic_fields(image, schema):
    """Read specific operands/data; no instruction state or execution model."""
    return {p['name']: int.from_bytes(image.at(int(p['va'], 16), p['bytes']), 'little')
            for p in schema}


def bindings(image, layout, frames):
    all_relas = relas(image)
    require(set(r['type'] for r in all_relas) <= {6, 7, 8}, 'unadmitted RELA writer width')
    hb = image.sections['.eh_frame_hdr'][3]
    require(image.at(hb, 4) == bytes.fromhex('011b033b'), 'unwind header encoding')
    require(hb+4+struct.unpack('<i', image.at(hb+4, 4))[0] == image.sections['.eh_frame'][3], 'unwind base')
    count = struct.unpack('<I', image.at(hb+8, 4))[0]
    require(12+8*count == image.sections['.eh_frame_hdr'][5], 'unwind extent')
    index = [tuple(hb+x for x in struct.unpack('<ii', image.at(hb+12+8*i, 8))) for i in range(count)]
    require(all(a[0] < b[0] for a, b in zip(index, index[1:])), 'unwind order')
    result = dict(bodies=[], calls=[], branches=[], literals=[], fields=semantic_fields(image, layout['fields']),
                  rela_count=len(all_relas), rela_types=dict(Counter(str(r['type']) for r in all_relas)))
    protected = [(hb, hb+image.sections['.eh_frame_hdr'][5])]
    for p in layout['bodies']:
        a, z = int(p['start'], 16), int(p['end'], 16)
        text = image.sections['.text']
        require(text[3] <= a < z <= text[3]+text[5] and text[2] & 4, 'text extent')
        require(any(h[0] == 1 and h[1]&1 and h[3] <= a < z <= h[3]+h[5] for h in image.loads), 'executable load')
        f = frame(image, frames, a, z)
        hits = [i for i, pair in enumerate(index) if pair == (a, int(f['fde_va'], 16))]
        require(len(hits) == 1, 'unique unwind index binding')
        f['index_va'] = hex(hb+12+8*hits[0]); f['index_raw'] = image.at(int(f['index_va'],16),8).hex()
        result['bodies'].append(dict(p, file_offset=image.offset(a,z-a), sha256=sha(image.at(a,z-a)), frame=f))
        protected.append((a,z))
        for va, raw in [('fde_va','fde_raw'), ('cie_va','cie_raw')]:
            protected.append((int(f[va],16),int(f[va],16)+len(bytes.fromhex(f[raw]))))
        if 'lsda_va' in f:
            f['lsda'] = lsda(image, int(f['lsda_va'],16), a)
            f['personality'] = binding(image, all_relas, int(f['personality_slot'],16))
            protected.append((int(f['lsda_va'],16),int(f['lsda_va'],16)+len(bytes.fromhex(f['lsda']['raw']))))
    for p in layout['calls']:
        a, n = int(p['site'],16), p['bytes']
        raw = image.at(a,n)
        item = dict(p, raw=raw.hex())
        if p['kind'] == 'direct':
            require(n == 5 and raw[0] == 0xe8, 'direct call encoding')
            item['target'] = hex(a+5+struct.unpack_from('<i',raw,1)[0])
        elif p['kind'] == 'rip-slot':
            require(n == 6 and raw[:2] == b'\xff\x15', 'RIP call encoding')
            item['binding'] = binding(image,all_relas,a+6+struct.unpack_from('<i',raw,2)[0])
        else:
            require(p['kind'] == 'rbx-from-slot' and raw == b'\xff\xd3', 'register call encoding')
            producer = int(p['producer'],16)
            load = image.at(producer,7)
            require(load[:3] == b'\x48\x8b\x1d', 'RBX load producer')
            item['producer_raw'] = load.hex()
            item['binding'] = binding(image,all_relas,producer+7+struct.unpack_from('<i',load,3)[0])
        result['calls'].append(item)
    for p in layout['branches']:
        a = int(p['site'],16)
        raw = image.at(a,p['bytes'])
        result['branches'].append(dict(p, target=hex(branch(raw,a))))
    for p in layout['literals']:
        a = int(p['va'],16); raw = image.at(a,p['bytes'])
        result['literals'].append(dict(p, raw=raw.hex(), file_offset=image.offset(a,len(raw))))
        protected.append((a,a+len(raw)))
    # Panic-location records contain legitimate relocations; retain their bindings.
    result['opaque_data'] = []
    for p in layout['opaque_data']:
        a = int(p['va'],16); z = a+p['bytes']
        result['opaque_data'].append(dict(p, raw=image.at(a,z-a).hex(),
            relas=[r for r in all_relas if r['destination'] < z and a < r['destination']+8]))
    result['data_edges'] = []
    for p in layout['data_edges']:
        a=int(p['site'],16); raw=image.at(a,7)
        require(raw[0] in (0x48,0x4c) and raw[1]==0x8d and raw[2]&0xc7==5,'RIP LEA encoding')
        result['data_edges'].append(dict(p,raw=raw.hex(),target=hex(a+7+struct.unpack_from('<i',raw,3)[0])))
    a=0x7a6820; raw=image.at(a,16)
    require(raw[:2]==b'\xff\x25','Unwind PLT entry')
    result['unwind_plt']=dict(va=hex(a),raw=raw.hex(),binding=binding(image,all_relas,a+6+struct.unpack_from('<i',raw,2)[0]))
    protected.append((a,a+16))
    require(not any(r['destination'] < z and a < r['destination']+8 for r in all_relas for a,z in protected),
            'RELA overlaps code/constant/unwind evidence')
    result['protected_rela_overlap'] = []
    result['scope'] = 'Four complete FDEs; one-shot initialized digest value and conditional wrapper only. No target execution.'
    return result


def admit_fields(image, pins):
    require(semantic_fields(image,pins['layout']['fields']) == pins['bindings']['fields'], 'operand/data field mismatch')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo',type=Path,default=REPO)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--gnu',default='/opt/homebrew/opt/binutils/bin/objdump')
    ap.add_argument('--llvm',default='/usr/bin/objdump')
    ap.add_argument('--readelf',default='/opt/homebrew/opt/binutils/bin/readelf')
    args = ap.parse_args()
    require(not args.out.exists(),'fresh output required')
    pins=json.loads((HERE/'BASIS-PINS.json').read_text())
    image=authenticate(args.repo,pins)
    frames=native([args.readelf,'--debug-dump=frames',pins['target']['path']],args.repo)
    measured=bindings(image,pins['layout'],frames)
    require(measured==pins['bindings'],'native evidence graph differs')
    args.out.mkdir(parents=True)
    providers={}
    for name,tool in [('gnu',args.gnu),('llvm',args.llvm),('readelf',args.readelf)]:
        providers[name]=dict(path=tool,sha256=sha(Path(tool).resolve().read_bytes()),
                             version=native([tool,'--version'],args.repo).strip())
    exports=[]
    for body in pins['layout']['bodies']:
        partitions={}
        for label,tool,opts in [('gnu',args.gnu,['-Mintel','--insn-width=16']),('llvm',args.llvm,['--x86-asm-syntax=intel'])]:
            argv=[tool,'-d',*opts,'--start-address='+body['start'],'--stop-address='+body['end'],pins['target']['path']]
            text=native(argv,args.repo)
            decoded=rows(text,image,int(body['start'],16),int(body['end'],16))
            require(len(decoded)==body['rows'],'row count')
            calls=[hex(a) for a,r,t in decoded if t.startswith('call')]
            require(calls==[c['site'] for c in pins['layout']['calls'] if int(body['start'],16)<=int(c['site'],16)<int(body['end'],16)],'full call inventory')
            branches=[hex(a) for a,r,t in decoded if t.split()[0].startswith('j')]
            require(branches==[c['site'] for c in pins['layout']['branches'] if int(body['start'],16)<=int(c['site'],16)<int(body['end'],16)],'full branch inventory')
            boundaries={a for a,r,t in decoded}
            require(all(branch(r,a) in boundaries for a,r,t in decoded if t.split()[0].startswith('j')),
                    'direct branch does not target an admitted instruction boundary')
            require(any(t.split()[0].startswith('ret') for a,r,t in decoded),'vacuous return inventory')
            partitions[label]=[(a,r.hex()) for a,r,t in decoded]
            name=body['name']+'.'+label+'.txt.gz'
            (args.out/name).write_bytes(gzip.compress(text.encode(),mtime=0))
            exports.append(dict(argv=argv,exit=0,stderr='',file=name,sha256=sha(text.encode()),rows=len(decoded)))
        require(partitions['gnu']==partitions['llvm'],'independent raw partitions differ')
    require((args.repo/pins['target']['path']).read_bytes()==image.data,'capture changed')
    write_json(args.out/'records.json',dict(bindings=measured,providers=providers,exports=exports))
    print(json.dumps(dict(status='PASS static evidence only',bodies=4,bytes=3612,rows=877,calls=len(measured['calls']))))


if __name__=='__main__':
    main()
