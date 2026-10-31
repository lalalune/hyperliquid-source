#!/usr/bin/env python3
"""Static node #94 gossip RPC timeout / retry constants, checked from authenticated bytes.

Question: which f64 second constants and retry counts do the gossip RPC
request paths store next to their descriptors, and is there a 60-second
connect timeout in the request futures as the lead source claims?

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; RIP-relative LEA / movsd / call
targets are decoded here and the referenced strings and f64 constants are read
back from their sections.  Nothing from the binary is executed.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = 'artifacts/node/94/hl-node'
SECONDS_TO_MICROS = 0x20ae60
FMT_SLOT = 0x576e040

# (FDE, window VA, exact bytes, descriptor LEA length, descriptor bytes, f64 immediate, f64 movsd constant)
TIMEOUTS = (
    dict(name='gossip_rpc_request (4001 verified path)', fde=0x1fd4570, va=0x1fd4656,
         hex='4c8d3db3ff3efe' '4c897b60' '48c7436812000000' '48894b70' '48895378' 'c6833801000000'
             '48b80000000000002440' '48898370040000' '488d83380d0000' '4889442410' 'c683380d000000'
             'f20f1005046223fe',
         desc=b'gossip_rpc_request', imm_at=0x1fd4678, movsd_at=0x1fd469c),
    dict(name='verify_rpc (4001 verified path)', fde=0x1fd4570, va=0x1fd4eff,
         hex='4c8d3d33f73efe' '4c897b20' '48c743280a000000' '66c743300000' '894b32' '66894336'
             'c6831801000000' '48b80000000000001440' '48898320010000' '488d83c8030000' '4889442420'
             'c683c803000000' 'f20f10053e5923fe',
         desc=b'verify_rpc', imm_at=0x1fd4f26, movsd_at=0x1fd4f4a),
    dict(name='gossip_rpc_request wrapper', fde=0x226bb20, va=0x226bb82,
         hex='4c8d3584be16fe' '4c897338' '48c7434012000000' '48894348' '48894b50' 'c6831001000000'
             '48b80000000000002440' '48898348040000' '488d83100d0000' '4889442418' 'c683100d000000'
             'f20f1005d8ecf9fd',
         desc=b'gossip_rpc_request', imm_at=0x226bba4, movsd_at=0x226bbc8),
    dict(name='gossip_rpc_request wrapper', fde=0x435cb20, va=0x435cb73,
         hex='4c8d35354539fc' '4c897338' '48c7434012000000' '48894348' '48894b50'
             'c6831001000000' '48b80000000000002440' '48898348040000' '488d83100d0000' '4889442418'
             'c683100d000000' 'f20f1005e7dceafb',
         desc=b'gossip_rpc_request', imm_at=0x435cb95, movsd_at=0x435cbb9),
)

# lea rsi,[template]; lea rdi; lea rdx; call [fmt]; ... record at [rbx+0x148]: {r14, desc ptr, desc len, 10, 2.0}
RETRIES = (
    dict(fde=0x2039060, va=0x2039253, writer_call=0x20399f7, sixty_at=0x20399c0,
         hex='488d35ad8e1bfe' '488dbc2498000000' '488d942450010000' 'ff15d04d7303'),
    dict(fde=0x4387f40, va=0x4388133, writer_call=0x43888d7, sixty_at=0x43888a0,
         hex='488d35cd9fe6fb' '488dbc2498000000' '488d942450010000' 'ff15f05e3e01'),
)
RECORD = ('488b8424a8000000' '48898380010000' 'f30f6f842498000000' 'f30f7f8370010000'
          '488b8378010000' '488b9380010000' '488d8b48010000' '4c89b348010000' '48898350010000'
          '48899358010000' '48c783600100000a000000' '48b80000000000000040' '48898368010000')
RETRY_TEMPLATE_TEXT = b'rpc connect '
# mov QWORD [rbx+disp],10; movabs rax,2.0
CENSUS = re.compile(rb'\x48\xc7(?:\x43(.)|\x83(....))\x0a\x00\x00\x00\x48\xb8' + struct.pack('<d', 2.0), re.S)
CENSUS_COUNT = 8
# lea rax,[rip+desc]; mov [rbx+disp-0x10],rax; mov QWORD [rbx+disp-8],len
STATIC_DESC = re.compile(rb'\x48\x8d\x05(....)\x48\x89\x83(....)\x48\xc7\x83(....)(....)', re.S)
MOVABS_F64 = re.compile(rb'[\x48\x49]\xb8(?=(.{8}))', re.S)
RIP_MOVSD = re.compile(rb'\xf2[\x40-\x4f]?\x0f\x10[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](?=(....))', re.S)


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        self.relative = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def section_of(self, va):
        hits = [s['name'] for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va < s['address'] + s['size']]
        return hits[0] if len(hits) == 1 else None

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, start):
        hits = [f for f in self.fdes if f[0] == start]
        require(len(hits) == 1, f'{start:#x} is not exactly one FDE start')
        return hits[0]

    def expect(self, va, want, what):
        want = bytes.fromhex(want)
        require(self.read(va, len(want)) == want, f'{what} at {va:#x}: bytes changed')

    def rip(self, va, length):
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]

    def f64(self, va):
        return struct.unpack('<d', self.read(va, 8))[0]


def inside(img, fde, lo, hi):
    start, end = img.fde(fde)
    require(start <= lo and hi <= end, f'window {lo:#x}..{hi:#x} is outside FDE {fde:#x}')


def f64_sites(img, fde):
    """Every movabs-r64 imm64 and RIP-relative movsd load in an FDE, decoded to f64."""
    start, end = img.fde(fde)
    body = img.read(start, end - start)
    imms = [(start + m.start(), struct.unpack('<d', m.group(1))[0]) for m in MOVABS_F64.finditer(body)]
    loads = []
    for m in RIP_MOVSD.finditer(body):
        va = start + m.start()
        length = m.end() - m.start() + 4
        target = va + length + struct.unpack('<i', m.group(1))[0]
        if img.section_of(target) == '.rodata':
            loads.append((va, target, img.f64(target)))
    return imms, loads


def check_timeout(img, t):
    raw = bytes.fromhex(t['hex'])
    inside(img, t['fde'], t['va'], t['va'] + len(raw))
    img.expect(t['va'], t['hex'], t['name'])
    desc_va = img.rip(t['va'], 7)
    desc = img.read(desc_va, len(t['desc']))
    require(desc == t['desc'], f"{t['name']}: descriptor at {desc_va:#x} is {desc!r}")
    store = raw[7 + 4:7 + 4 + 8]
    require(store[:3] == b'\x48\xc7\x43' and struct.unpack('<I', store[4:8])[0] == len(t['desc']),
            f"{t['name']}: descriptor length store is not {len(t['desc'])}")
    imm = struct.unpack('<d', img.read(t['imm_at'] + 2, 8))[0]
    const_va = img.rip(t['movsd_at'], 8)
    const = img.f64(const_va)
    require(imm == const, f"{t['name']}: immediate {imm} != movsd constant {const}")
    start, end = img.fde(t['fde'])
    body = img.read(start, end - start)
    mul = [start + m.start() for m in re.finditer(rb'\xf2[\x40-\x4f]?\x0f\x59[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', body)
           if img.rip(start + m.start(), m.end() - m.start() + 4) == SECONDS_TO_MICROS]
    require(mul, f"{t['name']}: no multiply by the 1e6 constant in FDE {t['fde']:#x}")
    return dict(name=t['name'], fde=hex(t['fde']), descriptor=t['desc'].decode(), descriptor_va=hex(desc_va),
                descriptor_len=len(t['desc']), seconds=imm, seconds_imm_at=hex(t['imm_at']),
                seconds_const=hex(const_va), micros_multiplies=[hex(v) for v in mul])


def check_retry(img, r):
    head, rec = bytes.fromhex(r['hex']), bytes.fromhex(RECORD)
    lo, hi = r['va'], r['va'] + len(head) + len(rec)
    inside(img, r['fde'], lo, hi)
    img.expect(r['va'], r['hex'], 'retry descriptor format')
    img.expect(r['va'] + len(head), RECORD, 'retry record stores')
    template = img.rip(r['va'], 7)
    require(img.read(template + 1, len(RETRY_TEMPLATE_TEXT)) == RETRY_TEMPLATE_TEXT,
            f'template {template:#x} does not carry {RETRY_TEMPLATE_TEXT!r}')
    slot = img.rip(r['va'] + 23, 6)
    require(slot == FMT_SLOT and slot in img.relative, f'format call slot {slot:#x} is not the RELATIVE {FMT_SLOT:#x}')
    rec_va = r['va'] + len(head)
    tries_at = rec_va + rec.index(bytes.fromhex('48c78360010000'))
    secs_at = rec_va + rec.index(bytes.fromhex('48b8'))
    tries = struct.unpack('<I', img.read(tries_at + 7, 4))[0]
    secs = struct.unpack('<d', img.read(secs_at + 2, 8))[0]
    imms, loads = f64_sites(img, r['fde'])
    sixty = [hex(va) for va, v in imms if v == 60.0] + [hex(va) for va, _, v in loads if v == 60.0]
    require(sixty == [hex(r['sixty_at'])], f"FDE {r['fde']:#x}: 60.0 sites are {sixty}")
    require(0 < r['writer_call'] - r['sixty_at'] < 0x40, 'the 60.0 immediate is not next to the writer call')
    img.expect(r['writer_call'], 'e8', 'writer call opcode')
    return dict(fde=hex(r['fde']), template=hex(template), format_slot=hex(slot), format_slot_target=hex(img.relative[slot]),
                record_base='[rbx+0x148]', tries=tries, tries_store=hex(tries_at), sleep_seconds=secs,
                sleep_store=hex(secs_at), sixty_sites=sixty, writer_call=hex(r['writer_call']),
                writer_target=hex(img.rip(r['writer_call'], 5)),
                f64_immediates=sorted({v for _, v in imms if 1e-6 < abs(v) < 1e7}))


def formatted_template(img, va):
    """Last call through FMT_SLOT within 0x90 bytes before va, and the last `lea rsi,[rip+t]` within 0x40 before it."""
    window = img.read(va - 0x90, 0x90)
    calls = [va - 0x90 + m.start() for m in re.finditer(rb'\xff\x15', window)
             if img.rip(va - 0x90 + m.start(), 6) == FMT_SLOT]
    require(calls, f'census site {va:#x}: no format call through {FMT_SLOT:#x} before it')
    call = calls[-1]
    before = img.read(call - 0x40, 0x40)
    leas = [call - 0x40 + m.start() for m in re.finditer(rb'\x48\x8d\x35', before) if m.start() + 7 <= 0x40]
    require(leas, f'census site {va:#x}: no lea rsi template before format call {call:#x}')
    template = img.rip(leas[-1], 7)
    n = img.read(template, 1)[0]
    literal = img.read(template + 1, n)
    require(all(0x20 <= c < 0x7f for c in literal), f'template {template:#x} literal is not printable')
    return dict(template_lea=hex(leas[-1]), format_call=hex(call), template=hex(template),
                template_literal=literal.decode())


def retry_census(img):
    """Every `mov QWORD [rbx+d],10; movabs rax,2.0` in .text, with the descriptor stored before it."""
    text = next(s for s in img.secs if s['name'] == '.text' and s['type'] != 8)
    body = img.data[text['offset']:text['offset'] + text['size']]
    matches = list(CENSUS.finditer(body))
    require(len(matches) == CENSUS_COUNT, f'{len(matches)} retry-record sites, expected {CENSUS_COUNT}')
    rows = []
    for m in matches:
        va = text['address'] + m.start()
        disp = struct.unpack('<b', m.group(1))[0] if m.group(1) is not None else struct.unpack('<i', m.group(2))[0]
        start = [f for f in img.fdes if f[0] <= va < f[1]]
        require(len(start) == 1, f'census site {va:#x} is not in exactly one FDE')
        row = dict(va=hex(va), fde=hex(start[0][0]), count_slot=f'[rbx+{disp:#x}]')
        head = img.read(va - 25, 25)
        s = STATIC_DESC.fullmatch(head)
        if s and struct.unpack('<i', s.group(2))[0] == disp - 0x10 and struct.unpack('<i', s.group(3))[0] == disp - 8:
            desc_va = va - 25 + 7 + struct.unpack('<i', s.group(1))[0]
            length = struct.unpack('<I', s.group(4))[0]
            text_ = img.read(desc_va, length)
            require(all(0x20 <= c < 0x7f for c in text_), f'static descriptor at {desc_va:#x} is not printable')
            row.update(descriptor='static', descriptor_va=hex(desc_va), descriptor_text=text_.decode())
        else:
            row.update(descriptor='not static (no RIP LEA + immediate length store before the count)')
            row.update(formatted_template(img, va))
        row['end'] = hex(va + m.end() - m.start())
        rows.append(row)
    return rows


def analyse(data):
    img = Image(data)
    return dict(target=TARGET, seconds_to_micros=img.f64(SECONDS_TO_MICROS),
                timeouts=[check_timeout(img, t) for t in TIMEOUTS],
                retries=[check_retry(img, r) for r in RETRIES],
                retry_census=retry_census(img))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == TARGET)
    path = ROOT / TARGET
    check(path, identity)
    result = dict(analyse(path.read_bytes()), target_sha256=identity['sha256'])
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    for t in result['timeouts']:
        print(f"{t['fde']} {t['descriptor']!r}: {t['seconds']} s, scaled by {result['seconds_to_micros']}")
    for r in result['retries']:
        print(f"{r['fde']} rpc connect retry: tries={r['tries']} sleep={r['sleep_seconds']} s; "
              f"only 60.0 at {r['sixty_sites']} feeds writer {r['writer_call']}")
    statics = sorted({r['descriptor_text'] for r in result['retry_census'] if 'descriptor_text' in r})
    print(f"{len(result['retry_census'])} (10, 2.0) retry records; static descriptors {statics}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
