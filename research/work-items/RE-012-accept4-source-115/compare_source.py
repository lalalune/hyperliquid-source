"""Compare complete source function symbols; no target or object code executes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from accept4_source115 import inspect, Image, need, sha


class Object:
    def __init__(self, data):
        self.data = data
        h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
        need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:3] == (1, 62), 'Linux x86-64 ET_REL')
        need(h[11] == 64 and h[6] + h[11] * h[12] <= len(data), 'section table bounds')
        self.sh = [struct.unpack_from('<IIQQQQIIQQ', data, h[6] + i * h[11]) for i in range(h[12])]
        strings = self.contents(h[13])
        self.names = [strings[s[0]:].split(b'\0', 1)[0].decode() for s in self.sh]

    def contents(self, index):
        s = self.sh[index]
        need(s[4] + s[5] <= len(self.data), 'section contents bounds')
        return self.data[s[4]:s[4] + s[5]]

    def symbols(self, index):
        section = self.sh[index]; need(section[9] == 24, 'symbol entry width')
        strings = self.contents(section[6]); result = []
        for off in range(section[4], section[4] + section[5], 24):
            name, info, other, owner, value, size = struct.unpack_from('<IBBHQQ', self.data, off)
            result.append({'name': strings[name:].split(b'\0', 1)[0].decode(), 'info': info,
                           'other': other, 'section': owner, 'value': value, 'size': size})
        return result

    def relas(self):
        result = []
        for index, s in enumerate(self.sh):
            if s[1] != 4:
                continue
            need(s[9] == 24 and s[5] % 24 == 0, 'RELA entry width')
            symbols = self.symbols(s[6])
            for at in range(s[4], s[4] + s[5], 24):
                where, info, addend = struct.unpack_from('<QQq', self.data, at)
                sym = symbols[info >> 32]
                result.append({'owner': s[7], 'offset': where, 'kind': info & 0xffffffff,
                               'addend': addend, 'symbol': sym})
        return result


def source_body(data):
    obj = Object(data); symbols = obj.symbols(obj.names.index('.symtab'))
    prefix = '_ZN3mio3net3tcp8listener11TcpListener6accept17h'
    hits = [s for s in symbols if s['name'].startswith(prefix) and s['info'] & 15 == 2]
    need(len(hits) == 1, 'exactly one complete Mio TcpListener accept FUNC symbol')
    symbol = hits[0]; section = obj.contents(symbol['section'])
    need(symbol['size'] > 0 and symbol['value'] + symbol['size'] <= len(section), 'complete symbol extent')
    raw = section[symbol['value']:symbol['value'] + symbol['size']]
    rows = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, 0))
    need(rows and sum(i.size for i in rows) == len(raw), 'complete source decode')
    relas = obj.relas(); fields = [r for r in relas if r['owner'] == symbol['section']]
    need(all(symbol['value'] <= r['offset'] < symbol['value'] + symbol['size'] for r in fields), 'source relocation within selected whole symbol')
    # Bind the exact FDE through its PC-begin relocation; never infer its size
    # from a neighboring function, symbol suffix or truncated .text slice.
    eh_index = obj.names.index('.eh_frame'); eh = obj.contents(eh_index); at = 0; matches = []
    while at + 4 <= len(eh):
        n = struct.unpack_from('<I', eh, at)[0]
        if n == 0:
            break
        need(n >= 4 and at + 4 + n <= len(eh), 'source frame bounds')
        back = struct.unpack_from('<I', eh, at + 4)[0]
        rs = [r for r in relas if r['owner'] == eh_index and r['offset'] == at + 8
              and r['symbol']['section'] == symbol['section']]
        if back and rs:
            need(len(rs) == 1 and rs[0]['kind'] == 2, 'unique PC32 source frame relocation')
            need(rs[0]['symbol']['value'] + rs[0]['addend'] == symbol['value'], 'FDE PC begin identifies FUNC start')
            cie_at = at + 4 - back
            need(0 <= cie_at < at and eh[cie_at:cie_at + 24].hex() ==
                 '1400000000000000017a5200017810011b0c070890010000',
                 'source CIE declares pcrel sdata4 frame pointers')
            extent = struct.unpack_from('<I', eh, at + 12)[0]
            need(extent == symbol['size'], 'FDE covers complete source symbol')
            matches.append({'offset': at, 'raw_hex': eh[at:at + 4 + n].hex(), 'relocation': rs[0], 'extent': extent, 'cie_offset': cie_at, 'cie_raw_hex': eh[cie_at:cie_at + 24].hex()})
        at += 4 + n
    need(len(matches) == 1, 'unique complete source FDE')
    return raw, {'symbol': symbol, 'section': obj.names[symbol['section']], 'bytes': len(raw),
                 'sha256': sha(raw), 'instructions': len(rows), 'relocations': fields, 'fde': matches[0],
                 'rows': [{'offset': i.address, 'bytes': bytes(i.bytes).hex(), 'mnemonic': i.mnemonic,
                           'operands': i.op_str} for i in rows]}


def compare(target, source):
    # There is no instruction truncation, padding, opcode mask or alignment.
    # At unequal complete extents no normalized equality can hold either.
    return {'target_bytes': len(target), 'source_bytes': len(source),
            'raw_equal': target == source, 'same_extent': len(target) == len(source),
            'normalization': 'none', 'normalized_equal': target == source,
            'unmatched': target != source}


def record(target, object_raw):
    inspect(target); image = Image(target)
    body, source = source_body(object_raw)
    source['object_sha256'] = sha(object_raw)
    source['source_version_candidate'] = 'mio 1.0.2'
    source['build_reused_from'] = 'RE-012-listener-source-94'
    source['new_native_build_claimed'] = False
    # Bind actual call relocation semantics and every selected byte.
    need([r['symbol']['name'] for r in source['relocations']] ==
         ['accept4', '__errno_location', 'close'], 'three source import relocations')
    for r in source['relocations']:
        need(r['kind'] == 9 and r['addend'] == -4 and body[r['offset'] - 2:r['offset']] == b'\xff\x15',
             'source GOTPCREL call field')
    captured = image.read(0x475b050, 260)
    controls = {'identity': compare(body, body)['raw_equal'],
                'source_truncation': compare(body, body[:-1])['unmatched'],
                'source_extension': compare(body, body + b'\0')['unmatched'],
                'opcode_change': compare(body, bytes([body[0] ^ 1]) + body[1:])['unmatched']}
    need(all(controls.values()), 'whole source comparison controls')
    return body, {'target_sha256': sha(target), 'target_start': '0x475b050',
                  'target_end': '0x475b154', 'target_body_sha256': sha(captured),
                  'source': source, 'comparison': compare(captured, body),
                  'unique_target_intervals': 1, 'controls': controls,
                  'source_version_assignment_proved': False,
                  'source_error_publication': 'close call at +0xc8 before output writes at +0xd8/+0xe1',
                  'target_error_publication': 'output writes at 0x475b136/0x475b13a before close at 0x475b142',
                  'captured_execution': False, 'instruction_emulation': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    p.add_argument('--object', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    body, result = record(args.target.read_bytes(), args.object.read_bytes())
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'candidate-body.bin').write_bytes(body)
    (args.out / 'comparison.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'comparison': result['comparison'], 'source_instructions': result['source']['instructions']}))
