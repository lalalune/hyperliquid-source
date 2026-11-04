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
from keepalive_source115 import inspect, Image, need, sha, CALLERS, BODIES


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
    prefix = '_ZN7socket23sys17set_tcp_keepalive17h'
    hits = [s for s in symbols if s['name'].startswith(prefix) and s['info'] & 15 == 2]
    need(len(hits) == 1, 'exactly one complete internal keepalive FUNC symbol')
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
            need(0 <= cie_at < at and eh[cie_at:cie_at+24].hex() ==
                 '1400000000000000017a5200017810011b0c070890010000', 'source CIE pcrel-sdata4 encoding')
            extent = struct.unpack_from('<I', eh, at + 12)[0]
            need(extent == symbol['size'], 'FDE covers complete source symbol')
            matches.append({'offset': at, 'raw_hex': eh[at:at + 4 + n].hex(), 'relocation': rs[0], 'extent': extent})
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


def main(args):
    target = args.target.read_bytes(); inspect(target); im = Image(target)
    args.out.mkdir(parents=True, exist_ok=False)
    sources = []; comparisons = []
    for version in ['0.4.10', '0.5.7']:
        path = args.build / ('socket2-' + version) / 'opt0/socket2.o'
        data = path.read_bytes(); raw, record = source_body(data)
        (args.out / ('socket2-' + version + '-internal.bin')).write_bytes(raw)
        record.update({'version_candidate': version, 'object_sha256': sha(data), 'optimization': 0})
        sources.append(record)
        for va in CALLERS:
            comparisons.append({'target_start': hex(va), 'source_version_candidate': version,
                                **compare(im.read(va, BODIES[va][0] - va), raw)})
    controls = {'identity': compare(raw, raw)['raw_equal'],
                'appended_byte_rejected': compare(raw, raw + b'\0')['unmatched'],
                'removed_byte_rejected': compare(raw, raw[:-1])['unmatched'],
                'opcode_change_rejected': compare(raw, bytes([raw[0] ^ 1]) + raw[1:])['unmatched']}
    need(all(controls.values()), 'whole-body comparison controls')
    result = {'target_sha256': sha(target), 'sources': sources, 'comparisons': comparisons,
              'unique_target_windows': 2, 'alternative_candidate_comparisons': 4,
              'raw_equal_comparisons': sum(c['raw_equal'] for c in comparisons),
              'normalized_only_comparisons': 0, 'unmatched_comparisons': sum(c['unmatched'] for c in comparisons),
              'controls': controls, 'version_assignment_proved': False,
              'scope': 'Complete symbol/FDE identity comparison; opt0 helper calls remain explicit, not semantic target equivalence.'}
    (args.out / 'comparison.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ['sources', 'comparisons']}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    main(p.parse_args())
