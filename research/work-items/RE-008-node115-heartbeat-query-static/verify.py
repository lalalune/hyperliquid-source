#!/usr/bin/env python3
"""Recheck this packet against Node115 bytes; never execute/emulate the capture."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def environment(data, record):
    require(hashlib.sha256(data).hexdigest() == TARGET, 'target digest')
    for name, digest in record['helperSources'].items():
        require(hashlib.sha256((ROOT / 'tools' / name).read_bytes()).hexdigest() == digest,
                'helper source ' + name)
    sys.path.insert(0, str(ROOT / 'tools'))
    import fde_extents
    sections = fde_extents.sections(data)
    cies, fdes = fde_extents.eh_frame_records(data, sections)

    def at(va, size):
        choices = [s for s in sections if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(choices) == 1, 'ambiguous/non-file-backed virtual range')
        s = choices[0]
        offset = s['offset'] + va - s['address']
        return data[offset:offset + size]

    rela = next(s for s in sections if s['name'] == '.rela.dyn')
    rels = {}
    for offset in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        rels.setdefault(slot, []).append({'type': info & 0xffffffff,
                                         'symbolIndex': info >> 32, 'addend': hex(addend)})
    return at, cies, fdes, rels


def transfer_rows(rows, rels):
    result = []
    for row in rows:
        for ins in row['instructions']:
            if ins['mnemonic'] != 'call':
                continue
            raw = bytes.fromhex(ins['bytes'])
            va = int(ins['va'], 16)
            item = {'site': ins['va'], 'bytes': ins['bytes']}
            if len(raw) == 5 and raw[0] == 0xe8:
                item['directTarget'] = hex(va + 5 + struct.unpack_from('<i', raw, 1)[0])
            elif len(raw) == 6 and raw[:2] == b'\xff\x15':
                slot = va + 6 + struct.unpack_from('<i', raw, 2)[0]
                item.update(slot=hex(slot), relocations=rels.get(slot, []))
            else:
                item['unresolvedOperand'] = ins['operands']
            result.append(item)
    return result


def validate(record, at, cies, fdes, rels):
    require(record['targetSHA256'] == TARGET, 'record target identity')
    starts = [r['fde']['start'] for r in record['rows']]
    require(len(starts) == 9 and len(set(starts)) == 9, 'selected extent count')
    instruction_index = {}
    total = count = 0
    for row in record['rows']:
        f = row['fde']
        candidates = [x for x in fdes if x['start'] == f['start']]
        require(candidates == [f], 'exact unique FDE metadata')
        require(cies[f['cie']] == row['cie'], 'CIE metadata')
        require(row['bytes'] == f['end'] - f['start'], 'complete extent length')
        body = at(f['start'], row['bytes'])
        require(hashlib.sha256(body).hexdigest() == row['bodySHA256'], 'body digest')
        cursor = f['start']
        for ins in row['instructions']:
            raw = bytes.fromhex(ins['bytes'])
            require(int(ins['va'], 16) == cursor and 1 <= len(raw) <= 15,
                    'instruction partition')
            require(at(cursor, len(raw)) == raw, 'instruction bytes')
            instruction_index[cursor] = ins
            cursor += len(raw)
        require(cursor == f['end'], 'complete instruction partition')
        require(row['dualDecoderBytePairsEqual'] is True, 'original dual decode')
        total += row['bytes']
        count += len(row['instructions'])
    require(total == 6876 and count == 1488, 'explicit denominator')
    for loc in record['sourceLocations']:
        slot = int(loc['slot'], 16)
        require(rels.get(slot) == [{'type': 8, 'symbolIndex': 0,
                                   'addend': loc['fileVA']}], 'source path relocation')
        length, line, column = struct.unpack('<QII', at(slot + 8, 16))
        require((length, line, column) == (loc['fileLength'], loc['line'], loc['column']),
                'source location fields')
        require(at(int(loc['fileVA'], 16), length).decode() == loc['path'], 'source path bytes')
    for address, expected in record['constants'].items():
        require(at(int(address, 16), 8).hex() == expected, 'constant bytes')
    for address, expected in record['dataBlocks'].items():
        require(at(int(address, 16), len(bytes.fromhex(expected))).hex() == expected,
                'data block bytes')
    require(transfer_rows(record['rows'], rels) == record['calls'], 'call/relocation bindings')
    for site, target in [(0x5a71e3d, 0x64b8cf0), (0x5a720fe, 0x64b8d08)]:
        raw = bytes.fromhex(instruction_index[site]['bytes'])
        require(len(raw) == 7 and raw[:2] == b'\x48\x8d', 'source LEA instruction')
        require(site + 7 + struct.unpack_from('<i', raw, 3)[0] == target, 'source LEA destination')
    return {'completeFDEExtents': 9, 'targetBytes': total, 'instructionPairs': count}


def decoder_check(record, objdump, target):
    version = subprocess.check_output([objdump, '--version'], text=True, timeout=10).splitlines()[0]
    require('GNU objdump' in version, 'GNU objdump required')
    for row in record['rows']:
        f = row['fde']
        raw = subprocess.check_output([objdump, '-d', '--wide', '--insn-width=16', '-M', 'intel',
                                       '--start-address=' + str(f['start']),
                                       '--stop-address=' + str(f['end']), str(target)], timeout=30)
        pairs = []
        for line in raw.decode().splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)', line)
            if match and f['start'] <= int(match[1], 16) < f['end']:
                pairs.append((int(match[1], 16), bytes.fromhex(match[2]).hex()))
        require(pairs == [(int(i['va'], 16), i['bytes']) for i in row['instructions']],
                'fresh GNU / frozen Capstone pairs')
    return version


def negative_controls(record, env):
    results = []
    mutations = [
        ('wrong target', lambda r: r.update(targetSHA256='0' * 64)),
        ('wrong FDE end', lambda r: r['rows'][0]['fde'].update(end=r['rows'][0]['fde']['end'] - 1)),
        ('wrong CIE', lambda r: r['rows'][0]['cie'].update(augmentation='invalid')),
        ('missing instruction', lambda r: r['rows'][0]['instructions'].pop()),
        ('wrong instruction VA', lambda r: r['rows'][0]['instructions'][0].update(va='0x0')),
        ('wrong instruction bytes', lambda r: r['rows'][0]['instructions'][0].update(bytes='90')),
        ('wrong source line', lambda r: r['sourceLocations'][0].update(line=0)),
        ('wrong source path', lambda r: r['sourceLocations'][0].update(path='node/other.rs')),
        ('wrong constant', lambda r: r['constants'].update({'0x4597f8': '0000000000000000'})),
        ('wrong calendar table', lambda r: r['dataBlocks'].update({'0x46bcaa': 'ff'})),
        ('missing call', lambda r: r['calls'].pop()),
        ('wrong call metadata', lambda r: r['calls'][0].update(bytes='00')),
    ]
    for name, mutate in mutations:
        bad = copy.deepcopy(record)
        mutate(bad)
        try:
            validate(bad, *env)
        except ValueError as error:
            results.append({'control': name, 'rejected': True, 'reason': str(error)})
        else:
            raise ValueError('accepted corrupted record: ' + name)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--objdump', default='objdump')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    record = json.loads((PACKET / 'native.json').read_text(encoding='utf-8'))
    env = environment(args.target.read_bytes(), record)
    result = validate(record, *env)
    result.update(targetSHA256=TARGET, freshGNUVersion=decoder_check(record, args.objdump, args.target),
                  negativeControls=negative_controls(record, env), targetExecuted=False,
                  targetEmulated=False, sourceTargetComparisons=0, normalizationMasks=0)
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
