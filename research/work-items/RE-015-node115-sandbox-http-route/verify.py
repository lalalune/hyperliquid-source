"""Check the two HTTP callers, the selector arms, and the sandbox value formatter."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections

NODE = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def check(test, msg):
    if not test:
        raise ValueError(msg)


def observe():
    blob = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    check(hashlib.sha256(blob).hexdigest() == NODE, 'Wrong capture')
    loaded = [s for s in sections(blob) if s['flags'] & 2 and s['type'] != 8]

    def read(va, n):
        sec, = [s for s in loaded if s['address'] <= va and va+n <= s['address']+s['size']]
        off = sec['offset'] + va - sec['address']
        return blob[off:off+n]

    def operand(va, tag):
        op = bytes.fromhex(tag)
        check(read(va, len(op)) == op, f'Unexpected instruction at {va:#x}')
        after = va + len(op) + 4
        return after + struct.unpack('<i', read(after-4, 4))[0]

    root = 0x154afa0
    words = []
    for caller in (0x2ae800d, 0x2cb380d):
        check(read(caller+8, 3) == bytes.fromhex('c0e304'), 'Expected shift by four')
        load = caller + 0x23
        check(read(load, 2) == bytes.fromhex('48b8'), 'Missing packed selectors')
        selectors = struct.unpack('<4H', read(load+2, 8))
        check(read(load+12, 3) == bytes.fromhex('48d3e8'), 'Wrong selector shift')
        check(operand(caller+0x4a, 'e8') == root, 'Wrong helper')
        fmt = operand(caller+0x66, '488d35')
        check(read(fmt, 7) == b'\x04http\xc0\0', 'Wrong HTTP format literal')
        words.append(selectors)
    check(words[0] == words[1] == (6, 4, 3, 2), 'Disagreeing chain selections')
    jt = operand(root+0x23, '488d0d')
    arms = [jt+v for v in struct.unpack('<6i', read(jt, 24))]
    check(read(root+0x14, 4) == bytes.fromhex('6683e802'), 'Expected subtraction by two')
    check([arms[tag-2] for tag in words[0]] == [0x154b017,0x154b053,0x154b265,0x154afd3], 'Wrong arm')
    main = read(operand(0x154afe7, '0f1005'),16) + read(0x154aff3,8)
    local = read(operand(0x154b02b, '0f1005'),16) + read(0x154b039,2)
    test = read(operand(0x154b284, '0f1005'),16) + read(operand(0x154b279, '0f1005'),16)
    key = read(operand(0x154b089, '4c8d35'),10)
    template = read(operand(0x154b252, '488d35'),13)
    check(key == b'WebSandbox' and template == b'\x03://\xc0\x06:3001/\0', 'Wrong configuration or format')
    check(read(0x154b234,7) == bytes.fromhex('8b849810010000'), 'Wrong width of map value')
    table, = [s for s in loaded if s['name']=='.rela.dyn']
    slots = {p: d for p, kind, d in struct.iter_unpack('<QQq', read(table['address'], table['size'])) if kind == 8}
    formatter = slots[operand(0x154b246,'488b05')]
    record, = [w for w in json.loads((ROOT/'research/byte-windows.json').read_bytes())['windows']
               if w['start'] == formatter]
    check('Ipv4Addr' in record['label'] and 'Display' in record['label'], 'Wrong formatter binding')
    check(hashlib.sha256(read(formatter, record['end'] - formatter)).hexdigest() == record['target_body_sha256'],
          'Formatter body differs from registry')
    return {'caller_sites':[hex(a) for a in (0x2ae8057,0x2cb3857)], 'selectors': list(words[0]),
            'fixed_http':{k:'http'+v.decode() for k,v in [('Local',local),('Testnet',test),('Mainnet',main)]},
            'sandbox_key':key.decode(),'sandbox_descriptor_hex':template.hex(),
            'formatter_start':hex(formatter),'formatter_body_sha256':record['target_body_sha256']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--print', action='store_true', dest='show')
    result = observe()
    if p.parse_args().show:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        check(result == json.loads((HERE/'result.json').read_bytes()), 'Evidence drift')
        print('Two HTTP consumers, four chain selections and the IPv4 formatter verified.')
