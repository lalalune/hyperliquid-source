"""Join the recorded Zstandard body and its two data references to frame behavior."""
import argparse
import csv
import ctypes as c
import hashlib
import json
import re
import struct
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections

NODE = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
VENDOR = HERE.parent / 'RE-002-node115-vendor-census'
LINKAGE = HERE.parent / 'RE-002-node115-native-zstd-stream-linkage' / 'linkage.tsv'
CRATES = {'eb81183ddd97d0c74cedf1d50d85c8d08c1b8b68ee863bdee9e706eedba1a237',
          '481ada9c543b2323cbb7bbdbb5249177fbf0188ed959ed2c15e4b22421c84ed3'}
UNKNOWN = (1 << 64) - 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_tables(crate):
    digest = sha(crate.read_bytes())
    require(digest in CRATES, 'Unexpected source archive')
    with tarfile.open(crate) as archive:
        header, = [m for m in archive if m.name.endswith('/zstd/lib/common/zstd_internal.h')]
        source = archive.extractfile(header).read().decode()
    tables = {}
    for name in ('fcs', 'did'):
        values, = re.findall(r'ZSTD_' + name + r'_fieldSize\[4\] = \{ ([\d, ]+) \}', source)
        tables[name] = [int(v) for v in values.split(',')]
    return digest, tables


def linked_image(tables):
    node = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    require(sha(node) == NODE, 'Unexpected target digest')
    text, = [s for s in sections(node) if s['name'] == '.text']
    rodata, = [s for s in sections(node) if s['name'] == '.rodata']
    items = json.loads((VENDOR / 'census.json').read_bytes())['records']
    row, = [r for r in items if r['symbol'] == 'ZSTD_getFrameContentSize']
    start, end = row['start'], row['end']
    offset = text['offset'] + start - text['address']
    target = node[offset:offset + end - start]
    src_offset = row['source_offset']
    reference = (VENDOR / 'bodies.bin').read_bytes()[src_offset:src_offset + len(target)]
    require(sha(target) == row['target_body_sha256'] and sha(reference) == row['source_body_sha256'],
            'Body hashes disagree with the census')
    with LINKAGE.open() as f:
        next(f)
        calls = {int(r[1], 16) + 1 - start: int(r[4], 16)
                 for r in csv.reader(f, delimiter='\t') if int(r[0], 16) == start}
    patched = bytearray(reference)
    data_refs = {}
    for field in row['relocations']:
        off = field['offset']
        require(field['width'] == 4 and field['addend'] == -4, 'Unexpected relocation layout')
        if field['kind'] == 4:
            dest = calls.pop(off)
        else:
            require(field['kind'] == 2 and target[off-3:off] == bytes.fromhex('488d0d'),
                    'Expected a RIP-relative load address')
            dest = start + off + 4 + struct.unpack_from('<i', target, off)[0]
            require(rodata['address'] <= dest <= rodata['address'] + rodata['size'] - 32,
                    'Table outside read-only data')
            fileoff = rodata['offset'] + dest - rodata['address']
            values = list(struct.unpack_from('<4Q', node, fileoff))
            name, = [key for key, expected in tables.items() if expected == values]
            require(name not in data_refs, 'Repeated table')
            data_refs[name] = {'instruction_va': hex(start + off - 3), 'table_va': hex(dest),
                               'bytes_sha256': sha(node[fileoff:fileoff+32]), 'widths': values}
        struct.pack_into('<i', patched, off, dest - (start + off + 4))
    require(not calls and data_refs.keys() == tables.keys() and patched == target,
            'Full reference body and all fields must agree')
    return {'body_start': hex(start), 'body_bytes': len(target), 'body_sha256': sha(target),
            'relocations': len(row['relocations']), 'data_refs': data_refs}


class Header(c.Structure):
    _fields_ = [('content', c.c_uint64), ('window', c.c_uint64)] + [
        (key, c.c_uint) for key in
        ('block_max', 'type', 'header_size', 'dictionary', 'checksum', 'reserved1', 'reserved2')]


def public_controls(lib, widths):
    api = c.CDLL(str(lib.resolve()))
    require(api.ZSTD_versionNumber() == 10507, 'Expected public libzstd 1.5.7')
    api.ZSTD_getFrameContentSize.argtypes = [c.c_void_p, c.c_size_t]
    api.ZSTD_getFrameContentSize.restype = c.c_uint64
    api.ZSTD_getFrameHeader.argtypes = [c.POINTER(Header), c.c_void_p, c.c_size_t]
    api.ZSTD_getFrameHeader.restype = c.c_size_t
    records = []
    for desc in range(256):
        if desc & 0x18:  # unused and reserved bits are zero in these conforming headers
            continue
        flag, single, checksum, dictionary = desc >> 6, (desc >> 5) & 1, (desc >> 2) & 1, desc & 3
        did_width = widths['did'][dictionary]
        fcs_width = widths['fcs'][flag] or single
        did = int.from_bytes(b'\x2b' * did_width, 'little')
        for raw in sorted({0, ((1 << (8*fcs_width)) - 1) // 2, (1 << (8*fcs_width)) - 1}):
            expected = raw + 256 if fcs_width == 2 else raw if fcs_width else UNKNOWN
            # The two top u64 values are reserved API sentinels. Use ordinary sizes only.
            if fcs_width == 8 and expected >= UNKNOWN - 1:
                continue
            header = (bytes.fromhex('28b52ffd') + bytes([desc]) + (b'' if single else b'\x00') +
                      did.to_bytes(did_width, 'little') + raw.to_bytes(fcs_width, 'little'))
            got = Header()
            require(api.ZSTD_getFrameHeader(c.byref(got), header, len(header)) == 0, 'Header rejected')
            require((got.content, got.dictionary, got.checksum, got.header_size) ==
                    (expected, did, checksum, len(header)), 'Decoded fields disagree')
            require(api.ZSTD_getFrameContentSize(header, len(header)) == expected, 'Size API disagrees')
            records.append([desc, header.hex(), expected])
    return {'descriptors': len({r[0] for r in records}), 'cases': len(records),
            'vectors_sha256': sha(json.dumps(records, separators=(',', ':')).encode())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path, help='public libzstd 1.5.7 shared library for this host')
    parser.add_argument('archives', type=Path, nargs=2, help='the two published zstd-sys archive files')
    parser.add_argument('--print', action='store_true', dest='show')
    args = parser.parse_args()
    sources = dict(source_tables(p) for p in args.archives)
    require(sources.keys() == CRATES, 'Supply each candidate once')
    first, second = sources.values()
    require(first == second, 'Source tables differ')
    result = {'target_sha256': NODE, 'source_sha256': sorted(sources), 'linked': linked_image(first),
              'public_controls': public_controls(args.library, first)}
    if args.show:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        require(json.loads((HERE / 'result.json').read_bytes()) == result, 'Recorded result differs')
        print(f"{result['linked']['body_bytes']} linked bytes; {result['public_controls']['cases']} public controls")


if __name__ == '__main__':
    main()
