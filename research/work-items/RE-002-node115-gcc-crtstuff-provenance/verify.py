"""Replay the complete Ubuntu crtbeginS .text against the pinned node115 ELF."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections

NODE = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
DEBS = ('cd689db2691edaa10f37329307292796bb599e722e0505c79e14caaa1fe9a93a',
        'd36c9acb969dd37fdc0496120715d8bba67a5cc43a0c2569717314e6ad80020c')
START = 0x1419330  # Previously mapped range after the ELF entry function.
SYMBOL = '__cxa_finalize'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def payload(image, section):
    require(section['type'] != 8, 'NOBITS has no payload')
    return image[section['offset']:section['offset'] + section['size']]


def source_objects(package, expected):
    require(digest(package.read_bytes()) == expected, 'Ubuntu package checksum mismatch')
    names = subprocess.check_output(['ar', 't', package], text=True).splitlines()
    member, = [n for n in names if n in ('data.tar.zst', 'data.tar.xz')]
    data = subprocess.check_output(['ar', 'p', package, member])
    if member.endswith('.zst'):
        data = subprocess.check_output(['zstd', '-dc'], input=data)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        objects = {}
        for name in ('crtbegin.o', 'crtbeginS.o', 'crtbeginT.o'):
            entry, = [m for m in archive.getmembers() if m.name.lstrip('./') ==
                      f'usr/lib/gcc/x86_64-linux-gnu/13/{name}' and m.isfile()]
            objects[name] = archive.extractfile(entry).read()
    return objects


def relocations(image, tables, rela, symbols, strings):
    data = payload(image, tables[symbols])
    names = payload(image, tables[strings])
    for offset, info, addend in struct.iter_unpack('<QQq', payload(image, tables[rela])):
        index = info >> 32
        nameoff, symbol_info, _, shndx, _, _ = struct.unpack_from('<IBBHQQ', data, 24 * index)
        if symbol_info & 15 == 3:
            symbol = list(tables)[shndx]
        else:
            symbol = names[nameoff:names.index(0, nameoff)].decode()
        yield offset, info & 0xffffffff, symbol, addend


def capture_addresses(data, table):
    dyn = list(relocations(data, table, '.rela.dyn', '.dynsym', '.dynstr'))
    jmps = list(relocations(data, table, '.rela.plt', '.dynsym', '.dynstr'))
    got = {name: offset for offset, kind, name, _ in dyn if kind == 6}
    relatives = {off: add for off, kind, name, add in dyn if kind == 8 and not name}
    jump_slot, = [off for off, kind, name, _ in jmps if kind == 7 and name == SYMBOL]
    plt = table['.plt']
    code = payload(data, plt)
    stub, = [plt['address'] + i for i in range(0, len(code) - 5, 16)
             if code[i:i+2] == b'\xff\x25' and
             plt['address'] + i + 6 + struct.unpack_from('<i', code, i + 2)[0] == jump_slot]
    tm = table['.tm_clone_table']
    start = table['.data']['address']
    require(relatives[start] == start, 'missing self-relative DSO handle')
    names = {(2, '.tm_clone_table'): tm['address'], (2, '__TMC_END__'): tm['address'] + tm['size'],
             (2, '.bss'): table['.bss']['address'], (2, '__dso_handle'): start,
             (9, SYMBOL): got[SYMBOL], (4, SYMBOL): stub}
    for name in ('_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable'):
        names[42, name] = got[name]
    return names, relatives


def report(node, current, older):
    image = node.read_bytes()
    require(digest(image) == NODE, 'wrong node #115')
    target = {s['name']: s for s in sections(image)}
    names, relative = capture_addresses(image, target)
    candidates = []
    for package, expected in zip((current, older), DEBS):
        inputs = source_objects(package, expected)
        for name, obj in inputs.items():
            tables = {s['name']: s for s in sections(obj)}
            code = payload(obj, tables['.text'])
            offset = target['.text']['offset'] + START - target['.text']['address']
            original = image[offset:offset + len(code)]
            stamp, = [s.decode() for s in payload(obj, tables['.comment']).split(b'\0') if s]
            row = dict(package_sha256=expected, object=name, object_sha256=digest(obj), text_bytes=len(code),
                       text_sha256=digest(code), gcc_stamp=stamp,
                       stamp_in_node=stamp.encode() in payload(image, target['.comment']).split(b'\0'))
            if name == 'crtbeginS.o':
                result = bytearray(code)
                fields = []
                for off, kind, symbol, addend in relocations(obj, tables, '.rela.text', '.symtab', '.strtab'):
                    address = names[kind, symbol]
                    struct.pack_into('<i', result, off, address + addend - (START + off))
                    fields.append(dict(offset=off, kind=kind, symbol=symbol, addend=addend, destination=hex(address)))
                require(len(fields) == 11 and result == original, 'linked .text differs from capture')
                for sec, slot in (('.fini_array', 0), ('.init_array', 1)):
                    entry, = relocations(obj, tables, '.rela' + sec, '.symtab', '.strtab')
                    require(entry[:3] == (0, 1, '.text') and
                            relative[target[sec]['address'] + 8*slot] == START + entry[3],
                            f'{sec} does not select packaged entry')
                row.update(raw_equal=sum(a == b for a, b in zip(code, original)), relocations=fields,
                           linked_sha256=digest(result), linked_equal=True)
            candidates.append(row)
    return dict(target=NODE, start=hex(START), candidates=candidates)


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('update_deb', type=Path)
    cli.add_argument('base_deb', type=Path)
    cli.add_argument('--node', type=Path, default=ROOT/'artifacts/node/115/hl-node')
    cli.add_argument('--emit', action='store_true', help='print measured data instead of checking retained result')
    args = cli.parse_args()
    result = report(args.node, args.update_deb, args.base_deb)
    if args.emit:
        print(json.dumps(result, indent=2))
    else:
        require(result == json.loads((HERE/'result.json').read_text()), 'result differs')
        print('Two GCC packages, six objects: both crtbeginS text sections reproduced all 185 bytes; only the update stamp matches.')
