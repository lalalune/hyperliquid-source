#!/usr/bin/env python3
"""Pin the abci checkpoint compress and upload thread body in node #94.

Every number comes from ELF bytes read with struct: section headers through
tools/elf_index.py, FDE extents through tools/fde_extents.py, relocations from
.rela.dyn, strings and tables from .rodata and .data.rel.ro. Instruction facts
are fixed byte pins. No external program runs and the binary is never executed.
"""
import argparse
import bisect
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

BINARY = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
JSON_NAME = 'abci-checkpoint-upload.json'
TSV_NAME = 'abci-checkpoint-pins.tsv'
SHT_NOBITS = 8
SHF_ALLOC = 2
R_X86_64_GLOB_DAT = 6
R_X86_64_RELATIVE = 8
LOCATION_MARK = b'/code_Mainnet/'

FUNCTIONS = {
    'closure': 0x432fc10,
    'retry': 0x13c96c0,
    'worker': 0x14503b0,
    'mv': 0x1404d90,
    'getter': 0x14050e0,
    'remove': 0x144cca0,
    'thread': 0x433a9a0,
}
CALL_TARGETS = {
    0x13c96c0: 'retry',
    0x14503b0: 'worker',
}
SLOTS = {
    0x576efd8: 0x1404d90,
    0x5776630: 0x432fc10,
    0x576efe0: 0x14050e0,
    0x576ef90: 0x144cca0,
    0x576e858: 0x4ecc3d0,
    0x576e8c8: 0x13e4e40,
    0x576e9e8: 0x144a710,
}
IMPORT_SLOTS = {0x576f690: 'unlink'}
TEMPLATES = {
    'lz4_command': (0x1fe1c4, 'lz4 -q -9 {} {} {}'),
    'output_path': (0x1e0fd2, '{}{}'),
    'guard_error': (0x1fd0e7, 'zip_inner: {}'),
    'quote_error': (0x1dfb7c, 'zip_inner {}: {}'),
    'retry_exhausted': (0x1fceaf, 'sleep_retry retried {} for sleep times {} last err {}'),
    'upload_key_rodata': (0x1e1ad7, '{}/hyperliquid/abci_checkpoints/{}/{}.lz4'),
}
TEXTS = {
    'retry_label': (0x219c54, 15, 'zip_inner_retry'),
    'wait_label': (0x217773, 17, 'shell::wait_retry'),
    'suffix': (0x209d94, 4, '.lz4'),
    'remove_source_flag': (0x20a0f4, 4, '--rm'),
    'word_aws': (0x218504, 3, 'aws'),
    'word_s3': (0x218507, 2, 's3'),
    'word_mv': (0x218502, 2, 'mv'),
}
SUFFIX_STR = 0x566aa10
LOCATIONS = {
    'compress_unwrap': (0x571cef8, 'node/src/abci_checkpoint.rs', 26, 26),
    'mv_unwrap': (0x571cf10, 'node/src/abci_checkpoint.rs', 27, 55),
}
SLEEPS = (0x216dd8, 0x216df0)
SLEEP_VALUES = (0.001, 0.05, 1.0)
MICROS = 0x20ae60
THREAD_VTABLE = 0x571cac8
THREAD_VTABLE_ROWS = (0x4341630, 0x50, 8, 0x433a9a0)
FLAG_BYTE = 0x57883f1
CONFIG_SLOT = 0x576eb70
CONFIG_OFFSETS = {'option_tag': 0x1a8, 'pointer': 0x1b0, 'length': 0x1b8}
EXPECTED_DIRECT = {0x13c96c0: [0x432fc69], 0x14503b0: [0x13c9716, 0x13c98ef]}
EXPECTED_SLOT_USES = {0x576efd8: [0x432fc97], 0x5776630: [0x433aa1a]}
EXPECTED_RELOCS = {0x1404d90: [0x576efd8], 0x432fc10: [0x5776630], 0x433a9a0: [0x571cae0]}
LEA_TARGETS = [0x13c96c0, 0x14503b0, 0x1404d90, 0x432fc10, 0x433a9a0]

# (function, va, raw bytes, target or None, meaning)
PINS = [
    ('closure', 0x432fc20, '488b4718', None, 'source pointer read from closure +0x18'),
    ('closure', 0x432fc24, '488b4f20', None, 'source length read from closure +0x20'),
    ('closure', 0x432fc32, '66c744240e0001', None, 'two option bytes: byte 0 = 0, byte 1 = 1'),
    ('closure', 0x432fc4d, '488d1500a0eefb', 0x219c54, 'retry label pointer'),
    ('closure', 0x432fc5e, 'b90f000000', None, 'retry label length 15'),
    ('closure', 0x432fc66, '4531c0', None, 'sleep list pointer None'),
    ('closure', 0x432fc69, 'e8529a09fd', 0x13c96c0, 'call retry helper'),
    ('closure', 0x432fc79, '0f8025010000', 0x432fda4, 'Err branch to unwrap panic'),
    ('closure', 0x432fc89, '4c8b6308', None, 'destination pointer from closure +0x08'),
    ('closure', 0x432fc8d, '488b4b10', None, 'destination length from closure +0x10'),
    ('closure', 0x432fc91, '4c89ff', None, 'first argument = compressed path pointer'),
    ('closure', 0x432fc97, 'ff153bf34301', 0x576efd8, 'call the mv helper through its GOT slot'),
    ('closure', 0x432fc9d, '4885c0', None, 'test mv result'),
    ('closure', 0x432fca0, '756d', 0x432fd0f, 'nonzero mv result goes to unwrap panic'),
    ('closure', 0x432fcc2, 'c6052887450101', 0x57883f1, 'store 1 in the byte beside the lock'),
    ('closure', 0x432fd22, '4c8d05e7d13e01', 0x571cf10, 'mv unwrap Location'),
    ('closure', 0x432fdcb, '4c8d0526d13e01', 0x571cef8, 'compress unwrap Location'),
    ('retry', 0x13c96f5, '0fb60e', None, 'option byte 0 into ecx'),
    ('retry', 0x13c96fd, '440fb64601', None, 'option byte 1 into r8d'),
    ('retry', 0x13c9716, 'e8956c0800', 0x14503b0, 'first attempt'),
    ('retry', 0x13c9720, '0f819a020000', 0x13c99c0, 'Ok first attempt returns at once'),
    ('retry', 0x13c9737, '7419', 0x13c9752, 'None sleep list takes the default table'),
    ('retry', 0x13c9746, '0f84e0010000', 0x13c992c, 'empty explicit list goes straight to exhaustion'),
    ('retry', 0x13c9752, '4c8d3d7fd6e4fe', 0x216dd8, 'default table start'),
    ('retry', 0x13c975e, '48c744243003000000', None, 'default table length 3'),
    ('retry', 0x13c9767, '488d0582d6e4fe', 0x216df0, 'default table end'),
    ('retry', 0x13c9795, 'f20f590dc316e4fe', 0x20ae60, 'seconds to microseconds factor'),
    ('retry', 0x13c98ce, '0fb608', None, 'option byte 0 for the retried call'),
    ('retry', 0x13c98d1, '440fb64001', None, 'option byte 1 for the retried call'),
    ('retry', 0x13c98ef, 'e8bc6a0800', 0x14503b0, 'retried attempt'),
    ('retry', 0x13c9902, '0f85ab000000', 0x13c99b3, 'Ok retried attempt leaves the loop'),
    ('retry', 0x13c9926, '0f8564feffff', 0x13c9790, 'next sleep while entries remain'),
    ('retry', 0x13c9971, '488d353735e3fe', 0x1fceaf, 'exhaustion template'),
    ('worker', 0x14503d1, '4883fa04', None, 'length below 4 skips the suffix test'),
    ('worker', 0x14503d7, '817c16fc2e6c7a34', None, 'last four bytes compared with .lz4'),
    ('worker', 0x14503df, '0f8441030000', 0x1450726, 'match goes to the zip_inner error'),
    ('worker', 0x14503e5, '894c2444', None, 'option byte 0 saved'),
    ('worker', 0x14503ff, '488d050aa62104', 0x566aa10, 'static &str holding .lz4'),
    ('worker', 0x1450410, '488d35bb0bd9fe', 0x1e0fd2, 'template for path ++ .lz4'),
    ('worker', 0x145043c, 'ff154eeb3104', 0x576ef90, 'remove any old output file'),
    ('worker', 0x1450442, '807c240801', None, 'removal error tag'),
    ('worker', 0x1450453, '488d059a9cdbfe', 0x20a0f4, '--rm text'),
    ('worker', 0x145045a, '4584ed', None, 'option byte 1 test'),
    ('worker', 0x1450462, '480f45c8', None, 'pointer = --rm when option byte 1 is set'),
    ('worker', 0x145046a, 'c1e002', None, 'length = option byte 1 times 4'),
    ('worker', 0x145047d, '488b542460', None, 'input path pointer for first quote'),
    ('worker', 0x1450496, 'ff15bce33104', 0x576e858, 'quote input path'),
    ('worker', 0x1450563, 'ff15efe23104', 0x576e858, 'quote output path'),
    ('worker', 0x14505f9, '488d8424c8000000', None, 'command argument 0 = option text'),
    ('worker', 0x145060b, '488d842488000000', None, 'command argument 1 = quoted input'),
    ('worker', 0x1450624, '488d4c2470', None, 'command argument 2 = quoted output'),
    ('worker', 0x1450633, '488d358adbdafe', 0x1fe1c4, 'command template'),
    ('worker', 0x14506c2, '807c244400', None, 'option byte 0 test'),
    ('worker', 0x14506c9, 'c68424b800000001', None, 'shell flag byte set when option byte 0 is set'),
    ('worker', 0x14506d9, 'ff15e9e13104', 0x576e8c8, 'run the shell command'),
    ('worker', 0x145073c, '488d35a4c9dafe', 0x1fd0e7, 'guard error template'),
    ('mv', 0x1404db1, 'ff1529a23604', 0x576efe0, 'read optional config string'),
    ('mv', 0x1404dc2, '7107', 0x1404dcb, 'Some continues'),
    ('mv', 0x1404dc4, '31c0', None, 'None returns Ok with nothing run'),
    ('mv', 0x1404de4, '488d051937e1fe', 0x218504, 'argument 0 text'),
    ('mv', 0x1404df0, '48c744243803000000', None, 'argument 0 length'),
    ('mv', 0x1404df9, '488d050737e1fe', 0x218507, 'argument 1 text'),
    ('mv', 0x1404e05, '48c744244802000000', None, 'argument 1 length'),
    ('mv', 0x1404e0e, '488d05ed36e1fe', 0x218502, 'argument 2 text'),
    ('mv', 0x1404e1a, '48c744245802000000', None, 'argument 2 length'),
    ('mv', 0x1404e23, '4c89642460', None, 'argument 3 pointer = first path'),
    ('mv', 0x1404e28, '4c897c2468', None, 'argument 3 length'),
    ('mv', 0x1404e2d, '4c89742470', None, 'argument 4 pointer = second path'),
    ('mv', 0x1404e32, '48895c2478', None, 'argument 4 length'),
    ('mv', 0x1404e53, 'e8a80d0500', 0x1455c00, 'join the five words'),
    ('mv', 0x1404e71, 'c644242800', None, 'shell flag byte clear'),
    ('mv', 0x1404e80, '488d35ec28e1fe', 0x217773, 'wait_retry label'),
    ('mv', 0x1404e8c, 'ba11000000', None, 'wait_retry label length 17'),
    ('mv', 0x1404e91, '31c9', None, 'sleep list None'),
    ('mv', 0x1404e93, 'e8e841fcff', 0x13c9080, 'run with wait_retry'),
    ('getter', 0x14050ed, '4c8b3d7c9a3604', 0x576eb70, 'global config pointer slot'),
    ('getter', 0x140510f, '493b87a8010000', None, 'option tag at config +0x1a8'),
    ('getter', 0x1405118, '4d8bb7b8010000', None, 'string length at config +0x1b8'),
    ('getter', 0x1405127, '4d8bbfb0010000', None, 'string pointer at config +0x1b0'),
    ('remove', 0x144ccc8, 'ff151a1d3204', 0x576e9e8, 'exists test'),
    ('remove', 0x144ccd2, '0f84d2010000', 0x144ceaa, 'missing file returns Ok'),
    ('remove', 0x144cd2e, 'ff155c293204', 0x576f690, 'unlink through the GOT'),
    ('thread', 0x433a9f7, '488d4328', None, 'payload at closure box +0x28'),
    ('thread', 0x433aa1a, 'ff1510bc4301', 0x5776630, 'call the closure'),
]


class Image:
    """Section, relocation and FDE view over the ELF bytes."""

    def __init__(self, data):
        self.data = data
        self.sections = elf_index.sections(data)
        self.mapped = [s for s in self.sections
                       if s['type'] != SHT_NOBITS and s['flags'] & SHF_ALLOC and s['address'] and s['size']]
        self.relocs = {}
        rela = self.section('.rela.dyn')
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            self.relocs[where] = (info & 0xffffffff, info >> 32, addend)
        _, ordered, _ = fde_extents.fde_extents(data)
        self.extent = {}
        for fde in ordered:
            self.extent.setdefault(fde['start'], fde['end'])

    def section(self, name):
        return next(s for s in self.sections if s['name'] == name)

    def read(self, va, size):
        for sec in self.mapped:
            if sec['address'] <= va and va + size <= sec['address'] + sec['size']:
                start = va - sec['address'] + sec['offset']
                return self.data[start:start + size]
        raise ValueError(f'No file bytes for {va:#x}+{size:#x}')

    def text(self):
        sec = self.section('.text')
        return self.data[sec['offset']:sec['offset'] + sec['size']], sec['address']

    def symbol(self, index):
        dynsym, dynstr = self.section('.dynsym'), self.section('.dynstr')
        name = struct.unpack_from('<I', self.data, dynsym['offset'] + 24 * index)[0]
        start = dynstr['offset'] + name
        return self.data[start:self.data.index(b'\0', start)].decode('ascii')


class Patched(Image):
    """Same parsed image with some VA ranges replaced, for negative controls."""

    def __init__(self, base, patches):
        self.__dict__.update(base.__dict__)
        self.base = base
        self.patches = patches

    def read(self, va, size):
        out = bytearray(self.base.read(va, size))
        for where, value in self.patches.items():
            for index, byte in enumerate(value):
                if va <= where + index < va + size:
                    out[where + index - va] = byte
        return bytes(out)


def instruction_target(raw, va):
    """Resolve the one relative operand of a pinned instruction from its bytes."""
    end = va + len(raw)
    if raw[0] in (0xe8, 0xe9):
        return end + struct.unpack('<i', raw[1:5])[0]
    if 0x70 <= raw[0] <= 0x7f:
        return end + struct.unpack('<b', raw[1:2])[0]
    if raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return end + struct.unpack('<i', raw[2:6])[0]
    if raw[0] == 0xff and raw[1] in (0x15, 0x25):
        return end + struct.unpack('<i', raw[2:6])[0]
    if raw[0] == 0xc6 and raw[1] == 0x05:
        return end + struct.unpack('<i', raw[2:6])[0]
    if raw[0] in (0x48, 0x4c) and raw[1] in (0x8b, 0x8d) and raw[2] & 0xc7 == 0x05:
        return end + struct.unpack('<i', raw[3:7])[0]
    if raw[:3] == b'\xf2\x0f\x59' and raw[3] & 0xc7 == 0x05:
        return end + struct.unpack('<i', raw[4:8])[0]
    raise ValueError(f'No relative operand form for {raw.hex()} at {va:#x}')


def check_pins(image):
    rows = []
    for name, va, raw, target, meaning in PINS:
        start = FUNCTIONS[name]
        end = image.extent.get(start)
        if end is None or not start <= va < end:
            raise ValueError(f'Pin {va:#x} is outside {name}')
        expected = bytes.fromhex(raw)
        actual = image.read(va, len(expected))
        if actual != expected:
            raise ValueError(f'Pin {va:#x} bytes differ: {actual.hex()}')
        resolved = instruction_target(actual, va) if target is not None else None
        if resolved != target:
            raise ValueError(f'Pin {va:#x} target differs: {resolved:#x}')
        rows.append((name, va, raw, resolved, meaning))
    return rows


def decode_template(raw):
    """Walk a format template: 0 ends, 1..0x7f is a literal length, 0xc0 is {}."""
    out, pos = [], 0
    while True:
        byte = raw[pos]
        pos += 1
        if byte == 0:
            return ''.join(out)
        if byte == 0xc0:
            out.append('{}')
        elif byte < 0x80:
            literal = raw[pos:pos + byte]
            if len(literal) != byte:
                raise ValueError('Template literal runs past the window')
            out.append(literal.decode('ascii'))
            pos += byte
        else:
            raise ValueError(f'Template byte {byte:#x} is outside the walker rule')


def check_templates(image):
    out = {}
    for name, (va, expected) in TEMPLATES.items():
        text = decode_template(image.read(va, 80))
        if text != expected:
            raise ValueError(f'Template {name} differs: {text!r}')
        out[name] = {'va': f'{va:#x}', 'text': text}
    return out


def check_texts(image):
    out = {}
    for name, (va, size, expected) in TEXTS.items():
        text = image.read(va, size).decode('ascii')
        if text != expected:
            raise ValueError(f'Text {name} differs: {text!r}')
        out[name] = {'va': f'{va:#x}', 'length': size, 'text': text}
    relative = image.relocs.get(SUFFIX_STR)
    length = struct.unpack('<Q', image.read(SUFFIX_STR + 8, 8))[0]
    if relative is None or relative[2] != TEXTS['suffix'][0] or length != TEXTS['suffix'][1]:
        raise ValueError('Static .lz4 string row differs')
    return out


def check_sleeps(image):
    start, end = SLEEPS
    count = (end - start) // 8
    values = struct.unpack(f'<{count}d', image.read(start, end - start))
    factor = struct.unpack('<d', image.read(MICROS, 8))[0]
    if values != SLEEP_VALUES or factor != 1000000.0:
        raise ValueError(f'Sleep table differs: {values} {factor}')
    return {
        'table_va': f'{start:#x}',
        'seconds': list(values),
        'microseconds': [int(value * factor) for value in values],
        'attempts_when_all_fail': count + 1,
    }


def check_locations(image):
    out = {}
    for name, (row, path, line, column) in LOCATIONS.items():
        reloc = image.relocs.get(row)
        size, got_line, got_column = struct.unpack('<QII', image.read(row + 8, 16))
        if reloc is None:
            raise ValueError(f'Location {row:#x} has no relocation')
        text = image.read(reloc[2], size)
        short = text[text.index(LOCATION_MARK) + len(LOCATION_MARK):].decode('ascii')
        if (short, got_line, got_column) != (path, line, column):
            raise ValueError(f'Location {row:#x} differs: {short}:{got_line}:{got_column}')
        out[name] = {'row': f'{row:#x}', 'file': short, 'line': got_line, 'column': got_column}
    return out


def check_slots(image):
    rows = []
    for slot, target in SLOTS.items():
        reloc = image.relocs.get(slot)
        if reloc is None or reloc[0] != R_X86_64_RELATIVE or reloc[2] != target:
            raise ValueError(f'Slot {slot:#x} does not bind {target:#x}')
        rows.append({'slot': f'{slot:#x}', 'target': f'{target:#x}'})
    for slot, name in IMPORT_SLOTS.items():
        reloc = image.relocs.get(slot)
        if reloc is None or reloc[0] != R_X86_64_GLOB_DAT or image.symbol(reloc[1]) != name:
            raise ValueError(f'Slot {slot:#x} does not import {name}')
        rows.append({'slot': f'{slot:#x}', 'import': name})
    return rows


def check_vtable(image):
    drop = image.relocs.get(THREAD_VTABLE)
    size, align = struct.unpack('<QQ', image.read(THREAD_VTABLE + 8, 16))
    call = image.relocs.get(THREAD_VTABLE + 24)
    rows = (drop and drop[2], size, align, call and call[2])
    if rows != THREAD_VTABLE_ROWS:
        raise ValueError('Thread closure vtable differs')
    return {'va': f'{THREAD_VTABLE:#x}', 'drop': f'{rows[0]:#x}', 'size': size, 'align': align, 'call_once': f'{rows[3]:#x}'}


def direct_refs(text, base, targets):
    found = {target: [] for target in targets}
    for match in re.finditer(b'[\xe8\xe9]', text):
        pos = match.start()
        if pos + 5 > len(text):
            break
        target = base + pos + 5 + struct.unpack_from('<i', text, pos + 1)[0]
        if target in found:
            found[target].append(base + pos)
    return found


def slot_refs(text, base, slots):
    found = {slot: [] for slot in slots}
    for match in re.finditer(b'\xff[\x15\x25]|[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        pos = match.start()
        size = 2 if text[pos] == 0xff else 3
        if pos + size + 4 > len(text):
            break
        slot = base + pos + size + 4 + struct.unpack_from('<i', text, pos + size)[0]
        if slot in found:
            found[slot].append(base + pos)
    return found


def lea_refs(text, base, targets):
    found = {target: [] for target in targets}
    for match in re.finditer(b'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text):
        pos = match.start()
        if pos + 7 > len(text):
            break
        target = base + pos + 7 + struct.unpack_from('<i', text, pos + 3)[0]
        if target in found:
            found[target].append(base + pos)
    return found


def reloc_refs(relocs, targets):
    found = {target: [] for target in targets}
    for where, (kind, _, addend) in relocs.items():
        if kind == R_X86_64_RELATIVE and addend in found:
            found[addend].append(where)
    return {target: sorted(sites) for target, sites in found.items()}


def census(image):
    text, base = image.text()
    direct = direct_refs(text, base, list(EXPECTED_DIRECT))
    slots = slot_refs(text, base, list(EXPECTED_SLOT_USES))
    relocs = reloc_refs(image.relocs, list(EXPECTED_RELOCS))
    leas = lea_refs(text, base, LEA_TARGETS)
    if direct != EXPECTED_DIRECT or slots != EXPECTED_SLOT_USES or relocs != EXPECTED_RELOCS or any(leas.values()):
        raise ValueError(f'Call census differs: {direct} {slots} {relocs} {leas}')
    hexed = lambda table: {f'{key:#x}': [f'{site:#x}' for site in sites] for key, sites in table.items()}
    return {'direct_calls': hexed(direct), 'indirect_slot_uses': hexed(slots), 'relative_relocations': hexed(relocs),
            'rip_lea_uses': hexed(leas)}


def lz4_command(template, path, remove_source):
    """Render the worker's command, quoting left out, or raise for its guard."""
    if len(path) >= 4 and path[-4:] == '.lz4':
        raise ValueError(f'zip_inner: {path}')
    return template.format('--rm' if remove_source else '', path, path + '.lz4')


def upload_words(texts, compressed, destination):
    return [texts['word_aws']['text'], texts['word_s3']['text'], texts['word_mv']['text'], compressed, destination]


def analyse(image):
    rows = check_pins(image)
    templates = check_templates(image)
    texts = check_texts(image)
    report = {
        'target_sha256': SHA256,
        'coordinate_system': 'virtual addresses of node #94',
        'functions': {name: {'start': f'{start:#x}', 'end': f'{image.extent[start]:#x}',
                             'bytes': image.extent[start] - start}
                      for name, start in FUNCTIONS.items()},
        'closure_layout': {'destination_string': {'capacity': 0, 'pointer': 8, 'length': 16},
                           'source_str': {'pointer': 24, 'length': 32}},
        'option_bytes': {'shell_flag': 0, 'remove_source': 1},
        'templates': templates,
        'texts': texts,
        'default_sleeps': check_sleeps(image),
        'locations': check_locations(image),
        'slots': check_slots(image),
        'thread_vtable': check_vtable(image),
        'thread_payload_offset': 0x28,
        'census': census(image),
        'config_string_offsets': {'global_slot': f'{CONFIG_SLOT:#x}', **{k: f'{v:#x}' for k, v in CONFIG_OFFSETS.items()}},
        'flag_byte_written': f'{FLAG_BYTE:#x}',
        'model': {
            'command': lz4_command(templates['lz4_command']['text'], '<in>', True),
            'command_without_remove': lz4_command(templates['lz4_command']['text'], '<in>', False),
            'upload_words': upload_words(texts, '<in>.lz4', '<destination>'),
        },
        'pin_count': len(rows),
    }
    return report, rows


def load_binary(path=BINARY):
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise SystemExit(f'Input sha256 differs: {digest}')
    return data


def write_outputs(folder, report, rows):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / JSON_NAME).write_text(json.dumps(report, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    lines = ['function\tva\tbytes\ttarget\tmeaning']
    for name, va, raw, target, meaning in rows:
        lines.append(f"{name}\t{va:#x}\t{raw}\t{'' if target is None else f'{target:#x}'}\t{meaning}")
    (folder / TSV_NAME).write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report, rows = analyse(Image(load_binary()))
    write_outputs(args.out, report, rows)
    print(f"{len(rows)} pins, {report['default_sleeps']['attempts_when_all_fail']} attempts")


if __name__ == '__main__':
    main()
