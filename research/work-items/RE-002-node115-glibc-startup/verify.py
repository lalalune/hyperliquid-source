#!/usr/bin/env python3
"""Qualify authenticated Ubuntu startup objects against the previously mapped node #115 entry."""
import argparse
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
import entry_start_static as entry
from packages import RELEASES, ubuntu, require, sha

RELOC_TYPES = {2: 'R_X86_64_PC32', 41: 'R_X86_64_GOTPCRELX', 42: 'R_X86_64_REX_GOTPCRELX'}


def section_bytes(data, row):
    return data[row['offset']:row['offset'] + row['size']]


def section_named(rows, name):
    row, = (s for s in rows if s['name'] == name)
    return row


def abi_tag(data, rows):
    row = section_named(rows, '.note.ABI-tag')
    note = section_bytes(data, row)
    require(row['type'] == 7 and len(note) == 32 and note[:16] ==
            struct.pack('<III4s', 4, 16, 1, b'GNU\0'), 'Expected a single GNU NT_GNU_ABI_TAG')
    os_id, major, minor, patch = struct.unpack_from('<4I', note, 16)
    require(os_id == 0, 'Expected Linux ABI note')
    return dict(os='Linux', version=[major, minor, patch], sha256=sha(note), file_offset=row['offset'])


def startup_object(data):
    rows = sections(data)
    require(struct.unpack_from('<HH', data, 16) == (1, 62), 'Expected x86-64 relocatable object')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    stride = struct.unpack_from('<H', data, 58)[0]
    for i, row in enumerate(rows):
        row['link'], row['info'], _, row['entsize'] = struct.unpack_from('<IIQQ', data, shoff + stride*i + 40)
    table = section_named(rows, '.symtab')
    require(table['type'] == 2 and table['entsize'] == 24, 'Unexpected symbol table')
    names = section_bytes(data, rows[table['link']])
    symbols = []
    for idx, info, _, section, value, size in struct.iter_unpack('<IBBHQQ', section_bytes(data, table)):
        end = names.index(0, idx)
        name = names[idx:end].decode('ascii') or (rows[section]['name'] if info & 15 == 3 else '')
        symbols.append((name, info, section, value, size))
    _, info, owner, start, size = next(s for s in symbols if s[0] == '_start')
    require(sum(s[0] == '_start' for s in symbols) == 1 and info == 0x12 and rows[owner]['name'] == '.text',
            'Expected one global _start function in .text')
    text = section_bytes(data, rows[owner])
    require(0 < size <= len(text) - start, 'Invalid startup symbol extent')
    body = text[start:start+size]
    relocations = []
    for row in rows:
        if row['type'] != 4:
            continue
        require(row['link'] == rows.index(table) and row['entsize'] == 24, 'Unexpected RELA symbol table')
        for offset, rinfo, addend in struct.iter_unpack('<QQq', section_bytes(data, row)):
            symbol, _, sym_owner, _, _ = symbols[rinfo >> 32]
            relocations.append(dict(section=rows[row['info']]['name'], offset=offset,
                                    kind=RELOC_TYPES[rinfo & 0xffffffff], symbol=symbol,
                                    undefined=sym_owner == 0, addend=addend))
    record = dict(object_sha256=sha(data), object_bytes=len(data), section_text_bytes=len(text),
                  start_section_offset=start, start_file_offset=rows[owner]['offset'] + start, start_bytes=size,
                  start_sha256=sha(body), abi=abi_tag(data, rows), relocations=relocations)
    return record, body


def authenticated_target(path):
    data = path.read_bytes()
    require(len(data) == entry.SIZE and sha(data) == entry.SHA, 'Expected pinned node #115')
    mapped = entry.analyze(data)
    first = mapped['owners'][0]
    targets = mapped['start_handoff']
    va, end = int(first['start'], 16), int(first['end'], 16)
    off, body = entry.read(data, va, end-va)
    record = dict(node_sha256=entry.SHA, entry_va=va, file_offset=off, extent_bytes=len(body),
                  start_sha256=sha(body), abi=abi_tag(data, sections(data)),
                  main_va=int(targets['arguments']['rdi_main'], 16), libc_start_main_got=int(targets['callee_got_slot'], 16))
    return record, body


def compare(obj, raw, target, captured):
    if len(raw) != len(captured):
        return dict(outcome='different extent', candidate_bytes=len(raw), target_bytes=len(captured))
    start = obj['start_section_offset']
    rels = [r for r in obj['relocations'] if r['section'] == '.text' and start <= r['offset'] < start+len(raw)]
    require(len(rels) == 2 and {r['symbol'] for r in rels} == {'main', '__libc_start_main'},
            'Unexpected startup relocation set')
    linked = bytearray(raw)
    replay = []
    for r in rels:
        at = r['offset'] - start
        require(3 <= at <= len(raw)-4 and r['undefined'] and r['addend'] == -4 and raw[at:at+4] == bytes(4),
                'Unexpected input relocation')
        if r['symbol'] == 'main':
            require(r['kind'] == 'R_X86_64_REX_GOTPCRELX' and raw[at-3:at] == b'\x48\x8b\x3d',
                    'Unexpected relaxable main load')
            linked[at-2] = 0x8d  # REX.W MOV from the GOT relaxes to LEA of a non-preemptible local target.
            destination = target['main_va']
        else:
            require(r['kind'] == 'R_X86_64_GOTPCRELX' and raw[at-2:at] == b'\xff\x15',
                    'Unexpected libc indirect call')
            destination = target['libc_start_main_got']
        place = target['entry_va'] + at
        value = destination + r['addend'] - place
        struct.pack_into('<i', linked, at, value)
        replay.append(dict(symbol=r['symbol'], place=place, destination=destination, disp32=value))
    require(bytes(linked) == captured, 'Remaining startup bytes differ after bounded relocation replay')
    different = [i for i, (a, b) in enumerate(zip(raw, captured)) if a != b]
    return dict(outcome='equal after relocation and opcode relaxation', raw_equal_bytes=len(raw)-len(different),
                raw_difference_offsets=different, replay=replay, linked_sha256=sha(linked))


def report(cache, keyring, fetch, target_path):
    target, body = authenticated_target(target_path)
    entries = {}
    for suite in RELEASES:
        provenance, objects = ubuntu(cache, suite, keyring, fetch)
        rows = {}
        for name, data in objects.items():
            obj, raw = startup_object(data)
            obj['comparison'] = compare(obj, raw, target, body)
            obj['abi_note_matches_node'] = obj['abi']['sha256'] == target['abi']['sha256']
            rows[name] = obj
        entries[suite] = dict(distribution=provenance, objects=rows)
    return dict(target=target, distributions=entries)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('cache', type=Path)
    cli.add_argument('--keyring', type=Path, required=True)
    cli.add_argument('--fetch', action='store_true')
    cli.add_argument('--node', type=Path, default=entry.TARGET)
    cli.add_argument('--output', type=Path, help='Write recomputed evidence instead of comparing the retained result')
    args = cli.parse_args()
    data = report(args.cache, args.keyring, args.fetch, args.node)
    if args.output:
        args.output.write_text(json.dumps(data, indent=2) + '\n')
    else:
        require(json.loads((HERE / 'result.json').read_text()) == data, 'Retained comparison differs')
        print('Verified six startup objects from two signed releases against the #115 entry extent.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, struct.error, tarfile.TarError) as exc:
        sys.exit(str(exc))
