#!/usr/bin/env python3
"""Authenticate complete listener/caller bytes and imports; never execute them."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
from socket_calls_static import Image

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
MEMBERS = (0x3cd6690, 0x4f78960, 0x22c54a0, 0x438ed70, 0x47b4950)
IMPORTS = {'socket': 0x5775210, 'setsockopt': 0x576f0d0, 'bind': 0x5775220,
           'listen': 0x5776450, '__errno_location': 0x576e8d8, 'close': 0x576e708}
GNU = '/opt/homebrew/opt/binutils/bin/objdump'
LLVM = '/usr/bin/objdump'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def rows(text):
    found = []
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)', line)
        if m:
            found.append((int(m[1], 16), bytes.fromhex(m[2])))
    return found


def llvm_logical(raw, canonical):
    """Only combine LLVM's literal lone F0 prefix with its adjacent raw row."""
    out, joined = [], []
    at = 0
    for va, code in canonical:
        require(at < len(raw) and raw[at][0] == va, 'LLVM start mismatch')
        value = raw[at][1]
        at += 1
        if value == b'\xf0' and len(code) > 1:
            require(at < len(raw) and raw[at][0] == va + 1, 'LOCK adjacency')
            value += raw[at][1]
            at += 1
            joined.append(hex(va))
        require(value == code, 'LLVM complete byte mismatch')
        out.append((va, value))
    require(at == len(raw), 'extra LLVM rows')
    return out, joined


def census(data, pin):
    sec = pin['text_section']
    text = data[sec['offset']:sec['offset'] + sec['size']]
    result = {'direct': [], 'slot_calls': [], 'entry_relocations': []}
    targets = {0x3cd6690, 0x4f78960}
    slots = {0x5776490, 0x5773d08}
    for m in re.finditer(rb'[\xe8\xe9]', text):
        p = m.start()
        if p + 5 <= len(text):
            to = sec['address'] + p + 5 + struct.unpack_from('<i', text, p + 1)[0]
            if to in targets:
                result['direct'].append([hex(sec['address'] + p), hex(to), text[p]])
    for m in re.finditer(rb'\xff[\x15\x25]', text):
        p = m.start()
        if p + 6 <= len(text):
            to = sec['address'] + p + 6 + struct.unpack_from('<i', text, p + 2)[0]
            if to in slots:
                result['slot_calls'].append([hex(sec['address'] + p), hex(to), text[p + 1]])
    sec = pin['rela_section']
    for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, p)
        if addend in targets:
            result['entry_relocations'].append([hex(where), info, hex(addend), p])
    return result


def build_authority(data, image, directory):
    cies, fdes = eh_frame_records(data, image.secs)
    _, index = unwind_index(data)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    bindings, seen, members, commands = [], set(), [], []

    def bind(name, offset, size):
        if (offset, size) in seen:
            return
        value = data[offset:offset + size]
        require(len(value) == size, 'binding size')
        bindings.append({'name': name, 'offset': offset, 'size': size,
                         'hex': value.hex(), 'sha256': sha(value)})
        seen.add((offset, size))

    def unwind_record(name, va):
        size = int.from_bytes(image.read(va, 4), 'little') + 4
        bind(name, image.offset(va, size), size)

    for i, entry in enumerate(MEMBERS):
        start, end = image.fde_of(entry)
        require(start == entry, 'entry/FDE identity')
        code = image.read(start, end - start)
        ins = list(md.disasm(code, start))
        require(sum(x.size for x in ins) == len(code), 'incomplete decode')
        canonical = [(x.address, x.bytes) for x in ins]
        fde = next(f for f in fdes if f['start'] == entry)
        require(sum(x['start'] == entry and x['fde'] == fde['fde'] for x in index) == 1, 'unwind index binding')
        bind('body-' + hex(entry), image.offset(entry, len(code)), len(code))
        unwind_record('fde-' + hex(entry), fde['fde'])
        unwind_record('cie-' + hex(fde['cie']), fde['cie'])
        member = {'start': hex(start), 'end': hex(end), 'bytes': len(code), 'instructions': len(ins),
                  'body_sha256': sha(code), 'fde': fde, 'cie': cies[fde['cie']], 'exports': []}
        for label, tool, options in [('gnu', GNU, ['-d', '-M', 'intel', '--insn-width=16']),
                                     ('llvm', LLVM, ['-d', '--x86-asm-syntax=intel'])]:
            argv = [tool, *options, '--start-address=' + hex(start), '--stop-address=' + hex(end),
                    'artifacts/node/94/hl-node']
            proc = subprocess.run(argv, cwd=ROOT, capture_output=True)
            require(proc.returncode == 0, 'disassembler failed')
            file = f'member-{i}.{label}.txt'
            (directory / file).write_bytes(proc.stdout)
            (directory / (file + '.stderr')).write_bytes(proc.stderr)
            decoded = rows(proc.stdout.decode())
            joins = []
            if label == 'llvm':
                decoded, joins = llvm_logical(decoded, canonical)
            require(decoded == canonical, 'GNU/LLVM/Capstone partitions disagree')
            member['exports'].append({'file': file, 'sha256': sha(proc.stdout), 'bytes': len(proc.stdout),
                                      'standalone_lock_joins': joins})
            commands.append({'argv': argv, 'exit_code': proc.returncode,
                             'stdout': file, 'stdout_sha256': sha(proc.stdout),
                             'stderr': file + '.stderr', 'stderr_sha256': sha(proc.stderr),
                             'tool_sha256': sha(Path(tool).read_bytes()),
                             'version': subprocess.check_output([tool, '--version'], text=True).splitlines()[0]})
        members.append(member)
    require(members[0]['bytes'] == 305 and members[0]['instructions'] == 81, 'primary extent')
    sec = {x['name']: x for x in image.secs}
    symbols, relas, names = sec['.dynsym'], sec['.rela.dyn'], sec['.dynstr']
    import_records = []
    for name, slot in IMPORTS.items():
        require(image.named.get(name) == [slot], 'unique named import')
        matches = []
        for offset in range(relas['offset'], relas['offset'] + relas['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, offset)
            if where == slot:
                matches.append((offset, info, addend))
        require(len(matches) == 1, 'duplicate/missing import relocation')
        offset, info, addend = matches[0]
        require(info & 0xffffffff in (6, 7), 'named import kind')
        symbol = symbols['offset'] + (info >> 32) * 24
        name_at = names['offset'] + struct.unpack_from('<I', data, symbol)[0]
        require(data[name_at:name_at + len(name) + 1] == name.encode() + b'\0', 'actual dynamic name')
        bind('relocation-' + name, offset, 24)
        bind('symbol-' + name, symbol, 24)
        bind('name-' + name, name_at, len(name) + 1)
        calls = [v for v in image.slot_calls(slot) if 0x3cd6690 <= v < 0x3cd67c1]
        import_records.append({'name': name, 'slot': hex(slot), 'relocation_file_offset': offset,
                               'info': info, 'addend': addend, 'calls': [hex(x) for x in calls]})
    for slot, target in ((0x5776490, 0x3cd6690), (0x5773d08, 0x4f78960)):
        matches = [p for p in range(relas['offset'], relas['offset'] + relas['size'], 24)
                   if struct.unpack_from('<Q', data, p)[0] == slot]
        require(len(matches) == 1, 'unique context slot')
        offset = matches[0]
        require(struct.unpack_from('<QQq', data, offset) == (slot, 8, target), 'context slot binding')
        bind('context-slot-' + hex(slot), offset, 24)
    pin = {'target_sha256': TARGET, 'target_size': SIZE, 'members': members,
           'imports': import_records, 'bindings': bindings,
           'text_section': sec['.text'], 'rela_section': relas,
           'rela_records': relas['size'] // 24,
           'decoded_primary': [{'va': hex(x.address), 'size': x.size, 'bytes': x.bytes.hex(),
                                'mnemonic': x.mnemonic, 'operands': x.op_str}
                               for x in md.disasm(image.read(0x3cd6690, 305), 0x3cd6690)],
           'method': 'full static bytes/unwind/import bindings; raw direct/slot encoding census, boundary-confirmed in complete contexts; no captured execution or instruction interpretation'}
    pin['census'] = census(data, pin)
    require(pin['census']['direct'] == [], 'unexpected direct member entry')
    require(pin['census']['slot_calls'] == [
        ['0x22c5c3b', '0x5773d08', 21], ['0x4391062', '0x5773d08', 21],
        ['0x47b68fa', '0x5773d08', 21], ['0x4f78970', '0x5776490', 21]], 'slot census')
    return pin, commands


def check_bindings(data, pin, identity=True):
    require(len(data) == SIZE, 'target size')
    if identity:
        require(sha(data) == TARGET, 'target digest')
    for binding in pin['bindings']:
        at, size = binding['offset'], binding['size']
        require(data[at:at + size] == bytes.fromhex(binding['hex']), 'binding: ' + binding['name'])
    require(census(data, pin) == pin['census'], 'direct/slot/entry-relocation census')


def controls(data, pin):
    mutable = bytearray(data)
    selected, seen, results = [], set(), []
    primary = next(x for x in pin['bindings'] if x['name'] == 'body-0x3cd6690')
    for instruction in pin['decoded_primary']:
        at = primary['offset'] + int(instruction['va'], 16) - 0x3cd6690 + instruction['size'] - 1
        selected.append((instruction['va'] + ' ' + instruction['mnemonic'] + ' ' + instruction['operands'], at))
    for binding in pin['bindings']:
        if binding['name'] != 'body-0x3cd6690':
            selected.append((binding['name'], binding['offset']))
    for label, at in selected:
        if at in seen:
            continue
        seen.add(at)
        mutable[at] ^= 1
        try:
            check_bindings(mutable, pin, identity=False)
        except ValueError as error:
            results.append({'label': label, 'offset': at, 'xor': 1, 'rejected': str(error)})
        else:
            raise ValueError('surviving below-admission corruption: ' + label)
        finally:
            mutable[at] ^= 1
    # Reject an extra direct entry edge outside every existing pinned body.
    place = primary['offset'] + primary['size']
    original = bytes(mutable[place:place + 5])
    source = 0x3cd67c1
    require(original == b'\xcc' * 5, 'unclaimed padding for census control')
    mutable[place:place + 5] = b'\xe8' + struct.pack('<i', 0x3cd6690 - source - 5)
    try:
        check_bindings(mutable, pin, identity=False)
    except ValueError as error:
        results.append({'label': 'introduced direct entry outside bodies', 'offset': place, 'rejected': str(error)})
    else:
        raise ValueError('introduced direct entry survived')
    mutable[place:place + 5] = original
    try:
        check_bindings(data[:-1], pin)
    except ValueError as error:
        results.append({'label': 'truncated whole target', 'rejected': str(error)})
    else:
        raise ValueError('truncated target survived')
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--record', action='store_true')
    args = parser.parse_args()
    path = ROOT / 'artifacts/node/94/hl-node'
    data = path.read_bytes()
    require(len(data) == SIZE and sha(data) == TARGET, 'authenticated target')
    directory = HERE / 'static'
    authority = directory / 'authority.json'
    if args.record:
        require(not authority.exists(), 'do not replace static authority')
        directory.mkdir(parents=True, exist_ok=True)
        pin, commands = build_authority(data, Image(data), directory)
        authority.write_bytes(encoded(pin))
        (directory / 'commands.json').write_bytes(encoded(commands))
    else:
        pin = json.loads(authority.read_bytes())
        image = Image(data)
        for m in pin['members']:
            require(image.fde_of(int(m['start'], 16)) == (int(m['start'], 16), int(m['end'], 16)), 'fresh FDE extent')
            for ex in m['exports']:
                value = (directory / ex['file']).read_bytes()
                require(len(value) == ex['bytes'] and sha(value) == ex['sha256'], 'export changed')
    check_bindings(data, pin)
    rejected = controls(data, pin)
    require(sha(path.read_bytes()) == TARGET, 'artifact changed during static inspection')
    result = {'target_sha256': TARGET, 'primary_bytes': 305, 'primary_instructions': 81,
              'complete_context_bytes': sum(x['bytes'] for x in pin['members'][1:]),
              'named_imports': len(pin['imports']), 'negative_controls': len(rejected),
              'controls': rejected, 'target_execution': False, 'instruction_emulation': False}
    if args.record:
        (directory / 'qualification.json').write_bytes(encoded(result))
    print(json.dumps({k: v for k, v in result.items() if k != 'controls'}, sort_keys=True))


if __name__ == '__main__':
    main()
