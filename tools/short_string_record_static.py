#!/usr/bin/env python3
"""RE-001: one node94 compact-carrier consumer; static reads only.

The 439-byte unwind-described body is observed, not assigned an original Rust
signature. The 20-byte result, input iterator and conversion helpers stay opaque.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records, sleb, uleb

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
START, END = 0x13c6430, 0x13c65e7
SOURCE_BASE = '1f8c67c63ca4794c9689235471c60297f8a5c985'
REFERENCE = '999556f6e0a474b8312db96ec3149e1c44e97c23'
SOURCE_PATH = b'/home/ubuntu/hl/code_Mainnet/base/src/cid.rs'
# These instruction observations were independently read from authenticated
# bytes and bounded GNU disassembly, not from inferred reference implementation.
ANCHORS = {
    0x13c6441: ('488b4740', 'copy final qword of 72-byte input state'),
    0x13c6470: ('488b06', 'save first output-state word'),
    0x13c6477: ('4c8b7608', 'load initial index from output state +8'),
    0x13c647b: ('488b4610', 'load output base from output state +16'),
    0x13c647f: ('4b8d0c7648c1e104488d1c014883c310', 'initial cursor = base + 48*index +16'),
    0x13c649a: ('e8b1801000', 'call opaque source helper'),
    0x13c649f: ('488b4424284885c0747d', 'zero source headword selects index commit/drain'),
    0x13c64a9: ('488b4c243848c1e104', 'scale source index by16'),
    0x13c64b2: ('488b3c08488b740808', 'load pointer/length passed to constructor'),
    0x13c64bb: ('4c8bac08b0000000488bac08b8000000', 'save two arguments for opaque payload helper'),
    0x13c64cb: ('ff15c7823a04', 'call compact constructor through relocated slot'),
    0x13c64d1: ('4989c74989d4', 'save returned low/high halves'),
    0x13c64d7: ('488d7c24284c89ee4889ea', 'pass stack result and saved arguments to payload helper'),
    0x13c64e2: ('ff1558833a04', 'call opaque payload helper'),
    0x13c64e8: ('807c2428017476', 'status byte1 selects failure path'),
    0x13c64ef: ('488d4c2429', 'payload starts one byte after status'),
    0x13c64f4: ('8b4110', 'read final4 payload bytes'),
    0x13c64fb: ('0f1001', 'read first16 payload bytes'),
    0x13c6503: ('4c8963f8', 'store constructor high half at cursor-8'),
    0x13c6507: ('4c897bf0', 'store constructor low half at cursor-16'),
    0x13c6510: ('0f2903', 'store first16 opaque payload bytes at cursor'),
    0x13c6517: ('894310', 'store final4 opaque payload bytes at cursor+16'),
    0x13c651a: ('49ffc64883c330e96affffff', 'increment index, advance48, repeat'),
    0x13c6526: ('488b04244c8930', 'write index through saved first output-state word'),
    0x13c6546: ('e805801000', 'normal drain calls same source helper'),
    0x13c6551: ('75ed', 'repeat drain while returned headword is nonzero'),
    0x13c6564: ('c3', 'normal return'),
    0x13c6565: ('488b4424304889442408', 'save failure payload pointer'),
    0x13c656f: ('488d3d270ae5fe', 'address unwrap failure literal'),
    0x13c6576: ('488d0ddb092a04', 'address opaque formatter record'),
    0x13c657d: ('4c8d054c072a04', 'address source Location record'),
    0x13c6589: ('be2b000000', 'failure literal length43'),
    0x13c658e: ('ff15b47a3a04', 'call opaque failure helper'),
    0x13c6594: ('0f0b', 'UD2 after failure helper'),
    0x13c6596: ('4889c3eb0d', 'first landing pad saves exception and joins index commit'),
    0x13c659b: ('4889c3488b7c2408488b07ff10', 'second landing pad calls through opaque vtable'),
    0x13c65a8: ('488b04244c8930', 'landing-pad path also writes current index'),
    0x13c65c6: ('e8857f1000', 'cleanup drain calls source helper'),
    0x13c65d1: ('75ed', 'repeat cleanup drain while headword is nonzero'),
    0x13c65d3: ('4889dfe8359b2904', 'pass saved exception to resume PLT'),
    0x13c65db: ('ff15477b3a04', 'call opaque landing-pad helper'),
    0x13c65e1: ('ff15417b3a04', 'call same opaque landing-pad helper'),
}
BRANCHES = (0x13c64a7, 0x13c64ed, 0x13c6521, 0x13c6551, 0x13c6599, 0x13c65d1)
CALLS = (0x13c649a, 0x13c64cb, 0x13c64e2, 0x13c6546, 0x13c658e,
         0x13c65a6, 0x13c65c6, 0x13c65d6, 0x13c65db, 0x13c65e1)
SLOTS = {0x576e798: 0x1449a80, 0x576e840: 0x1444a00, 0x576e048: 0x157aa10,
         0x576e128: 0x157b63b, 0x5666cd0: 0x1e4c4a, 0x5666f58: 0x13d2f20}
LSDA_ROWS = ((96, 88, 358, 0), (184, 135, 0, 0), (319, 37, 363, 0),
             (374, 2, 433, 1), (400, 11, 427, 1), (411, 28, 0, 0))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read_va(data, secs, va, size):
    rows = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size']]
    require(size >= 0 and len(rows) == 1, f'No unique complete file mapping at {va:#x}')
    section = rows[0]
    offset = section['offset'] + va - section['address']
    require(offset + size <= len(data), f'Truncated bytes at {va:#x}')
    return offset, data[offset:offset + size]


def relocations(data, secs):
    rows = []
    for section in secs:
        if section['type'] != 4:
            continue
        require(section['size'] % 24 == 0, 'Partial RELA entry')
        for off in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            rows.append({'slot': slot, 'info': info, 'addend': addend, 'offset': off})
    return rows


def lsda(data, secs, va):
    origin, _ = read_va(data, secs, va, 1)
    section = next(s for s in secs if s['name'] == '.gcc_except_table')
    require(section['address'] <= va < section['address'] + section['size'], 'LSDA outside exception section')
    limit, pos = section['offset'] + section['size'], origin
    require(data[pos:pos + 2] == b'\xff\x9b', 'Unexpected LPStart/type encoding')
    pos += 2
    type_offset, pos = uleb(data, pos, limit)
    type_base = va + pos - origin + type_offset
    require(data[pos] == 1, 'Expected ULEB128 call-site encoding')
    pos += 1
    length, pos = uleb(data, pos, limit)
    end = pos + length
    require(end <= limit, 'Call-site table outside exception section')
    rows = []
    while pos < end:
        values = []
        for _ in range(4):
            value, pos = uleb(data, pos, end)
            values.append(value)
        begin, size, pad, action = values
        require(begin + size <= END - START and (pad == 0 or pad < END - START), 'Call-site coordinates leave body')
        rows.append({'start': hex(START + begin), 'end': hex(START + begin + size),
                     'landing_pad': hex(START + pad) if pad else None, 'action': action,
                     'raw_uleb_values': values})
    require(tuple(tuple(r['raw_uleb_values']) for r in rows) == LSDA_ROWS, 'Observed call-site rows changed')
    filter_value, pos = sleb(data, end, limit)
    next_action, pos = sleb(data, pos, limit)
    require((filter_value, next_action) == (-1, 0), 'Observed signed action pair changed')
    return {'va': hex(va), 'file_offset': hex(origin), 'type_encoding': '0x9b',
            'type_table_base': hex(type_base), 'call_site_encoding': 'ULEB128',
            'call_site_table_bytes': length, 'rows': rows,
            'action1': {'type_filter': filter_value, 'next_action': next_action,
                        'bytes': data[end:pos].hex()},
            'decoded_prefix_bytes': pos - origin,
            'decoded_prefix_hex': data[origin:pos].hex(),
            'limits': 'Type-table/filter semantics and personality implementation are not interpreted.'}


def inspect_bytes(data):
    """Local proof obligations; tests use copied target mutations below global SHA."""
    secs = sections(data)
    cies, fdes = eh_frame_records(data, secs)
    selected = [f for f in fdes if f['start'] == START]
    require(len(selected) == 1 and selected[0]['end'] == END, 'Expected one exact 439-byte FDE range')
    fde = selected[0]
    cie = cies[fde['cie']]
    offset, body = read_va(data, secs, START, END - START)
    require(any(s['name'] == '.text' and s['flags'] & 4 and s['address'] <= START < END <= s['address'] + s['size'] for s in secs), 'Body outside executable .text')
    anchors = []
    for va, (expected, meaning) in ANCHORS.items():
        off, observed = read_va(data, secs, va, len(bytes.fromhex(expected)))
        require(observed.hex() == expected, f'Instruction control changed at {va:#x}')
        anchors.append({'va': hex(va), 'file_offset': hex(off), 'bytes': observed.hex(), 'observation': meaning})
    rela = relocations(data, secs)
    bindings = []
    for slot, addend in SLOTS.items():
        matches = [r for r in rela if r['slot'] == slot]
        require(len(matches) == 1 and matches[0]['info'] == 8 and matches[0]['addend'] == addend, f'Relative binding changed at {slot:#x}')
        r = matches[0]
        bindings.append({'slot_va': hex(slot), 'target_va': hex(addend),
                         'type': 'R_X86_64_RELATIVE', 'file_offset': hex(r['offset'])})
    location_offset, location = read_va(data, secs, 0x5666cd0, 24)
    path_length, line, column = struct.unpack_from('<QII', location, 8)
    require((path_length, line, column) == (len(SOURCE_PATH), 28, 73), 'Source Location fields changed')
    path_offset, path = read_va(data, secs, SLOTS[0x5666cd0], path_length)
    require(path == SOURCE_PATH, 'Source path bytes changed')
    message_offset, message = read_va(data, secs, 0x216f9d, 43)
    require(message == b'called `Result::unwrap()` on an `Err` value', 'Failure literal changed')
    exception = lsda(data, secs, fde['lsda'])
    edges = []
    for va in BRANCHES:
        off, raw = read_va(data, secs, va, 2)
        length = 5 if raw[0] == 0xe9 else 2
        _, raw = read_va(data, secs, va, length)
        displacement = struct.unpack_from('<i' if length == 5 else '<b', raw, 1)[0]
        target = va + length + displacement
        require(START <= target < END, 'Branch leaves selected body')
        edges.append({'va': hex(va), 'file_offset': hex(off), 'bytes': raw.hex(), 'target_va': hex(target)})
    calls = []
    for va in CALLS:
        off, raw = read_va(data, secs, va, 6)
        if raw[0] == 0xe8:
            length, kind = 5, 'direct'
            target = va + length + struct.unpack_from('<i', raw, 1)[0]
        elif raw[:2] == b'\xff\x15':
            length, kind = 6, 'GOT'
            slot = va + length + struct.unpack_from('<i', raw, 2)[0]
            target = SLOTS[slot]
        else:
            require(raw[:2] == b'\xff\x10', 'Unexpected opaque vtable call')
            length, kind, target = 2, 'indirect-through-rax', None
        pc = va + length - 1  # Unwind return PC belongs to its predecessor byte.
        owners = [i for i, r in enumerate(exception['rows']) if int(r['start'], 16) <= pc < int(r['end'], 16)]
        require(len(owners) == 1, f'Call lacks unique LSDA row at {va:#x}')
        row = {'va': hex(va), 'file_offset': hex(off), 'bytes': raw[:length].hex(),
               'kind': kind, 'target_va': hex(target) if target is not None else None,
               'return_pc': hex(va + length), 'unwind_lookup_pc': hex(pc), 'lsda_row_index': owners[0]}
        if kind == 'GOT':
            row['slot_va'] = hex(slot)
        calls.append(row)
    # Independently resolve the direct resume edge through its real PLT entry.
    _, plt = read_va(data, secs, 0x5660110, 6)
    require(plt[:2] == b'\xff\x25', 'Resume PLT is not RIP-relative indirect jump')
    resume_slot = 0x5660110 + 6 + struct.unpack_from('<i', plt, 2)[0]
    matches = [r for r in rela if r['slot'] == resume_slot]
    require(len(matches) == 1 and matches[0]['info'] & 0xffffffff == 7, 'Resume JUMP_SLOT changed')
    resume = matches[0]
    symbols = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    symbol_index = resume['info'] >> 32
    require((symbol_index + 1) * 24 <= symbols['size'], 'Resume symbol outside table')
    name_offset = struct.unpack_from('<I', data, symbols['offset'] + symbol_index * 24)[0]
    require(name_offset < strings['size'], 'Resume symbol name outside table')
    name_start = strings['offset'] + name_offset
    name_end = data.find(b'\0', name_start, strings['offset'] + strings['size'])
    require(name_end >= name_start and data[name_start:name_end] == b'_Unwind_Resume', 'Resume symbol changed')
    return {
        'body': {'start_va': hex(START), 'end_va': hex(END), 'file_offset': hex(offset),
                 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()},
        'fde': {**{k: hex(v) if isinstance(v, int) else v for k, v in fde.items()},
                'file_offset': hex(read_va(data, secs, fde['fde'], 4)[0])},
        'cie': {**{k: hex(v) if isinstance(v, int) else v for k, v in cie.items()},
                'file_offset': hex(read_va(data, secs, fde['cie'], 4)[0])},
        'instruction_controls': anchors, 'branches': edges, 'calls': calls,
        'lsda': exception, 'relative_bindings': bindings,
        'source_record': {'va': '0x5666cd0', 'file_offset': hex(location_offset),
                          'path_va': '0x1e4c4a', 'path_file_offset': hex(path_offset),
                          'path': path.decode(), 'line': line, 'column': column, 'bytes': location.hex()},
        'failure_literal': {'va': '0x216f9d', 'file_offset': hex(message_offset), 'bytes': message.hex()},
        'resume_import': {'plt_va': '0x5660110', 'plt_bytes': plt.hex(), 'slot_va': hex(resume_slot),
                          'relocation_file_offset': hex(resume['offset']), 'symbol_index': symbol_index,
                          'symbol': '_Unwind_Resume', 'type': 'R_X86_64_JUMP_SLOT'},
        'record_store_observation': {'initial_cursor': 'third output-state word +48*second word +16',
                                     'step_bytes': 48, 'visible_stores_relative_to_record_start': [
                                         {'offset': 0, 'bytes': 8, 'source': 'constructor low half'},
                                         {'offset': 8, 'bytes': 8, 'source': 'constructor high half'},
                                         {'offset': 16, 'bytes': 16, 'source': 'opaque helper payload first16'},
                                         {'offset': 32, 'bytes': 4, 'source': 'opaque helper payload final4'}],
                                     'index_store_vas': ['0x13c652a', '0x13c65ac'],
                                     'remaining12bytes': 'No explicit store in append block; padding/type/alias effects not established.'},
    }


def analyze(data):
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256, 'Input is not pinned node94')
    return {'schema': 're001-short-string-record-94/1', 'target': {'release': 94, 'bytes': len(data), 'sha256': SHA256},
            'source_base': SOURCE_BASE, 'reference_revision': REFERENCE,
            **inspect_bytes(data), 'captured_binary_executed': False,
            'denominator': 'One 439-byte unwind-described body, six LSDA rows and ten decoded calls; no whole-node coverage.',
            'unknowns': ['Original Rust signature and record/value types', 'Opaque source, conversion, formatting, drop and personality helpers',
                         'Output capacity and aliasing contracts', 'Relationship to separate CID lookup/storage',
                         'Type-table/filter semantics and runtime exception behavior'],
            'component_gates_requested': False}


def native_evidence(binary, data):
    for tool in ['objdump', 'readelf']:
        version = subprocess.check_output([tool, '--version'], text=True, encoding='utf-8').splitlines()[0]
        require('GNU' in version, f'{tool} must be GNU binutils')
    raw = subprocess.check_output(['objdump', '-d', '-M', 'intel', f'--start-address={START:#x}',
                                   f'--stop-address={END:#x}', str(binary)], text=True, encoding='utf-8')
    chunks, starts, native_calls, native_branches, native_returns = [], set(), set(), set(), set()
    cursor = START
    for line in raw.splitlines():
        fields = line.split('\t')
        if len(fields) < 2 or not re.fullmatch(r'\s*[0-9a-f]+:', fields[0]):
            continue
        va = int(fields[0].strip()[:-1], 16)
        blob = bytes.fromhex(fields[1])
        require(va == cursor and va + len(blob) <= END, 'Native disassembly byte coverage changed')
        chunks.append(blob)
        cursor += len(blob)
        if len(fields) > 2 and fields[2].strip():
            starts.add(va)
            mnemonic = fields[2].strip().split()[0]
            if mnemonic in ('call', 'callq'):
                native_calls.add(va)
            elif mnemonic.startswith('j'):
                native_branches.add(va)
            elif mnemonic in ('ret', 'retq'):
                native_returns.add(va)
    secs = sections(data)
    require(cursor == END and b''.join(chunks) == read_va(data, secs, START, END - START)[1], 'Native bytes differ from authenticated body')
    require(set(CALLS + BRANCHES) <= starts, 'A claimed call/branch is not a decoded instruction start')
    require(native_calls == set(CALLS) and native_branches == set(BRANCHES)
            and native_returns == {0x13c6564}, 'Complete bounded call/branch/return census changed')
    frames, selected, count = [], False, 0
    with subprocess.Popen(['readelf', '-wf', str(binary)], stdout=subprocess.PIPE, text=True, encoding='utf-8') as process:
        for line in process.stdout:
            if 'FDE' in line and f'pc={START:016x}..{END:016x}' in line:
                selected, count = True, count + 1
            if selected:
                frames.append(line)
                if not line.strip():
                    selected = False
        require(process.wait() == 0 and count == 1, 'Native FDE extent check failed')
    # Preserve selected raw native RELA rows as an independent binding check.
    rela = subprocess.check_output(['readelf', '-rW', str(binary)], text=True, encoding='utf-8')
    wanted = set(SLOTS) | {0x5778db0}
    lines = [line for line in rela.splitlines() if re.match(r'^[0-9a-f]+\s', line)
             and int(line.split()[0], 16) in wanted]
    require(len(lines) == len(wanted), 'Native relocation row count changed')
    return {'consumer.objdump.txt': raw.replace(str(binary), '<authenticated-node94>'),
            'frames.txt': ''.join(frames), 'relocations.txt': '\n'.join(lines) + '\n'}


def source_unchanged(binary, before, expected_digest):
    """Bind source identity/bytes; unrelated hard-link ctime changes are harmless."""
    after = binary.stat()
    signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns)
    if signature(before) != signature(after):
        return False
    return hashlib.sha256(binary.read_bytes()).hexdigest() == expected_digest


def snapshot_evidence(data, reader):
    """Give a static reader only an owned, non-executable copy of admitted bytes."""
    expected = hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory(prefix='short-string-record-') as folder:
        directory = Path(folder)
        require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'Snapshot directory is not private')
        snapshot = directory / 'authenticated-input.elf'
        descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        before = snapshot.lstat()
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_nlink == 1, 'Snapshot is not an owned non-executable regular file')
        require(hashlib.sha256(snapshot.read_bytes()).hexdigest() == expected, 'Snapshot differs from admitted bytes')
        exports = reader(snapshot, data)
        after = snapshot.lstat()
        signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        require(signature(before) == signature(after), 'Owned snapshot changed during static collection')
        require(hashlib.sha256(snapshot.read_bytes()).hexdigest() == expected,
                'Owned snapshot changed during static collection')
        return exports


def generate(binary, output):
    before = binary.stat()
    data = binary.read_bytes()
    records = analyze(data)
    exports = snapshot_evidence(data, native_evidence)
    require(source_unchanged(binary, before, SHA256), 'Input changed during static collection')
    output.mkdir(parents=True, exist_ok=False)
    exports['records.json'] = json.dumps(records, indent=2, sort_keys=True) + '\n'
    for name, text in exports.items():
        (output / name).write_bytes(text.encode('utf-8'))
    return records


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    p.add_argument('--output', type=Path, required=True, help='new output directory; existing evidence is preserved')
    args = p.parse_args(argv)
    try:
        records = generate(args.binary.resolve(), args.output)
    except (OSError, ValueError, struct.error, subprocess.SubprocessError) as error:
        print(f'short_string_record_static: {error}', file=sys.stderr)
        return 1
    print(json.dumps({'target_sha256': records['target']['sha256'], 'body_bytes': records['body']['bytes'],
                      'calls': len(records['calls']), 'lsda_rows': len(records['lsda']['rows']), 'component_gates_requested': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
