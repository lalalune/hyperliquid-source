"""Resolve the node's two exception personalities and aggregate their bounded call-site tables."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from foundation_lsda_call_site import decode_lsda
import entry_start_static as entry


def check(ok, message):
    if not ok:
        raise ValueError(message)


def prior(path):
    return json.loads((HERE.parent / path).read_text())


def section(rows, name):
    result, = (r for r in rows if r['name'] == name and r['type'] != 8)
    return result


def relocation(data, rows, slot):
    table = section(rows, '.rela.dyn')
    entries = struct.iter_unpack('<QQq', memoryview(data)[table['offset']:table['offset']+table['size']])
    matches = [(info, addend) for address, info, addend in entries if address == slot]
    check(len(matches) == 1, 'Expected one relocation writer for the personality slot')
    info, addend = matches[0]
    return info & 0xffffffff, info >> 32, addend


def import_name(data, rows, index):
    symbols = section(rows, '.dynsym')
    check(0 < index < symbols['size']//24, 'Dynamic symbol index outside table')
    _, info, visibility, owner, value, size = struct.unpack_from('<IBBHQQ', data, symbols['offset'] + 24*index)
    check((info, visibility, owner, value, size) == (0x12, 0, 0, 0, 0), 'Expected undefined global function')
    return entry.dynsym_name(data, index)


def named_body(data, frames, start, end, sha):
    check((start, end) in frames, 'Missing retained FDE extent')
    _, body = entry.read(data, start, end-start)
    check(hashlib.sha256(body).hexdigest() == sha, 'Retained body digest differs')
    return body


def call_sites(blob, va, fde_size):
    result = decode_lsda(blob, va, va)
    header = result['header']
    check(header['lpstart_encoding'] == 255 and header['call_site_encoding'] == 1,
          'Unsupported landing-pad base or call-site encoding')
    counts = Counter()
    previous_end = 0
    for row in result['call_sites']:
        start, length = row['start_offset'], row['byte_length']
        landing = int(row['landing_pad'], 16)
        check(previous_end <= start and length > 0 and start+length <= fde_size and landing < fde_size,
              'Invalid call-site range or landing-pad offset')
        previous_end = start + length
        if landing == 0:
            check(row['action'] == 0, 'Action without a landing pad')
            counts['no_landing_pad'] += 1
        elif row['action'] == 0:
            counts['cleanup_only'] += 1
        else:
            counts['nonzero_action'] += 1
    return counts


def census(data):
    check(len(data) == entry.SIZE and hashlib.sha256(data).hexdigest() == entry.SHA, 'Wrong node #115')
    rows = sections(data)
    cies, fdes = eh_frame_records(data, rows)
    frames = {(f['start'], f['end']) for f in fdes}
    std = prior('RE-002-node115-std-census/census.json')
    check(std['target']['sha256'] == entry.SHA, 'Wrong standard library census')
    rust, = (r for r in std['records'] if r['symbol'] == 'rust_eh_personality')
    named_body(data, frames, rust['start'], rust['end'], rust['target_body_sha256'])
    per_cie = {}
    for va, cie in cies.items():
        slot = cie['personality_slot']
        record = dict(cie_va=va, personality_slot=slot, fdes=0, lsdas=0, call_sites=Counter())
        if slot is not None:
            kind, idx, addend = relocation(data, rows, slot)
            if kind == 8 and idx == 0 and addend == rust['start']:
                record.update(personality='rust_eh_personality (published-object attribution)',
                              relocation='R_X86_64_RELATIVE', destination=addend)
            elif kind == 1 and idx and addend == 0 and import_name(data, rows, idx) == '__gxx_personality_v0':
                record.update(personality='__gxx_personality_v0', relocation='R_X86_64_64', dynsym_index=idx)
            else:
                raise ValueError('Unexpected personality binding')
        per_cie[va] = record
    tables = {}
    for f in fdes:
        record = per_cie[f['cie']]
        record['fdes'] += 1
        if f['lsda'] is not None:
            check(f['lsda'] not in tables and record['personality_slot'] is not None, 'Ambiguous LSDA ownership')
            tables[f['lsda']] = f
    table = section(rows, '.gcc_except_table')
    limit = table['address'] + table['size']
    starts = sorted(tables)
    check(table['address'] <= starts[0] and starts[-1] < limit, 'LSDA outside exception section')
    for va, end in zip(starts, starts[1:]+[limit]):
        f = tables[va]
        offset = table['offset'] + va-table['address']
        counts = call_sites(data[offset:offset+end-va], va, f['end']-f['start'])
        owner = per_cie[f['cie']]
        owner['lsdas'] += 1
        owner['call_sites'].update(counts)
    payload = prior('RE-012-panic-exception-payload-115/records.json')
    check(payload['target_sha256'] == entry.SHA, 'Wrong panic runtime evidence')
    raise_owner, = (r for r in payload['owners'] if r['role'] == 'owner')
    start, end = int(raise_owner['start'], 16), int(raise_owner['end'], 16)
    body = named_body(data, frames, start, end, raise_owner['sha256'])
    check(b'MOZ\0RUST' in body, 'Rust exception class changed')
    raise_import, = (i for i in payload['imports'] if i['name'] == '_Unwind_RaiseException')
    got = int(raise_import['slot'], 16)
    kind, idx, addend = relocation(data, rows, got)
    check(kind == 6 and idx == raise_import['symbol_index'] and not addend
          and import_name(data, rows, idx) == '_Unwind_RaiseException', 'Wrong raise import')
    jumps = []
    for j in payload['branches']:
        ip = int(j['site'], 16)
        if start <= ip <= end-6 and body[ip-start:ip-start+2] == b'\xff\x25':
            delta, = struct.unpack_from('<i', body, ip-start+2)
            if ip+6+delta == got:
                jumps.append(ip)
    check(len(jumps) == 1, 'Missing Rust exception wrapper tail transfer')
    return dict(target_sha256=entry.SHA, entry_fdes=len(fdes), gcc_except_table_bytes=table['size'],
                personalities=list(per_cie.values()), rust_exception=dict(class_hex=b'MOZ\0RUST'.hex(),
                raise_wrapper_start=start, raise_wrapper_end=end, wrapper_sha256=raise_owner['sha256'],
                raise_jump_va=jumps[0], raise_import_slot=got))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    record = census(entry.TARGET.read_bytes())
    if args.output:
        args.output.write_text(json.dumps(record, indent=2)+'\n')
    else:
        check(record == json.loads((HERE/'census.json').read_text()), 'Retained census differs')
        print('Verified complete node #115 personality and call-site census.')
