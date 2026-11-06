#!/usr/bin/env python3
"""Read-only ELF/text binding; never executes or evaluates target instructions."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import struct


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--worktree', type=Path, required=True)
    parser.add_argument('--scout', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    target = args.worktree / 'artifacts/node/115/hl-node'
    image = target.read_bytes()
    target_hash = digest(image)
    require(target_hash == 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301', 'wrong target')
    require(image[:6] == b'\x7fELF\x02\x01', 'not ELF64 little endian')
    prior_path = args.scout / 'native-admission.json'
    prior_bytes = prior_path.read_bytes()
    require(digest(prior_bytes) == '5c74d8c5de3bd8d6b3c6cea89f8d155c03bee5760304a45cca65c9de9624ca6d', 'wrong prior static receipt')
    prior = json.loads(prior_bytes)
    phoff = struct.unpack_from('<Q', image, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', image, 54)
    loads = [struct.unpack_from('<IIQQQQQQ', image, phoff + i * phsize) for i in range(phcount)]
    loads = [p for p in loads if p[0] == 1]

    def mapped(va, size):
        candidates = [p for p in loads if p[3] <= va and va + size <= p[3] + p[5]]
        require(len(candidates) == 1, 'ambiguous or missing file-backed mapping')
        p = candidates[0]
        offset = p[2] + va - p[3]
        return offset, image[offset:offset + size]

    shoff = struct.unpack_from('<Q', image, 40)[0]
    shsize, shcount, shstrings = struct.unpack_from('<HHH', image, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', image, shoff + i * shsize) for i in range(shcount)]
    names = image[sections[shstrings][4]:sections[shstrings][4] + sections[shstrings][5]]

    def section_name(s):
        return names[s[0]:].split(b'\0', 1)[0].decode('ascii')

    relas = []
    for section in sections:
        if section[1] != 4:
            continue
        require(section[9] == 24, 'unexpected RELA entry size')
        for offset in range(section[4], section[4] + section[5], 24):
            va, info, addend = struct.unpack_from('<QQq', image, offset)
            relas.append((va, info, addend, offset, section))
    types = collections.Counter(info & 0xffffffff for _, info, _, _, _ in relas)

    def relocation(slot):
        matches = [r for r in relas if r[0] == slot]
        require(len(matches) == 1, 'nonunique slot relocation')
        va, info, addend, offset, section = matches[0]
        syms = sections[section[6]]
        require(syms[9] == 24, 'unexpected symbol size')
        index = info >> 32
        symoff = syms[4] + index * 24
        name_off, sym_info, other, ndx, value, size = struct.unpack_from('<IBBHQQ', image, symoff)
        strings = sections[syms[6]]
        string_data = image[strings[4]:strings[4] + strings[5]]
        symbol = string_data[name_off:].split(b'\0', 1)[0].decode('ascii')
        file_offset, slot_bytes = mapped(slot, 8)
        return {
            'slot': hex(slot), 'type': info & 0xffffffff, 'symbol_index': index,
            'addend': hex(addend), 'relocation_section': section_name(section),
            'relocation_file_offset': hex(offset), 'relocation_bytes': image[offset:offset + 24].hex(),
            'slot_file_offset': hex(file_offset), 'slot_file_bytes': slot_bytes.hex(),
            'symbol': {'name': symbol, 'info': sym_info, 'other': other, 'section_index': ndx,
                       'value': hex(value), 'size': size, 'file_offset': hex(symoff),
                       'raw': image[symoff:symoff + 24].hex()},
        }

    imports = [relocation(0x64dfb50), relocation(0x64df830)]
    require((imports[0]['type'], imports[0]['symbol_index'], imports[0]['addend'], imports[0]['symbol']['name']) == (6, 12, '0x0', 'memcmp'), 'memcmp mismatch')
    require((imports[0]['symbol']['info'], imports[0]['symbol']['section_index']) == (18, 0), 'memcmp symbol mismatch')
    require((imports[1]['type'], imports[1]['symbol_index'], imports[1]['addend']) == (8, 0, '0x1680c10'), 'failure target mismatch')

    eh = next(s for s in sections if section_name(s) == '.eh_frame')
    eh_data = image[eh[4]:eh[4] + eh[5]]
    labels = ['predicate', 'selected-fold', 'all-fold', 'key-iterator', 'flat-lookup']
    row_re = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(.*?)\s*$')
    bodies = []
    calls = []
    branches = []
    copied = []
    for label, old in zip(labels, prior['bodies'][:5], strict=True):
        start, end = int(old['start'], 16), int(old['end'], 16)
        text_path = (args.worktree / old['native_text_path']) if '/' in old['native_text_path'] else (args.scout / old['native_text_path'])
        raw = text_path.read_bytes()
        require(digest(raw) == old['native_text_sha256'], 'changed native text')
        file_offset, body = mapped(start, end - start)
        require(digest(body) == old['body_sha256'], 'changed body bytes')
        fde = old['fde']
        foff, coff = int(fde['fde_section_offset'], 16), int(fde['cie_section_offset'], 16)
        fbytes, cbytes = bytes.fromhex(fde['fde_record_hex']), bytes.fromhex(fde['cie_record_hex'])
        require(eh_data[foff:foff + len(fbytes)] == fbytes and eh_data[coff:coff + len(cbytes)] == cbytes, 'changed FDE/CIE')
        require(foff + 4 - struct.unpack_from('<I', fbytes, 4)[0] == coff, 'CIE back-reference')
        require(eh[3] + foff + 8 + struct.unpack_from('<i', fbytes, 8)[0] == start, 'FDE start')
        require(start + struct.unpack_from('<I', fbytes, 12)[0] == end, 'FDE extent')
        parsed = []
        cursor = start
        for line in raw.decode('utf-8').splitlines():
            m = row_re.match(line)
            if not m:
                continue
            va, opcode, assembly = int(m[1], 16), bytes.fromhex(m[2]), m[3]
            require(va == cursor and mapped(va, len(opcode))[1] == opcode, 'native row partition')
            parsed.append((va, opcode, assembly))
            cursor += len(opcode)
        require(cursor == end and len(parsed) == old['rows'], 'incomplete body')
        starts = {va for va, _, _ in parsed}
        for va, opcode, assembly in parsed:
            if assembly.startswith('call'):
                record = {'owner': label, 'va': hex(va), 'bytes': opcode.hex(), 'assembly': assembly}
                if len(opcode) == 5 and opcode[0] == 0xe8:
                    record.update(kind='direct', target=hex(va + 5 + struct.unpack_from('<i', opcode, 1)[0]))
                elif len(opcode) == 6 and opcode[:2] == b'\xff\x15':
                    slot = va + 6 + struct.unpack_from('<i', opcode, 2)[0]
                    record.update(kind='rip-slot', slot=hex(slot))
                    require(slot in (0x64dfb50, 0x64df830), 'unreviewed call slot')
                else:
                    require(va == 0x57f55bf and opcode == b'\xff\xd5', 'unreviewed register call')
                    load = next(x for x in parsed if x[0] == 0x57f5591)
                    require(load[1][:3] == b'\x48\x8b\x2d' and len(load[1]) == 7, 'RBP load encoding')
                    slot = load[0] + 7 + struct.unpack_from('<i', load[1], 3)[0]
                    require(slot == 0x64dfb50, 'RBP load slot')
                    record.update(kind='register', register='rbp', dominating_load_va=hex(load[0]), dominating_load_bytes=load[1].hex(), slot=hex(slot), premise='Manual register-write/control-flow audit plus ABI-preserved RBP across memcmp calls; no dynamic execution.')
                calls.append(record)
            if assembly.startswith('j'):
                if len(opcode) == 2 and (0x70 <= opcode[0] <= 0x7f or opcode[0] == 0xeb):
                    target_va = va + 2 + struct.unpack_from('<b', opcode, 1)[0]
                elif len(opcode) == 6 and opcode[0] == 0x0f and 0x80 <= opcode[1] <= 0x8f:
                    target_va = va + 6 + struct.unpack_from('<i', opcode, 2)[0]
                elif len(opcode) == 5 and opcode[0] == 0xe9:
                    target_va = va + 5 + struct.unpack_from('<i', opcode, 1)[0]
                else:
                    raise ValueError('unreviewed branch encoding')
                require(target_va in starts, 'branch not at same-body instruction start')
                branches.append({'owner': label, 'va': hex(va), 'bytes': opcode.hex(), 'target': hex(target_va)})
        # This conservative 16-byte window also covers potential writes starting before a body.
        overlap = [hex(va) for va, _, _, _, _ in relas if start - 16 < va < end]
        require(not overlap, 'relocation near selected body')
        destination = args.out / (label + '.gnu.txt')
        require(not destination.exists(), 'refuse existing output')
        destination.write_bytes(raw)
        copied.append({'path': destination.name, 'sha256': digest(raw), 'size': len(raw), 'source': str(text_path)})
        bodies.append({'label': label, 'start': hex(start), 'end': hex(end), 'size': len(body), 'rows': len(parsed), 'file_offset': hex(file_offset), 'body_sha256': digest(body), 'fde': fde})
    require(len(calls) == 16, 'call census mismatch')
    data = []
    for va, size, role in [(0x649cd70, 24, 'first Location'), (0x649cd58, 24, 'second Location'), (0x44ae86, 38, 'source path'), (0x64a3718, 24, 'excluded failure data'), (0x64a2068, 24, 'excluded failure data')]:
        off, value = mapped(va, size)
        record = {'va': hex(va), 'size': size, 'file_offset': hex(off), 'bytes': value.hex(), 'sha256': digest(value), 'role': role}
        if va in (0x649cd70, 0x649cd58):
            record['relocation'] = relocation(va)
            record['length'] = struct.unpack_from('<Q', value, 8)[0]
            record['line'], record['column'] = struct.unpack_from('<II', value, 16)
        if va == 0x44ae86:
            record['ascii'] = value.decode('ascii')
        data.append(record)
    require(digest(target.read_bytes()) == target_hash, 'target changed')
    result = {'schema': 'stake-static-bindings-v1', 'target_sha256': target_hash, 'target_size': len(image), 'prior_admission_sha256': digest(prior_bytes), 'script_sha256': digest(Path(__file__).read_bytes()), 'bodies': bodies, 'native_texts': copied, 'calls': calls, 'branches': branches, 'import_and_failure_bindings': imports, 'data': data, 'rela_count': len(relas), 'rela_types': {str(k): v for k, v in sorted(types.items())}, 'relocation_start_exclusion': 'No RELA start in (body.start-16, body.end) for any of the five bodies; this is static binding, not runtime loader verification.', 'captured_execution_or_emulation': False, 'limitation': 'Raw address/opcode parsing only. No instruction state, register evaluator, reference model or behavioral corpus. Manual proofs establish semantics; imported runtime identity/frame remains a premise.'}
    out = args.out / 'native-bindings.json'
    require(not out.exists(), 'refuse existing receipt')
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'bodies': len(bodies), 'bytes': sum(x['size'] for x in bodies), 'rows': sum(x['rows'] for x in bodies), 'calls': len(calls), 'branches': len(branches), 'rela_count': len(relas), 'receipt_sha256': digest(out.read_bytes())}))


if __name__ == '__main__':
    main()
