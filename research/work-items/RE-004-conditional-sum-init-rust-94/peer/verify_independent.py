"""Independent bytewise fixture and manual ELF review; stdout only, no execution.

Run from any directory with Python 3 and Capstone 5.0.7. This imports neither
the packet oracle/static verifier nor repository ELF/FDE parsing helpers.
"""
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent
ROOT = PACKET.parents[2]
SOURCE = ROOT / 'src/node94-conditional-sum-init'
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BEGIN, END = 0x5475e80, 0x5475ead
BODY = bytes.fromhex('f30f1efa4863c248c70700000000488947184801f085d2480f45f048c7471000000000b80100000048897708c3')
CIES = {
    0xce1518: '1400000000000000017a5200017810011b0c070890010000',
    0xfbdc2c: '1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000',
    0x1301ae8: '1c00000000000000017a504c5200017810079b3d5848041b1b0c070890010000',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def arithmetic_review():
    frozen = json.loads((PACKET / 'frozen.json').read_text())
    raw = gzip.decompress((PACKET / 'inputs.bin.gz').read_bytes())
    truth = gzip.decompress((PACKET / 'expected.bin.gz').read_bytes())
    require(sha(raw) == frozen['inputs_sha256'], 'input freeze')
    require(sha(truth) == frozen['expected_sha256'], 'expected freeze')
    require(sha((PACKET / 'oracle.py').read_bytes()) == frozen['oracle_sha256_at_freeze'], 'oracle freeze')
    require(sha((PACKET / 'static.json').read_bytes()) == frozen['static_sha256_at_freeze'], 'static freeze')
    require(len(raw) == 9690 * 168 and len(truth) == 9690 * 160, 'fixture framing')
    output = bytearray()
    stats = dict(cases=0, admitted=0, refusals=0, negative_low32=0,
                 zero_low32_with_high_bits=0, sum_wraps=0,
                 unaligned_destinations=0, exact_end_spans=0)
    for number in range(9690):
        row = raw[number * 168:(number + 1) * 168]
        base, dest, rsi, rdx, length = struct.unpack_from('<5Q', row)
        require(length <= 128, 'descriptor length')
        image = bytearray(row[40:])
        stats['cases'] += 1
        # Endpoint containment, without the author's dictionary or checked-sub API.
        admitted = base + length <= 2**64 and base <= dest and dest + 32 <= base + length
        if admitted:
            # Replicate the sign byte; never calculate signed = low - 2**32.
            low = row[24:28]
            extension = low + bytes([255 if low[3] & 128 else 0]) * 4
            total = bytearray(8)
            carry = 0
            for i, (left, right) in enumerate(zip(row[16:24], extension)):
                digit = left + right + carry
                total[i] = digit & 255
                carry = digit >> 8
            start = dest - base
            # Direct writes in actual target order, using only input snapshots.
            image[start:start + 8] = bytes(8)
            image[start + 24:start + 32] = extension
            image[start + 16:start + 24] = bytes(8)
            image[start + 8:start + 16] = total
            observed = struct.pack('<2Q', 1, 1) + total + row[24:32] + image
            stats['admitted'] += 1
            stats['negative_low32'] += bool(low[3] & 128)
            stats['zero_low32_with_high_bits'] += low == bytes(4) and row[28:32] != bytes(4)
            stats['sum_wraps'] += (not carry) if low[3] & 128 else bool(carry)
            stats['unaligned_destinations'] += dest % 8 != 0
            stats['exact_end_spans'] += dest + 32 == base + length
        else:
            observed = bytes(32) + image
            stats['refusals'] += 1
        expected = truth[number * 160:(number + 1) * 160]
        require(observed == expected, 'full output mismatch at row ' + str(number))
        output.extend(observed)
    require(all(frozen[key] == value for key, value in stats.items()), 'coverage counters')
    return {**stats, 'input_sha256': sha(raw), 'independent_output_sha256': sha(output),
            'expected_sha256': sha(truth), 'compared_bytes': len(output),
            'method': 'byte sign fill, bytewise carry, direct snapshot stores in native order'}


def static_review():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'whole target identity')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    require(header[0][:7] == b'\x7fELF\x02\x01\x01' and header[1:3] == (3, 62), 'ELF64 LE x86-64 ET_DYN')
    require(header[9] == 56 and header[11] == 64, 'ELF table entries')
    programs = [struct.unpack_from('<IIQQQQQQ', data, header[5] + i * 56) for i in range(header[10])]
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, header[6] + i * 64) for i in range(header[12])]
    name_section = sections[header[13]]
    names = data[name_section[4]:name_section[4] + name_section[5]]
    named = {names[s[0]:].split(b'\0', 1)[0].decode(): s for s in sections}

    def mapping(va, size):
        hits = [p for p in programs if p[0] == 1 and p[3] <= va and va + size <= p[3] + p[5]]
        require(len(hits) == 1, 'unique file-backed PT_LOAD')
        p = hits[0]
        offset = p[2] + va - p[3]
        return data[offset:offset + size], offset, p[1]

    body, offset, flags = mapping(BEGIN, END - BEGIN)
    require(body == BODY and flags & 1, 'fresh complete 45-byte executable body')
    require(mapping(END, 3)[0] == b'\xcc' * 3, 'separate padding')
    # The three bound CIE encodings all use 0x1b (pcrel sdata4) for FDE starts
    # and its 0x0b scalar format for ranges. Decode every actual FDE, not hdr seeds.
    eh = named['.eh_frame']
    cursor, limit = eh[4], eh[4] + eh[5]
    frames, cies = [], {}
    while cursor < limit:
        size = struct.unpack_from('<I', data, cursor)[0]
        if size == 0:
            require(not any(data[cursor:limit]), 'zero EH terminator padding')
            break
        require(4 <= size < 0xffffffff and cursor + 4 + size <= limit, 'EH record extent')
        va = eh[3] + cursor - eh[4]
        link = struct.unpack_from('<I', data, cursor + 4)[0]
        if link == 0:
            cies[va] = data[cursor:cursor + 4 + size].hex()
            require(cies[va] == CIES.get(va), 'exact reviewed CIE encoding')
        else:
            cie = va + 4 - link
            require(cie in cies, 'backward CIE reference')
            delta, span = struct.unpack_from('<ii', data, cursor + 8)
            require(span >= 0, 'nonnegative FDE span')
            start = va + 8 + delta
            frames.append((va, cie, start, start + span))
        cursor += size + 4
    require(cies == CIES and len(frames) == 121299, 'complete FDE/CIE inventory')
    retained = json.loads((PACKET / 'static.json').read_text())
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def listing(path):
        rows = []
        for line in path.read_text().splitlines():
            found = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
            if found:
                rows.append((int(found[1], 16), bytes.fromhex(found[2])))
        return rows

    windows, edges = [], []
    for record in retained['members'] + retained['callers']:
        start, end = record['begin'], record['end']
        raw, file_offset, flags = mapping(start, end - start)
        require(flags & 1 and sha(raw) == record['body_sha256'], 'full executable window')
        overlaps = [f for f in frames if f[2] < end and start < f[3]]
        expected_frame = record['frame']
        require(len(overlaps) == 1, 'one overlapping FDE')
        require(overlaps[0] == tuple(expected_frame[k] for k in ('fde', 'cie', 'start', 'end')), 'exact complete FDE')
        for kind in ('fde', 'cie'):
            saved = record['records'][kind]
            require(mapping(saved['va'], len(bytes.fromhex(saved['hex'])))[0].hex() == saved['hex'], 'raw ' + kind)
        decoded = list(decoder.disasm(raw, start))
        require(sum(i.size for i in decoded) == end - start and len(decoded) == record['instructions'], 'complete decode')
        label = ('member' if start == BEGIN else 'caller') + str(record['index'])
        partition = [(i.address, bytes(i.bytes)) for i in decoded]
        require(partition == listing(PACKET / (label + '.gnu.txt')) == listing(PACKET / (label + '.llvm.txt')), 'complete GNU/LLVM partitions')
        for site in record.get('sites', []):
            ins = next(i for i in decoded if i.address == site)
            require(ins.mnemonic == 'call' and int(ins.op_str, 16) == BEGIN, 'actual caller boundary')
            edges.append(site)
        windows.append({'start': start, 'end': end, 'bytes': len(raw), 'instructions': len(decoded),
                        'sha256': sha(raw), 'file_offset': file_offset, 'fde': overlaps[0]})
    text = named['.text']
    code = data[text[4]:text[4] + text[5]]
    candidates = {'E8': [], 'E9': []}
    for opcode, label in ((b'\xe8', 'E8'), (b'\xe9', 'E9')):
        cursor = 0
        while (cursor := code.find(opcode, cursor)) >= 0:
            if cursor + 5 <= len(code):
                target = text[3] + cursor + 5 + struct.unpack_from('<i', code, cursor + 1)[0]
                if BEGIN <= target < END + 3:
                    candidates[label].append([text[3] + cursor, target])
            cursor += 1
    require(candidates == {'E8': [[site, BEGIN] for site in sorted(edges)], 'E9': []}, 'whole text interval direct candidates')
    count, naming, writers = 0, [], []
    for section in sections:
        require(section[1] != 9, 'no unsupported REL sections')
        if section[1] != 4:
            continue
        require(section[9] == 24 and section[5] % 24 == 0, 'RELA shape')
        for where in range(section[4], section[4] + section[5], 24):
            dest, info, addend = struct.unpack_from('<QQq', data, where)
            require(info & 0xffffffff in (1, 6, 7, 8, 18), 'bound eight-byte relocation kinds')
            count += 1
            if BEGIN <= addend < END + 3:
                naming.append([where, dest, info, addend])
            if dest < END + 3 and BEGIN < dest + 8:
                writers.append([where, dest, info, addend])
    require(count == 80300 and not naming and not writers, 'complete RELA target interval closure')
    return {'target_sha256': sha(data), 'target_bytes': len(data), 'body_hex': body.hex(),
            'body_file_offset': offset, 'fde_count': len(frames), 'cie_count': len(cies),
            'windows': windows, 'direct_interval_candidates': candidates, 'rela_count': count,
            'naming_relocations': naming, 'code_writers': writers,
            'indirect_reachability_complete': False, 'capstone_version': capstone.__version__}


def main():
    protected = [SOURCE / 'lib.rs', SOURCE / 'input_only_driver.rs'] + [PACKET / x for x in
                 ('PROOF.md', 'oracle.py', 'frozen.json', 'static.json', 'inputs.bin.gz', 'expected.bin.gz', 'verify_static.py', 'verify_rust.py')]
    hashes = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in protected}
    result = {'arithmetic': arithmetic_review(), 'static': static_review(),
              'reviewed_sha256': hashes, 'reviewer_sha256': sha(Path(__file__).read_bytes()),
              'captured_code_executed': False, 'instruction_emulation': False,
              'native_rust_replayed': False, 'blockers': []}
    require(hashes == {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in protected}, 'protected files changed during review')
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
