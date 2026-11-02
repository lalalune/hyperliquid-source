#!/usr/bin/env python3
"""Extract selected PerpDex snapshot reader evidence from the authenticated ELF."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = ((0x16bf310, 0x16bfdf5), (0x24d17f0, 0x24d1a8b), (0x17a1540, 0x17a4564), (0x16d1610, 0x16d17e7), (0x2443bd0, 0x2443d8b), (0x2443580, 0x2443868))
# Each selected instruction window is checked in full; these are not masked comparisons.
WINDOWS = {
 'map_end_checks': (0x17a29ac, 0x17a2a62),
 'map_fourth_default': (0x17a2b7b, 0x17a2bac),
 'sequence_remainder': (0x17a2265, 0x17a22a5),
 'sequence_complete': (0x17a24a4, 0x17a24ce),
 'map_books_missing_branch': (0x17a3ae9, 0x17a3af7),
 'compact_writer': (0x2443be7, 0x2443d79),
 'json_writer': (0x244358d, 0x244377a),
 'classifier': (0x16d1610, 0x16d17e7),
 'key_call': (0x17a38c2, 0x17a38f6),
 'map_funding': (0x17a3dee, 0x17a3e10),
 'map_annotation': (0x17a3d04, 0x17a3d37),
 'outer_binding': (0x1a5472a, 0x1a54756),
 'outer_sequence': (0x16bfa4d, 0x16bfae7),
 'outer_depth': (0x16bfb46, 0x16bfb5c),
 'allocation_and_limit': (0x24d1806, 0x24d1841),
 'element_loop': (0x24d1870, 0x24d18d8),
 'element_failure': (0x24d1975, 0x24d19e5),
 'element_sequence_books': (0x17a1c35, 0x17a1cde),
 'element_sequence_funding': (0x17a1d80, 0x17a1d9f),
 'element_sequence_twap': (0x17a1e59, 0x17a1ec1),
 'element_sequence_default_fourth': (0x17a2029, 0x17a2054),
 'element_sequence_fourth': (0x17a2104, 0x17a212b),
 'element_map_dispatch': (0x17a3ac7, 0x17a3b13),
 'element_map_unknown': (0x17a3b55, 0x17a3b7c),
 'element_map_duplicate_twap': (0x17a3bdb, 0x17a3c00),
 'element_copy': (0x17a2368, 0x17a2387),
 'missing_books': (0x17a19ee, 0x17a1a44),
 'missing_funding': (0x17a1a90, 0x17a1ae9),
 'missing_twap': (0x17a2a14, 0x17a2a62),
 'duplicate_twap': (0x17a4201, 0x17a4257),
 'duplicate_annotation': (0x17a42b1, 0x17a4307),
 'duplicate_books': (0x17a43aa, 0x17a4405),
 'duplicate_funding': (0x17a445f, 0x17a44b5),
}
# Filled with SHA-256 of the exact ranges above, independently of objdump output.
PINS = {'map_end_checks': 'bb4300a6478e838a2dc29c50a8b169fb2fa135016d953a2d9b30ff7a3ef5cd9f', 'map_fourth_default': '08837551a25f432a182771416d8c83168d6082c45de02ec05fadc819c00408c3', 'sequence_remainder': '6f46eaeca126849c05ffd7ae40d0f3572243268bbd6c0afe56087f760f268761', 'sequence_complete': '2c62faf205585e8c15ef2cbb793646169f1e999c81f55dae92388d5f6e5e887b', 'map_books_missing_branch': 'ac972a2cf65509623ea7603179aa071a8a68adce233374dd0bbecc3055b42a67', 'compact_writer': '1ff446a52ddcc64e3e35425e6da452de91eb6bb9c73e4d8cded194e72b4dca18', 'json_writer': '8e65b0354e00a7cbf473e5893f8453b3062207ac7d919604a735446336366ac7', 'classifier': '6c301fa4aef450afda8be9fe54e1745ef30ecc27cedb417cb4b7c1c57befb64f', 'key_call': '480df16372a49e6b483c2f918f07c1adbb2c8a86ccd2df0df2a4c7390993b627', 'map_funding': '23730ab703c6ec8bab1c454066c9f464f466744457e6c5458359d24171be4333', 'map_annotation': '00f704937914a8f2bde1f5c73dd30eabb3b6538e090a69d0f6d12fa2f4739e35', 'outer_binding': '9baebbce2cd4c06bbd2ce7a471d6b41ecece4d0273795d8b9f3a1c638885c64d', 'outer_sequence': '34a90b7dca962b236b82ba9260022fc905773f68e20934760a5b6a940937b0ed', 'outer_depth': 'a012afcddab0410ca0489083a095b165e3d32a3f8bc4a03166513a658f753d86', 'allocation_and_limit': '901fd41f638792a1cb855a7aaad6bed64d8f614bd95922a4c8fe7d05c1b032ac', 'element_loop': '6b328d9c8c5b887fe793829951f321f02edf124a738851c2b1217c0cb26ff2f5', 'element_failure': 'facbf3b4d5d8f44d17e9551a147b19e43d5d42c4c99d7b253b7d7ffa48a87a7b', 'element_sequence_books': '3dffa035c98372d97f43130260874e718baa210e5c0155f731108087382a2119', 'element_sequence_funding': '78c119748f30991346bfe43fe5bf89701e6510e74f983643f423b7aaf85daca8', 'element_sequence_twap': 'a8a64107fb8f7760f9bc275c4ddc066848a3973bb3f9e586087ddd445b70683f', 'element_sequence_default_fourth': 'af399dc9654bdb7deb749bdccfbdb793e2681b67160482175dd43530fc41be63', 'element_sequence_fourth': '3bf1ec60be4fb93dd49c1ad087fdb41f936e44747036b1fbd5fa345c9a3ee696', 'element_map_dispatch': 'b5b0fab488f02406c0b012218db4b076082e0f494440530bb83e59f8caf64a42', 'element_map_unknown': '081ef3b8987648eeeacb151e8f6ab268d3d0482a5cf84e190b4b72e1a06000bd', 'element_map_duplicate_twap': '9267f5bc2dfc0212fc472f1d08762caf2cdcb0e65ceaaae255e918f531eba0d6', 'element_copy': '7f461b2fb1b8f09ccd356a8b573011c8db99bc60963f8ecf4cbe521e2e687361', 'missing_books': '9ca761bf02605a07bfd25c3760d01042480a19f28d51010e90438d887d840dd9', 'missing_funding': 'd7ffa73be59685a86713a3607be31014a16f8024a07ba99b6493f6f19044c7ef', 'missing_twap': '379842bec752d31f2863487952ffc23e71723f485bc51bdb21b087a029503195', 'duplicate_twap': '6f3dd0490f13b12c27a3fb798324adeeace7ca581b0769107e10efb88a288e54', 'duplicate_annotation': '72b37e07376ac7e5f375a55f2bc30dc3af573f26c396610bceb456eae50605c5', 'duplicate_books': 'ce8a6e20f430017f416c0492a5e81b47a3da9547412c59a2a1a32eca27fac9e6', 'duplicate_funding': 'f9f1e2567d5daad7c352fcc70eada2e96eededcd0a9520b56794d14f233d56d9'}

def authenticate(data, expected=DIGEST):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('node 94 SHA-256 mismatch')

def va_bytes(data, secs, va, size):
    if size < 0 or va < 0:
        raise ValueError('invalid range')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('VA is not uniquely file-backed')
    s = matches[0]; off = s['offset'] + va - s['address']
    return data[off:off + size], off

def direct_call(data, secs, site):
    raw, _ = va_bytes(data, secs, site, 5)
    if raw[0] != 0xe8:
        raise ValueError('expected direct call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]

def conditional(data, secs, site):
    raw, _ = va_bytes(data, secs, site, 2)
    if raw[0] == 0x0f and raw[1] in (0x84, 0x85):
        raw, _ = va_bytes(data, secs, site, 6)
        return ('je' if raw[1] == 0x84 else 'jne', site + 6 + struct.unpack_from('<i', raw, 2)[0])
    if raw[0] in (0x74, 0x75):
        return ('je' if raw[0] == 0x74 else 'jne', site + 2 + struct.unpack_from('<b', raw, 1)[0])
    raise ValueError('expected conditional branch')


def extract(data, expected=DIGEST):
    authenticate(data, expected)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {f['start']: f for f in fdes}
    indexed = {f['start']: f['fde'] for f in index}
    functions = []
    for start, end in FUNCTIONS:
        f = by_start[start]
        if f['end'] != end or indexed.get(start) != f['fde']:
            raise ValueError('FDE extent or index mismatch')
        raw, off = va_bytes(data, secs, start, end - start)
        functions.append({'start': hex(start), 'end_exclusive': hex(end), 'fde': hex(f['fde']), 'file_offset': hex(off), 'sha256': hashlib.sha256(raw).hexdigest()})
    windows = []
    for name, (start, end) in WINDOWS.items():
        raw, off = va_bytes(data, secs, start, end-start)
        if hashlib.sha256(raw).hexdigest() != PINS[name]:
            raise ValueError('instruction window mismatch: ' + name)
        windows.append({'name': name, 'va': hex(start), 'end_exclusive': hex(end), 'file_offset': hex(off), 'bytes': raw.hex()})
    # Decode the admitted byte-compare instructions, including short and near
    # conditional branches. The four starts and lengths are the selected arms.
    classified = []
    for start, count, tag in [(0x16d162c, 5, 0), (0x16d1666, 15, 1), (0x16d1702, 12, 2), (0x16d1771, 18, 3)]:
        pos = start; chars = bytearray()
        for i in range(count):
            op, _ = va_bytes(data, secs, pos, 2)
            if op == b'\xb0' + bytes([tag]):
                pos += 2
                op, _ = va_bytes(data, secs, pos, 2)
            if i == 0:
                raw, _ = va_bytes(data, secs, pos, 3)
                if raw[:2] != b'\x80\x3e': raise ValueError('invalid first key comparison')
                char = raw[2]; pos += 3
            else:
                raw, _ = va_bytes(data, secs, pos, 4)
                if raw[:3] != bytes((0x80, 0x7e, i)): raise ValueError('invalid key comparison offset')
                char = raw[3]; pos += 4
            chars.append(char)
            # The last comparison of the last arm uses JE to the common success.
            branch, _ = va_bytes(data, secs, pos, 2)
            if branch == b'\x0f\x85':
                raw, _ = va_bytes(data, secs, pos, 6)
                target = pos + 6 + struct.unpack_from('<i', raw, 2)[0]; pos += 6
                expected_target = 0x16d17de
            elif branch[0] in (0x75, 0x74):
                target = pos + 2 + struct.unpack('<b', branch[1:])[0]; pos += 2
                expected_target = 0x16d17e0 if branch[0] == 0x74 else 0x16d17de
            else:
                raise ValueError('invalid key mismatch branch')
            if target != expected_target: raise ValueError('unexpected key branch target')
        classified.append({'field': chars.decode('ascii'), 'tag': tag, 'compare_start': hex(start), 'length': len(chars)})
    if [x['field'] for x in classified] != ['books','funding_tracker','twap_tracker','perp_to_annotation']:
        raise ValueError('classifier mismatch')
    length_bytes, length_off = va_bytes(data, secs, 0x293b64, 14 * 4)
    length_targets = [0x293b64 + x for x in struct.unpack('<14i', length_bytes)]
    expected_lengths = {5: 0x16d162c, 12: 0x16d1702, 15: 0x16d1666, 18: 0x16d1771}
    if any(length_targets[n-5] != target for n, target in expected_lengths.items()):
        raise ValueError('classifier length table mismatch')
    calls = []
    for name, site, target in [('snapshot_field',0x1a54741,0x16bf310), ('sequence',0x16bfa94,0x24d17f0), ('element',0x24d18ae,0x17a1540), ('field_key',0x17a38d0,0x16d1610)]:
        actual = direct_call(data, secs, site)
        if actual != target:
            raise ValueError('unexpected call target')
        calls.append({'role': name, 'site': hex(site), 'target': hex(actual)})
    branches = []
    for role, site, condition, target in [
        ('sequence_missing_first', 0x17a1c6c, 'je', 0x17a1f9b),
        ('sequence_next_funding', 0x17a1cde, 'jne', 0x17a1d80),
        ('sequence_next_twap', 0x17a1e64, 'jne', 0x17a1eaf),
        ('sequence_fourth_or_default', 0x17a2039, 'jne', 0x17a2104),
        ('sequence_remainder', 0x17a2268, 'je', 0x17a24a4),
        ('map_duplicate_books', 0x17a3af1, 'jne', 0x17a4355),
        ('map_duplicate_funding', 0x17a3df8, 'jne', 0x17a440a),
        ('map_duplicate_twap', 0x17a3be8, 'jne', 0x17a41ac),
        ('map_duplicate_annotation', 0x17a3d07, 'jne', 0x17a425c),
        ('map_missing_books', 0x17a29b4, 'je', 0x17a19eb),
        ('compact_writer_skip_annotation', 0x2443d0f, 'je', 0x2443d4d),
        ('json_writer_skip_annotation', 0x244370a, 'je', 0x2443770),
    ]:
        observed, dest = conditional(data, secs, site)
        if (observed, dest) != (condition, target):
            raise ValueError('unexpected conditional branch')
        branches.append({'role': role, 'site': hex(site), 'condition': observed, 'target': hex(dest)})
    table, off = va_bytes(data, secs, 0x2cbc58, 20)
    targets = [0x2cbc58 + d for d in struct.unpack('<5i', table)]
    if targets != [0x17a3ae9,0x17a3dee,0x17a3bdb,0x17a3d04,0x17a3b55]:
        raise ValueError('field table mismatch')
    fields = []
    for name, a, n in [('books',0x3b0c92,5), ('funding_tracker',0x3b0c97,15), ('twap_tracker',0x3b0ca6,12), ('perp_to_annotation',0x3b0cb2,18)]:
        value, at = va_bytes(data, secs, a, n)
        if value != name.encode('ascii'):
            raise ValueError('field literal mismatch')
        fields.append({'name': value.decode('ascii'), 'va': hex(a), 'file_offset': hex(at), 'length': len(value)})
    writer_fields = []
    for site, length, name in [(0x2443c51, 5, 'books'), (0x2443c9f, 15, 'funding_tracker'), (0x2443cdd, 12, 'twap_tracker'), (0x2443d18, 18, 'perp_to_annotation')]:
        insn, _ = va_bytes(data, secs, site, 12)
        if insn[:3] != b'\x48\x8d\x35' or insn[7] != 0xba:
            raise ValueError('writer field setup mismatch')
        target = site + 7 + struct.unpack_from('<i', insn, 3)[0]
        length_from_code = struct.unpack_from('<I', insn, 8)[0]
        raw, at = va_bytes(data, secs, target, length_from_code)
        if length_from_code != length or raw != name.encode():
            raise ValueError('writer field mismatch')
        writer_fields.append({'site': hex(site), 'va': hex(target), 'file_offset': hex(at), 'length': length_from_code, 'name': raw.decode()})
    diagnostics = []
    for va, value in [(0x1df8f3, b'\x0fmissing field `\xc0\x01`\x00'), (0x1e0fd5, b'\x11duplicate field `\xc0\x01`\x00')]:
        actual, offset = va_bytes(data, secs, va, len(value))
        if actual != value: raise ValueError('diagnostic template mismatch')
        diagnostics.append({'va': hex(va), 'file_offset': hex(offset), 'bytes': actual.hex()})
    binding, _ = va_bytes(data, secs, 0x20acc8, 8)
    if binding != b'PerpDexs':
        raise ValueError('binding mismatch')
    return {'target_sha256': DIGEST, 'coordinate_system': 'ELF virtual addresses, exclusive ends', 'functions': functions, 'calls': calls, 'branches': branches, 'field_literals': fields, 'writer_fields': writer_fields, 'diagnostic_templates': diagnostics, 'field_classifier': classified, 'classifier_length_table': {'va': '0x293b64', 'file_offset': hex(length_off), 'first_length': 5, 'targets': [hex(x) for x in length_targets]}, 'map_table': {'va': '0x2cbc58', 'file_offset': hex(off), 'entries': [{'tag': i, 'field': classified[i]['field'] if i < len(classified) else 'unknown', 'target': hex(x)} for i,x in enumerate(targets)]}, 'windows': windows, 'limits': 'Selected bytes only; FDEs are unwind extents, not complete CFG or proof of runtime reachability.'}

def main():
    p = argparse.ArgumentParser(); p.add_argument('--out', type=Path, required=True); a = p.parse_args()
    result = extract(BINARY.read_bytes())
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
