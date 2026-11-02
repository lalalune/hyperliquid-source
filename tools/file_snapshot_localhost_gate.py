#!/usr/bin/env python3
"""RE-012: bind the fileSnapshot localhost admission rule to captured bytes.

Static only. It reads the digest-checked node #94 and #115 files and never executes them.
For each capture it locates the unique diagnostic template, the one .text LEA that loads
it, the FDE that owns that LEA (the info handler's request future), and then checks every
anchored instruction of the admission rule: the IpAddr tag test, the IPv4 dword compare,
the IPv6 16-byte compare against the ::1 constant, the out_path length bound, the
critical-log call with its Location record, and the state/dispatch plumbing around them.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import manifest_item
from bincode_varint import EvidenceError, bytes_in_section, fde_extents, relative_relocs, sections

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'research/work-items/RE-012-file-snapshot-localhost-gate-94'
TARGETS = {'94': 'artifacts/node/94/hl-node', '115': 'artifacts/node/115/hl-node'}
# Length-prefixed template: 0x45 = 69 text bytes, then one argument placeholder.
TEMPLATE = b'\x45not writing snapshot to file because request was not from localhost: \xc0\x00'
IPV6_LOOPBACK = bytes(15) + b'\x01'
IPV4_LOOPBACK_LE = 0x0100007f  # bytes 7f 00 00 01 = 127.0.0.1 as stored in Ipv4Addr
OUT_PATH_BOUND = 0x65  # len < 101 proceeds
HANDLER = {'94': '/home/ubuntu/hl/code_Mainnet/info_server/src/abci_state_info_handler.rs',
           '115': 'info_server/src/abci_state_info_handler.rs'}
CRIT_MARKER = b'base/src/crit_msg.rs'  # the critical-message module, as a Location path or a plain string

# (va, exact bytes, kind, expected target, meaning). Targets are VAs; GOT slots resolve
# through their RELATIVE addend. Instruction starts include prefixes.
ANCHORS = {
    '94': {
        'future': (0x27e91d0, 0x27ecdc2),
        'state_byte': 0x93,
        'ip_offset': 0x94,
        'out_path': {'cap': 0x20, 'ptr': 0x28, 'len': 0x30},
        'request_table': (0x3f0c80, 0x27e927a),
        'state_table': (0x3f0bac, 0x27e91fe),
        'vtable_slot': 0x56c39b0,
        # dyn Future vtable of the boxed inner future: [drop_in_place, size, align, poll]
        'inner_vtable': {'va': 0x56c3d98, 'drop': 0x2833ed0, 'size': 0x58, 'align': 0x8, 'poll': 0x27f45d0},
        'display_thunk': (0x157c690, 0x157c6a7),
        'logger': (0x143d010, 0x143e888),
        'log_location': (153, 21),
        'anchors': [
            (0x27e91e7, '0fb686 93000000', 'bytes', None, 'state byte: movzx eax,[rsi+0x93]'),
            (0x27e9223, '0f1083 80000000', 'bytes', None, 'copy 16 IpAddr bytes from input+0x80'),
            (0x27e922a, '0f1183 94000000', 'bytes', None, 'into future+0x94'),
            (0x27e9231, '0fb683 90000000', 'bytes', None, 'copy the 17th IpAddr byte from input+0x90'),
            (0x27e9238, '8883 a4000000', 'bytes', None, 'into future+0xa4'),
            (0x27e9266, '0fb64b50', 'bytes', None, 'request discriminant: movzx ecx,[rbx+0x50]'),
            (0x27e926a, '488d35 0f7ac0fd', 'lea', 0x3f0c80, 'request jump table'),
            (0x27e9289, '4c8b7b20', 'bytes', None, 'out_path cap -> r15'),
            (0x27e928d, '4c8b6328', 'bytes', None, 'out_path ptr -> r12'),
            (0x27e9295, '80bb 94000000 00', 'bytes', None, 'IpAddr tag == 0 (V4)?'),
            (0x27e929c, '0f84 f7320000', 'jcc', 0x27ec599, 'V4: go to the dword compare'),
            (0x27e92a2, 'f30f6f83 95000000', 'bytes', None, 'V6: load 16 octets at future+0x95'),
            (0x27e92aa, '660f7405 4ec9a1fd', 'pcmpeqb', 0x205c00, 'compare with the ::1 constant'),
            (0x27e92b2, '66440fd7c0', 'bytes', None, 'pmovmskb r8d,xmm0'),
            (0x27e92b7, '4181f8 ffff0000', 'bytes', None, 'all 16 bytes equal?'),
            (0x27e92be, '0f85 e5320000', 'jcc', 0x27ec5a9, 'not ::1: reject'),
            (0x27e92cb, '488b6b30', 'bytes', None, 'out_path len -> rbp'),
            (0x27e92cf, '4883fd65', 'bytes', None, 'len < 0x65?'),
            (0x27e92d3, '0f82 1e330000', 'jcc', 0x27ec5f7, 'yes: box the file_snapshot future'),
            (0x27e92e6, 'ff15 244df802', 'call_got', 0x54c8cb0, 'no: free out_path'),
            (0x27e9308, 'bd 43010000', 'bytes', None, 'length-reject code 0x143'),
            (0x27ec599, '81bb 95000000 7f000001', 'bytes', None, 'V4 octets == 127.0.0.1 exactly'),
            (0x27ec5a3, '0f84 1bcdffff', 'jcc', 0x27e92c4, 'equal: continue to the length check'),
            (0x27ec5a9, '488d83 94000000', 'bytes', None, 'reject: &IpAddr for the log argument'),
            (0x27ec5ca, '488b05 2f41f802', 'load_got', 0x157c690, 'IpAddr Display thunk'),
            (0x27ec5d6, '488d35 59799ffd', 'lea_template', None, 'the diagnostic template'),
            (0x27ec5dd, '488d0d d473ed02', 'lea_location', None, 'log Location'),
            (0x27ec5ec, 'ff15 8623f802', 'call_got', 0x143d010, 'critical logger'),
            (0x27ec5f2, 'e9 51ebffff', 'jmp', 0x27eb148, 'then free out_path and finish'),
            (0x27ec63e, 'e8 0d470000', 'call_rel', 0x27f0d50, 'box the inner future (0x58 bytes)'),
            (0x27ec64d, '488d05 4477ed02', 'lea', 0x56c3d98, 'inner future vtable'),
            (0x27f0d80, 'bf 58000000', 'bytes', None, 'inner future allocation size'),
            (0x157c696, '803801', 'bytes', None, 'Display thunk: tag == 1 selects the V6 formatter'),
        ],
    },
    '115': {
        'future': (0x29738e0, 0x2977559),
        'state_byte': 0xb3,
        'ip_offset': 0xb4,
        'out_path': {'cap': 0x0, 'ptr': 0x8, 'len': 0x10},
        'request_table': (0x600060, 0x2973998),
        'state_table': (0x5fff80, 0x297390e),
        'vtable_slot': 0x6441e98,
        'display_thunk': (0x1687690, 0x16876a7),
        'logger': (0x150b310, 0x150baaf),
        'log_location': (156, 21),
        'anchors': [
            (0x29738f7, '0fb686 b3000000', 'bytes', None, 'state byte: movzx eax,[rsi+0xb3]'),
            (0x2973950, 'f30f6f83 a0000000', 'bytes', None, 'copy 16 IpAddr bytes from input+0xa0'),
            (0x2973958, 'f30f7f83 b4000000', 'bytes', None, 'into future+0xb4'),
            (0x2973960, '0fb683 b0000000', 'bytes', None, 'copy the 17th IpAddr byte from input+0xb0'),
            (0x2973967, '8883 c4000000', 'bytes', None, 'into future+0xc4'),
            (0x2973988, '488d0d d1c6c8fd', 'lea', 0x600060, 'request jump table (niche-encoded index)'),
            (0x2973998, '4c8b7b18', 'bytes', None, 'FileSnapshot arm entry'),
            (0x29739a9, '4c8b2b', 'bytes', None, 'out_path cap -> r13'),
            (0x29739ac, '488b6b08', 'bytes', None, 'out_path ptr -> rbp'),
            (0x29739b7, '80bb b4000000 00', 'bytes', None, 'IpAddr tag == 0 (V4)?'),
            (0x29739be, '0f84 eb300000', 'jcc', 0x2976aaf, 'V4: go to the dword compare'),
            (0x29739c4, 'f30f6f83 b5000000', 'bytes', None, 'V6: load 16 octets at future+0xb5'),
            (0x29739cc, '660f7405 4cf7adfd', 'pcmpeqb', 0x453120, 'compare with the ::1 constant'),
            (0x29739d4, '660fd7c8', 'bytes', None, 'pmovmskb ecx,xmm0'),
            (0x29739d8, '81f9 ffff0000', 'bytes', None, 'all 16 bytes equal?'),
            (0x29739de, '0f85 db300000', 'jcc', 0x2976abf, 'not ::1: reject'),
            (0x29739ef, '488b5310', 'bytes', None, 'out_path len -> rdx'),
            (0x29739f3, '4883fa65', 'bytes', None, 'len < 0x65?'),
            (0x29739f7, '0f82 65310000', 'jcc', 0x2976b62, 'yes: build the file_snapshot future'),
            (0x2973a11, 'ff15 89bab603', 'call_got', 0x635de30, 'no: free out_path'),
            (0x2976aaf, '81bb b5000000 7f000001', 'bytes', None, 'V4 octets == 127.0.0.1 exactly'),
            (0x2976ab9, '0f84 25cfffff', 'jcc', 0x29739e4, 'equal: continue to the length check'),
            (0x2976ac2, '488d83 b4000000', 'bytes', None, 'reject: &IpAddr for the log argument'),
            (0x2976aef, '488b05 82b4b603', 'load_got', 0x1687690, 'IpAddr Display thunk'),
            (0x2976afe, '488d05 6aeeabfd', 'lea_template', None, 'the diagnostic template (inner)'),
            (0x2976b2d, '488d05 dc9ac8ff', 'lea', 0x2600610, 'Display of the formatted inner template'),
            (0x2976b3c, '488d35 144dacfd', 'lea_outer', None, 'outer one-argument template'),
            (0x2976b43, '488d0d 56b3ac03', 'lea_location', None, 'log Location'),
            (0x2976b57, 'ff15 bb9fb603', 'call_got', 0x150b310, 'critical logger'),
            (0x2976b5d, 'e9 ceebffff', 'jmp', 0x2975730, 'then free out_path and finish'),
            (0x1687696, '803801', 'bytes', None, 'Display thunk: tag == 1 selects the V6 formatter'),
        ],
    },
}
OUTER_TEMPLATE = b'\xc0\x00'


def checked(release):
    rel = TARGETS[release]
    data = (ROOT / rel).read_bytes()
    item = manifest_item(ROOT, rel)
    if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise EvidenceError(f'{rel}: size/SHA-256 mismatch')
    return data, item['sha256']


def location(data, secs, relocs, va):
    if va not in relocs:
        raise EvidenceError(f'Location {va:#x} has no RELATIVE relocation')
    length, line, col = struct.unpack_from('<QII', bytes_in_section(data, secs, va + 8, 16))
    path = bytes_in_section(data, secs, relocs[va], length).decode()
    return path, line, col


def rip_target(insn, va):
    if insn[:1] == b'\xe8' or insn[:1] == b'\xe9':
        return va + 5 + struct.unpack_from('<i', insn, 1)[0]
    if insn[:2] in (b'\x0f\x84', b'\x0f\x85', b'\x0f\x82'):
        return va + 6 + struct.unpack_from('<i', insn, 2)[0]
    if insn[:2] == b'\xff\x15':
        return va + 6 + struct.unpack_from('<i', insn, 2)[0]
    if insn[:4] == b'\x66\x0f\x74\x05':
        return va + 8 + struct.unpack_from('<i', insn, 4)[0]
    if insn[0] in (0x48, 0x4c) and insn[1] in (0x8d, 0x8b) and insn[2] & 0xc7 == 0x05:
        return va + 7 + struct.unpack_from('<i', insn, 3)[0]
    raise EvidenceError(f'no RIP-relative operand at {va:#x}')


def lea_sites(text, text_va, start, end, target):
    out = []
    lo, hi = start - text_va, end - text_va
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text[lo:hi]):
        p = lo + m.start()
        if text_va + p + 7 + struct.unpack_from('<i', text, p + 3)[0] == target:
            out.append(text_va + p)
    return out


def owner(fdes, va):
    for s, e in fdes.items():
        if s <= va < e:
            return s, e
    raise EvidenceError(f'{va:#x} is not inside any FDE')


def check_anchor(data, secs, relocs, release, cfg, template_va, anchor):
    va, hexbytes, kind, want, meaning = anchor
    raw = bytes.fromhex(hexbytes.replace(' ', ''))
    got = bytes_in_section(data, secs, va, len(raw))
    if got != raw:
        raise EvidenceError(f'#{release} {va:#x}: bytes {got.hex()} != {raw.hex()}')
    rec = {'va': hex(va), 'bytes': raw.hex(), 'kind': kind, 'meaning': meaning}
    if kind == 'bytes':
        return rec
    tgt = rip_target(raw, va)
    rec['target'] = hex(tgt)
    if kind in ('jcc', 'jmp', 'call_rel', 'lea'):
        if tgt != want:
            raise EvidenceError(f'#{release} {va:#x}: target {tgt:#x} != {want:#x}')
    elif kind in ('call_got', 'load_got'):
        if relocs.get(tgt) != want:
            raise EvidenceError(f'#{release} {va:#x}: slot {tgt:#x} -> {relocs.get(tgt)} != {want:#x}')
        rec['slot'], rec['target'] = hex(tgt), hex(want)
    elif kind == 'pcmpeqb':
        if tgt != want or bytes_in_section(data, secs, tgt, 16) != IPV6_LOOPBACK:
            raise EvidenceError(f'#{release} {va:#x}: 16-byte operand at {tgt:#x} is not ::1')
        rec['constant'] = IPV6_LOOPBACK.hex()
    elif kind == 'lea_template':
        if tgt != template_va:
            raise EvidenceError(f'#{release} {va:#x}: lea target {tgt:#x} != template {template_va:#x}')
    elif kind == 'lea_outer':
        if bytes_in_section(data, secs, tgt, 2) != OUTER_TEMPLATE:
            raise EvidenceError(f'#{release} {va:#x}: outer template at {tgt:#x} is not one placeholder')
    elif kind == 'lea_location':
        path, line, col = location(data, secs, relocs, tgt)
        if (path, line, col) != (HANDLER[release], *cfg['log_location']):
            raise EvidenceError(f'#{release} {va:#x}: Location {path}:{line}:{col} != {cfg["log_location"]}')
        rec['source'] = f'{path}:{line}:{col}'
    return rec


def crit_marker_refs(data, secs, relocs, text, text_va, fde):
    """LEA sites inside `fde` whose target names base/src/crit_msg.rs.

    #94 reaches it as a panic Location record (path, len, line, col) behind a RELATIVE slot;
    #115 reaches the plain path string in .rodata.
    """
    out = []
    lo, hi = fde[0] - text_va, fde[1] - text_va
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text[lo:hi]):
        p = lo + m.start()
        tgt = text_va + p + 7 + struct.unpack_from('<i', text, p + 3)[0]
        try:
            if tgt in relocs:
                length, line, col = struct.unpack_from('<QII', bytes_in_section(data, secs, tgt + 8, 16))
                if 0 < length < 256 and bytes_in_section(data, secs, relocs[tgt], length).endswith(CRIT_MARKER):
                    out.append({'lea': hex(text_va + p), 'location': hex(tgt), 'line': line, 'column': col})
            elif bytes_in_section(data, secs, tgt, len(CRIT_MARKER) + 1) == CRIT_MARKER + b'\0':
                out.append({'lea': hex(text_va + p), 'string': hex(tgt)})
        except (EvidenceError, struct.error):
            continue
    return out


def table_index(data, secs, table_va, target, limit=128):
    for i in range(limit):
        off = struct.unpack_from('<i', bytes_in_section(data, secs, table_va + 4 * i, 4))[0]
        if table_va + off == target:
            return i
    raise EvidenceError(f'jump table {table_va:#x} has no entry for {target:#x}')


def check_inner_vtable(data, secs, relocs, fdes, release, vt):
    """Bind the boxed inner future's vtable layout: slot 0 is drop_in_place, then size, align, poll."""
    va = vt['va']
    for slot, key in ((0, 'drop'), (3, 'poll')):
        tgt = relocs.get(va + 8 * slot)
        if tgt != vt[key]:
            raise EvidenceError(f'#{release}: inner vtable slot {slot} ({va + 8 * slot:#x}) -> '
                              f'{tgt if tgt is None else hex(tgt)} != {vt[key]:#x}')
        if owner(fdes, tgt)[0] != tgt:
            raise EvidenceError(f'#{release}: inner vtable {key} {tgt:#x} is not an FDE start')
    for slot, key in ((1, 'size'), (2, 'align')):
        if va + 8 * slot in relocs:
            raise EvidenceError(f'#{release}: inner vtable {key} slot is relocated, expected a literal')
        got = int.from_bytes(bytes_in_section(data, secs, va + 8 * slot, 8), 'little')
        if got != vt[key]:
            raise EvidenceError(f'#{release}: inner vtable {key} {got:#x} != {vt[key]:#x}')
    return {'va': hex(va), 'slot0_drop_in_place': hex(vt['drop']), 'slot1_size': hex(vt['size']),
            'slot2_align': hex(vt['align']), 'slot3_poll': hex(vt['poll'])}


def analyze(data, secs, relocs, fdes, release):
    cfg = ANCHORS[release]
    hits = [m.start() for m in re.finditer(re.escape(TEMPLATE), data)]
    if len(hits) != 1:
        raise EvidenceError(f'#{release}: template occurs {len(hits)} times')
    rodata = secs['.rodata']
    template_va = rodata['addr'] + hits[0] - rodata['offset']
    if not rodata['offset'] <= hits[0] < rodata['offset'] + rodata['size']:
        raise EvidenceError(f'#{release}: template is outside .rodata')
    t = secs['.text']
    text = data[t['offset']:t['offset'] + t['size']]
    sites = lea_sites(text, t['addr'], t['addr'], t['addr'] + t['size'], template_va)
    if len(sites) != 1:
        raise EvidenceError(f'#{release}: template has {len(sites)} LEA sites')
    start, end = owner(fdes, sites[0])
    if (start, end) != cfg['future']:
        raise EvidenceError(f'#{release}: owner FDE {start:#x}..{end:#x} != {cfg["future"]}')
    if relocs.get(cfg['vtable_slot']) != start:
        raise EvidenceError(f'#{release}: vtable slot {cfg["vtable_slot"]:#x} does not point at the future')
    inner = None
    if 'inner_vtable' in cfg:
        inner = check_inner_vtable(data, secs, relocs, fdes, release, cfg['inner_vtable'])
    if owner(fdes, cfg['display_thunk'][0]) != cfg['display_thunk']:
        raise EvidenceError(f'#{release}: Display thunk FDE mismatch')
    if owner(fdes, cfg['logger'][0]) != cfg['logger']:
        raise EvidenceError(f'#{release}: logger FDE mismatch')
    crit_refs = crit_marker_refs(data, secs, relocs, text, t['addr'], cfg['logger'])
    if not crit_refs:
        raise EvidenceError(f'#{release}: logger never references {CRIT_MARKER.decode()}')
    req_table, req_arm = cfg['request_table']
    st_table, st_entry = cfg['state_table']
    rec = {
        'path': TARGETS[release],
        'template_va': hex(template_va),
        'template_lea': hex(sites[0]),
        'future_fde': [hex(start), hex(end)],
        'future_bytes': end - start,
        'future_vtable_slot': hex(cfg['vtable_slot']),
        **({'inner_future_vtable': inner} if inner else {}),
        'state_byte_offset': hex(cfg['state_byte']),
        'ip_addr_offset': hex(cfg['ip_offset']),
        'out_path_offsets': {k: hex(v) for k, v in cfg['out_path'].items()},
        'request_table': {'va': hex(req_table), 'file_snapshot_index': table_index(data, secs, req_table, req_arm),
                          'arm': hex(req_arm)},
        'state_table': {'va': hex(st_table), 'initial_index': table_index(data, secs, st_table, st_entry),
                        'entry': hex(st_entry)},
        'display_thunk_fde': [hex(v) for v in cfg['display_thunk']],
        'logger_fde': [hex(v) for v in cfg['logger']],
        'logger_crit_marker': crit_refs,
        'rules': {
            'ipv4': 'IpAddr tag 0 and octets == 127.0.0.1 (dword 0x0100007f); any other 127/8 address is rejected',
            'ipv6': 'IpAddr tag 1 and all 16 octets == ::1',
            'out_path_len': f'len < {OUT_PATH_BOUND:#x} ({OUT_PATH_BOUND}) bytes proceeds; otherwise the String is freed and a reject result is returned without the log',
            'reject_log': 'template + Display(&IpAddr) through the critical logger, then the String is freed',
        },
        'anchors': [check_anchor(data, secs, relocs, release, cfg, template_va, a) for a in cfg['anchors']],
    }
    return rec


def build():
    result = {'schema': 'hyperliquid-source/re-012-file-snapshot-localhost-gate/v1', 'targets': {}}
    for release in TARGETS:
        data, sha = checked(release)
        secs = sections(data)
        relocs = relative_relocs(data, secs)
        fdes = fde_extents(data, secs)
        rec = analyze(data, secs, relocs, fdes, release)
        rec['sha256'] = sha
        result['targets'][release] = rec
    return result


def render(result):
    return (json.dumps(result, indent=1, sort_keys=True) + '\n').encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', type=Path, default=OUT)
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args(argv)
    path = args.out / 'file-snapshot-localhost-gate.json'
    data = render(build())
    if args.check:
        if not path.is_file() or path.read_bytes() != data:
            print(f'{path}: differs from regenerated output', file=sys.stderr)
            return 1
        print(f'{path}: OK')
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
